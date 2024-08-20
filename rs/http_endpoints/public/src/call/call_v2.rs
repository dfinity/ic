//! Module that deals with requests to /api/v2/canister/.../call

use super::{IngressError, IngressValidator, IngressWatcherHandle};
use crate::{
    common::{Cbor, CborUserError, WithTimeout},
    metrics::HttpHandlerMetrics,
    HttpError,
};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    response::{IntoResponse, Response},
    Router,
};
use http::Request;
use hyper::StatusCode;
use ic_types::{
    messages::{HttpCallContent, HttpRequestEnvelope},
    CanisterId,
};
use std::convert::Infallible;
use tower::{util::BoxCloneService, ServiceBuilder};

#[derive(Clone)]
pub struct CallServiceV2 {
    ingress_watcher_handle: IngressWatcherHandle,
    ingress_validator: IngressValidator,
}

impl CallServiceV2 {
    pub(crate) fn route() -> &'static str {
        "/api/v2/canister/:effective_canister_id/call"
    }

    pub(crate) fn new_router(
        ingress_validator: IngressValidator,
        ingress_watcher_handle: IngressWatcherHandle,
    ) -> Router {
        Router::new().route_service(
            Self::route(),
            axum::routing::post(call_v2)
                .with_state(Self {
                    ingress_validator,
                    ingress_watcher_handle,
                })
                .layer(ServiceBuilder::new().layer(DefaultBodyLimit::disable())),
        )
    }

    pub fn new_service(
        call_handler: IngressValidator,
        ingress_watcher_handle: IngressWatcherHandle,
    ) -> BoxCloneService<Request<Body>, Response, Infallible> {
        let router = Self::new_router(call_handler, ingress_watcher_handle);
        BoxCloneService::new(router.into_service())
    }
}

/// Handles a call to /api/v2/canister/../call
async fn call_v2(
    axum::extract::Path(effective_canister_id): axum::extract::Path<CanisterId>,
    State(CallServiceV2 {
        ingress_validator,
        ingress_watcher_handle,
    }): State<CallServiceV2>,
    WithTimeout(Cbor(request)): WithTimeout<Cbor<HttpRequestEnvelope<HttpCallContent>>>,
) -> Result<impl IntoResponse, Response> {
    let ingress_submitter = ingress_validator
        .validate_ingress_message(request, effective_canister_id)
        .await
        .map_err(|err| match err {
            IngressError::UserError(user_error) => CborUserError(user_error).into_response(),
            IngressError::HttpError(HttpError { status, message }) => {
                (status, message).into_response()
            }
        })?;

    let message_id = ingress_submitter.message_id();

    // We spawn a task to register the certification time of the message.
    // The subscriber in the spawned task records the certification time of the message
    // when `wait_for_certification` is called.
    tokio::spawn(async move {
        let Ok(certification_tracker) = ingress_watcher_handle
            .subscribe_for_certification(message_id)
            .await
        else {
            return;
        };

        certification_tracker.wait_for_certification().await;
    });

    ingress_submitter
        .try_submit()
        .map_err(|HttpError { status, message }| (status, message).into_response())?;

    Ok(StatusCode::ACCEPTED)
}
