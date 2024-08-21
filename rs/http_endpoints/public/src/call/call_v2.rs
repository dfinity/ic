//! Module that deals with requests to /api/v2/canister/.../call

use super::{IngressError, IngressValidator};
use crate::{
    common::{Cbor, CborUserError, WithTimeout},
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

pub struct CallServiceV2;

impl CallServiceV2 {
    pub(crate) fn route() -> &'static str {
        "/api/v2/canister/:effective_canister_id/call"
    }

    pub(crate) fn new_router(call_handler: IngressValidator) -> Router {
        Router::new().route_service(
            Self::route(),
            axum::routing::post(call_v2)
                .with_state(call_handler)
                .layer(ServiceBuilder::new().layer(DefaultBodyLimit::disable())),
        )
    }

    pub fn new_service(
        call_handler: IngressValidator,
    ) -> BoxCloneService<Request<Body>, Response, Infallible> {
        let router = Self::new_router(call_handler);
        BoxCloneService::new(router.into_service())
    }
}

/// Handles a call to /api/v2/canister/../call
async fn call_v2(
    axum::extract::Path(effective_canister_id): axum::extract::Path<CanisterId>,
    State(call_handler): State<IngressValidator>,
    WithTimeout(Cbor(request)): WithTimeout<Cbor<HttpRequestEnvelope<HttpCallContent>>>,
) -> Result<impl IntoResponse, Response> {
    call_handler
        .validate_ingress_message(request, effective_canister_id)
        .await
        .map_err(|err| match err {
            IngressError::UserError(user_error) => CborUserError(user_error).into_response(),
            IngressError::HttpError(HttpError { status, message }) => {
                (status, message).into_response()
            }
        })?
        .try_submit()
        .map_err(|HttpError { status, message }| (status, message).into_response())?;

    Ok(StatusCode::ACCEPTED)
}
