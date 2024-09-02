//! Module that deals with requests to /api/v2/canister/.../call

use super::{IngressError, IngressValidator, IngressWatcherHandle};
use crate::{
    common::{Cbor, CborUserError, WithTimeout},
    HttpError,
};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    response::{IntoResponse, Response},
    Router,
};
use http::Request;
use hyper::StatusCode;
use ic_logger::warn;
use ic_types::{
    messages::{HttpCallContent, HttpRequestEnvelope},
    CanisterId,
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tokio_util::time::FutureExt;
use tower::{util::BoxCloneService, ServiceBuilder};

/// The maximum time we wait for a message to be certified
/// before recording its certification time.
const MAX_CERTIFICATION_WAIT_TIME: Duration = Duration::from_secs(16);

/// Used to bound the number of tokio tasks spawned for tracking the
/// certification time of messages. 10_000 is chosen as it is roughly
/// the pool size.
const MAX_CONCURRENT_TRACKING_TASKS: usize = 10_000;

#[derive(Clone)]
pub struct AsynchronousCallHandlerState {
    ingress_watcher_handle: Option<IngressWatcherHandle>,
    ingress_validator: IngressValidator,
    ingress_tracking_semaphore: Arc<Semaphore>,
}

impl AsynchronousCallHandlerState {
    pub fn new(
        ingress_validator: IngressValidator,
        ingress_watcher_handle: Option<IngressWatcherHandle>,
    ) -> Self {
        Self {
            ingress_validator,
            ingress_watcher_handle,
            ingress_tracking_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_TRACKING_TASKS)),
        }
    }
}

pub(super) struct Accepted;

impl IntoResponse for Accepted {
    fn into_response(self) -> Response {
        StatusCode::ACCEPTED.into_response()
    }
}

impl IntoResponse for IngressError {
    fn into_response(self) -> Response {
        match self {
            IngressError::UserError(user_error) => CborUserError(user_error).into_response(),
            IngressError::HttpError(HttpError { status, message }) => {
                (status, message).into_response()
            }
        }
    }
}

pub(crate) fn route() -> &'static str {
    "/api/v2/canister/:effective_canister_id/call"
}

pub(crate) fn new_router(
    ingress_validator: IngressValidator,
    ingress_watcher_handle: Option<IngressWatcherHandle>,
) -> Router {
    Router::new().route_service(
        route(),
        axum::routing::post(handler)
            .with_state(AsynchronousCallHandlerState::new(
                ingress_validator,
                ingress_watcher_handle,
            ))
            .layer(ServiceBuilder::new().layer(DefaultBodyLimit::disable())),
    )
}

pub fn new_service(
    call_handler: IngressValidator,
) -> BoxCloneService<Request<Body>, Response, Infallible> {
    let router = new_router(call_handler, None);
    BoxCloneService::new(router.into_service())
}

pub(super) type CallV2Response = Result<Accepted, IngressError>;

/// Handles a call to /api/v2/canister/../call
pub(super) async fn handler(
    Path(effective_canister_id): Path<CanisterId>,
    State(AsynchronousCallHandlerState {
        ingress_tracking_semaphore,
        ingress_validator,
        ingress_watcher_handle,
    }): State<AsynchronousCallHandlerState>,
    WithTimeout(Cbor(request)): WithTimeout<Cbor<HttpRequestEnvelope<HttpCallContent>>>,
) -> CallV2Response {
    let logger = ingress_validator.log.clone();

    let ingress_submitter = ingress_validator
        .validate_ingress_message(request, effective_canister_id)
        .await?;

    let message_id = ingress_submitter.message_id();

    ingress_submitter.try_submit()?;

    // We spawn a task to register the certification time of the message.
    // The subscriber in the spawned task records the certification time of the message
    // when `wait_for_certification` is called.
    if let Some(ingress_watcher_handle) = ingress_watcher_handle {
        tokio::spawn(async move {
            // We acquire a permit to bound the number of concurrent tasks. If no permits are available,
            // we return early to terminate the task.
            let ingress_tracking_permit = ingress_tracking_semaphore.try_acquire();
            let Ok(_permit) = ingress_tracking_permit else {
                warn!(
                    logger,
                    "Failed to acquire permit for tracking certification time of message."
                );
                return;
            };

            let Ok(certification_tracker) = ingress_watcher_handle
                .subscribe_for_certification(message_id)
                .await
            else {
                return;
            };

            let _ = certification_tracker
                .wait_for_certification()
                .timeout(MAX_CERTIFICATION_WAIT_TIME)
                .await;
        });
    }

    Ok(Accepted)
}
