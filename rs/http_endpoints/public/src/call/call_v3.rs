//! Module that deals with requests to /api/v3/canister/.../call.

use super::{
    ingress_watcher::{IngressWatcherHandle, SubscriptionError},
    IngressError, IngressValidator,
};
use crate::{
    common::{into_cbor, Cbor},
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
use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, Label, Path};
use ic_interfaces_state_manager::StateReader;
use ic_logger::{error, warn};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    messages::{Blob, Certificate, CertificateDelegation, HttpCallContent, HttpRequestEnvelope},
    CanisterId,
};
use serde_cbor::Value as CBOR;
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, RwLock},
    time::Duration,
};
use tower::{util::BoxCloneService, ServiceBuilder};

#[derive(Clone)]
pub struct CallServiceV3 {
    ingress_watcher_handle: IngressWatcherHandle,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ingress_message_certificate_timeout_seconds: u64,
    call_handler: IngressValidator,
}

impl CallServiceV3 {
    pub(crate) fn route() -> &'static str {
        "/api/v3/canister/:effective_canister_id/call"
    }

    pub(crate) fn new_router(
        call_handler: IngressValidator,
        ingress_watcher_handle: IngressWatcherHandle,
        ingress_message_certificate_timeout_seconds: u64,
        delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> Router {
        let call_service = Self {
            delegation_from_nns,
            ingress_watcher_handle,
            ingress_message_certificate_timeout_seconds,
            call_handler,
            state_reader,
        };

        Router::new().route_service(
            Self::route(),
            axum::routing::post(call_sync_v3)
                .with_state(call_service)
                .layer(ServiceBuilder::new().layer(DefaultBodyLimit::disable())),
        )
    }

    #[allow(dead_code)]
    pub fn new_service(
        call_handler: IngressValidator,
        ingress_watcher_handle: IngressWatcherHandle,
        ingress_message_certificate_timeout_seconds: u64,
        delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> BoxCloneService<Request<Body>, Response, Infallible> {
        let router = Self::new_router(
            call_handler,
            ingress_watcher_handle,
            ingress_message_certificate_timeout_seconds,
            delegation_from_nns,
            state_reader,
        );
        BoxCloneService::new(router.into_service())
    }
}

/// Handles a call to /api/v3/canister/../call
async fn call_sync_v3(
    axum::extract::Path(effective_canister_id): axum::extract::Path<CanisterId>,
    State(CallServiceV3 {
        call_handler,
        ingress_watcher_handle,
        ingress_message_certificate_timeout_seconds,
        state_reader,
        delegation_from_nns,
    }): State<CallServiceV3>,
    request: Cbor<HttpRequestEnvelope<HttpCallContent>>,
) -> Result<impl IntoResponse, Response> {
    let log = call_handler.log.clone();

    let ingress_submitter = call_handler
        .validate_ingress_message(request, effective_canister_id)
        .await
        .map_err(|err| match err {
            IngressError::UserError(user_err) => Cbor(CBOR::Map(BTreeMap::from([
                (
                    CBOR::Text("status".to_string()),
                    CBOR::Text("non_replicated_rejection".to_string()),
                ),
                (
                    CBOR::Text("error_code".to_string()),
                    CBOR::Text(user_err.code().to_string()),
                ),
                (
                    CBOR::Text("reject_message".to_string()),
                    CBOR::Text(user_err.description().to_string()),
                ),
                (
                    CBOR::Text("reject_code".to_string()),
                    CBOR::Integer(user_err.reject_code() as i128),
                ),
            ])))
            .into_response(),
            IngressError::HttpError(HttpError { status, message }) => {
                (status, message).into_response()
            }
        })?;

    let message_id = ingress_submitter.message_id();

    let certification_subscriber = match tokio::time::timeout(
        Duration::from_secs(ingress_message_certificate_timeout_seconds),
        ingress_watcher_handle.subscribe_for_certification(message_id.clone()),
    )
    .await
    {
        Ok(Ok(message_subscriber)) => Ok(message_subscriber),
        Ok(Err(SubscriptionError::DuplicateSubscriptionError)) => {
            // TODO: At this point we could return early without submitting the ingress message.
            Err("Duplicate request. Message is already being tracked and executed.")
        }
        Ok(Err(SubscriptionError::IngressWatcherNotRunning { error_message })) => {
            // TODO: Send a warning or notification.
            // This probably means that the ingress watcher panicked.
            error!(
                log,
                "Error while waiting for subscriber of ingress message: {}", error_message
            );
            Err("Could not track the ingress message. Please try /read_state for the status.")
        }
        Err(_) => {
            warn!(
                log,
                "Timed out while submitting a certification subscription.";
            );
            Err("Could not track the ingress message. Please try /read_state for the status.")
        }
    };

    ingress_submitter
        .try_submit()
        .map_err(|HttpError { status, message }| (status, message).into_response())?;

    let make_accepted_response =
        |reason: &str| Ok((StatusCode::ACCEPTED, reason.to_string()).into_response());

    let certification_subscriber = match certification_subscriber {
        Ok(certification_subscriber) => certification_subscriber,
        Err(reason) => {
            return make_accepted_response(reason);
        }
    };

    match tokio::time::timeout(
        Duration::from_secs(ingress_message_certificate_timeout_seconds),
        certification_subscriber,
    )
    .await
    {
        Ok(()) => (),
        Err(_) => {
            return make_accepted_response(
                "Message did not complete execution and certification within the replica defined timeout.",
            );
        }
    }

    let certified_state_reader = match tokio::task::spawn_blocking(move || {
        state_reader.get_certified_state_snapshot()
    })
    .await
    {
        Ok(Some(certified_state_reader)) => certified_state_reader,
        Ok(None) | Err(_) => {
            return make_accepted_response(
                "Certified state is not available. Please try /read_state.",
            );
        }
    };

    // We always add time path to comply with the IC spec.
    let time_path = Path::from(Label::from("time"));
    let request_status_path =
        Path::from(vec![Label::from("request_status"), Label::from(message_id)]);

    let tree: ic_crypto_tree_hash::LabeledTree<()> =
        sparse_labeled_tree_from_paths(&[time_path, request_status_path])
            .expect("Path is within length bound.");

    let Some((tree, certification)) = certified_state_reader.read_certified_state(&tree) else {
        return make_accepted_response("Certified state is not available. Please try /read_state.");
    };

    let delegation_from_nns = delegation_from_nns.read().unwrap().clone();
    let signature = certification.signed.signature.signature.get().0;
    let certified_response = Cbor(CBOR::Map(BTreeMap::from([
        (
            CBOR::Text("status".to_string()),
            CBOR::Text("replied".to_string()),
        ),
        (
            CBOR::Text("certificate".to_string()),
            CBOR::Bytes(into_cbor(&Certificate {
                tree,
                signature: Blob(signature),
                delegation: delegation_from_nns,
            })),
        ),
    ])));

    Ok(certified_response.into_response())
}
