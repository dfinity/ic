//! Module that deals with requests to /api/v3/canister/.../call.

use super::{
    ingress_watcher::{IngressWatcherHandle, SubscriptionError},
    IngressError, IngressValidator,
};
use crate::{
    common::{into_cbor, Cbor, WithTimeout},
    metrics::{
        HttpHandlerMetrics, CALL_V3_EARLY_RESPONSE_CERTIFICATION_TIMEOUT,
        CALL_V3_EARLY_RESPONSE_DUPLICATE_SUBSCRIPTION,
        CALL_V3_EARLY_RESPONSE_INGRESS_WATCHER_NOT_RUNNING,
        CALL_V3_EARLY_RESPONSE_SUBSCRIPTION_TIMEOUT,
    },
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
use ic_crypto_tree_hash::{
    sparse_labeled_tree_from_paths, Label, LookupStatus, MixedHashTree, Path,
};
use ic_error_types::UserError;
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
use tokio_util::time::FutureExt;
use tower::{util::BoxCloneService, ServiceBuilder};

const LOG_EVERY_N_SECONDS: i32 = 10;

/// The timeout duration used when creating a subscriber for the ingres message,
/// by calling [`IngressWatcherHandle::subscribe_for_certification`].
const SUBSCRIPTION_TIMEOUT: Duration = Duration::from_secs(1);

enum CallV3Response {
    Certificate(Certificate),
    UserError(UserError),
    Accepted(&'static str),
    HttpError(HttpError),
}

impl IntoResponse for CallV3Response {
    fn into_response(self) -> Response {
        match self {
            CallV3Response::Certificate(cert) => Cbor(CBOR::Map(BTreeMap::from([
                (
                    CBOR::Text("status".to_string()),
                    CBOR::Text("replied".to_string()),
                ),
                (
                    CBOR::Text("certificate".to_string()),
                    CBOR::Bytes(into_cbor(&cert)),
                ),
            ])))
            .into_response(),

            CallV3Response::UserError(user_err) => Cbor(CBOR::Map(BTreeMap::from([
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

            CallV3Response::Accepted(reason) => {
                (StatusCode::ACCEPTED, reason.to_string()).into_response()
            }

            CallV3Response::HttpError(HttpError { status, message }) => {
                (status, message).into_response()
            }
        }
    }
}

impl From<IngressError> for CallV3Response {
    fn from(err: IngressError) -> Self {
        match err {
            IngressError::UserError(user_err) => CallV3Response::UserError(user_err),
            IngressError::HttpError(http_err) => CallV3Response::HttpError(http_err),
        }
    }
}

#[derive(Clone)]
pub struct CallServiceV3 {
    ingress_watcher_handle: IngressWatcherHandle,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    metrics: HttpHandlerMetrics,
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
        metrics: HttpHandlerMetrics,
        ingress_message_certificate_timeout_seconds: u64,
        delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> Router {
        let call_service = Self {
            delegation_from_nns,
            ingress_watcher_handle,
            metrics,
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

    pub fn new_service(
        call_handler: IngressValidator,
        ingress_watcher_handle: IngressWatcherHandle,
        metrics: HttpHandlerMetrics,
        ingress_message_certificate_timeout_seconds: u64,
        delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> BoxCloneService<Request<Body>, Response, Infallible> {
        let router = Self::new_router(
            call_handler,
            ingress_watcher_handle,
            metrics,
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
        metrics,
        ingress_message_certificate_timeout_seconds,
        state_reader,
        delegation_from_nns,
    }): State<CallServiceV3>,
    WithTimeout(Cbor(request)): WithTimeout<Cbor<HttpRequestEnvelope<HttpCallContent>>>,
) -> CallV3Response {
    let log = call_handler.log.clone();

    let ingress_submitter = match call_handler
        .validate_ingress_message(request, effective_canister_id)
        .await
    {
        Ok(ingress_submitter) => ingress_submitter,
        Err(err) => return CallV3Response::from(err),
    };

    let message_id = ingress_submitter.message_id();

    let certification_subscriber = match ingress_watcher_handle
        .subscribe_for_certification(message_id.clone())
        .timeout(SUBSCRIPTION_TIMEOUT)
        .await
    {
        Ok(Ok(message_subscriber)) => Ok(message_subscriber),
        Ok(Err(SubscriptionError::DuplicateSubscriptionError)) => {
            // TODO: At this point we could return early without submitting the ingress message.
            Err((
                "Duplicate request. Message is already being tracked and executed.",
                CALL_V3_EARLY_RESPONSE_DUPLICATE_SUBSCRIPTION,
            ))
        }
        Ok(Err(SubscriptionError::IngressWatcherNotRunning { error_message })) => {
            // TODO: Send a warning or notification.
            // This probably means that the ingress watcher panicked.
            error!(
                every_n_seconds => LOG_EVERY_N_SECONDS,
                log,
                "Error while waiting for subscriber of ingress message: {}", error_message
            );
            Err((
                "Could not track the ingress message. Please try /read_state for the status.",
                CALL_V3_EARLY_RESPONSE_INGRESS_WATCHER_NOT_RUNNING,
            ))
        }
        Err(_) => {
            warn!(
                every_n_seconds => LOG_EVERY_N_SECONDS,
                log,
                "Timed out while submitting a certification subscription.";
            );
            Err((
                "Could not track the ingress message. Please try /read_state for the status.",
                CALL_V3_EARLY_RESPONSE_SUBSCRIPTION_TIMEOUT,
            ))
        }
    };

    let ingres_submission = ingress_submitter.try_submit();

    if let Err(ingress_submission) = ingres_submission {
        return CallV3Response::HttpError(ingress_submission);
    }
    // The ingress message was submitted successfully.
    // From this point on we only return a certificate or `Accepted 202``.
    let certification_subscriber = match certification_subscriber {
        Ok(certification_subscriber) => certification_subscriber,
        Err((reason, metric_label)) => {
            metrics
                .call_v3_early_response_trigger_total
                .with_label_values(&[metric_label])
                .inc();
            return CallV3Response::Accepted(reason);
        }
    };

    match certification_subscriber
        .wait_for_certification()
        .timeout(Duration::from_secs(
            ingress_message_certificate_timeout_seconds,
        ))
        .await
    {
        Ok(()) => (),
        Err(_) => {
            metrics
                .call_v3_early_response_trigger_total
                .with_label_values(&[CALL_V3_EARLY_RESPONSE_CERTIFICATION_TIMEOUT])
                .inc();
            return CallV3Response::Accepted(
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
            return CallV3Response::Accepted(
                "Certified state is not available. Please try /read_state.",
            );
        }
    };

    // We always add time path to comply with the IC spec.
    let time_path = Path::from(Label::from("time"));
    let request_status_path = Path::from(vec![
        Label::from("request_status"),
        Label::from(message_id.clone()),
    ]);

    let tree: ic_crypto_tree_hash::LabeledTree<()> =
        sparse_labeled_tree_from_paths(&[time_path, request_status_path])
            .expect("Path is within length bound.");

    let Some((tree, certification)) = certified_state_reader.read_certified_state(&tree) else {
        return CallV3Response::Accepted(
            "Certified state is not available. Please try /read_state.",
        );
    };

    {
        let status_path = [&b"request_status"[..], message_id.as_ref(), &b"status"[..]];

        let status_label = match tree.lookup(&status_path) {
            LookupStatus::Found(MixedHashTree::Leaf(status)) => String::from_utf8(status.clone())
                .unwrap_or_else(|_| "invalid_utf8_status".to_string()),
            // This should never happen. Otherwise the tree is not following the spec.
            LookupStatus::Found(_) => "Status not a leaf".to_string(),
            LookupStatus::Absent | LookupStatus::Unknown => "unknown".to_string(),
        };

        metrics
            .call_v3_certificate_status_total
            .with_label_values(&[&status_label])
            .inc();
    }

    let delegation_from_nns = delegation_from_nns.read().unwrap().clone();
    let signature = certification.signed.signature.signature.get().0;

    CallV3Response::Certificate(Certificate {
        tree,
        signature: Blob(signature),
        delegation: delegation_from_nns,
    })
}
