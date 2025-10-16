//! Module that deals with requests to /api/{v3,v4}/canister/.../call.

use super::{
    IngressError, IngressValidator,
    ingress_watcher::{IngressWatcherHandle, SubscriptionError},
};
use crate::{
    HttpError,
    common::{Cbor, WithTimeout, into_cbor},
    metrics::{
        HttpHandlerMetrics, SYNC_CALL_EARLY_RESPONSE_CERTIFICATION_TIMEOUT,
        SYNC_CALL_EARLY_RESPONSE_DUPLICATE_SUBSCRIPTION,
        SYNC_CALL_EARLY_RESPONSE_INGRESS_WATCHER_NOT_RUNNING,
        SYNC_CALL_EARLY_RESPONSE_MESSAGE_ALREADY_IN_CERTIFIED_STATE,
        SYNC_CALL_EARLY_RESPONSE_SUBSCRIPTION_TIMEOUT, SYNC_CALL_STATUS_IS_INVALID_UTF8,
        SYNC_CALL_STATUS_IS_NOT_LEAF,
    },
};
use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    response::{IntoResponse, Response},
};
use http::Request;
use hyper::StatusCode;
use ic_crypto_tree_hash::{
    Label, LookupStatus, MixedHashTree, Path, sparse_labeled_tree_from_paths,
};
use ic_error_types::UserError;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{error, warn};
use ic_nns_delegation_manager::{CanisterRangesFilter, NNSDelegationReader};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    CanisterId,
    consensus::certification::Certification,
    messages::{Blob, Certificate, HttpCallContent, HttpRequestEnvelope, MessageId},
};
use serde_cbor::Value as CBOR;
use std::{collections::BTreeMap, convert::Infallible, sync::Arc, time::Duration};
use tokio_util::time::FutureExt;
use tower::{ServiceBuilder, util::BoxCloneService};

const LOG_EVERY_N_SECONDS: i32 = 10;

/// The timeout duration used when creating a subscriber for the ingres message,
/// by calling [`IngressWatcherHandle::subscribe_for_certification`].
const SUBSCRIPTION_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Copy, Clone)]
pub enum Version {
    // Synchronous endpoint with the NNS delegation using the flat format of the canister ranges.
    V3,
    // Synchronous endpoint with the NNS delegation using the tree format of the canister ranges.
    V4,
}

enum SyncCallResponse {
    Certificate(Certificate),
    Accepted(&'static str),
    UserError(UserError),
    HttpError(HttpError),
}

#[derive(Clone)]
struct SynchronousCallHandlerState {
    ingress_watcher_handle: IngressWatcherHandle,
    nns_delegation_reader: NNSDelegationReader,
    metrics: HttpHandlerMetrics,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ingress_message_certificate_timeout_seconds: u64,
    call_handler: IngressValidator,
    version: Version,
}

impl IntoResponse for SyncCallResponse {
    fn into_response(self) -> Response {
        match self {
            SyncCallResponse::Certificate(cert) => Cbor(CBOR::Map(BTreeMap::from([
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

            SyncCallResponse::UserError(user_err) => Cbor(CBOR::Map(BTreeMap::from([
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

            SyncCallResponse::Accepted(reason) => {
                (StatusCode::ACCEPTED, reason.to_string()).into_response()
            }

            SyncCallResponse::HttpError(HttpError { status, message }) => {
                (status, message).into_response()
            }
        }
    }
}

impl From<IngressError> for SyncCallResponse {
    fn from(err: IngressError) -> Self {
        match err {
            IngressError::UserError(user_err) => SyncCallResponse::UserError(user_err),
            IngressError::HttpError(http_err) => SyncCallResponse::HttpError(http_err),
        }
    }
}

pub(crate) fn route(version: Version) -> &'static str {
    match version {
        Version::V3 => "/api/v3/canister/{effective_canister_id}/call",
        Version::V4 => "/api/v4/canister/{effective_canister_id}/call",
    }
}

pub(crate) fn new_router(
    call_handler: IngressValidator,
    ingress_watcher_handle: IngressWatcherHandle,
    metrics: HttpHandlerMetrics,
    ingress_message_certificate_timeout_seconds: u64,
    nns_delegation_reader: NNSDelegationReader,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    version: Version,
) -> Router {
    let call_service = SynchronousCallHandlerState {
        nns_delegation_reader,
        ingress_watcher_handle,
        metrics,
        ingress_message_certificate_timeout_seconds,
        call_handler,
        state_reader,
        version,
    };

    Router::new().route_service(
        route(version),
        axum::routing::post(call_sync)
            .with_state(call_service)
            .layer(ServiceBuilder::new().layer(DefaultBodyLimit::disable())),
    )
}

pub fn new_service(
    call_handler: IngressValidator,
    ingress_watcher_handle: IngressWatcherHandle,
    metrics: HttpHandlerMetrics,
    ingress_message_certificate_timeout_seconds: u64,
    nns_delegation_reader: NNSDelegationReader,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    version: Version,
) -> BoxCloneService<Request<Body>, Response, Infallible> {
    let router = new_router(
        call_handler,
        ingress_watcher_handle,
        metrics,
        ingress_message_certificate_timeout_seconds,
        nns_delegation_reader,
        state_reader,
        version,
    );
    BoxCloneService::new(router.into_service())
}

/// Handles a call to /api/{v3,v4}/canister/../call
async fn call_sync(
    axum::extract::Path(effective_canister_id): axum::extract::Path<CanisterId>,
    State(SynchronousCallHandlerState {
        call_handler,
        ingress_watcher_handle,
        metrics,
        ingress_message_certificate_timeout_seconds,
        state_reader,
        nns_delegation_reader,
        version,
    }): State<SynchronousCallHandlerState>,
    WithTimeout(Cbor(request)): WithTimeout<Cbor<HttpRequestEnvelope<HttpCallContent>>>,
) -> SyncCallResponse {
    let log = call_handler.log.clone();

    let ingress_submitter = match call_handler
        .validate_ingress_message(request, effective_canister_id)
        .await
    {
        Ok(ingress_submitter) => ingress_submitter,
        Err(ingress_error) => return SyncCallResponse::from(ingress_error),
    };

    let message_id = ingress_submitter.message_id();

    // Check if the message is already known.
    // If it is known, we can return the certificate without re-submitting the message
    // to the ingress pool.
    if let Some((tree, certification)) =
        tree_and_certificate_for_message(state_reader.clone(), message_id.clone()).await
        && let ParsedMessageStatus::Known(_) = parsed_message_status(&tree, &message_id)
    {
        let delegation_from_nns = match version {
            Version::V3 => nns_delegation_reader.get_delegation(CanisterRangesFilter::Flat),
            Version::V4 => nns_delegation_reader
                .get_delegation(CanisterRangesFilter::Tree(effective_canister_id)),
        };
        let signature = certification.signed.signature.signature.get().0;

        metrics
            .sync_call_early_response_trigger_total
            .with_label_values(&[SYNC_CALL_EARLY_RESPONSE_MESSAGE_ALREADY_IN_CERTIFIED_STATE])
            .inc();

        return SyncCallResponse::Certificate(Certificate {
            tree,
            signature: Blob(signature),
            delegation: delegation_from_nns,
        });
    };

    let certification_subscriber = match ingress_watcher_handle
        .subscribe_for_certification(message_id.clone())
        .timeout(SUBSCRIPTION_TIMEOUT)
        .await
    {
        Ok(Ok(message_subscriber)) => Ok(message_subscriber),
        Ok(Err(SubscriptionError::DuplicateSubscriptionError)) => Err((
            "Duplicate request. Message is already being tracked and executed.",
            SYNC_CALL_EARLY_RESPONSE_DUPLICATE_SUBSCRIPTION,
        )),
        Ok(Err(SubscriptionError::IngressWatcherNotRunning { error_message })) => {
            error!(
                every_n_seconds => LOG_EVERY_N_SECONDS,
                log,
                "Error while waiting for subscriber of ingress message: {}", error_message
            );
            Err((
                "Could not track the ingress message. Please try /read_state for the status.",
                SYNC_CALL_EARLY_RESPONSE_INGRESS_WATCHER_NOT_RUNNING,
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
                SYNC_CALL_EARLY_RESPONSE_SUBSCRIPTION_TIMEOUT,
            ))
        }
    };

    let ingres_submission = ingress_submitter.try_submit();

    if let Err(ingress_submission) = ingres_submission {
        return SyncCallResponse::HttpError(ingress_submission);
    }
    // The ingress message was submitted successfully.
    // From this point on we only return a certificate or `Accepted 202``.
    let certification_subscriber = match certification_subscriber {
        Ok(certification_subscriber) => certification_subscriber,
        Err((reason, metric_label)) => {
            metrics
                .sync_call_early_response_trigger_total
                .with_label_values(&[metric_label])
                .inc();
            return SyncCallResponse::Accepted(reason);
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
                .sync_call_early_response_trigger_total
                .with_label_values(&[SYNC_CALL_EARLY_RESPONSE_CERTIFICATION_TIMEOUT])
                .inc();
            return SyncCallResponse::Accepted(
                "Message did not complete execution and certification within the replica defined timeout.",
            );
        }
    }

    let Some((tree, certification)) =
        tree_and_certificate_for_message(state_reader, message_id.clone()).await
    else {
        return SyncCallResponse::Accepted(
            "Certified state is not available. Please try /read_state.",
        );
    };

    let status_label = match parsed_message_status(&tree, &message_id) {
        ParsedMessageStatus::Known(status) => status,
        ParsedMessageStatus::Unknown => "unknown".to_string(),
    };

    metrics
        .sync_call_certificate_status_total
        .with_label_values(&[&status_label])
        .inc();

    let delegation_from_nns = match version {
        Version::V3 => nns_delegation_reader.get_delegation(CanisterRangesFilter::Flat),
        Version::V4 => {
            nns_delegation_reader.get_delegation(CanisterRangesFilter::Tree(effective_canister_id))
        }
    };
    let signature = certification.signed.signature.signature.get().0;

    SyncCallResponse::Certificate(Certificate {
        tree,
        signature: Blob(signature),
        delegation: delegation_from_nns,
    })
}

enum ParsedMessageStatus {
    Known(String),
    Unknown,
}

fn parsed_message_status(tree: &MixedHashTree, message_id: &MessageId) -> ParsedMessageStatus {
    let status_path = [&b"request_status"[..], message_id.as_ref(), &b"status"[..]];

    match tree.lookup(&status_path) {
        LookupStatus::Found(MixedHashTree::Leaf(status)) => ParsedMessageStatus::Known(
            String::from_utf8(status.clone())
                .unwrap_or_else(|_| SYNC_CALL_STATUS_IS_INVALID_UTF8.to_string()),
        ),
        LookupStatus::Found(_) => {
            ParsedMessageStatus::Known(SYNC_CALL_STATUS_IS_NOT_LEAF.to_string())
        }
        LookupStatus::Absent | LookupStatus::Unknown => ParsedMessageStatus::Unknown,
    }
}

async fn tree_and_certificate_for_message(
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    message_id: MessageId,
) -> Option<(MixedHashTree, Certification)> {
    let certified_state_reader = match tokio::task::spawn_blocking(move || {
        state_reader.get_certified_state_snapshot()
    })
    .await
    {
        Ok(Some(certified_state_reader)) => Some(certified_state_reader),
        Ok(None) | Err(_) => None,
    }?;

    // We always add time path to comply with the IC spec.
    let time_path = Path::from(Label::from("time"));
    let request_status_path = Path::from(vec![
        Label::from("request_status"),
        Label::from(message_id.clone()),
    ]);

    let tree: ic_crypto_tree_hash::LabeledTree<()> =
        sparse_labeled_tree_from_paths(&[time_path, request_status_path])
            .expect("Path is within length bound.");

    certified_state_reader.read_certified_state(&tree)
}
