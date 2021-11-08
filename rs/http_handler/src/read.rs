//! Module that deals with requests to /api/v2/canister/.../{query,read_state}

use crate::{
    common,
    metrics::HttpHandlerMetrics,
    types::{ApiReqType, RequestType},
    ReplicaHealthStatus,
};
use hyper::{Body, Response, StatusCode};
use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, Label, Path};
use ic_interfaces::{
    crypto::IngressSigVerifier, execution_environment::QueryExecutionService,
    registry::RegistryClient, state_manager::StateReader,
};
use ic_logger::{trace, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    canonical_error::{
        invalid_argument_error, not_found_error, permission_denied_error, resource_exhausted_error,
        CanonicalError,
    },
    malicious_flags::MaliciousFlags,
    messages::{
        Blob, Certificate, CertificateDelegation, HttpReadContent, HttpReadStateResponse,
        HttpRequest, HttpRequestEnvelope, MessageId, ReadContent, ReadState, SignedRequestBytes,
        EXPECTED_MESSAGE_ID_LENGTH,
    },
    time::current_time,
    Time, UserId,
};
use ic_validator::{get_authorized_canisters, CanisterIdSet};
use std::convert::TryFrom;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
use tower::{Service, ServiceExt};

const MAX_READ_STATE_REQUEST_IDS: u8 = 100;

/// Handles a call to /api/v2/canister/.../{query,read_state}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
    log: &ReplicaLogger,
    health_status: Arc<RwLock<ReplicaHealthStatus>>,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    query_handler: Arc<Mutex<QueryExecutionService>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    validator: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    body: Vec<u8>,
    metrics: Arc<HttpHandlerMetrics>,
    malicious_flags: MaliciousFlags,
) -> (Response<Body>, ApiReqType) {
    trace!(log, "in handle read");
    use ApiReqType::*;
    if *health_status.read().unwrap() != ReplicaHealthStatus::Healthy {
        return (
            common::make_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Replica is starting. Check the /api/v2/status for more information.",
            ),
            Unknown,
        );
    }
    let delegation_from_nns = delegation_from_nns.read().unwrap().clone();

    let request =
        match <HttpRequestEnvelope<HttpReadContent>>::try_from(&SignedRequestBytes::from(body)) {
            Ok(request) => request,
            Err(e) => {
                return (
                    common::make_response(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!("Could not parse body as read request: {}", e).as_str(),
                    ),
                    Unknown,
                );
            }
        };

    // Convert the message to a strongly-typed struct, making structural validations
    // on the way.
    let request = match HttpRequest::try_from(request) {
        Ok(request) => request,
        Err(e) => {
            return (
                common::make_response(
                    StatusCode::BAD_REQUEST,
                    format!("Malformed request: {:?}", e).as_str(),
                ),
                Unknown,
            )
        }
    };

    let targets = match get_authorized_canisters(
        &request,
        validator.as_ref(),
        current_time(),
        registry_client.get_latest_version(),
        &malicious_flags,
    ) {
        Ok(targets) => targets,
        Err(err) => {
            metrics.observe_forbidden_request(&RequestType::Read, "ReadReqAuthFailed");
            return (
                common::make_response_on_validation_error(request.id(), err, log),
                Unknown,
            );
        }
    };

    match request.content() {
        ReadContent::Query(query) => {
            if !targets.contains(&query.receiver) {
                return (
                    common::make_response(StatusCode::UNAUTHORIZED, "Unauthorized."),
                    Query,
                );
            }
            // Here we want to hold the mutex only for the duration of the non-blocking
            // call, and not for duration until the query completes. Hence the await on
            // the callback is after the mutex was released.
            let callback = query_handler
                .lock()
                .await
                .ready()
                .await
                .expect("The service must always be able to process requests")
                .call((query.clone(), delegation_from_nns));
            let result = match callback.await {
                Ok(query_result) => common::cbor_response(&query_result),
                Err(canonical_error) => common::make_response(
                    StatusCode::from(canonical_error.code),
                    canonical_error.message.as_str(),
                ),
            };
            (result, Query)
        }
        ReadContent::ReadState(read_state) => (
            handle_read_state(
                delegation_from_nns,
                state_reader,
                read_state.clone(),
                targets,
                metrics,
            ),
            ReadState,
        ),
    }
}

fn handle_read_state(
    delegation_from_nns: Option<CertificateDelegation>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    read_state: ReadState,
    targets: CanisterIdSet,
    metrics: Arc<HttpHandlerMetrics>,
) -> Response<Body> {
    // Verify that the sender has authorization to the paths requested.
    if let Err(err) = verify_paths(
        state_reader.as_ref(),
        &read_state.source,
        &read_state.paths,
        &targets,
    ) {
        metrics.observe_forbidden_request(&RequestType::Read, "InvalidPaths");
        return common::make_response(StatusCode::from(err.code), err.message.as_str());
    }
    metrics.observe_unreliable_request_acceptance_duration(
        RequestType::Read,
        ApiReqType::ReadState,
        Time::from_nanos_since_unix_epoch(read_state.ingress_expiry),
    );

    let mut paths: Vec<Path> = read_state.paths;

    // Always add "time" to the paths even if not explicitly requested.
    paths.push(Path::from(Label::from("time")));

    let labeled_tree = sparse_labeled_tree_from_paths(&mut paths);

    match state_reader.read_certified_state(&labeled_tree) {
        Some((_state, tree, certification)) => {
            let signature = certification.signed.signature.signature.get().0;
            let res = HttpReadStateResponse {
                certificate: Blob(common::into_cbor(&Certificate {
                    tree,
                    signature: Blob(signature),
                    delegation: delegation_from_nns,
                })),
            };
            common::cbor_response(&res)
        }
        None => common::make_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Certified state is not available yet. Please try again...",
        ),
    }
}

// Verifies that the `user` is authorized to retrieve the `paths` requested.
fn verify_paths(
    state_reader: &dyn StateReader<State = ReplicatedState>,
    user: &UserId,
    paths: &[Path],
    targets: &CanisterIdSet,
) -> Result<(), CanonicalError> {
    let state = state_reader.get_latest_state().take();
    let mut num_request_ids = 0;

    // Convert the paths to slices to make it easier to match below.
    let paths: Vec<Vec<&[u8]>> = paths
        .iter()
        .map(|path| path.iter().map(|label| label.as_bytes()).collect())
        .collect();

    for path in paths {
        match path.as_slice() {
            [b"time"] => {}
            [b"canister", _canister_id, b"controller"] => {}
            [b"canister", _canister_id, b"controllers"] => {}
            [b"canister", _canister_id, b"module_hash"] => {}
            [b"subnet", _subnet_id, b"public_key"] => {}
            [b"subnet", _subnet_id, b"canister_ranges"] => {}
            [b"request_status", request_id] | [b"request_status", request_id, ..] => {
                num_request_ids += 1;

                if num_request_ids > MAX_READ_STATE_REQUEST_IDS {
                    return Err(resource_exhausted_error(&format!(
                        "Can only request up to {} request IDs.",
                        MAX_READ_STATE_REQUEST_IDS
                    )));
                }

                // Verify that the request was signed by the same user.
                if let Ok(message_id) = MessageId::try_from(*request_id) {
                    let ingress_status = state.get_ingress_status(&message_id);

                    if let Some(ingress_user_id) = ingress_status.user_id() {
                        if let Some(receiver) = ingress_status.receiver() {
                            if ingress_user_id != *user || !targets.contains(&receiver) {
                                return Err(permission_denied_error(
                                    "Request IDs must be for requests signed by the caller.",
                                ));
                            }
                        }
                    }
                } else {
                    return Err(invalid_argument_error(&format!(
                        "Request IDs must be {} bytes in length.",
                        EXPECTED_MESSAGE_ID_LENGTH
                    )));
                }
            }
            _ => {
                // All other paths are unsupported.
                return Err(not_found_error("Invalid path requested."));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::common::test::{array, assert_cbor_ser_equal, bytes, int};
    use ic_crypto_tree_hash::{Digest, Label, MixedHashTree};

    #[test]
    fn encoding_read_state_tree_empty() {
        let tree = MixedHashTree::Empty;
        assert_cbor_ser_equal(&tree, array(vec![int(0)]));
    }

    #[test]
    fn encoding_read_state_tree_leaf() {
        let tree = MixedHashTree::Leaf(vec![1, 2, 3]);
        assert_cbor_ser_equal(&tree, array(vec![int(3), bytes(&[1, 2, 3])]));
    }

    #[test]
    fn encoding_read_state_tree_pruned() {
        let tree = MixedHashTree::Pruned(Digest([1; 32]));
        assert_cbor_ser_equal(&tree, array(vec![int(4), bytes(&[1; 32])]));
    }

    #[test]
    fn encoding_read_state_tree_fork() {
        let tree = MixedHashTree::Fork(Box::new((
            MixedHashTree::Leaf(vec![1, 2, 3]),
            MixedHashTree::Leaf(vec![4, 5, 6]),
        )));
        assert_cbor_ser_equal(
            &tree,
            array(vec![
                int(1),
                array(vec![int(3), bytes(&[1, 2, 3])]),
                array(vec![int(3), bytes(&[4, 5, 6])]),
            ]),
        );
    }

    #[test]
    fn encoding_read_state_tree_mixed() {
        let tree = MixedHashTree::Fork(Box::new((
            MixedHashTree::Labeled(
                Label::from(vec![1, 2, 3]),
                Box::new(MixedHashTree::Pruned(Digest([2; 32]))),
            ),
            MixedHashTree::Leaf(vec![4, 5, 6]),
        )));
        assert_cbor_ser_equal(
            &tree,
            array(vec![
                int(1),
                array(vec![
                    int(2),
                    bytes(&[1, 2, 3]),
                    array(vec![int(4), bytes(&[2; 32])]),
                ]),
                array(vec![int(3), bytes(&[4, 5, 6])]),
            ]),
        );
    }
}
