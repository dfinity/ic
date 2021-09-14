//! Module that deals with requests to /api/v2/canister/.../{query,read_state}

use crate::{
    common,
    metrics::HttpHandlerMetrics,
    types::{ApiReqType, RequestType},
};
use hyper::{Body, Response, StatusCode};
use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, Label, Path};
use ic_interfaces::crypto::IngressSigVerifier;
use ic_interfaces::execution_environment::QueryHandler;
use ic_interfaces::state_manager::StateReader;
use ic_logger::{info, trace, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    ingress::WasmResult,
    malicious_flags::MaliciousFlags,
    messages::{
        Blob, Certificate, CertificateDelegation, HttpQueryResponse, HttpQueryResponseReply,
        HttpReadContent, HttpReadStateResponse, HttpRequest, HttpRequestEnvelope, MessageId,
        ReadContent, ReadState, SignedRequestBytes, UserQuery, EXPECTED_MESSAGE_ID_LENGTH,
    },
    time::current_time,
    user_error::RejectCode,
    RegistryVersion, Time, UserId,
};
use ic_validator::{get_authorized_canisters, CanisterIdSet};
use std::convert::TryFrom;
use std::sync::Arc;

const MAX_READ_STATE_REQUEST_IDS: u8 = 100;

enum VerifyPathsError {
    InvalidPath,
    InvalidRequestId,
    UnauthorizedRequestId,
    TooManyRequests,
}

impl VerifyPathsError {
    pub fn description(&self) -> String {
        match self {
            VerifyPathsError::InvalidRequestId => format!(
                "Request IDs must be {} bytes in length.",
                EXPECTED_MESSAGE_ID_LENGTH
            ),
            VerifyPathsError::InvalidPath => String::from("Invalid path requested."),
            VerifyPathsError::UnauthorizedRequestId => {
                String::from("Request IDs must be for requests signed by the caller.")
            }
            VerifyPathsError::TooManyRequests => format!(
                "Can only request up to {} request IDs.",
                MAX_READ_STATE_REQUEST_IDS
            ),
        }
    }
}

/// Handles a call to /api/v2/canister/.../{query,read_state}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
    log: &ReplicaLogger,
    delegation_from_nns: Option<CertificateDelegation>,
    query_handler: Arc<dyn QueryHandler<State = ReplicatedState>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    validator: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_version: RegistryVersion,
    body: Vec<u8>,
    metrics: Arc<HttpHandlerMetrics>,
    malicious_flags: MaliciousFlags,
) -> (Response<Body>, ApiReqType) {
    trace!(log, "in handle read");
    use ApiReqType::*;
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
        registry_version,
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
        ReadContent::Query(query) => (
            handle_query(
                log,
                delegation_from_nns,
                query_handler,
                query.clone(),
                targets,
                metrics,
            )
            .await,
            Query,
        ),
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

// TODO(INF-328): The errors codes below are mostly 500. They should be more
// descriptive.
async fn handle_query(
    log: &ReplicaLogger,
    delegation_from_nns: Option<CertificateDelegation>,
    query_handler: Arc<dyn QueryHandler<State = ReplicatedState>>,
    query: UserQuery,
    targets: CanisterIdSet,
    metrics: Arc<HttpHandlerMetrics>,
) -> Response<Body> {
    if !targets.contains(&query.receiver) {
        return common::make_response(StatusCode::UNAUTHORIZED, "Unauthorized.");
    }
    metrics.observe_unreliable_request_acceptance_duration(
        RequestType::Read,
        ApiReqType::Query,
        Time::from_nanos_since_unix_epoch(query.ingress_expiry),
    );

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let c_log = log.clone();
    let callback = move |res| {
        if let Err(err) = tx.blocking_send(res) {
            info!(
                c_log,
                "Broken channel (query execution). Most likely the user dropped the request: {}",
                err
            );
        }
    };
    query_handler.query_latest_certified_state(query, delegation_from_nns, Box::new(callback));
    // TODO: add a timeout for the await as a safety guard.
    let res = match rx.recv().await {
        None => {
            return common::make_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Broken channel. Query execution didn't return a value.",
            )
        }
        Some(res) => res,
    };

    match res {
        Ok(res) => {
            let response = match res {
                WasmResult::Reply(vec) => HttpQueryResponse::Replied {
                    reply: HttpQueryResponseReply { arg: Blob(vec) },
                },
                WasmResult::Reject(message) => HttpQueryResponse::Rejected {
                    reject_code: RejectCode::CanisterReject as u64,
                    reject_message: message,
                },
            };

            common::cbor_response(&response)
        }

        Err(user_error) => {
            info!(log, "Could not perform query on canister: {}", user_error);
            let response = HttpQueryResponse::Rejected {
                reject_code: user_error.reject_code() as u64,
                reject_message: user_error.to_string(),
            };
            common::cbor_response(&response)
        }
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
        return common::make_response(StatusCode::FORBIDDEN, &err.description());
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
) -> Result<(), VerifyPathsError> {
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
                    return Err(VerifyPathsError::TooManyRequests);
                }

                // Verify that the request was signed by the same user.
                if let Ok(message_id) = MessageId::try_from(*request_id) {
                    let ingress_status = state.get_ingress_status(&message_id);

                    if let Some(ingress_user_id) = ingress_status.user_id() {
                        if let Some(receiver) = ingress_status.receiver() {
                            if ingress_user_id != *user || !targets.contains(&receiver) {
                                return Err(VerifyPathsError::UnauthorizedRequestId);
                            }
                        }
                    }
                } else {
                    return Err(VerifyPathsError::InvalidRequestId);
                }
            }
            _ => {
                // All other paths are unsupported.
                return Err(VerifyPathsError::InvalidPath);
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
