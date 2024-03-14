use super::{parse_principal_id, verify_principal_ids};
use crate::{
    common::{cbor_response, into_cbor, make_plaintext_response, remove_effective_principal_id},
    receive_request_body,
    state_reader_executor::StateReaderExecutor,
    EndpointService, HttpError, ReplicaHealthStatus,
};

use axum::body::Body;
use crossbeam::atomic::AtomicCell;
use http::Request;
use hyper::{Response, StatusCode};
use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, Label, Path, TooLongPathError};
use ic_logger::{error, ReplicaLogger};
use ic_types::{
    messages::{
        Blob, Certificate, CertificateDelegation, HttpReadStateContent, HttpReadStateResponse,
        HttpRequest, HttpRequestEnvelope, ReadState, SignedRequestBytes,
    },
    PrincipalId,
};
use std::convert::{Infallible, TryFrom};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tower::{util::BoxCloneService, Service};

#[derive(Clone)]
pub(crate) struct SubnetReadStateService {
    log: ReplicaLogger,
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    state_reader_executor: StateReaderExecutor,
}

impl SubnetReadStateService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_service(
        log: ReplicaLogger,
        health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
        delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
        state_reader_executor: StateReaderExecutor,
    ) -> EndpointService {
        let base_service = Self {
            log,
            health_status,
            delegation_from_nns,
            state_reader_executor,
        };
        BoxCloneService::new(base_service)
    }
}

impl Service<Request<Body>> for SubnetReadStateService {
    type Response = Response<Body>;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        if self.health_status.load() != ReplicaHealthStatus::Healthy {
            let res = make_plaintext_response(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Replica is unhealthy: {}. Check the /api/v2/status for more information.",
                    self.health_status.load(),
                ),
            );
            return Box::pin(async move { Ok(res) });
        }
        let (mut parts, body) = request.into_parts();
        // By removing the principal id we get ownership and avoid having to clone it when creating the future.
        let effective_principal_id = match remove_effective_principal_id(&mut parts) {
            Ok(canister_id) => canister_id,
            Err(res) => {
                error!(
                    self.log,
                    "Effective principal ID is not attached to read state request. This is a bug."
                );
                return Box::pin(async move { Ok(res) });
            }
        };

        let delegation_from_nns = self.delegation_from_nns.read().unwrap().clone();
        let state_reader_executor = self.state_reader_executor.clone();
        Box::pin(async move {
            let make_service_unavailable_response = || {
                make_plaintext_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Certified state is not available yet. Please try again...".to_string(),
                )
            };
            let body = match receive_request_body(body).await {
                Ok(bytes) => bytes,
                Err(e) => return Ok(e),
            };
            let request = match <HttpRequestEnvelope<HttpReadStateContent>>::try_from(
                &SignedRequestBytes::from(body.to_vec()),
            ) {
                Ok(request) => request,
                Err(e) => {
                    let res = make_plaintext_response(
                        StatusCode::BAD_REQUEST,
                        format!("Could not parse body as read request: {}", e),
                    );
                    return Ok(res);
                }
            };

            // Convert the message to a strongly-typed struct.
            let request = match HttpRequest::<ReadState>::try_from(request) {
                Ok(request) => request,
                Err(e) => {
                    let res = make_plaintext_response(
                        StatusCode::BAD_REQUEST,
                        format!("Malformed request: {:?}", e),
                    );
                    return Ok(res);
                }
            };
            let read_state = request.content().clone();
            let certified_state_reader =
                match state_reader_executor.get_certified_state_snapshot().await {
                    Ok(Some(reader)) => reader,
                    Ok(None) => return Ok(make_service_unavailable_response()),
                    Err(HttpError { status, message }) => {
                        return Ok(make_plaintext_response(status, message))
                    }
                };

            // Verify authorization for requested paths.
            if let Err(HttpError { status, message }) =
                verify_paths(&read_state.paths, effective_principal_id)
            {
                return Ok(make_plaintext_response(status, message));
            }

            // Create labeled tree. This may be an expensive operation and by
            // creating the labeled tree after verifying the paths we know that
            // the depth is max 4.
            // Always add "time" to the paths even if not explicitly requested.
            let mut paths: Vec<Path> = read_state.paths;
            paths.push(Path::from(Label::from("time")));
            let labeled_tree = match sparse_labeled_tree_from_paths(&paths) {
                Ok(tree) => tree,
                Err(TooLongPathError) => {
                    let res = make_plaintext_response(
                        StatusCode::BAD_REQUEST,
                        "Failed to parse requested paths: path is too long.".to_string(),
                    );
                    return Ok(res);
                }
            };

            let (tree, certification) =
                match certified_state_reader.read_certified_state(&labeled_tree) {
                    Some(r) => r,
                    None => return Ok(make_service_unavailable_response()),
                };

            let signature = certification.signed.signature.signature.get().0;
            let res = HttpReadStateResponse {
                certificate: Blob(into_cbor(&Certificate {
                    tree,
                    signature: Blob(signature),
                    delegation: delegation_from_nns,
                })),
            };
            let (resp, _body_size) = cbor_response(&res);
            Ok(resp)
        })
    }
}

fn verify_paths(paths: &[Path], effective_principal_id: PrincipalId) -> Result<(), HttpError> {
    // Convert the paths to slices to make it easier to match below.
    let paths: Vec<Vec<&[u8]>> = paths
        .iter()
        .map(|path| path.iter().map(|label| label.as_bytes()).collect())
        .collect();

    for path in paths {
        match path.as_slice() {
            [b"time"] => {}
            [b"subnet"] => {}
            [b"subnet", subnet_id]
            | [b"subnet", subnet_id, b"public_key" | b"canister_ranges" | b"node" | b"metrics"] => {
                let principal_id = parse_principal_id(subnet_id)?;
                verify_principal_ids(&principal_id, &effective_principal_id)?;
            }
            [b"subnet", subnet_id, b"node", _node_id]
            | [b"subnet", subnet_id, b"node", _node_id, b"public_key"] => {
                let principal_id = parse_principal_id(subnet_id)?;
                verify_principal_ids(&principal_id, &effective_principal_id)?;
            }
            _ => {
                // All other paths are unsupported.
                return Err(HttpError {
                    status: StatusCode::NOT_FOUND,
                    message: "Invalid path requested.".to_string(),
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_crypto_tree_hash::{Label, Path};
    use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id};
    use serde_bytes::ByteBuf;

    #[test]
    fn test_verify_path() {
        assert_eq!(
            verify_paths(&[Path::from(Label::from("time"))], subnet_test_id(1).get(),),
            Ok(())
        );
        assert_eq!(
            verify_paths(
                &[Path::from(Label::from("subnet"))],
                subnet_test_id(1).get(),
            ),
            Ok(())
        );

        assert_eq!(
            verify_paths(
                &[
                    Path::new(vec![
                        Label::from("subnet"),
                        ByteBuf::from(subnet_test_id(1).get().to_vec()).into(),
                        Label::from("public_key")
                    ]),
                    Path::new(vec![
                        Label::from("subnet"),
                        ByteBuf::from(subnet_test_id(1).get().to_vec()).into(),
                        Label::from("canister_ranges")
                    ]),
                    Path::new(vec![
                        Label::from("subnet"),
                        ByteBuf::from(subnet_test_id(1).get().to_vec()).into(),
                        Label::from("metrics")
                    ]),
                ],
                subnet_test_id(1).get(),
            ),
            Ok(())
        );

        assert!(verify_paths(
            &[
                Path::new(vec![
                    Label::from("request_status"),
                    [0; 32].into(),
                    Label::from("status")
                ]),
                Path::new(vec![
                    Label::from("request_status"),
                    [0; 32].into(),
                    Label::from("reply")
                ])
            ],
            subnet_test_id(1).get(),
        )
        .is_err());

        assert!(verify_paths(
            &[
                Path::new(vec![
                    Label::from("canister"),
                    ByteBuf::from(canister_test_id(1).get().to_vec()).into(),
                    Label::from("controllers")
                ]),
                Path::new(vec![
                    Label::from("request_status"),
                    ByteBuf::from(canister_test_id(1).get().to_vec()).into(),
                    Label::from("module_hash")
                ])
            ],
            subnet_test_id(1).get(),
        )
        .is_err());
    }
}
