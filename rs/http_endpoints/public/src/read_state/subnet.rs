use super::{parse_principal_id, verify_principal_ids};
use crate::{
    common::{into_cbor, Cbor, WithTimeout},
    HttpError, ReplicaHealthStatus,
};

use axum::{
    body::Body,
    extract::State,
    response::{IntoResponse, Response},
    Router,
};
use crossbeam::atomic::AtomicCell;
use http::Request;
use hyper::StatusCode;
use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, Label, Path, TooLongPathError};
use ic_interfaces_state_manager::StateReader;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    messages::{
        Blob, Certificate, CertificateDelegation, HttpReadStateContent, HttpReadStateResponse,
        HttpRequest, HttpRequestEnvelope, ReadState,
    },
    CanisterId, PrincipalId,
};
use std::{
    convert::{Infallible, TryFrom},
    sync::Arc,
};
use tokio::sync::OnceCell;
use tower::util::BoxCloneService;

#[derive(Clone)]
pub(crate) struct SubnetReadStateService {
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    delegation_from_nns: Arc<OnceCell<CertificateDelegation>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
}

pub struct SubnetReadStateServiceBuilder {
    health_status: Option<Arc<AtomicCell<ReplicaHealthStatus>>>,
    delegation_from_nns: Arc<OnceCell<CertificateDelegation>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
}

impl SubnetReadStateService {
    pub(crate) fn route() -> &'static str {
        "/api/v2/subnet/:effective_canister_id/read_state"
    }
}

impl SubnetReadStateServiceBuilder {
    pub fn builder(
        delegation_from_nns: Arc<OnceCell<CertificateDelegation>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> Self {
        Self {
            health_status: None,
            delegation_from_nns,
            state_reader,
        }
    }

    pub fn with_health_status(
        mut self,
        health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    ) -> Self {
        self.health_status = Some(health_status);
        self
    }

    pub(crate) fn build_router(self) -> Router {
        let state = SubnetReadStateService {
            health_status: self
                .health_status
                .unwrap_or_else(|| Arc::new(AtomicCell::new(ReplicaHealthStatus::Healthy))),
            delegation_from_nns: self.delegation_from_nns,
            state_reader: self.state_reader,
        };
        Router::new().route_service(
            SubnetReadStateService::route(),
            axum::routing::post(read_state_subnet).with_state(state),
        )
    }

    pub fn build_service(self) -> BoxCloneService<Request<Body>, Response, Infallible> {
        let router = self.build_router();
        BoxCloneService::new(router.into_service())
    }
}

pub(crate) async fn read_state_subnet(
    axum::extract::Path(effective_canister_id): axum::extract::Path<CanisterId>,
    State(SubnetReadStateService {
        health_status,
        delegation_from_nns,
        state_reader,
    }): State<SubnetReadStateService>,
    WithTimeout(Cbor(request)): WithTimeout<Cbor<HttpRequestEnvelope<HttpReadStateContent>>>,
) -> impl IntoResponse {
    if health_status.load() != ReplicaHealthStatus::Healthy {
        let status = StatusCode::SERVICE_UNAVAILABLE;
        let text = format!(
            "Replica is unhealthy: {:?}. Check the /api/v2/status for more information.",
            health_status.load(),
        );
        return (status, text).into_response();
    }

    let delegation_from_nns = delegation_from_nns.get().cloned();
    let make_service_unavailable_response = || {
        let status = StatusCode::SERVICE_UNAVAILABLE;
        let text = "Certified state is not available yet. Please try again...".to_string();
        (status, text).into_response()
    };

    // Convert the message to a strongly-typed struct.
    let request = match HttpRequest::<ReadState>::try_from(request) {
        Ok(request) => request,
        Err(e) => {
            let status = StatusCode::BAD_REQUEST;
            let text = format!("Malformed request: {:?}", e);
            return (status, text).into_response();
        }
    };
    let read_state = request.content().clone();
    let response = tokio::task::spawn_blocking(move || {
        let certified_state_reader = match state_reader.get_certified_state_snapshot() {
            Some(reader) => reader,
            None => return make_service_unavailable_response(),
        };

        // Verify authorization for requested paths.
        if let Err(HttpError { status, message }) =
            verify_paths(&read_state.paths, effective_canister_id.into())
        {
            return (status, message).into_response();
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
                let status = StatusCode::BAD_REQUEST;
                let text = "Failed to parse requested paths: path is too long.".to_string();
                return (status, text).into_response();
            }
        };

        let (tree, certification) = match certified_state_reader.read_certified_state(&labeled_tree)
        {
            Some(r) => r,
            None => return make_service_unavailable_response(),
        };

        let signature = certification.signed.signature.signature.get().0;
        Cbor(HttpReadStateResponse {
            certificate: Blob(into_cbor(&Certificate {
                tree,
                signature: Blob(signature),
                delegation: delegation_from_nns,
            })),
        })
        .into_response()
    })
    .await;
    match response {
        Ok(res) => res,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
            [b"api_boundary_nodes"] => {}
            [b"api_boundary_nodes", _node_id]
            | [b"api_boundary_nodes", _node_id, b"domain" | b"ipv4_address" | b"ipv6_address"] => {}
            [b"subnet"] => {}
            [b"subnet", _subnet_id]
            | [b"subnet", _subnet_id, b"public_key" | b"canister_ranges" | b"node"] => {}
            [b"subnet", _subnet_id, b"node", _node_id]
            | [b"subnet", _subnet_id, b"node", _node_id, b"public_key"] => {}
            [b"subnet", subnet_id, b"metrics"] => {
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
