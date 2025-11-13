use super::{
    DeprecatedCanisterRangesFilter, get_certificate_and_create_response,
    make_service_unavailable_response, parse_principal_id, verify_principal_ids,
};
use crate::{
    HttpError, ReplicaHealthStatus,
    common::{Cbor, WithTimeout},
};

use axum::{
    Router,
    body::Body,
    extract::State,
    response::{IntoResponse, Response},
};
use crossbeam::atomic::AtomicCell;
use http::Request;
use hyper::StatusCode;
use ic_crypto_tree_hash::Path;
use ic_interfaces_state_manager::StateReader;
use ic_nns_delegation_manager::{CanisterRangesFilter, NNSDelegationReader};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    CanisterId, PrincipalId, SubnetId,
    messages::{HttpReadStateContent, HttpRequest, HttpRequestEnvelope, ReadState},
};
use std::{
    convert::{Infallible, TryFrom},
    sync::Arc,
};
use tower::util::BoxCloneService;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Version {
    /// Endpoint with the NNS delegation using the flat format of the canister ranges.
    /// `/subnet/<subnet_id>/canister_ranges` path is allowed
    V2,
    /// Endpoint with the NNS delegation will all canister ranges pruned out.
    /// Explicitly requesting `/subnet/<subnet_id>/canister_ranges` path is NOT allowed
    /// except when `subnet_id == nns_subnet_id`. Moreover, all paths of the form
    /// `/subnet/<subnet_id>/canister_ranges`, where `subnet_id != nns_subnet_id`, are
    /// pruned from the returned certificate.
    V3,
}

#[derive(Clone)]
pub(crate) struct SubnetReadStateService {
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    nns_delegation_reader: NNSDelegationReader,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    nns_subnet_id: SubnetId,
    version: Version,
}

pub struct SubnetReadStateServiceBuilder {
    health_status: Option<Arc<AtomicCell<ReplicaHealthStatus>>>,
    nns_delegation_reader: NNSDelegationReader,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    nns_subnet_id: SubnetId,
    version: Version,
}

impl SubnetReadStateService {
    pub(crate) fn route(version: Version) -> &'static str {
        match version {
            Version::V2 => "/api/v2/subnet/{effective_canister_id}/read_state",
            Version::V3 => "/api/v3/subnet/{effective_canister_id}/read_state",
        }
    }
}

impl SubnetReadStateServiceBuilder {
    pub fn builder(
        nns_delegation_reader: NNSDelegationReader,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        nns_subnet_id: SubnetId,
        version: Version,
    ) -> Self {
        Self {
            health_status: None,
            nns_delegation_reader,
            state_reader,
            nns_subnet_id,
            version,
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
            nns_delegation_reader: self.nns_delegation_reader,
            state_reader: self.state_reader,
            nns_subnet_id: self.nns_subnet_id,
            version: self.version,
        };
        Router::new().route_service(
            SubnetReadStateService::route(self.version),
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
        nns_delegation_reader,
        state_reader,
        nns_subnet_id,
        version,
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

    // Convert the message to a strongly-typed struct.
    let request = match HttpRequest::<ReadState>::try_from(request) {
        Ok(request) => request,
        Err(e) => {
            let status = StatusCode::BAD_REQUEST;
            let text = format!("Malformed request: {e:?}");
            return (status, text).into_response();
        }
    };
    let read_state = request.content().clone();

    let response = tokio::task::spawn_blocking(move || {
        let Some(certified_state_reader) = state_reader.get_certified_state_snapshot() else {
            return make_service_unavailable_response();
        };

        // Verify authorization for requested paths.
        if let Err(HttpError { status, message }) = verify_paths(
            version,
            &read_state.paths,
            effective_canister_id.into(),
            nns_subnet_id,
        ) {
            return (status, message).into_response();
        }

        let delegation_from_nns = match version {
            Version::V2 => nns_delegation_reader.get_delegation(CanisterRangesFilter::Flat),
            Version::V3 => nns_delegation_reader.get_delegation(CanisterRangesFilter::None),
        };

        let maybe_nns_subnet_filter = match version {
            Version::V2 => DeprecatedCanisterRangesFilter::KeepAll,
            Version::V3 => DeprecatedCanisterRangesFilter::KeepOnlyNNS(nns_subnet_id),
        };

        get_certificate_and_create_response(
            read_state.paths,
            delegation_from_nns,
            certified_state_reader.as_ref(),
            maybe_nns_subnet_filter,
        )
    })
    .await;

    match response {
        Ok(res) => res,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn verify_paths(
    version: Version,
    paths: &[Path],
    effective_principal_id: PrincipalId,
    nns_subnet_id: SubnetId,
) -> Result<(), HttpError> {
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
            | [
                b"api_boundary_nodes",
                _node_id,
                b"domain" | b"ipv4_address" | b"ipv6_address",
            ] => {}
            [b"subnet"] => {}
            [b"subnet", _subnet_id] | [b"subnet", _subnet_id, b"public_key" | b"node"] => {}
            // `/subnet/<subnet_id>/canister_ranges` is always allowed on the `/api/v2` endpoint
            [b"subnet", _subnet_id, b"canister_ranges"] if version == Version::V2 => {}
            // `/subnet/<subnet_id>/canister_ranges` is allowed on the `/api/v3` endpoint
            // only when `subnet_id == nns_subnet_id`.
            [b"subnet", subnet_id, b"canister_ranges"]
                if version == Version::V3
                    && parse_principal_id(subnet_id)? == nns_subnet_id.get() => {}
            [b"subnet", _subnet_id, b"node", _node_id]
            | [b"subnet", _subnet_id, b"node", _node_id, b"public_key"] => {}
            [b"canister_ranges", _subnet_id] => {}
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
    use ic_test_utilities_types::ids::{SUBNET_0, SUBNET_1, canister_test_id, subnet_test_id};
    use rstest::rstest;
    use serde_bytes::ByteBuf;

    const NNS_SUBNET_ID: SubnetId = SUBNET_0;
    const APP_SUBNET_ID: SubnetId = SUBNET_1;

    #[rstest]
    fn test_verify_path(#[values(Version::V2, Version::V3)] version: Version) {
        assert_eq!(
            verify_paths(
                version,
                &[Path::from(Label::from("time"))],
                APP_SUBNET_ID.get(),
                NNS_SUBNET_ID,
            ),
            Ok(())
        );
        assert_eq!(
            verify_paths(
                version,
                &[Path::from(Label::from("subnet"))],
                APP_SUBNET_ID.get(),
                NNS_SUBNET_ID,
            ),
            Ok(())
        );

        assert_eq!(
            verify_paths(
                version,
                &[
                    Path::new(vec![
                        Label::from("subnet"),
                        APP_SUBNET_ID.get().to_vec().into(),
                        Label::from("public_key")
                    ]),
                    Path::new(vec![
                        Label::from("subnet"),
                        APP_SUBNET_ID.get().to_vec().into(),
                        Label::from("metrics")
                    ]),
                    Path::new(vec![
                        Label::from("canister_ranges"),
                        ByteBuf::from(subnet_test_id(1).get().to_vec()).into(),
                    ]),
                ],
                APP_SUBNET_ID.get(),
                NNS_SUBNET_ID,
            ),
            Ok(())
        );

        let err = verify_paths(
            version,
            &[
                Path::new(vec![
                    Label::from("request_status"),
                    [0; 32].into(),
                    Label::from("status"),
                ]),
                Path::new(vec![
                    Label::from("request_status"),
                    [0; 32].into(),
                    Label::from("reply"),
                ]),
            ],
            APP_SUBNET_ID.get(),
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail the validation");
        assert_eq!(err.status, StatusCode::NOT_FOUND);

        let err = verify_paths(
            version,
            &[
                Path::new(vec![
                    Label::from("canister"),
                    ByteBuf::from(canister_test_id(1).get().to_vec()).into(),
                    Label::from("controllers"),
                ]),
                Path::new(vec![
                    Label::from("request_status"),
                    ByteBuf::from(canister_test_id(1).get().to_vec()).into(),
                    Label::from("module_hash"),
                ]),
            ],
            APP_SUBNET_ID.get(),
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail the validation");
        assert_eq!(err.status, StatusCode::NOT_FOUND);

        let err = verify_paths(
            version,
            &[Path::new(vec![Label::from("canister_ranges")])],
            APP_SUBNET_ID.get(),
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail the validation");
        assert_eq!(err.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn deprecated_canister_ranges_path_is_not_allowed_on_the_v3_endpoint_except_for_the_nns_subnet()
    {
        let err = verify_paths(
            Version::V3,
            &[Path::new(vec![
                Label::from("subnet"),
                APP_SUBNET_ID.get().to_vec().into(),
                Label::from("canister_ranges"),
            ])],
            APP_SUBNET_ID.get(),
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail the validation");
        assert_eq!(err.status, StatusCode::NOT_FOUND);

        assert!(
            verify_paths(
                Version::V3,
                &[Path::new(vec![
                    Label::from("subnet"),
                    NNS_SUBNET_ID.get().to_vec().into(),
                    Label::from("canister_ranges"),
                ])],
                APP_SUBNET_ID.get(),
                NNS_SUBNET_ID,
            )
            .is_ok()
        );
    }

    #[test]
    fn deprecated_canister_ranges_path_is_allowed_on_the_v2_endpoint() {
        assert!(
            verify_paths(
                Version::V2,
                &[Path::new(vec![
                    Label::from("subnet"),
                    APP_SUBNET_ID.get().to_vec().into(),
                    Label::from("canister_ranges"),
                ])],
                APP_SUBNET_ID.get(),
                NNS_SUBNET_ID,
            )
            .is_ok()
        );

        assert!(
            verify_paths(
                Version::V2,
                &[Path::new(vec![
                    Label::from("subnet"),
                    NNS_SUBNET_ID.get().to_vec().into(),
                    Label::from("canister_ranges"),
                ])],
                APP_SUBNET_ID.get(),
                NNS_SUBNET_ID,
            )
            .is_ok()
        );
    }
}
