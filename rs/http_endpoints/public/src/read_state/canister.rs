use super::{
    DeprecatedCanisterRangesFilter, get_certificate_and_create_response,
    make_service_unavailable_response, parse_principal_id, verify_principal_ids,
};
use crate::{
    HttpError, ReplicaHealthStatus,
    common::{Cbor, WithTimeout, build_validator, validation_error_to_http_error},
};

use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    response::{IntoResponse, Response},
};
use crossbeam::atomic::AtomicCell;
use http::Request;
use hyper::StatusCode;
use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_crypto_tree_hash::Path;
use ic_interfaces::time_source::{SysTimeSource, TimeSource};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::ReplicaLogger;
use ic_nns_delegation_manager::{CanisterRangesFilter, NNSDelegationReader};
use ic_registry_client_helpers::crypto::root_of_trust::RegistryRootOfTrustProvider;
use ic_replicated_state::{ReplicatedState, canister_state::execution_state::CustomSectionType};
use ic_types::{
    CanisterId, PrincipalId, SubnetId, UserId,
    malicious_flags::MaliciousFlags,
    messages::{
        EXPECTED_MESSAGE_ID_LENGTH, HttpReadStateContent, HttpRequest, HttpRequestEnvelope,
        MessageId, ReadState,
    },
};
use ic_validator::{CanisterIdSet, HttpRequestVerifier};
use std::{
    convert::{Infallible, TryFrom},
    sync::Arc,
};
use tower::{ServiceBuilder, util::BoxCloneService};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Version {
    /// Endpoint with the NNS delegation using the flat format of the canister ranges.
    /// `/subnet/<subnet_id>/canister_ranges` path is allowed
    V2,
    /// Endpoint with the NNS delegation using the tree format of the canister ranges.
    /// Explicitly requesting `/subnet/<subnet_id>/canister_ranges` path is NOT allowed
    /// except when `subnet_id == nns_subnet_id`. Moreover, all paths of the form
    /// `/subnet/<subnet_id>/canister_ranges`, where `subnet_id != nns_subnet_id`, are
    /// pruned from the returned certificate.
    V3,
}

#[derive(Clone)]
pub struct CanisterReadStateService {
    log: ReplicaLogger,
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    nns_delegation_reader: NNSDelegationReader,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    time_source: Arc<dyn TimeSource>,
    validator: Arc<dyn HttpRequestVerifier<ReadState, RegistryRootOfTrustProvider>>,
    registry_client: Arc<dyn RegistryClient>,
    nns_subnet_id: SubnetId,
    version: Version,
}

pub struct CanisterReadStateServiceBuilder {
    log: ReplicaLogger,
    health_status: Option<Arc<AtomicCell<ReplicaHealthStatus>>>,
    malicious_flags: Option<MaliciousFlags>,
    nns_delegation_reader: NNSDelegationReader,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    time_source: Option<Arc<dyn TimeSource>>,
    ingress_verifier: Arc<dyn IngressSigVerifier>,
    registry_client: Arc<dyn RegistryClient>,
    nns_subnet_id: SubnetId,
    version: Version,
}

impl CanisterReadStateService {
    pub(crate) fn route(version: Version) -> &'static str {
        match version {
            Version::V2 => "/api/v2/canister/{effective_canister_id}/read_state",
            Version::V3 => "/api/v3/canister/{effective_canister_id}/read_state",
        }
    }
}

impl CanisterReadStateServiceBuilder {
    pub fn builder(
        log: ReplicaLogger,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        registry_client: Arc<dyn RegistryClient>,
        ingress_verifier: Arc<dyn IngressSigVerifier>,
        nns_delegation_reader: NNSDelegationReader,
        nns_subnet_id: SubnetId,
        version: Version,
    ) -> Self {
        Self {
            log,
            health_status: None,
            malicious_flags: None,
            nns_delegation_reader,
            state_reader,
            time_source: None,
            ingress_verifier,
            registry_client,
            nns_subnet_id,
            version,
        }
    }

    pub(crate) fn with_malicious_flags(mut self, malicious_flags: MaliciousFlags) -> Self {
        self.malicious_flags = Some(malicious_flags);
        self
    }

    pub fn with_time_source(mut self, time_source: Arc<dyn TimeSource>) -> Self {
        self.time_source = Some(time_source);
        self
    }

    pub fn with_health_status(
        mut self,
        health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    ) -> Self {
        self.health_status = Some(health_status);
        self
    }

    pub(crate) fn build_router(self) -> Router {
        let state = CanisterReadStateService {
            log: self.log,
            health_status: self
                .health_status
                .unwrap_or_else(|| Arc::new(AtomicCell::new(ReplicaHealthStatus::Healthy))),
            nns_delegation_reader: self.nns_delegation_reader,
            state_reader: self.state_reader,
            time_source: self.time_source.unwrap_or(Arc::new(SysTimeSource::new())),
            validator: build_validator(self.ingress_verifier, self.malicious_flags),
            registry_client: self.registry_client,
            nns_subnet_id: self.nns_subnet_id,
            version: self.version,
        };
        Router::new().route(
            CanisterReadStateService::route(self.version),
            axum::routing::post(canister_read_state)
                .with_state(state)
                .layer(ServiceBuilder::new().layer(DefaultBodyLimit::disable())),
        )
    }

    pub fn build_service(self) -> BoxCloneService<Request<Body>, Response, Infallible> {
        let router = self.build_router();
        BoxCloneService::new(router.into_service())
    }
}

pub(crate) async fn canister_read_state(
    axum::extract::Path(effective_canister_id): axum::extract::Path<CanisterId>,
    State(CanisterReadStateService {
        log,
        health_status,
        nns_delegation_reader,
        state_reader,
        time_source,
        validator,
        registry_client,
        nns_subnet_id,
        version,
    }): State<CanisterReadStateService>,
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
    let registry_version = registry_client.get_latest_version();

    let root_of_trust_provider =
        RegistryRootOfTrustProvider::new(Arc::clone(&registry_client), registry_version);
    // Since spawn blocking requires 'static we can't use any references
    let request_c = request.clone();

    let response = tokio::task::spawn_blocking(move || {
        let targets = match validator.validate_request(
            &request_c,
            time_source.get_relative_time(),
            &root_of_trust_provider,
        ) {
            Ok(targets) => targets,
            Err(err) => {
                let http_err = validation_error_to_http_error(&request, err, &log);
                return (http_err.status, http_err.message).into_response();
            }
        };

        let Some(certified_state_reader) = state_reader.get_certified_state_snapshot() else {
            return make_service_unavailable_response();
        };

        // Verify authorization for requested paths.
        if let Err(HttpError { status, message }) = verify_paths(
            version,
            certified_state_reader.get_state(),
            &read_state.source,
            &read_state.paths,
            &targets,
            effective_canister_id.into(),
            nns_subnet_id,
        ) {
            return (status, message).into_response();
        }

        let delegation_from_nns = match version {
            Version::V2 => nns_delegation_reader.get_delegation(CanisterRangesFilter::Flat),
            Version::V3 => nns_delegation_reader
                .get_delegation(CanisterRangesFilter::Tree(effective_canister_id)),
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

// Verifies that the `user` is authorized to retrieve the `paths` requested.
fn verify_paths(
    version: Version,
    state: &ReplicatedState,
    user: &UserId,
    paths: &[Path],
    targets: &CanisterIdSet,
    effective_principal_id: PrincipalId,
    nns_subnet_id: SubnetId,
) -> Result<(), HttpError> {
    let mut last_request_status_id: Option<MessageId> = None;

    // Convert the paths to slices to make it easier to match below.
    let paths: Vec<Vec<&[u8]>> = paths
        .iter()
        .map(|path| path.iter().map(|label| label.as_bytes()).collect())
        .collect();

    for path in paths {
        match path.as_slice() {
            [b"time"] => {}
            [b"canister", canister_id, b"controllers" | b"module_hash"] => {
                let canister_id = parse_principal_id(canister_id)?;
                verify_principal_ids(&canister_id, &effective_principal_id)?;
            }
            [b"canister", canister_id, b"metadata", name] => {
                let name = String::from_utf8(Vec::from(*name)).map_err(|err| HttpError {
                    status: StatusCode::BAD_REQUEST,
                    message: format!("Could not parse the custom section name: {err}."),
                })?;

                // Get principal id from byte slice.
                let principal_id = parse_principal_id(canister_id)?;
                // Verify that canister id and effective canister id match.
                verify_principal_ids(&principal_id, &effective_principal_id)?;
                can_read_canister_metadata(
                    user,
                    &CanisterId::unchecked_from_principal(principal_id),
                    &name,
                    state,
                )?
            }
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
            [b"request_status", request_id]
            | [
                b"request_status",
                request_id,
                b"status" | b"reply" | b"reject_code" | b"reject_message" | b"error_code",
            ] => {
                let message_id = MessageId::try_from(*request_id).map_err(|_| HttpError {
                    status: StatusCode::BAD_REQUEST,
                    message: format!(
                        "Invalid request id in paths. \
                        Maybe the request ID is not \
                        of {EXPECTED_MESSAGE_ID_LENGTH} bytes in length?!"
                    ),
                })?;

                if let Some(x) = last_request_status_id
                    && x != message_id
                {
                    return Err(HttpError {
                        status: StatusCode::BAD_REQUEST,
                        message: format!(
                            "More than one non-unique request ID exists in \
                                request_status paths: {x} and {message_id}."
                        ),
                    });
                }
                last_request_status_id = Some(message_id.clone());

                // Verify that the request was signed by the same user.
                let ingress_status = state.get_ingress_status(&message_id);
                if let Some(ingress_user_id) = ingress_status.user_id()
                    && ingress_user_id != *user
                {
                    return Err(HttpError {
                        status: StatusCode::FORBIDDEN,
                        message: "The user tries to access Request ID not signed by the caller."
                            .to_string(),
                    });
                }

                if let Some(receiver) = ingress_status.receiver()
                    && !targets.contains(&receiver)
                {
                    return Err(HttpError {
                        status: StatusCode::FORBIDDEN,
                        message: "The user tries to access request IDs for canisters \
                                      not belonging to sender delegation targets."
                            .to_string(),
                    });
                }
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

fn can_read_canister_metadata(
    user: &UserId,
    canister_id: &CanisterId,
    custom_section_name: &str,
    state: &ReplicatedState,
) -> Result<(), HttpError> {
    let canister = match state.canister_states.get(canister_id) {
        Some(canister) => canister,
        None => return Ok(()),
    };

    match &canister.execution_state {
        Some(execution_state) => {
            let custom_section = match execution_state
                .metadata
                .get_custom_section(custom_section_name)
            {
                Some(section) => section,
                None => return Ok(()),
            };

            // Only the controller can request this custom section.
            if custom_section.visibility() == CustomSectionType::Private
                && !canister.system_state.controllers.contains(&user.get())
            {
                return Err(HttpError {
                    status: StatusCode::FORBIDDEN,
                    message: format!(
                        "Custom section {custom_section_name:.100} can only be requested by the controllers of the canister."
                    ),
                });
            }

            Ok(())
        }
        None => Ok(()),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        HttpError,
        common::test::{array, assert_cbor_ser_equal, bytes, int},
    };
    use hyper::StatusCode;
    use ic_crypto_tree_hash::{Digest, Label, MixedHashTree, Path};
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        CanisterQueues, RefundPool, ReplicatedState, SystemMetadata,
        canister_snapshots::CanisterSnapshots,
    };
    use ic_test_utilities_state::insert_dummy_canister;
    use ic_test_utilities_types::ids::{SUBNET_0, SUBNET_1, canister_test_id, user_test_id};
    use ic_types::{batch::RawQueryStats, time::UNIX_EPOCH};
    use ic_validator::CanisterIdSet;
    use rstest::rstest;
    use std::collections::BTreeMap;

    const NNS_SUBNET_ID: SubnetId = SUBNET_0;
    const APP_SUBNET_ID: SubnetId = SUBNET_1;

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

    #[test]
    fn user_can_read_canister_metadata() {
        let canister_id = canister_test_id(100);
        let controller = user_test_id(24);
        let non_controller = user_test_id(20);

        let mut state = ReplicatedState::new(APP_SUBNET_ID, SubnetType::Application);
        insert_dummy_canister(&mut state, canister_id, controller.get());

        let public_name = "dummy";
        // Controller can read the public custom section
        assert!(can_read_canister_metadata(&controller, &canister_id, public_name, &state).is_ok());

        // Non-controller can read public custom section
        assert!(
            can_read_canister_metadata(&non_controller, &canister_id, public_name, &state).is_ok()
        );

        let private_name = "candid";
        // Controller can read private custom section
        assert!(
            can_read_canister_metadata(&controller, &canister_id, private_name, &state).is_ok()
        );
    }

    #[test]
    fn user_cannot_read_canister_metadata() {
        let canister_id = canister_test_id(100);
        let controller = user_test_id(24);
        let non_controller = user_test_id(20);

        let mut state = ReplicatedState::new(APP_SUBNET_ID, SubnetType::Application);
        insert_dummy_canister(&mut state, canister_id, controller.get());

        // Non-controller cannot read private custom section named `candid`.
        assert_eq!(
            can_read_canister_metadata(&non_controller, &canister_id, "candid", &state),
            Err(HttpError {
                status: StatusCode::FORBIDDEN,
                message: "Custom section candid can only be requested by the controllers of the canister."
                    .to_string()
            })
        );

        // Non existent public custom section.
        assert_eq!(
            can_read_canister_metadata(&non_controller, &canister_id, "unknown-name", &state),
            Ok(())
        );
    }

    fn fake_replicated_state() -> ReplicatedState {
        let mut metadata = SystemMetadata::new(APP_SUBNET_ID, SubnetType::Application);
        metadata.batch_time = UNIX_EPOCH;
        ReplicatedState::new_from_checkpoint(
            BTreeMap::new(),
            metadata,
            CanisterQueues::default(),
            RefundPool::default(),
            RawQueryStats::default(),
            CanisterSnapshots::default(),
        )
    }

    #[rstest]
    fn test_canister_ranges_are_not_allowed(#[values(Version::V2, Version::V3)] version: Version) {
        let state = fake_replicated_state();

        let error = verify_paths(
            version,
            &state,
            &user_test_id(1),
            &[Path::new(vec![
                Label::from("canister_ranges"),
                [0; 32].into(),
            ])],
            &CanisterIdSet::all(),
            canister_test_id(1).get(),
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail because canister_ranges are not allowed");

        assert_eq!(error.status, StatusCode::NOT_FOUND)
    }

    #[rstest]
    fn test_verify_path(#[values(Version::V2, Version::V3)] version: Version) {
        let state = fake_replicated_state();
        assert_eq!(
            verify_paths(
                version,
                &state,
                &user_test_id(1),
                &[Path::from(Label::from("time"))],
                &CanisterIdSet::all(),
                canister_test_id(1).get(),
                NNS_SUBNET_ID,
            ),
            Ok(())
        );

        assert_eq!(
            verify_paths(
                version,
                &state,
                &user_test_id(1),
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
                    ]),
                ],
                &CanisterIdSet::all(),
                canister_test_id(1).get(),
                NNS_SUBNET_ID,
            ),
            Ok(())
        );

        let err = verify_paths(
            version,
            &state,
            &user_test_id(1),
            &[
                Path::new(vec![Label::from("request_status"), [0; 32].into()]),
                Path::new(vec![Label::from("request_status"), [1; 32].into()]),
            ],
            &CanisterIdSet::all(),
            canister_test_id(1).get(),
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail the validation");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn deprecated_canister_ranges_path_is_not_allowed_on_the_v3_endpoint_except_for_the_nns_subnet()
    {
        let state = fake_replicated_state();
        let err = verify_paths(
            Version::V3,
            &state,
            &user_test_id(1),
            &[Path::new(vec![
                Label::from("subnet"),
                APP_SUBNET_ID.get().to_vec().into(),
                Label::from("canister_ranges"),
            ])],
            &CanisterIdSet::all(),
            canister_test_id(1).get(),
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail the validation");
        assert_eq!(err.status, StatusCode::NOT_FOUND);

        assert!(
            verify_paths(
                Version::V3,
                &state,
                &user_test_id(1),
                &[Path::new(vec![
                    Label::from("subnet"),
                    NNS_SUBNET_ID.get().to_vec().into(),
                    Label::from("canister_ranges"),
                ])],
                &CanisterIdSet::all(),
                canister_test_id(1).get(),
                NNS_SUBNET_ID,
            )
            .is_ok()
        );
    }

    #[test]
    fn deprecated_canister_ranges_path_is_allowed_on_the_v2_endpoint() {
        let state = fake_replicated_state();
        assert!(
            verify_paths(
                Version::V2,
                &state,
                &user_test_id(1),
                &[Path::new(vec![
                    Label::from("subnet"),
                    APP_SUBNET_ID.get().to_vec().into(),
                    Label::from("canister_ranges"),
                ])],
                &CanisterIdSet::all(),
                canister_test_id(1).get(),
                NNS_SUBNET_ID,
            )
            .is_ok()
        );
    }
}
