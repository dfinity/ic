use super::{parse_principal_id, verify_principal_ids};
use crate::{
    common::{build_validator, into_cbor, validation_error_to_http_error, Cbor, WithTimeout},
    HttpError, ReplicaHealthStatus,
};

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    response::{IntoResponse, Response},
    Router,
};
use crossbeam::atomic::AtomicCell;
use http::Request;
use hyper::StatusCode;
use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, Label, Path, TooLongPathError};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::ReplicaLogger;
use ic_registry_client_helpers::crypto::root_of_trust::RegistryRootOfTrustProvider;
use ic_replicated_state::{canister_state::execution_state::CustomSectionType, ReplicatedState};
use ic_types::{
    malicious_flags::MaliciousFlags,
    messages::{
        Blob, Certificate, CertificateDelegation, HttpReadStateContent, HttpReadStateResponse,
        HttpRequest, HttpRequestEnvelope, MessageId, ReadState, EXPECTED_MESSAGE_ID_LENGTH,
    },
    time::current_time,
    CanisterId, PrincipalId, UserId,
};
use ic_validator::{CanisterIdSet, HttpRequestVerifier};
use std::convert::{Infallible, TryFrom};
use std::sync::{Arc, RwLock};
use tower::{util::BoxCloneService, ServiceBuilder};

#[derive(Clone)]
pub struct CanisterReadStateService {
    log: ReplicaLogger,
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    validator: Arc<dyn HttpRequestVerifier<ReadState, RegistryRootOfTrustProvider>>,
    registry_client: Arc<dyn RegistryClient>,
}

pub struct CanisterReadStateServiceBuilder {
    log: ReplicaLogger,
    health_status: Option<Arc<AtomicCell<ReplicaHealthStatus>>>,
    malicious_flags: Option<MaliciousFlags>,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ingress_verifier: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
}

impl CanisterReadStateService {
    pub(crate) fn route() -> &'static str {
        "/api/v2/canister/:effective_canister_id/read_state"
    }
}

impl CanisterReadStateServiceBuilder {
    pub fn builder(
        log: ReplicaLogger,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        registry_client: Arc<dyn RegistryClient>,
        ingress_verifier: Arc<dyn IngressSigVerifier + Send + Sync>,
        delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    ) -> Self {
        Self {
            log,
            health_status: None,
            malicious_flags: None,
            delegation_from_nns,
            state_reader,
            ingress_verifier,
            registry_client,
        }
    }

    pub(crate) fn with_malicious_flags(mut self, malicious_flags: MaliciousFlags) -> Self {
        self.malicious_flags = Some(malicious_flags);
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
            delegation_from_nns: self.delegation_from_nns,
            state_reader: self.state_reader,
            validator: build_validator(self.ingress_verifier, self.malicious_flags),
            registry_client: self.registry_client,
        };
        Router::new().route(
            CanisterReadStateService::route(),
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
        delegation_from_nns,
        state_reader,
        validator,
        registry_client,
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

    let delegation_from_nns = delegation_from_nns.read().unwrap().clone();

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
    let registry_version = registry_client.get_latest_version();

    let make_service_unavailable_response = || {
        let status = StatusCode::SERVICE_UNAVAILABLE;
        let text = "Certified state is not available yet. Please try again...".to_string();
        (status, text).into_response()
    };
    let root_of_trust_provider =
        RegistryRootOfTrustProvider::new(Arc::clone(&registry_client), registry_version);
    // Since spawn blocking requires 'static we can't use any references
    let request_c = request.clone();
    let response = tokio::task::spawn_blocking(move || {
        let targets =
            match validator.validate_request(&request_c, current_time(), &root_of_trust_provider) {
                Ok(targets) => targets,
                Err(err) => {
                    let http_err = validation_error_to_http_error(request.id(), err, &log);
                    return (http_err.status, http_err.message).into_response();
                }
            };

        let certified_state_reader = match state_reader.get_certified_state_snapshot() {
            Some(reader) => reader,
            None => return make_service_unavailable_response(),
        };

        // Verify authorization for requested paths.
        if let Err(HttpError { status, message }) = verify_paths(
            certified_state_reader.get_state(),
            &read_state.source,
            &read_state.paths,
            &targets,
            effective_canister_id.into(),
        ) {
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
        let res = HttpReadStateResponse {
            certificate: Blob(into_cbor(&Certificate {
                tree,
                signature: Blob(signature),
                delegation: delegation_from_nns,
            })),
        };
        Cbor(res).into_response()
    })
    .await;
    match response {
        Ok(res) => res,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// Verifies that the `user` is authorized to retrieve the `paths` requested.
fn verify_paths(
    state: &ReplicatedState,
    user: &UserId,
    paths: &[Path],
    targets: &CanisterIdSet,
    effective_principal_id: PrincipalId,
) -> Result<(), HttpError> {
    let mut request_status_id: Option<MessageId> = None;

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
                    message: format!("Could not parse the custom section name: {}.", err),
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
            | [b"api_boundary_nodes", _node_id, b"domain" | b"ipv4_address" | b"ipv6_address"] => {}
            [b"subnet"] => {}
            [b"subnet", _subnet_id]
            | [b"subnet", _subnet_id, b"public_key" | b"canister_ranges" | b"node"] => {}
            [b"subnet", _subnet_id, b"node", _node_id]
            | [b"subnet", _subnet_id, b"node", _node_id, b"public_key"] => {}
            [b"request_status", request_id]
            | [b"request_status", request_id, b"status" | b"reply" | b"reject_code" | b"reject_message" | b"error_code"] =>
            {
                // Verify that the request was signed by the same user.
                if let Ok(message_id) = MessageId::try_from(*request_id) {
                    if let Some(request_status_id) = request_status_id {
                        if request_status_id != message_id {
                            return Err(HttpError {
                                status: StatusCode::BAD_REQUEST,
                                message:
                                    "Can only request a single request ID in request_status paths."
                                        .to_string(),
                            });
                        }
                    }

                    let ingress_status = state.get_ingress_status(&message_id);
                    if let Some(ingress_user_id) = ingress_status.user_id() {
                        if let Some(receiver) = ingress_status.receiver() {
                            if ingress_user_id != *user {
                                return Err(HttpError {
                                    status: StatusCode::FORBIDDEN,
                                    message:
                                        "Request IDs must be for requests signed by the caller."
                                            .to_string(),
                                });
                            }

                            if !targets.contains(&receiver) {
                                return Err(HttpError {
                                    status: StatusCode::FORBIDDEN,
                                    message:
                                        "Request IDs must be for requests to canisters belonging to sender delegation targets."
                                            .to_string(),
                                });
                            }
                        }
                    }

                    request_status_id = Some(message_id);
                } else {
                    return Err(HttpError {
                        status: StatusCode::BAD_REQUEST,
                        message: format!(
                            "Request IDs must be {} bytes in length.",
                            EXPECTED_MESSAGE_ID_LENGTH
                        ),
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
                        "Custom section {:.100} can only be requested by the controllers of the canister.",
                        custom_section_name
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
        common::test::{array, assert_cbor_ser_equal, bytes, int},
        HttpError,
    };
    use hyper::StatusCode;
    use ic_crypto_tree_hash::{Digest, Label, MixedHashTree, Path};
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        canister_snapshots::CanisterSnapshots, CanisterQueues, ReplicatedState, SystemMetadata,
    };
    use ic_test_utilities_state::insert_dummy_canister;
    use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id, user_test_id};
    use ic_types::{batch::RawQueryStats, time::UNIX_EPOCH};
    use ic_validator::CanisterIdSet;
    use std::collections::BTreeMap;

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

        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
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

        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
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

    #[test]
    fn test_verify_path() {
        let subnet_id = subnet_test_id(1);
        let mut metadata = SystemMetadata::new(subnet_id, SubnetType::Application);
        metadata.batch_time = UNIX_EPOCH;
        let state = ReplicatedState::new_from_checkpoint(
            BTreeMap::new(),
            metadata,
            CanisterQueues::default(),
            RawQueryStats::default(),
            CanisterSnapshots::default(),
        );
        assert_eq!(
            verify_paths(
                &state,
                &user_test_id(1),
                &[Path::from(Label::from("time"))],
                &CanisterIdSet::all(),
                canister_test_id(1).get(),
            ),
            Ok(())
        );
        assert_eq!(
            verify_paths(
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
                    ])
                ],
                &CanisterIdSet::all(),
                canister_test_id(1).get(),
            ),
            Ok(())
        );
        assert!(verify_paths(
            &state,
            &user_test_id(1),
            &[
                Path::new(vec![Label::from("request_status"), [0; 32].into()]),
                Path::new(vec![Label::from("request_status"), [1; 32].into()])
            ],
            &CanisterIdSet::all(),
            canister_test_id(1).get(),
        )
        .is_err());
    }
}
