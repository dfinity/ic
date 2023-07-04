//! Module that deals with requests to /api/v2/canister/.../read_state

use crate::{
    body::BodyReceiverLayer,
    common::{cbor_response, into_cbor, make_plaintext_response},
    metrics::LABEL_UNKNOWN,
    state_reader_executor::StateReaderExecutor,
    types::ApiReqType,
    validator_executor::ValidatorExecutor,
    EndpointService, HttpError, HttpHandlerMetrics, ReplicaHealthStatus,
};
use crossbeam::atomic::AtomicCell;
use http::Request;
use hyper::{Body, Response, StatusCode};
use ic_config::http_handler::Config;
use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, Label, Path, TooLongPathError};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, ReplicaLogger};
use ic_replicated_state::{canister_state::execution_state::CustomSectionType, ReplicatedState};
use ic_types::{
    messages::{
        Blob, Certificate, CertificateDelegation, HttpReadStateContent, HttpReadStateResponse,
        HttpRequest, HttpRequestEnvelope, MessageId, ReadState, SignedRequestBytes,
        EXPECTED_MESSAGE_ID_LENGTH,
    },
    CanisterId, UserId,
};
use ic_validator::CanisterIdSet;
use std::convert::{Infallible, TryFrom};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tower::{
    limit::concurrency::GlobalConcurrencyLimitLayer, util::BoxCloneService, Service, ServiceBuilder,
};

#[derive(Clone)]
pub(crate) struct ReadStateService {
    log: ReplicaLogger,
    metrics: HttpHandlerMetrics,
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    state_reader_executor: StateReaderExecutor,
    validator_executor: ValidatorExecutor<ReadState>,
    registry_client: Arc<dyn RegistryClient>,
}

impl ReadStateService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_service(
        config: Config,
        log: ReplicaLogger,
        metrics: HttpHandlerMetrics,
        health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
        delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
        state_reader_executor: StateReaderExecutor,
        validator_executor: ValidatorExecutor<ReadState>,
        registry_client: Arc<dyn RegistryClient>,
    ) -> EndpointService {
        let base_service = Self {
            log,
            metrics,
            health_status,
            delegation_from_nns,
            state_reader_executor,
            validator_executor,
            registry_client,
        };
        let base_service = BoxCloneService::new(
            ServiceBuilder::new()
                .layer(GlobalConcurrencyLimitLayer::new(
                    config.max_read_state_concurrent_requests,
                ))
                .service(base_service),
        );
        BoxCloneService::new(
            ServiceBuilder::new()
                .layer(BodyReceiverLayer::new(&config))
                .service(base_service),
        )
    }
}

impl Service<Request<Vec<u8>>> for ReadStateService {
    type Response = Response<Body>;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Vec<u8>>) -> Self::Future {
        self.metrics
            .request_body_size_bytes
            .with_label_values(&[ApiReqType::ReadState.into(), LABEL_UNKNOWN])
            .observe(request.body().len() as f64);

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
        // By removing the canister id we get ownership and avoid having to clone it when creating the future.
        let effective_canister_id = match parts.extensions.remove::<CanisterId>() {
            Some(canister_id) => canister_id,
            _ => {
                error!(
                    self.log,
                    "Effective canister ID is not attached to read state request. This is a bug."
                );
                let res = make_plaintext_response(
                    StatusCode::BAD_REQUEST,
                    "Malformed request".to_string(),
                );
                return Box::pin(async move { Ok(res) });
            }
        };

        let delegation_from_nns = self.delegation_from_nns.read().unwrap().clone();

        let request = match <HttpRequestEnvelope<HttpReadStateContent>>::try_from(
            &SignedRequestBytes::from(body),
        ) {
            Ok(request) => request,
            Err(e) => {
                let res = make_plaintext_response(
                    StatusCode::BAD_REQUEST,
                    format!("Could not parse body as read request: {}", e),
                );
                return Box::pin(async move { Ok(res) });
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
                return Box::pin(async move { Ok(res) });
            }
        };

        let read_state = request.content().clone();
        let registry_client = self.registry_client.get_latest_version();
        let state_reader_executor = self.state_reader_executor.clone();
        let validator_executor = self.validator_executor.clone();
        let metrics = self.metrics.clone();
        Box::pin(async move {
            let targets_fut = validator_executor.validate_request(request.clone(), registry_client);

            let targets = match targets_fut.await {
                Ok(targets) => targets,
                Err(http_err) => {
                    let res = make_plaintext_response(http_err.status, http_err.message);
                    return Ok(res);
                }
            };
            // Verify authorization for requested paths.
            if let Err(HttpError { status, message }) = verify_paths(
                &state_reader_executor,
                &read_state.source,
                &read_state.paths,
                &targets,
                effective_canister_id,
                &metrics,
            )
            .await
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

            let res = match state_reader_executor
                .read_certified_state(&labeled_tree)
                .await
            {
                Ok(r) => r,
                Err(e) => return Ok(make_plaintext_response(e.status, e.message)),
            };

            let res = match res {
                Some((_state, tree, certification)) => {
                    let signature = certification.signed.signature.signature.get().0;
                    let res = HttpReadStateResponse {
                        certificate: Blob(into_cbor(&Certificate {
                            tree,
                            signature: Blob(signature),
                            delegation: delegation_from_nns,
                        })),
                    };
                    let (resp, body_size) = cbor_response(&res);
                    metrics
                        .response_body_size_bytes
                        .with_label_values(&[ApiReqType::ReadState.into()])
                        .observe(body_size as f64);
                    resp
                }
                None => make_plaintext_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Certified state is not available yet. Please try again...".to_string(),
                ),
            };

            Ok(res)
        })
    }
}

// Verifies that the `user` is authorized to retrieve the `paths` requested.
async fn verify_paths(
    state_reader_executor: &StateReaderExecutor,
    user: &UserId,
    paths: &[Path],
    targets: &CanisterIdSet,
    effective_canister_id: CanisterId,
    metrics: &HttpHandlerMetrics,
) -> Result<(), HttpError> {
    let state = state_reader_executor.get_latest_state().await?.take();
    let mut request_status_id: Option<MessageId> = None;

    // Convert the paths to slices to make it easier to match below.
    let paths: Vec<Vec<&[u8]>> = paths
        .iter()
        .map(|path| path.iter().map(|label| label.as_bytes()).collect())
        .collect();

    for path in paths {
        match path.as_slice() {
            [b"time"] => {}
            [b"canister", canister_id, b"controller"] => {
                let canister_id = parse_canister_id(canister_id)?;
                verify_canister_ids(&canister_id, &effective_canister_id)?;
                metrics.read_state_canister_controller_total.inc();
            }
            [b"canister", canister_id, b"controllers" | b"module_hash"] => {
                let canister_id = parse_canister_id(canister_id)?;
                verify_canister_ids(&canister_id, &effective_canister_id)?;
            }
            [b"canister", canister_id, b"metadata", name] => {
                let name = String::from_utf8(Vec::from(*name)).map_err(|err| HttpError {
                    status: StatusCode::BAD_REQUEST,
                    message: format!("Could not parse the custom section name: {}.", err),
                })?;

                // Get canister id from byte slice.
                let canister_id = parse_canister_id(canister_id)?;
                // Verify that canister id and effective canister id match.
                verify_canister_ids(&canister_id, &effective_canister_id)?;
                can_read_canister_metadata(user, &canister_id, &name, &state)?
            }
            [b"subnet"] => {}
            [b"subnet", _subnet_id, b"public_key" | b"canister_ranges"] => {}
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
                            if ingress_user_id != *user || !targets.contains(&receiver) {
                                return Err(HttpError {
                                    status: StatusCode::FORBIDDEN,
                                    message:
                                        "Request IDs must be for requests signed by the caller."
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

fn parse_canister_id(canister_id: &[u8]) -> Result<CanisterId, HttpError> {
    match CanisterId::try_from(canister_id) {
        Ok(canister_id) => Ok(canister_id),
        Err(err) => Err(HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Could not parse Canister ID: {}.", err),
        }),
    }
}

fn verify_canister_ids(
    canister_id: &CanisterId,
    effective_canister_id: &CanisterId,
) -> Result<(), HttpError> {
    if canister_id != effective_canister_id {
        return Err(HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "Effective canister id in URL {} does not match requested canister id: {}.",
                effective_canister_id, canister_id
            ),
        });
    }
    Ok(())
}

fn can_read_canister_metadata(
    user: &UserId,
    canister_id: &CanisterId,
    custom_section_name: &str,
    state: &ReplicatedState,
) -> Result<(), HttpError> {
    let canister = state
        .canister_states
        .get(canister_id)
        .ok_or_else(|| HttpError {
            status: StatusCode::NOT_FOUND,
            message: format!("Canister {} not found.", canister_id),
        })?;

    match &canister.execution_state {
        Some(execution_state) => {
            let custom_section = execution_state
                .metadata
                .get_custom_section(custom_section_name)
                .ok_or_else(|| HttpError {
                    status: StatusCode::NOT_FOUND,
                    message: format!("Custom section {:.100} not found.", custom_section_name),
                })?;

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
        }
        None => {
            return Err(HttpError {
                status: StatusCode::NOT_FOUND,
                message: format!("Canister {} has no module.", canister_id),
            })
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::{
        common::test::{array, assert_cbor_ser_equal, bytes, int},
        metrics::HttpHandlerMetrics,
        read_state::{can_read_canister_metadata, verify_paths},
        state_reader_executor::StateReaderExecutor,
        HttpError,
    };
    use hyper::StatusCode;
    use ic_crypto_tree_hash::{Digest, Label, MixedHashTree, Path};
    use ic_interfaces_state_manager::Labeled;
    use ic_interfaces_state_manager_mocks::MockStateManager;
    use ic_metrics::MetricsRegistry;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{CanisterQueues, ReplicatedState, SystemMetadata};
    use ic_test_utilities::{
        mock_time,
        state::insert_dummy_canister,
        types::ids::{canister_test_id, subnet_test_id, user_test_id},
    };
    use ic_types::Height;
    use ic_validator::CanisterIdSet;
    use std::{collections::BTreeMap, sync::Arc};

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
            Err(HttpError {
                status: StatusCode::NOT_FOUND,
                message: "Custom section unknown-name not found.".to_string()
            })
        );
    }

    #[tokio::test]
    async fn async_verify_path() {
        let subnet_id = subnet_test_id(1);
        let mut mock_state_manager = MockStateManager::new();
        mock_state_manager
            .expect_get_latest_state()
            .returning(move || {
                let mut metadata = SystemMetadata::new(subnet_id, SubnetType::Application);
                metadata.batch_time = mock_time();
                Labeled::new(
                    Height::from(1),
                    Arc::new(ReplicatedState::new_from_checkpoint(
                        BTreeMap::new(),
                        metadata,
                        CanisterQueues::default(),
                    )),
                )
            });

        let state_manager = Arc::new(mock_state_manager);
        let sre = StateReaderExecutor::new(state_manager.clone());
        assert_eq!(
            verify_paths(
                &sre,
                &user_test_id(1),
                &[Path::from(Label::from("time"))],
                &CanisterIdSet::all(),
                canister_test_id(1),
                &HttpHandlerMetrics::new(&MetricsRegistry::default())
            )
            .await,
            Ok(())
        );
        assert_eq!(
            verify_paths(
                &sre,
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
                canister_test_id(1),
                &HttpHandlerMetrics::new(&MetricsRegistry::default())
            )
            .await,
            Ok(())
        );
        assert!(verify_paths(
            &sre,
            &user_test_id(1),
            &[
                Path::new(vec![Label::from("request_status"), [0; 32].into()]),
                Path::new(vec![Label::from("request_status"), [1; 32].into()])
            ],
            &CanisterIdSet::all(),
            canister_test_id(1),
            &HttpHandlerMetrics::new(&MetricsRegistry::default())
        )
        .await
        .is_err());
    }
}
