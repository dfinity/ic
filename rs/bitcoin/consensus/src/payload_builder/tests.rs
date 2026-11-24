use crate::{BitcoinPayloadBuilder, payload_builder::parse};
use ic_btc_replica_types::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponse, BitcoinAdapterResponseWrapper,
    BitcoinReject, GetSuccessorsRequestInitial, GetSuccessorsResponseComplete, Network,
    SendTransactionRequest, SendTransactionResponse,
};
use ic_config::bitcoin_payload_builder_config::Config;
use ic_error_types::RejectCode;
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext},
    consensus::InvalidPayloadReason,
    self_validating_payload::{
        InvalidSelfValidatingPayloadReason, SelfValidatingPayloadBuilder,
        SelfValidatingPayloadValidationFailure,
    },
    validation::ValidationError,
};
use ic_interfaces_adapter_client::{Options, RpcAdapterClient, RpcError, RpcResult};
use ic_interfaces_registry::RegistryValue;
use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_test_utilities::self_validating_payload_builder::FakeSelfValidatingPayloadBuilder;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_state::ReplicatedStateBuilder;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::{
    Height, NumBytes, RegistryVersion, SubnetId,
    batch::{SelfValidatingPayload, ValidationContext},
    crypto::{CryptoHash, CryptoHashOf},
    messages::CallbackId,
    state_manager::StateManagerError,
    time::UNIX_EPOCH,
};
use mockall::mock;
use std::sync::Arc;

pub(crate) const CERTIFIED_HEIGHT: Height = Height::new(9);
pub(crate) const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(101);
pub(crate) const SELF_VALIDATING_PAYLOAD_BYTE_LIMIT: NumBytes = NumBytes::new(2 * 1024 * 1024); // 2MiB.
pub(crate) const MAX_BLOCK_PAYLOAD_SIZE: NumBytes = NumBytes::new(4 * 1024 * 1024); // 4MiB.

mock! {
    pub AdapterClient {}

    impl RpcAdapterClient<BitcoinAdapterRequestWrapper> for AdapterClient {
        type Response = BitcoinAdapterResponseWrapper;

        fn send_blocking(
            &self,
            request: BitcoinAdapterRequestWrapper,
            opts: Options,
        ) -> RpcResult<BitcoinAdapterResponseWrapper>;
    }
}

// Returns a `MockStateManager` that returns a state with the provided
// `bitcoin_adapter_requests`.
pub(crate) fn mock_state_manager(
    bitcoin_adapter_requests: Vec<BitcoinAdapterRequestWrapper>,
) -> MockStateManager {
    let mut state_manager = MockStateManager::new();
    state_manager.expect_get_state_at().return_const(Ok(
        ic_interfaces_state_manager::Labeled::new(
            CERTIFIED_HEIGHT,
            Arc::new(
                ReplicatedStateBuilder::default()
                    .with_bitcoin_adapter_requests(bitcoin_adapter_requests)
                    .build(),
            ),
        ),
    ));
    state_manager
}

pub(crate) fn mock_registry_client(max_block_payload_size: NumBytes) -> MockRegistryClient {
    let mut registry_client = MockRegistryClient::new();
    registry_client
        .expect_get_value()
        .withf(move |key, version| {
            key == make_subnet_record_key(subnet_test_id(0)).as_str()
                && version == &REGISTRY_VERSION
        })
        .return_const(Ok(Some(
            SubnetRecord {
                max_block_payload_size: max_block_payload_size.get(),
                ..SubnetRecord::default()
            }
            .encode_to_vec(),
        )));
    registry_client
}

/// NOTE: This function was copied from the registry (to not have an unnecessary dependency)
fn make_subnet_record_key(subnet_id: SubnetId) -> String {
    const SUBNET_RECORD_KEY_PREFIX: &str = "subnet_record_";
    format!("{SUBNET_RECORD_KEY_PREFIX}{subnet_id}")
}

fn bitcoin_payload_builder_test(
    bitcoin_mainnet_adapter_client: MockAdapterClient,
    bitcoin_testnet_adapter_client: MockAdapterClient,
    state_manager: MockStateManager,
    registry_client: MockRegistryClient,
    run_test: impl FnOnce(ProposalContext, BitcoinPayloadBuilder),
) {
    with_test_replica_logger(|log| {
        let time = UNIX_EPOCH;

        let validation_context = ValidationContext {
            registry_version: REGISTRY_VERSION,
            certified_height: CERTIFIED_HEIGHT,
            time,
        };
        let proposal_context = ProposalContext {
            proposer: node_test_id(0),
            validation_context: &validation_context,
        };

        let bitcoin_payload_builder = BitcoinPayloadBuilder::new(
            Arc::new(state_manager),
            &MetricsRegistry::new(),
            Box::new(bitcoin_mainnet_adapter_client),
            Box::new(bitcoin_testnet_adapter_client),
            Box::new(MockAdapterClient::new()),
            Box::new(MockAdapterClient::new()),
            subnet_test_id(0),
            Arc::new(registry_client),
            Config::default(),
            log,
        );

        run_test(proposal_context, bitcoin_payload_builder);
    });
}

#[test]
fn can_successfully_create_bitcoin_payload() {
    // Create a mock bitcoin adapter client that returns a dummy response
    // for each request.
    fn mock_adapter() -> MockAdapterClient {
        let mut adapter_client = MockAdapterClient::new();
        adapter_client
            .expect_send_blocking()
            .times(1)
            .returning(|_, _| {
                Ok(BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                    GetSuccessorsResponseComplete {
                        blocks: vec![],
                        next: vec![],
                    },
                ))
            });
        adapter_client
    }

    let registry_client = mock_registry_client(MAX_BLOCK_PAYLOAD_SIZE);

    // Create a mock state manager that returns a `ReplicatedState` with
    // some bitcoin adapter requests.
    let state_manager =
        mock_state_manager(vec![BitcoinAdapterRequestWrapper::GetSuccessorsRequest(
            GetSuccessorsRequestInitial {
                processed_block_hashes: vec![vec![10; 32]],
                anchor: vec![10; 32],
                network: Network::BitcoinTestnet,
            },
        )]);

    bitcoin_payload_builder_test(
        MockAdapterClient::new(),
        mock_adapter(),
        state_manager,
        registry_client,
        |proposal_context, bitcoin_payload_builder| {
            let expected_payload = FakeSelfValidatingPayloadBuilder::new()
                .with_responses(vec![BitcoinAdapterResponse {
                    response: BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                        GetSuccessorsResponseComplete {
                            blocks: vec![],
                            next: vec![],
                        },
                    ),
                    callback_id: 0,
                }])
                .build();

            let payload = bitcoin_payload_builder
                .get_self_validating_payload(
                    proposal_context.validation_context,
                    &[],
                    SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
                    0,
                )
                .0;
            assert_eq!(payload, expected_payload);
        },
    );
}

#[test]
fn includes_responses_in_the_payload() {
    // Create a mock bitcoin adapter client that returns a successful response
    // for the first request and an error for the second.
    fn mock_adapter() -> MockAdapterClient {
        let mut adapter_client = MockAdapterClient::new();
        adapter_client
            .expect_send_blocking()
            .times(1)
            .returning(|_, _| {
                Ok(BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                    GetSuccessorsResponseComplete {
                        blocks: vec![],
                        next: vec![],
                    },
                ))
            });
        adapter_client
            .expect_send_blocking()
            .times(1)
            .returning(|_, _| Err(RpcError::ConnectionBroken));
        adapter_client
    }

    let state_manager = mock_state_manager(vec![
        BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequestInitial {
            processed_block_hashes: vec![vec![10; 32]],
            anchor: vec![10; 32],
            network: Network::BitcoinTestnet,
        }),
        BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequestInitial {
            processed_block_hashes: vec![vec![20; 32]],
            anchor: vec![20; 32],
            network: Network::BitcoinTestnet,
        }),
    ]);

    let registry_client = mock_registry_client(MAX_BLOCK_PAYLOAD_SIZE);

    bitcoin_payload_builder_test(
        MockAdapterClient::new(),
        mock_adapter(),
        state_manager,
        registry_client,
        |proposal_context, bitcoin_payload_builder| {
            let expected_payload = FakeSelfValidatingPayloadBuilder::new()
                .with_responses(vec![
                    BitcoinAdapterResponse {
                        response: BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                            GetSuccessorsResponseComplete {
                                blocks: vec![],
                                next: vec![],
                            },
                        ),
                        callback_id: 0,
                    },
                    BitcoinAdapterResponse {
                        response: BitcoinAdapterResponseWrapper::GetSuccessorsReject(
                            BitcoinReject {
                                reject_code: RejectCode::SysTransient,
                                message: "ConnectionBroken".to_string(),
                            },
                        ),
                        callback_id: 1,
                    },
                ])
                .build();
            let expected_payload = parse::payload_to_bytes(
                &expected_payload,
                SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
                &no_op_logger(),
            );

            let payload = bitcoin_payload_builder.build_payload(
                Height::new(1),
                SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
                &[],
                proposal_context.validation_context,
            );
            let validation_result = bitcoin_payload_builder.validate_payload(
                Height::new(1),
                &proposal_context,
                &payload,
                &[],
            );
            assert!(
                validation_result.is_ok(),
                "validation did not pass {validation_result:?}"
            );

            assert_eq!(payload, expected_payload);
        },
    );
}

#[test]
fn includes_only_responses_for_callback_ids_not_seen_in_past_payloads() {
    // Create a mock bitcoin adapter client that returns a dummy response
    // for each request.
    let bitcoin_mainnet_adapter_client = MockAdapterClient::new();
    let mut bitcoin_testnet_adapter_client = MockAdapterClient::new();
    bitcoin_testnet_adapter_client
        .expect_send_blocking()
        .times(1)
        .returning(|_, _| {
            Ok(BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                GetSuccessorsResponseComplete {
                    blocks: vec![],
                    next: vec![],
                },
            ))
        });

    // Create a mock state manager that returns a `ReplicatedState` with
    // some bitcoin adapter requests.
    let state_manager = mock_state_manager(vec![
        BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequestInitial {
            processed_block_hashes: vec![vec![10; 32]],
            anchor: vec![10; 32],
            network: Network::BitcoinTestnet,
        }),
        BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequestInitial {
            processed_block_hashes: vec![vec![20; 32]],
            anchor: vec![20; 32],
            network: Network::BitcoinTestnet,
        }),
    ]);

    let registry_client = mock_registry_client(MAX_BLOCK_PAYLOAD_SIZE);

    bitcoin_payload_builder_test(
        bitcoin_mainnet_adapter_client,
        bitcoin_testnet_adapter_client,
        state_manager,
        registry_client,
        |proposal_context, bitcoin_payload_builder| {
            let past_payload = FakeSelfValidatingPayloadBuilder::new()
                .with_responses(vec![BitcoinAdapterResponse {
                    response: BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                        GetSuccessorsResponseComplete {
                            blocks: vec![],
                            next: vec![],
                        },
                    ),
                    callback_id: 0,
                }])
                .build();
            let past_payload = parse::payload_to_bytes(
                &past_payload,
                SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
                &no_op_logger(),
            );
            let past_payloads = vec![PastPayload {
                height: Height::from(0),
                time: UNIX_EPOCH,
                block_hash: CryptoHashOf::from(CryptoHash(vec![])),
                payload: &past_payload,
            }];

            let expected_payload = FakeSelfValidatingPayloadBuilder::new()
                .with_responses(vec![BitcoinAdapterResponse {
                    response: BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                        GetSuccessorsResponseComplete {
                            blocks: vec![],
                            next: vec![],
                        },
                    ),
                    callback_id: 1,
                }])
                .build();
            let expected_payload = parse::payload_to_bytes(
                &expected_payload,
                SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
                &no_op_logger(),
            );

            let payload = bitcoin_payload_builder.build_payload(
                Height::new(1),
                SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
                &past_payloads,
                proposal_context.validation_context,
            );
            let validation_result = bitcoin_payload_builder.validate_payload(
                Height::new(1),
                &proposal_context,
                &payload,
                &past_payloads,
            );
            assert!(
                validation_result.is_ok(),
                "validation did not pass {validation_result:?}"
            );

            assert_eq!(payload, expected_payload);
        },
    );
}

#[test]
fn bitcoin_payload_builder_fits_largest_blocks() {
    // Create a mock bitcoin adapter client that returns a dummy response
    // for each request.
    let bitcoin_mainnet_adapter_client = MockAdapterClient::new();
    let mut bitcoin_testnet_adapter_client = MockAdapterClient::new();
    bitcoin_testnet_adapter_client
        .expect_send_blocking()
        .returning(move |_, _| {
            Ok(BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                GetSuccessorsResponseComplete {
                    blocks: vec![vec![0; MAX_BLOCK_PAYLOAD_SIZE.get() as usize]],
                    next: vec![vec![0; 80]],
                },
            ))
        });

    // Create a mock state manager that returns a `ReplicatedState` with
    // some bitcoin adapter requests.
    let state_manager =
        mock_state_manager(vec![BitcoinAdapterRequestWrapper::GetSuccessorsRequest(
            GetSuccessorsRequestInitial {
                processed_block_hashes: vec![vec![10; 32]],
                anchor: vec![10; 32],
                network: Network::BitcoinTestnet,
            },
        )]);

    let registry_client = mock_registry_client(MAX_BLOCK_PAYLOAD_SIZE);

    bitcoin_payload_builder_test(
        bitcoin_mainnet_adapter_client,
        bitcoin_testnet_adapter_client,
        state_manager,
        registry_client,
        |proposal_context, bitcoin_payload_builder| {
            let (payload, _) = bitcoin_payload_builder.get_self_validating_payload(
                proposal_context.validation_context,
                &[],
                MAX_BLOCK_PAYLOAD_SIZE,
                0,
            );

            let validation_result = bitcoin_payload_builder.validate_self_validating_payload(
                &payload,
                proposal_context.validation_context,
                &[],
            );
            assert!(
                validation_result.is_ok(),
                "validation did not pass {validation_result:?}"
            );
            assert!(!payload.is_empty());

            // Now test again, but priority is not zero. This should generate an empty payload
            let (payload, _) = bitcoin_payload_builder.get_self_validating_payload(
                proposal_context.validation_context,
                &[],
                MAX_BLOCK_PAYLOAD_SIZE,
                1,
            );
            assert!(payload.is_empty());

            // Test again, this time priority is not zero, but the byte limit is doubles, such that the block fits.
            let (payload, _) = bitcoin_payload_builder.get_self_validating_payload(
                proposal_context.validation_context,
                &[],
                NumBytes::new(2 * MAX_BLOCK_PAYLOAD_SIZE.get()),
                1,
            );
            assert!(!payload.is_empty());
        },
    );
}

// Returns requests that end up as a pending `get_successors` request with
// callback ID 0 and a pending `send_transaction` request with callback ID 1.
fn get_successors_and_send_transaction_requests() -> Vec<BitcoinAdapterRequestWrapper> {
    vec![
        BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequestInitial {
            processed_block_hashes: vec![vec![10; 32]],
            anchor: vec![10; 32],
            network: Network::BitcoinTestnet,
        }),
        BitcoinAdapterRequestWrapper::SendTransactionRequest(SendTransactionRequest {
            network: Network::BitcoinTestnet,
            transaction: vec![],
        }),
    ]
}

fn get_successors_response() -> BitcoinAdapterResponseWrapper {
    BitcoinAdapterResponseWrapper::GetSuccessorsResponse(GetSuccessorsResponseComplete {
        blocks: vec![],
        next: vec![],
    })
}

fn get_successors_reject() -> BitcoinAdapterResponseWrapper {
    BitcoinAdapterResponseWrapper::GetSuccessorsReject(BitcoinReject {
        reject_code: RejectCode::SysTransient,
        message: "ConnectionBroken".to_string(),
    })
}

fn send_transaction_response() -> BitcoinAdapterResponseWrapper {
    BitcoinAdapterResponseWrapper::SendTransactionResponse(SendTransactionResponse {})
}

fn send_transaction_reject() -> BitcoinAdapterResponseWrapper {
    BitcoinAdapterResponseWrapper::SendTransactionReject(BitcoinReject {
        reject_code: RejectCode::SysTransient,
        message: "ConnectionBroken".to_string(),
    })
}

fn payload_with(responses: Vec<(BitcoinAdapterResponseWrapper, u64)>) -> SelfValidatingPayload {
    SelfValidatingPayload::new(
        responses
            .into_iter()
            .map(|(response, callback_id)| BitcoinAdapterResponse {
                response,
                callback_id,
            })
            .collect(),
    )
}

#[test]
fn validation_accepts_responses_to_pending_requests_of_matching_type() {
    bitcoin_payload_builder_test(
        MockAdapterClient::new(),
        MockAdapterClient::new(),
        mock_state_manager(get_successors_and_send_transaction_requests()),
        mock_registry_client(MAX_BLOCK_PAYLOAD_SIZE),
        |proposal_context, bitcoin_payload_builder| {
            for payload in [
                payload_with(vec![
                    (get_successors_response(), 0),
                    (send_transaction_response(), 1),
                ]),
                payload_with(vec![
                    (get_successors_reject(), 0),
                    (send_transaction_reject(), 1),
                ]),
            ] {
                let validation_result = bitcoin_payload_builder.validate_self_validating_payload(
                    &payload,
                    proposal_context.validation_context,
                    &[],
                );
                assert!(
                    validation_result.is_ok(),
                    "validation did not pass {validation_result:?}"
                );
            }
        },
    );
}

#[test]
fn validation_rejects_responses_without_pending_request_of_matching_type() {
    bitcoin_payload_builder_test(
        MockAdapterClient::new(),
        MockAdapterClient::new(),
        mock_state_manager(get_successors_and_send_transaction_requests()),
        mock_registry_client(MAX_BLOCK_PAYLOAD_SIZE),
        |proposal_context, bitcoin_payload_builder| {
            for (response, callback_id) in [
                // There is no pending request with callback ID 2.
                (get_successors_response(), 2),
                (send_transaction_reject(), 2),
                // Responses of the wrong type.
                (send_transaction_response(), 0),
                (send_transaction_reject(), 0),
                (get_successors_response(), 1),
                (get_successors_reject(), 1),
            ] {
                let validation_result = bitcoin_payload_builder.validate_self_validating_payload(
                    &payload_with(vec![(response.clone(), callback_id)]),
                    proposal_context.validation_context,
                    &[],
                );
                assert!(
                    matches!(
                        validation_result,
                        Err(ValidationError::InvalidArtifact(
                            InvalidSelfValidatingPayloadReason::NonMatchingResponse(id)
                        )) if id == CallbackId::from(callback_id)
                    ),
                    "{response:?} for callback ID {callback_id}: unexpected result {validation_result:?}"
                );
            }
        },
    );
}

#[test]
fn validation_rejects_duplicate_responses() {
    bitcoin_payload_builder_test(
        MockAdapterClient::new(),
        MockAdapterClient::new(),
        mock_state_manager(get_successors_and_send_transaction_requests()),
        mock_registry_client(MAX_BLOCK_PAYLOAD_SIZE),
        |proposal_context, bitcoin_payload_builder| {
            // Two responses for the same request in one payload.
            let validation_result = bitcoin_payload_builder.validate_self_validating_payload(
                &payload_with(vec![
                    (get_successors_response(), 0),
                    (get_successors_reject(), 0),
                ]),
                proposal_context.validation_context,
                &[],
            );
            assert!(
                matches!(
                    validation_result,
                    Err(ValidationError::InvalidArtifact(
                        InvalidSelfValidatingPayloadReason::DuplicateResponse(id)
                    )) if id == CallbackId::from(0)
                ),
                "unexpected result {validation_result:?}"
            );

            // A response for a request that a past payload already answered.
            let past_payload = payload_with(vec![(send_transaction_reject(), 1)]);
            let validation_result = bitcoin_payload_builder.validate_self_validating_payload(
                &payload_with(vec![(send_transaction_response(), 1)]),
                proposal_context.validation_context,
                &[&past_payload],
            );
            assert!(
                matches!(
                    validation_result,
                    Err(ValidationError::InvalidArtifact(
                        InvalidSelfValidatingPayloadReason::DuplicateResponse(id)
                    )) if id == CallbackId::from(1)
                ),
                "unexpected result {validation_result:?}"
            );

            // The same, through `BatchPayloadBuilder::validate_payload()`.
            let past_payload = parse::payload_to_bytes(
                &past_payload,
                SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
                &no_op_logger(),
            );
            let payload = parse::payload_to_bytes(
                &payload_with(vec![(send_transaction_response(), 1)]),
                SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
                &no_op_logger(),
            );
            let validation_result = bitcoin_payload_builder.validate_payload(
                Height::new(1),
                &proposal_context,
                &payload,
                &[PastPayload {
                    height: Height::from(0),
                    time: UNIX_EPOCH,
                    block_hash: CryptoHashOf::from(CryptoHash(vec![])),
                    payload: &past_payload,
                }],
            );
            assert!(
                matches!(
                    validation_result,
                    Err(ValidationError::InvalidArtifact(
                        InvalidPayloadReason::InvalidSelfValidatingPayload(
                            InvalidSelfValidatingPayloadReason::DuplicateResponse(id)
                        )
                    )) if id == CallbackId::from(1)
                ),
                "unexpected result {validation_result:?}"
            );
        },
    );
}

#[test]
fn validation_fails_if_state_is_unavailable() {
    let mut state_manager = MockStateManager::new();
    state_manager
        .expect_get_state_at()
        .return_const(Err(StateManagerError::StateNotCommittedYet(
            CERTIFIED_HEIGHT,
        )));

    bitcoin_payload_builder_test(
        MockAdapterClient::new(),
        MockAdapterClient::new(),
        state_manager,
        mock_registry_client(MAX_BLOCK_PAYLOAD_SIZE),
        |proposal_context, bitcoin_payload_builder| {
            let validation_result = bitcoin_payload_builder.validate_self_validating_payload(
                &payload_with(vec![(get_successors_response(), 0)]),
                proposal_context.validation_context,
                &[],
            );
            assert!(
                matches!(
                    validation_result,
                    Err(ValidationError::ValidationFailed(
                        SelfValidatingPayloadValidationFailure::StateUnavailable
                    ))
                ),
                "unexpected result {validation_result:?}"
            );
        },
    );
}
