use crate::{payload_builder::parse, BitcoinPayloadBuilder};
use ic_btc_interface::Network;
use ic_btc_replica_types::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponse, BitcoinAdapterResponseWrapper,
    BitcoinReject, GetSuccessorsRequestInitial, GetSuccessorsResponseComplete,
};
use ic_config::bitcoin_payload_builder_config::Config;
use ic_error_types::RejectCode;
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext},
    self_validating_payload::SelfValidatingPayloadBuilder,
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
    batch::ValidationContext,
    crypto::{CryptoHash, CryptoHashOf},
    time::UNIX_EPOCH,
    Height, NumBytes, RegistryVersion, SubnetId,
};
use mockall::mock;
use std::sync::Arc;

pub(crate) const CERTIFIED_HEIGHT: Height = Height::new(9);
pub(crate) const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(101);
pub(crate) const SELF_VALIDATING_PAYLOAD_BYTE_LIMIT: NumBytes = NumBytes::new(2 * 1024 * 1024); // 2MiB.
pub(crate) const MAX_BLOCK_PAYLOAD_SIZE: NumBytes = NumBytes::new(4 * 1024 * 1024); // 4MiB.

mock! {
    pub BitcoinAdapterClient {}

    impl RpcAdapterClient<BitcoinAdapterRequestWrapper> for BitcoinAdapterClient {
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
    format!("{}{}", SUBNET_RECORD_KEY_PREFIX, subnet_id)
}

fn bitcoin_payload_builder_test(
    bitcoin_mainnet_adapter_client: MockBitcoinAdapterClient,
    bitcoin_testnet_adapter_client: MockBitcoinAdapterClient,
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
    fn mock_adapter() -> MockBitcoinAdapterClient {
        let mut adapter_client = MockBitcoinAdapterClient::new();
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
                network: Network::Testnet,
            },
        )]);

    bitcoin_payload_builder_test(
        MockBitcoinAdapterClient::new(),
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
    fn mock_adapter() -> MockBitcoinAdapterClient {
        let mut adapter_client = MockBitcoinAdapterClient::new();
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
            network: Network::Testnet,
        }),
        BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequestInitial {
            processed_block_hashes: vec![vec![20; 32]],
            anchor: vec![20; 32],
            network: Network::Testnet,
        }),
    ]);

    let registry_client = mock_registry_client(MAX_BLOCK_PAYLOAD_SIZE);

    bitcoin_payload_builder_test(
        MockBitcoinAdapterClient::new(),
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
                "validation did not pass {:?}",
                validation_result
            );

            assert_eq!(payload, expected_payload);
        },
    );
}

#[test]
fn includes_only_responses_for_callback_ids_not_seen_in_past_payloads() {
    // Create a mock bitcoin adapter client that returns a dummy response
    // for each request.
    let bitcoin_mainnet_adapter_client = MockBitcoinAdapterClient::new();
    let mut bitcoin_testnet_adapter_client = MockBitcoinAdapterClient::new();
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
            network: Network::Testnet,
        }),
        BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequestInitial {
            processed_block_hashes: vec![vec![20; 32]],
            anchor: vec![20; 32],
            network: Network::Testnet,
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
                "validation did not pass {:?}",
                validation_result
            );

            assert_eq!(payload, expected_payload);
        },
    );
}

#[test]
fn bitcoin_payload_builder_fits_largest_blocks() {
    // Create a mock bitcoin adapter client that returns a dummy response
    // for each request.
    let bitcoin_mainnet_adapter_client = MockBitcoinAdapterClient::new();
    let mut bitcoin_testnet_adapter_client = MockBitcoinAdapterClient::new();
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
                network: Network::Testnet,
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
                "validation did not pass {:?}",
                validation_result
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
