use crate::BitcoinPayloadBuilder;
use ic_btc_interface::Network;
use ic_btc_types_internal::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponse, BitcoinAdapterResponseWrapper,
    GetSuccessorsRequestInitial, GetSuccessorsResponseComplete,
};
use ic_interfaces::self_validating_payload::SelfValidatingPayloadBuilder;
use ic_interfaces_adapter_client::{Options, RpcAdapterClient, RpcError, RpcResult};
use ic_interfaces_registry::RegistryValue;
use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_test_utilities::{
    mock_time, self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
    state::ReplicatedStateBuilder, types::ids::subnet_test_id,
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types::{batch::ValidationContext, Height, NumBytes, RegistryVersion, SubnetId};
use mockall::mock;
use std::sync::Arc;

const CERTIFIED_HEIGHT: Height = Height::new(9);
const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(101);
const SELF_VALIDATING_PAYLOAD_BYTE_LIMIT: NumBytes = NumBytes::new(2 * 1024 * 1024); // 2MiB.
const MAX_BLOCK_PAYLOAD_SIZE: NumBytes = NumBytes::new(4 * 1024 * 1024); // 4MiB.

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
fn mock_state_manager(
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

fn mock_registry_client(max_block_payload_size: NumBytes) -> MockRegistryClient {
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
    run_test: impl FnOnce(ValidationContext, BitcoinPayloadBuilder),
) {
    with_test_replica_logger(|log| {
        let time = mock_time();
        let validation_context = ValidationContext {
            registry_version: REGISTRY_VERSION,
            certified_height: CERTIFIED_HEIGHT,
            time,
        };

        let bitcoin_payload_builder = BitcoinPayloadBuilder::new(
            Arc::new(state_manager),
            &MetricsRegistry::new(),
            Box::new(bitcoin_mainnet_adapter_client),
            Box::new(bitcoin_testnet_adapter_client),
            subnet_test_id(0),
            Arc::new(registry_client),
            log,
        );

        run_test(validation_context, bitcoin_payload_builder);
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
        |validation_context, bitcoin_payload_builder| {
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
                    &validation_context,
                    &[],
                    SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
                )
                .0;
            assert_eq!(payload, expected_payload);
        },
    );
}

#[test]
fn includes_only_successful_responses_in_the_payload() {
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
        |validation_context, bitcoin_payload_builder| {
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
                    &validation_context,
                    &[],
                    SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
                )
                .0;
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
        |validation_context, bitcoin_payload_builder| {
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

            let payload = bitcoin_payload_builder
                .get_self_validating_payload(
                    &validation_context,
                    &[&past_payload],
                    SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
                )
                .0;
            assert_eq!(payload, expected_payload);
        },
    );
}

#[test]
fn bitcoin_payload_builder_respects_byte_limit() {
    let dummy_header = vec![0; 80];

    let dummy_response =
        BitcoinAdapterResponseWrapper::GetSuccessorsResponse(GetSuccessorsResponseComplete {
            blocks: vec![],
            next: vec![dummy_header],
        });
    let dummy_response_wrapper = BitcoinAdapterResponse {
        response: dummy_response.clone(),
        callback_id: 0,
    };
    let dummy_response_wrapper_size = dummy_response_wrapper.count_bytes() as u64;

    // There are 3 adapter requests available in the bitcoin state. We test with
    // 4 different byte limits:
    //   1. A value that allows 1 of the 3 responses to be included.
    //   2. A value that allows 2 of the 3 responses to be included.
    //   3. A value that allows *exactly* all 3 responses.
    //   4. A large enough value that allows all 3 responses.
    let byte_limits = vec![
        NumBytes::from(dummy_response_wrapper_size),
        NumBytes::from(3 * dummy_response_wrapper_size - 10),
        NumBytes::from(3 * dummy_response_wrapper_size),
        NumBytes::from(100 * dummy_response_wrapper_size),
    ];
    let one_response = vec![BitcoinAdapterResponse {
        response: dummy_response.clone(),
        callback_id: 0,
    }];
    let mut two_responses = one_response.clone();
    two_responses.push(BitcoinAdapterResponse {
        response: dummy_response.clone(),
        callback_id: 1,
    });
    let mut three_responses = two_responses.clone();
    three_responses.push(BitcoinAdapterResponse {
        response: dummy_response,
        callback_id: 2,
    });

    // Set the expected payloads for the 4 cases.
    let expected_payloads = vec![
        FakeSelfValidatingPayloadBuilder::new()
            .with_responses(one_response)
            .build(),
        FakeSelfValidatingPayloadBuilder::new()
            .with_responses(two_responses)
            .build(),
        FakeSelfValidatingPayloadBuilder::new()
            .with_responses(three_responses.clone())
            .build(),
        FakeSelfValidatingPayloadBuilder::new()
            .with_responses(three_responses)
            .build(),
    ];

    for (i, byte_limit) in byte_limits.into_iter().enumerate() {
        // Create a mock bitcoin adapter client that returns a dummy response
        // for each request.
        let bitcoin_mainnet_adapter_client = MockBitcoinAdapterClient::new();
        let mut bitcoin_testnet_adapter_client = MockBitcoinAdapterClient::new();
        bitcoin_testnet_adapter_client
            .expect_send_blocking()
            .returning(move |_, _| {
                Ok(BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                    GetSuccessorsResponseComplete {
                        blocks: vec![],
                        next: vec![vec![0; 80]],
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
            BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequestInitial {
                processed_block_hashes: vec![vec![30; 32]],
                anchor: vec![30; 32],
                network: Network::Testnet,
            }),
        ]);

        let registry_client = mock_registry_client(byte_limit);

        bitcoin_payload_builder_test(
            bitcoin_mainnet_adapter_client,
            bitcoin_testnet_adapter_client,
            state_manager,
            registry_client,
            |validation_context, bitcoin_payload_builder| {
                let payload = bitcoin_payload_builder
                    .get_self_validating_payload(&validation_context, &[], byte_limit)
                    .0;
                assert_eq!(
                    payload, expected_payloads[i],
                    "Test case {}: Actual payload {:?} does not match expected payload {:?}",
                    i, payload, expected_payloads[i]
                );
            },
        );
    }
}
