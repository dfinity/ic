use crate::BitcoinPayloadBuilder;
use ic_interfaces::{
    bitcoin_adapter_client::RpcError, self_validating_payload::SelfValidatingPayloadBuilder,
};
use ic_metrics::MetricsRegistry;
use ic_protobuf::bitcoin::v1 as pb_bitcoin;
use ic_registry_subnet_features::SubnetFeatures;
use ic_test_utilities::{
    bitcoin_adapter_client::MockBitcoinAdapterClient, mock_time,
    self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
    state::ReplicatedStateBuilder, state_manager::MockStateManager, with_test_replica_logger,
};
use ic_types::{
    batch::ValidationContext,
    bitcoin::{
        BitcoinAdapterRequestWrapper, BitcoinAdapterResponse, BitcoinAdapterResponseWrapper,
        GetSuccessorsRequest, GetSuccessorsResponse,
    },
    CountBytes, Height, NumBytes, RegistryVersion,
};
use std::{str::FromStr, sync::Arc};

const CERTIFIED_HEIGHT: Height = Height::new(9);
const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(101);
const SELF_VALIDATING_PAYLOAD_BYTE_LIMIT: NumBytes = NumBytes::new(2 * 1024 * 1024); // 2MiB.

// Returns a `MockStateManager` that returns a state with the provided
// `subnet_features` and `bitcoin_adapter_requests`.
fn mock_state_manager(
    subnet_features: SubnetFeatures,
    bitcoin_adapter_requests: Vec<BitcoinAdapterRequestWrapper>,
) -> MockStateManager {
    let mut state_manager = MockStateManager::new();
    state_manager.expect_get_state_at().return_const(Ok(
        ic_interfaces::state_manager::Labeled::new(
            CERTIFIED_HEIGHT,
            Arc::new(
                ReplicatedStateBuilder::default()
                    .with_subnet_features(subnet_features)
                    .with_bitcoin_adapter_requests(bitcoin_adapter_requests)
                    .build(),
            ),
        ),
    ));
    state_manager
}

fn bitcoin_payload_builder_test(
    bitcoin_adapter_client: MockBitcoinAdapterClient,
    state_manager: MockStateManager,
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
            Arc::new(bitcoin_adapter_client),
            log,
        );

        run_test(validation_context, bitcoin_payload_builder);
    });
}

#[test]
fn can_successfully_create_bitcoin_payload_if_feature_enabled() {
    // Create a mock bitcoin adapter client that returns a dummy response
    // for each request.
    let mut bitcoin_adapter_client = MockBitcoinAdapterClient::new();
    bitcoin_adapter_client
        .expect_send_request()
        .times(1)
        .returning(|_, _| {
            Ok(pb_bitcoin::BitcoinAdapterResponseWrapper {
                r: Some(
                    pb_bitcoin::bitcoin_adapter_response_wrapper::R::GetSuccessorsResponse(
                        pb_bitcoin::GetSuccessorsResponse {
                            blocks: vec![],
                            next: vec![],
                        },
                    ),
                ),
            })
        });

    // Create a mock state manager that returns a `ReplicatedState` with
    // bitcoin testnet feature enabled and some bitcoin adapter requests.
    let state_manager = mock_state_manager(
        SubnetFeatures::from_str("bitcoin_testnet").unwrap(),
        vec![BitcoinAdapterRequestWrapper::GetSuccessorsRequest(
            GetSuccessorsRequest {
                processed_block_hashes: vec![vec![10; 32]],
                anchor: vec![10; 32],
            },
        )],
    );

    bitcoin_payload_builder_test(
        bitcoin_adapter_client,
        state_manager,
        |validation_context, bitcoin_payload_builder| {
            let expected_payload = FakeSelfValidatingPayloadBuilder::new()
                .with_responses(vec![BitcoinAdapterResponse {
                    response: BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                        GetSuccessorsResponse {
                            blocks: vec![],
                            next: vec![],
                        },
                    ),
                    callback_id: 0,
                }])
                .build();

            let payload = bitcoin_payload_builder.get_self_validating_payload(
                &validation_context,
                &[],
                SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
            );
            assert_eq!(payload, expected_payload);
        },
    );
}

#[test]
fn bitcoin_payload_builder_does_not_send_requests_if_feature_is_not_enabled() {
    let state_managers = vec![
        mock_state_manager(
            SubnetFeatures::from_str("bitcoin_testnet_paused").unwrap(),
            vec![],
        ),
        mock_state_manager(SubnetFeatures::default(), vec![]),
    ];

    for state_manager in state_managers.into_iter() {
        // No calls to `send_request` are expected.
        let bitcoin_adapter_client = MockBitcoinAdapterClient::new();

        bitcoin_payload_builder_test(
            bitcoin_adapter_client,
            state_manager,
            |validation_context, bitcoin_payload_builder| {
                let expected_payload = FakeSelfValidatingPayloadBuilder::new().build();

                let payload = bitcoin_payload_builder.get_self_validating_payload(
                    &validation_context,
                    &[],
                    SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
                );
                assert_eq!(payload, expected_payload);
            },
        );
    }
}

#[test]
fn includes_only_successful_responses_in_the_payload() {
    // Create a mock bitcoin adapter client that returns a successful response
    // for the first request and an error for the second.
    let mut bitcoin_adapter_client = MockBitcoinAdapterClient::new();
    bitcoin_adapter_client
        .expect_send_request()
        .times(1)
        .returning(|_, _| {
            Ok(pb_bitcoin::BitcoinAdapterResponseWrapper {
                r: Some(
                    pb_bitcoin::bitcoin_adapter_response_wrapper::R::GetSuccessorsResponse(
                        pb_bitcoin::GetSuccessorsResponse {
                            blocks: vec![],
                            next: vec![],
                        },
                    ),
                ),
            })
        });
    bitcoin_adapter_client
        .expect_send_request()
        .times(1)
        .returning(|_, _| Err(RpcError::ConnectionBroken));

    // Create a mock state manager that returns a `ReplicatedState` with
    // bitcoin testnet feature enabled and some bitcoin adapter requests.
    let state_manager = mock_state_manager(
        SubnetFeatures::from_str("bitcoin_testnet").unwrap(),
        vec![
            BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequest {
                processed_block_hashes: vec![vec![10; 32]],
                anchor: vec![10; 32],
            }),
            BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequest {
                processed_block_hashes: vec![vec![20; 32]],
                anchor: vec![20; 32],
            }),
        ],
    );

    bitcoin_payload_builder_test(
        bitcoin_adapter_client,
        state_manager,
        |validation_context, bitcoin_payload_builder| {
            let expected_payload = FakeSelfValidatingPayloadBuilder::new()
                .with_responses(vec![BitcoinAdapterResponse {
                    response: BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                        GetSuccessorsResponse {
                            blocks: vec![],
                            next: vec![],
                        },
                    ),
                    callback_id: 0,
                }])
                .build();
            let payload = bitcoin_payload_builder.get_self_validating_payload(
                &validation_context,
                &[],
                SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
            );
            assert_eq!(payload, expected_payload);
        },
    );
}

#[test]
fn includes_only_responses_for_callback_ids_not_seen_in_past_payloads() {
    // Create a mock bitcoin adapter client that returns a dummy response
    // for each request.
    let mut bitcoin_adapter_client = MockBitcoinAdapterClient::new();
    bitcoin_adapter_client
        .expect_send_request()
        .times(1)
        .returning(|_, _| {
            Ok(pb_bitcoin::BitcoinAdapterResponseWrapper {
                r: Some(
                    pb_bitcoin::bitcoin_adapter_response_wrapper::R::GetSuccessorsResponse(
                        pb_bitcoin::GetSuccessorsResponse {
                            blocks: vec![],
                            next: vec![],
                        },
                    ),
                ),
            })
        });

    // Create a mock state manager that returns a `ReplicatedState` with
    // bitcoin testnet feature enabled and some bitcoin adapter requests.
    let state_manager = mock_state_manager(
        SubnetFeatures::from_str("bitcoin_testnet").unwrap(),
        vec![
            BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequest {
                processed_block_hashes: vec![vec![10; 32]],
                anchor: vec![10; 32],
            }),
            BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequest {
                processed_block_hashes: vec![vec![20; 32]],
                anchor: vec![20; 32],
            }),
        ],
    );

    bitcoin_payload_builder_test(
        bitcoin_adapter_client,
        state_manager,
        |validation_context, bitcoin_payload_builder| {
            let past_payload = FakeSelfValidatingPayloadBuilder::new()
                .with_responses(vec![BitcoinAdapterResponse {
                    response: BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                        GetSuccessorsResponse {
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
                        GetSuccessorsResponse {
                            blocks: vec![],
                            next: vec![],
                        },
                    ),
                    callback_id: 1,
                }])
                .build();

            let payload = bitcoin_payload_builder.get_self_validating_payload(
                &validation_context,
                &[&past_payload],
                SELF_VALIDATING_PAYLOAD_BYTE_LIMIT,
            );
            assert_eq!(payload, expected_payload);
        },
    );
}

#[test]
fn bitcoin_payload_builder_respects_byte_limit() {
    let dummy_header = pb_bitcoin::BlockHeader {
        version: 1,
        prev_blockhash: vec![10; 32],
        merkle_root: vec![20; 32],
        time: 100,
        bits: 128,
        nonce: 42,
    };

    let dummy_response =
        BitcoinAdapterResponseWrapper::GetSuccessorsResponse(GetSuccessorsResponse {
            blocks: vec![],
            next: vec![dummy_header.into()],
        });
    let dummy_response_wrapper = BitcoinAdapterResponse {
        response: dummy_response.clone(),
        callback_id: 0,
    };
    let dummy_response_wrapper_size = dummy_response_wrapper.count_bytes() as u64;

    // There are 3 adapter requests available in the bitcoin state. We test with
    // 4 different byte limits:
    //   1. A value that is smaller than one response to ensure we always include
    //      at least one response in the payload.
    //   2. A value that allows 2 of the 3 responses to be included.
    //   3. A value that allows *exactly* all 3 responses.
    //   4. A large enough value that allows all 3 responses.
    let byte_limits = vec![
        NumBytes::from(dummy_response_wrapper_size - 10),
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
        let mut bitcoin_adapter_client = MockBitcoinAdapterClient::new();
        bitcoin_adapter_client
            .expect_send_request()
            .returning(move |_, _| {
                Ok(pb_bitcoin::BitcoinAdapterResponseWrapper {
                    r: Some(
                        pb_bitcoin::bitcoin_adapter_response_wrapper::R::GetSuccessorsResponse(
                            pb_bitcoin::GetSuccessorsResponse {
                                blocks: vec![],
                                next: vec![pb_bitcoin::BlockHeader {
                                    version: 1,
                                    prev_blockhash: vec![10; 32],
                                    merkle_root: vec![20; 32],
                                    time: 100,
                                    bits: 128,
                                    nonce: 42,
                                }],
                            },
                        ),
                    ),
                })
            });

        // Create a mock state manager that returns a `ReplicatedState` with
        // bitcoin testnet feature enabled and some bitcoin adapter requests.
        let state_manager = mock_state_manager(
            SubnetFeatures::from_str("bitcoin_testnet").unwrap(),
            vec![
                BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequest {
                    processed_block_hashes: vec![vec![10; 32]],
                    anchor: vec![10; 32],
                }),
                BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequest {
                    processed_block_hashes: vec![vec![20; 32]],
                    anchor: vec![20; 32],
                }),
                BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequest {
                    processed_block_hashes: vec![vec![30; 32]],
                    anchor: vec![30; 32],
                }),
            ],
        );

        bitcoin_payload_builder_test(
            bitcoin_adapter_client,
            state_manager,
            |validation_context, bitcoin_payload_builder| {
                let payload = bitcoin_payload_builder.get_self_validating_payload(
                    &validation_context,
                    &[],
                    byte_limit,
                );
                assert_eq!(
                    payload, expected_payloads[i],
                    "Test case {}: Actual payload {:?} does not match expected payload {:?}",
                    i, payload, expected_payloads[i]
                );
            },
        );
    }
}
