use ic00::BitcoinGetBlockHeadersArgs;
use ic_async_utils::incoming_from_path;
use ic_base_types::CanisterId;
use ic_btc_interface::NetworkInRequest as BitcoinNetwork;
use ic_btc_replica_types::{GetSuccessorsResponseComplete, GetSuccessorsResponsePartial};
use ic_btc_service::{
    btc_service_server::{BtcService, BtcServiceServer},
    BtcServiceGetSuccessorsRequest, BtcServiceGetSuccessorsResponse,
    BtcServiceSendTransactionRequest, BtcServiceSendTransactionResponse,
};
use ic_config::bitcoin_payload_builder_config::Config as BitcoinPayloadBuilderConfig;
use ic_config::{
    execution_environment::{BitcoinConfig, Config as HypervisorConfig},
    subnet_config::SubnetConfig,
};
use ic_error_types::RejectCode;
use ic_management_canister_types::{
    self as ic00, BitcoinGetBalanceArgs, BitcoinGetCurrentFeePercentilesArgs,
    BitcoinGetSuccessorsArgs, BitcoinGetUtxosArgs, BitcoinSendTransactionArgs,
    BitcoinSendTransactionInternalArgs, EmptyBlob, Method, Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_replica_tests as utils;
use ic_state_machine_tests::{StateMachine, StateMachineConfig};
use ic_test_utilities::universal_canister::{call_args, wasm};
use ic_types::ingress::WasmResult;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tonic::transport::Server;

struct MockBitcoinAdapterBuilder {
    get_successors_response: Result<BtcServiceGetSuccessorsResponse, tonic::Status>,
    send_transaction_response: Result<BtcServiceSendTransactionResponse, tonic::Status>,
}

impl MockBitcoinAdapterBuilder {
    fn new() -> Self {
        Self {
            get_successors_response: Ok(BtcServiceGetSuccessorsResponse {
                blocks: vec![],
                next: vec![],
            }),

            send_transaction_response: Ok(BtcServiceSendTransactionResponse {}),
        }
    }

    fn with_get_successors_reply(self, reply: BtcServiceGetSuccessorsResponse) -> Self {
        Self {
            get_successors_response: Ok(reply),
            ..self
        }
    }

    fn with_get_successors_reject(self, reject: tonic::Status) -> Self {
        Self {
            get_successors_response: Err(reject),
            ..self
        }
    }

    fn with_send_transaction_reply(self, reply: BtcServiceSendTransactionResponse) -> Self {
        Self {
            send_transaction_response: Ok(reply),
            ..self
        }
    }

    fn with_send_transaction_reject(self, reject: tonic::Status) -> Self {
        Self {
            send_transaction_response: Err(reject),
            ..self
        }
    }

    fn build(self) -> MockBitcoinAdapter {
        MockBitcoinAdapter {
            get_successors_response: self.get_successors_response,
            send_transaction_response: self.send_transaction_response,
        }
    }
}

struct MockBitcoinAdapter {
    get_successors_response: Result<BtcServiceGetSuccessorsResponse, tonic::Status>,
    send_transaction_response: Result<BtcServiceSendTransactionResponse, tonic::Status>,
}

#[tonic::async_trait]
impl BtcService for MockBitcoinAdapter {
    async fn get_successors(
        &self,
        _request: tonic::Request<BtcServiceGetSuccessorsRequest>,
    ) -> Result<tonic::Response<BtcServiceGetSuccessorsResponse>, tonic::Status> {
        self.get_successors_response
            .clone()
            .map(tonic::Response::new)
    }

    async fn send_transaction(
        &self,
        _request: tonic::Request<BtcServiceSendTransactionRequest>,
    ) -> Result<tonic::Response<BtcServiceSendTransactionResponse>, tonic::Status> {
        self.send_transaction_response
            .clone()
            .map(tonic::Response::new)
    }
}

fn spawn_mock_bitcoin_adapter(
    uds_path: Arc<TempDir>,
    adapter: MockBitcoinAdapter,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        Server::builder()
            .add_service(BtcServiceServer::new(adapter))
            .serve_with_incoming(incoming_from_path(uds_path.path().join("uds.socket")))
            .await
            .expect("gRPC server crashed");
    })
}

fn call_get_successors(
    canister: &ic_replica_tests::UniversalCanister,
    args: BitcoinGetSuccessorsArgs,
) -> WasmResult {
    canister
        .update(
            wasm().call_simple(
                ic00::IC_00,
                Method::BitcoinGetSuccessors,
                call_args()
                    .other_side(args.encode())
                    .on_reject(wasm().reject_message().reject()),
            ),
        )
        .unwrap()
}

fn call_send_transaction_internal(
    canister: &ic_replica_tests::UniversalCanister,
    args: BitcoinSendTransactionInternalArgs,
) -> WasmResult {
    canister
        .update(
            wasm().call_simple(
                ic00::IC_00,
                Method::BitcoinSendTransactionInternal,
                call_args()
                    .other_side(args.encode())
                    .on_reject(wasm().reject_message().reject()),
            ),
        )
        .unwrap()
}

fn bitcoin_test<F>(adapter: MockBitcoinAdapter, test: F)
where
    F: FnOnce(utils::LocalTestRuntime) + 'static,
{
    bitcoin_test_with_config(adapter, true, test)
}

fn bitcoin_test_with_config<F>(adapter: MockBitcoinAdapter, privileged_access: bool, test: F)
where
    F: FnOnce(utils::LocalTestRuntime) + 'static,
{
    let (mut config, _tmpdir) = ic_config::Config::temp_config();
    if privileged_access {
        // Give canister the privileged access of calling the internal bitcoin APIs.
        config.hypervisor.bitcoin = BitcoinConfig {
            privileged_access: vec![CanisterId::from_str("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap()],
            ..Default::default()
        };
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _rt_guard = rt.enter();
    let tmp_uds_dir = Arc::new(tempfile::tempdir().unwrap());
    let _ma = spawn_mock_bitcoin_adapter(tmp_uds_dir.clone(), adapter);
    config.adapters_config.bitcoin_mainnet_uds_path = Some(tmp_uds_dir.path().join("uds.socket"));
    config.adapters_config.bitcoin_testnet_uds_path = Some(tmp_uds_dir.path().join("uds.socket"));
    config.bitcoin_payload_builder_config = BitcoinPayloadBuilderConfig {
        adapter_timeout: Duration::from_secs(1),
    };

    utils::canister_test_with_config(config, test);
}

#[test]
fn bitcoin_get_successors() {
    bitcoin_test(
        MockBitcoinAdapterBuilder::new()
            .with_get_successors_reply(BtcServiceGetSuccessorsResponse {
                blocks: vec![],
                next: vec![],
            })
            .build(),
        |runtime| {
            let canister_id = runtime.create_universal_canister();
            let canister = ic_replica_tests::UniversalCanister {
                runtime,
                canister_id,
            };

            let response = call_get_successors(
                &canister,
                ic00::BitcoinGetSuccessorsArgs::Initial(ic00::BitcoinGetSuccessorsRequestInitial {
                    network: ic_btc_interface::Network::Regtest,
                    anchor: vec![],
                    processed_block_hashes: vec![],
                }),
            );

            // Expect a dummy response.
            let expected_response =
                ic00::BitcoinGetSuccessorsResponse::Complete(GetSuccessorsResponseComplete {
                    blocks: vec![],
                    next: vec![],
                });

            assert_eq!(response, WasmResult::Reply(expected_response.encode()));
        },
    );
}

#[test]
fn bitcoin_get_successors_pagination() {
    bitcoin_test(
        // A mock adapter response returning a large payload that doesn't fit.
        MockBitcoinAdapterBuilder::new()
            .with_get_successors_reply(BtcServiceGetSuccessorsResponse {
                blocks: vec![vec![0; 4_000_000]],
                next: vec![],
            })
            .build(),
        |runtime| {
            let canister_id = runtime.create_universal_canister();
            let canister = ic_replica_tests::UniversalCanister {
                runtime,
                canister_id,
            };

            let response = call_get_successors(
                &canister,
                ic00::BitcoinGetSuccessorsArgs::Initial(ic00::BitcoinGetSuccessorsRequestInitial {
                    network: ic_btc_interface::Network::Regtest,
                    anchor: vec![],
                    processed_block_hashes: vec![],
                }),
            );

            let expected_response =
                ic00::BitcoinGetSuccessorsResponse::Partial(GetSuccessorsResponsePartial {
                    partial_block: vec![0; 2_000_000],
                    next: vec![],
                    remaining_follow_ups: 1,
                });

            assert_eq!(response, WasmResult::Reply(expected_response.encode()));

            let response = call_get_successors(&canister, BitcoinGetSuccessorsArgs::FollowUp(0));
            let expected_response =
                ic00::BitcoinGetSuccessorsResponse::FollowUp(vec![0; 2_000_000]);
            assert_eq!(response, WasmResult::Reply(expected_response.encode()));

            let response = call_get_successors(&canister, BitcoinGetSuccessorsArgs::FollowUp(1));
            assert_eq!(response, WasmResult::Reject("Page not found.".to_string()));
        },
    );
}

#[test]
fn bitcoin_get_successors_pagination_invalid_adapter_request() {
    bitcoin_test(
        // A mock adapter response returning a large payload that doesn't fit.
        MockBitcoinAdapterBuilder::new()
            .with_get_successors_reply(BtcServiceGetSuccessorsResponse {
                blocks: vec![vec![0; 4_000_000], vec![0]],
                next: vec![],
            })
            .build(),
        |runtime| {
            let canister_id = runtime.create_universal_canister();
            let canister = ic_replica_tests::UniversalCanister {
                runtime,
                canister_id,
            };

            let response = call_get_successors(
                &canister,
                ic00::BitcoinGetSuccessorsArgs::Initial(ic00::BitcoinGetSuccessorsRequestInitial {
                    network: ic_btc_interface::Network::Regtest,
                    anchor: vec![],
                    processed_block_hashes: vec![],
                }),
            );

            assert_eq!(
                response,
                WasmResult::Reject(
                    "Received invalid response from adapter: NotOneBlock".to_string()
                )
            );
        },
    );
}

#[test]
fn bitcoin_get_successors_reject() {
    let err_message = "get_successors error has occurred";
    bitcoin_test(
        MockBitcoinAdapterBuilder::new()
            .with_get_successors_reject(tonic::Status::unavailable(err_message))
            .build(),
        move |runtime| {
            let canister_id = runtime.create_universal_canister();
            let canister = ic_replica_tests::UniversalCanister {
                runtime,
                canister_id,
            };

            // Send a request.
            let response = call_get_successors(
                &canister,
                ic00::BitcoinGetSuccessorsArgs::Initial(ic00::BitcoinGetSuccessorsRequestInitial {
                    network: ic_btc_interface::Network::Regtest,
                    anchor: vec![],
                    processed_block_hashes: vec![],
                }),
            );

            // Expect the reject message to be received.
            assert_eq!(
                response,
                WasmResult::Reject(format!("Unavailable({})", err_message))
            );
        },
    );
}

#[test]
fn bitcoin_send_transaction_internal_valid_request() {
    bitcoin_test(
        MockBitcoinAdapterBuilder::new()
            .with_send_transaction_reply(BtcServiceSendTransactionResponse {})
            .build(),
        |runtime| {
            let canister_id = runtime.create_universal_canister();
            let canister = ic_replica_tests::UniversalCanister {
                runtime,
                canister_id,
            };

            // Send a request.
            let response = call_send_transaction_internal(
                &canister,
                ic00::BitcoinSendTransactionInternalArgs {
                    network: ic_btc_interface::Network::Regtest,
                    transaction: vec![1, 2, 3],
                },
            );

            // Expect an empty response.
            assert_eq!(response, WasmResult::Reply(EmptyBlob.encode()));
        },
    );
}

#[test]
fn bitcoin_send_transaction_internal_reject() {
    let err_message = "send_transaction error has occurred";
    bitcoin_test(
        MockBitcoinAdapterBuilder::new()
            .with_send_transaction_reject(tonic::Status::unavailable(err_message))
            .build(),
        move |runtime| {
            let canister_id = runtime.create_universal_canister();
            let canister = ic_replica_tests::UniversalCanister {
                runtime,
                canister_id,
            };

            // Send a request.
            let response = call_send_transaction_internal(
                &canister,
                ic00::BitcoinSendTransactionInternalArgs {
                    network: ic_btc_interface::Network::Regtest,
                    transaction: vec![1, 2, 3],
                },
            );

            // Expect the reject message to be received.
            assert_eq!(
                response,
                WasmResult::Reject(format!("Unavailable({})", err_message))
            );
        },
    );
}

#[test]
fn bitcoin_send_transaction_internal_invalid_request() {
    bitcoin_test(MockBitcoinAdapterBuilder::new().build(), |runtime| {
        let canister_id = runtime.create_universal_canister();
        let canister = ic_replica_tests::UniversalCanister {
            runtime,
            canister_id,
        };

        // Send a request.
        let response = canister
            .update(wasm().call_simple(
                ic00::IC_00,
                Method::BitcoinSendTransactionInternal,
                call_args().other_side(vec![1, 2, 3]), // garbage payload
            ))
            .unwrap();

        // Expect request to be rejected.
        utils::assert_reject(Ok(response), RejectCode::CanisterReject);
    });
}

#[test]
fn bitcoin_send_transaction_internal_no_permissions() {
    bitcoin_test_with_config(
        MockBitcoinAdapterBuilder::new().build(),
        false, // Do not give permission to call internal bitcoin APIs.
        |runtime| {
            let canister_id = runtime.create_universal_canister();
            let canister = ic_replica_tests::UniversalCanister {
                runtime,
                canister_id,
            };

            // Send a valid request.
            let response = call_send_transaction_internal(
                &canister,
                ic00::BitcoinSendTransactionInternalArgs {
                    network: ic_btc_interface::Network::Regtest,
                    transaction: vec![1, 2, 3],
                },
            );

            // Expect request to be rejected. No permission to canister.
            assert_eq!(
                response,
                WasmResult::Reject("Permission denied.".to_string())
            );
        },
    );
}

// Returns a WAT that exposes all the bitcoin endpoints.
// The endpoints simply return a message mentioning the network.
fn mock_bitcoin_canister_wat(network: BitcoinNetwork) -> String {
    format!(
        r#"(module
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))

              (func $ping
                (call $msg_reply_data_append
                  (i32.const 0)
                  (i32.const 19))
                (call $msg_reply))

              (memory $memory 1)
              (export "memory" (memory $memory))
              (data (i32.const 0) "Hello from {}!")
              (export "canister_update bitcoin_get_balance" (func $ping))
              (export "canister_update bitcoin_get_utxos" (func $ping))
              (export "canister_update bitcoin_get_block_headers" (func $ping))
              (export "canister_update bitcoin_send_transaction" (func $ping))
              (export "canister_update bitcoin_get_current_fee_percentiles" (func $ping))
            )"#,
        network
    )
}

fn test_canister_routing(env: StateMachine, networks: Vec<BitcoinNetwork>) {
    let canister = utils::install_universal_canister(&env, vec![]);

    for network in networks {
        let tests = [
            (
                "bitcoin_get_balance",
                BitcoinGetBalanceArgs {
                    network,
                    address: String::from(""),
                    min_confirmations: None,
                }
                .encode(),
            ),
            (
                "bitcoin_get_utxos",
                BitcoinGetUtxosArgs {
                    network,
                    address: String::from(""),
                    filter: None,
                }
                .encode(),
            ),
            (
                "bitcoin_get_block_headers",
                BitcoinGetBlockHeadersArgs {
                    network,
                    start_height: 0,
                    end_height: None,
                }
                .encode(),
            ),
            (
                "bitcoin_get_current_fee_percentiles",
                BitcoinGetCurrentFeePercentilesArgs { network }.encode(),
            ),
            (
                "bitcoin_send_transaction",
                BitcoinSendTransactionArgs {
                    network,
                    transaction: vec![1, 2, 3],
                }
                .encode(),
            ),
        ];

        for (method, payload) in tests {
            utils::assert_reply(
                canister.update(wasm().call_simple(
                    CanisterId::ic_00(),
                    method,
                    call_args().other_side(payload),
                )),
                format!("Hello from {}!", network).as_bytes(),
            );
        }
    }
}

#[test]
fn testnet_requests_are_routed_to_testnet_canister() {
    let bitcoin_canister_id: CanisterId =
        CanisterId::from_str("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();

    let env = StateMachine::new_with_config(StateMachineConfig::new(
        SubnetConfig::new(SubnetType::System),
        HypervisorConfig {
            bitcoin: BitcoinConfig {
                testnet_canister_id: Some(bitcoin_canister_id),
                ..Default::default()
            },
            ..Default::default()
        },
    ));

    let canister_id = env.install_canister_wat(
        &mock_bitcoin_canister_wat(BitcoinNetwork::Testnet),
        vec![],
        None,
    );

    // The canister we installed had the ID we expected.
    assert_eq!(canister_id, bitcoin_canister_id);

    test_canister_routing(env, vec![BitcoinNetwork::Testnet, BitcoinNetwork::testnet]);
}

#[test]
fn regtest_requests_are_routed_to_testnet_canister() {
    let bitcoin_canister_id: CanisterId =
        CanisterId::from_str("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();

    let env = StateMachine::new_with_config(StateMachineConfig::new(
        SubnetConfig::new(SubnetType::System),
        HypervisorConfig {
            bitcoin: BitcoinConfig {
                testnet_canister_id: Some(bitcoin_canister_id),
                ..Default::default()
            },
            ..Default::default()
        },
    ));

    let canister_id = env.install_canister_wat(
        &mock_bitcoin_canister_wat(BitcoinNetwork::Regtest),
        vec![],
        None,
    );

    // The canister we installed had the ID we expected.
    assert_eq!(canister_id, bitcoin_canister_id);

    test_canister_routing(env, vec![BitcoinNetwork::Regtest, BitcoinNetwork::regtest]);
}

#[test]
fn mainnet_requests_are_routed_to_mainnet_canister() {
    let bitcoin_canister_id: CanisterId =
        CanisterId::from_str("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();

    let env = StateMachine::new_with_config(StateMachineConfig::new(
        SubnetConfig::new(SubnetType::System),
        HypervisorConfig {
            bitcoin: BitcoinConfig {
                mainnet_canister_id: Some(bitcoin_canister_id),
                ..Default::default()
            },
            ..Default::default()
        },
    ));

    let canister_id = env.install_canister_wat(
        &mock_bitcoin_canister_wat(BitcoinNetwork::Mainnet),
        vec![],
        None,
    );

    // The canister we installed had the ID we expected.
    assert_eq!(canister_id, bitcoin_canister_id);

    test_canister_routing(env, vec![BitcoinNetwork::Mainnet, BitcoinNetwork::mainnet]);
}

#[test]
fn requests_are_rejected_if_no_bitcoin_canisters_are_set() {
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        SubnetConfig::new(SubnetType::System),
        HypervisorConfig {
            // No bitcoin canisters set.
            bitcoin: BitcoinConfig::default(),
            ..Default::default()
        },
    ));

    let canister = utils::install_universal_canister(&env, vec![]);

    for network in [
        BitcoinNetwork::Testnet,
        BitcoinNetwork::testnet,
        BitcoinNetwork::Mainnet,
        BitcoinNetwork::mainnet,
        BitcoinNetwork::Regtest,
        BitcoinNetwork::regtest,
    ] {
        let tests = [
            (
                "bitcoin_get_balance",
                BitcoinGetBalanceArgs {
                    network,
                    address: String::from(""),
                    min_confirmations: None,
                }
                .encode(),
            ),
            (
                "bitcoin_get_utxos",
                BitcoinGetUtxosArgs {
                    network,
                    address: String::from(""),
                    filter: None,
                }
                .encode(),
            ),
            (
                "bitcoin_get_block_headers",
                BitcoinGetBlockHeadersArgs {
                    network,
                    start_height: 0,
                    end_height: None,
                }
                .encode(),
            ),
            (
                "bitcoin_get_current_fee_percentiles",
                BitcoinGetCurrentFeePercentilesArgs { network }.encode(),
            ),
            (
                "bitcoin_send_transaction",
                BitcoinSendTransactionArgs {
                    network,
                    transaction: vec![],
                }
                .encode(),
            ),
        ];

        for (method, payload) in tests {
            utils::assert_reject(
                canister.update(wasm().call_simple(
                    CanisterId::ic_00(),
                    method,
                    call_args().other_side(payload),
                )),
                RejectCode::CanisterReject,
            );
        }
    }
}
