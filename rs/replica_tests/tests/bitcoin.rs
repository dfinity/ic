use ic_async_utils::incoming_from_path;
use ic_base_types::PrincipalId;
use ic_btc_service::{
    btc_service_server::{BtcService, BtcServiceServer},
    BtcServiceGetSuccessorsRequest, BtcServiceGetSuccessorsResponse,
    BtcServiceSendTransactionRequest, BtcServiceSendTransactionResponse,
};
use ic_btc_types_internal::{
    CanisterGetSuccessorsResponseComplete, CanisterGetSuccessorsResponsePartial,
};
use ic_ic00_types::{self as ic00, BitcoinGetSuccessorsArgs, Method, Payload};
use ic_replica_tests as utils;
use ic_test_utilities::universal_canister::{call_args, wasm};
use ic_types::ingress::WasmResult;
use std::str::FromStr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tonic::transport::Server;

struct MockBitcoinAdapter(BtcServiceGetSuccessorsResponse);

#[tonic::async_trait]
impl BtcService for MockBitcoinAdapter {
    async fn get_successors(
        &self,
        _request: tonic::Request<BtcServiceGetSuccessorsRequest>,
    ) -> Result<tonic::Response<BtcServiceGetSuccessorsResponse>, tonic::Status> {
        Ok(tonic::Response::new(self.0.clone()))
    }

    async fn send_transaction(
        &self,
        _request: tonic::Request<BtcServiceSendTransactionRequest>,
    ) -> Result<tonic::Response<BtcServiceSendTransactionResponse>, tonic::Status> {
        Ok(tonic::Response::new(BtcServiceSendTransactionResponse {}))
    }
}

fn spawn_mock_bitcoin_adapter(
    uds_path: Arc<TempDir>,
    mock_response: BtcServiceGetSuccessorsResponse,
) -> JoinHandle<()> {
    let adapter = MockBitcoinAdapter(mock_response);
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

fn bitcoin_test<F: 'static>(adapter_response: BtcServiceGetSuccessorsResponse, test: F)
where
    F: FnOnce(utils::LocalTestRuntime),
{
    let (mut config, _tmpdir) = ic_config::Config::temp_config();
    config.hypervisor.bitcoin_canisters =
        vec![PrincipalId::from_str("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap()];

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _rt_guard = rt.enter();
    let tmp_uds_dir = Arc::new(tempfile::tempdir().unwrap());
    let _ma = spawn_mock_bitcoin_adapter(tmp_uds_dir.clone(), adapter_response);
    config.adapters_config.bitcoin_mainnet_uds_path = Some(tmp_uds_dir.path().join("uds.socket"));
    config.adapters_config.bitcoin_testnet_uds_path = Some(tmp_uds_dir.path().join("uds.socket"));

    utils::canister_test_with_config(config, test);
}

#[test]
fn bitcoin_get_successors() {
    bitcoin_test(
        BtcServiceGetSuccessorsResponse {
            blocks: vec![],
            next: vec![],
        },
        |runtime| {
            let canister_id = runtime.create_universal_canister();
            let canister = ic_replica_tests::UniversalCanister {
                runtime,
                canister_id,
            };

            let response = call_get_successors(
                &canister,
                ic00::BitcoinGetSuccessorsArgs::Initial(ic00::BitcoinGetSuccessorsRequestInitial {
                    network: ic_btc_types::NetworkSnakeCase::Regtest,
                    anchor: vec![],
                    processed_block_hashes: vec![],
                }),
            );

            // Expect a dummy response.
            let expected_response = ic00::BitcoinGetSuccessorsResponse::Complete(
                CanisterGetSuccessorsResponseComplete {
                    blocks: vec![],
                    next: vec![],
                },
            );

            assert_eq!(response, WasmResult::Reply(expected_response.encode()));
        },
    );
}

#[test]
fn bitcoin_get_successors_pagination() {
    bitcoin_test(
        // A mock adapter response returning a large payload that doesn't fit.
        BtcServiceGetSuccessorsResponse {
            blocks: vec![vec![0; 4_000_000]],
            next: vec![],
        },
        |runtime| {
            let canister_id = runtime.create_universal_canister();
            let canister = ic_replica_tests::UniversalCanister {
                runtime,
                canister_id,
            };

            let response = call_get_successors(
                &canister,
                ic00::BitcoinGetSuccessorsArgs::Initial(ic00::BitcoinGetSuccessorsRequestInitial {
                    network: ic_btc_types::NetworkSnakeCase::Regtest,
                    anchor: vec![],
                    processed_block_hashes: vec![],
                }),
            );

            let expected_response =
                ic00::BitcoinGetSuccessorsResponse::Partial(CanisterGetSuccessorsResponsePartial {
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
        BtcServiceGetSuccessorsResponse {
            blocks: vec![vec![0; 4_000_000], vec![0]],
            next: vec![],
        },
        |runtime| {
            let canister_id = runtime.create_universal_canister();
            let canister = ic_replica_tests::UniversalCanister {
                runtime,
                canister_id,
            };

            let response = call_get_successors(
                &canister,
                ic00::BitcoinGetSuccessorsArgs::Initial(ic00::BitcoinGetSuccessorsRequestInitial {
                    network: ic_btc_types::NetworkSnakeCase::Regtest,
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
