mod setup;

use crate::setup::EvmRpcSetup;
use alloy_primitives::{address, b256, bloom, bytes, Address, Bytes, FixedBytes, B256, B64, U256};
use alloy_rpc_types::{BlockNumberOrTag, BlockTransactions};
use assert_matches::assert_matches;
use candid::{CandidType, Encode, Principal};
use canhttp::http::json::{ConstantSizeId, Id};
use evm_rpc_client::{DoubleCycles, EvmRpcEndpoint, NoRetry, RequestBuilder};
use evm_rpc_types::{
    BlockTag, ConsensusStrategy, EthMainnetService, EthSepoliaService, GetLogsRpcConfig, Hex,
    Hex32, HttpOutcallError, InstallArgs, JsonRpcError, LegacyRejectionCode, MultiRpcResult,
    Nat256, ProviderError, RpcApi, RpcError, RpcResult, RpcService, RpcServices, ValidationError,
};
use ic_canister_runtime::CyclesWalletRuntime;
use ic_error_types::RejectCode;
use ic_http_types::HttpRequest;
use ic_pocket_canister_runtime::{
    CanisterHttpReject, CanisterHttpReply, JsonRpcRequestMatcher, JsonRpcResponse,
    MockHttpOutcalls, MockHttpOutcallsBuilder, PocketIcRuntime,
};
use pocket_ic::{common::rest::CanisterHttpResponse, ErrorCode};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::{fmt::Debug, iter};
use strum::IntoEnumIterator;

const DEFAULT_CALLER_TEST_ID: Principal =
    Principal::from_slice(&[0x0, 0x0, 0x0, 0x0, 0x0, 0x31, 0x1, 0x8, 0x1, 0x1]);
const DEFAULT_CONTROLLER_TEST_ID: Principal = Principal::from_slice(&[0x9d, 0xf7, 0x02]);
const ADDITIONAL_TEST_ID: Principal = Principal::from_slice(&[0x9d, 0xf7, 0x03]);

const INITIAL_CYCLES: u128 = 100_000_000_000_000_000;

const MOCK_REQUEST_METHOD: &str = "eth_gasPrice";
const MOCK_REQUEST_ID: Id = Id::Number(1);
const MOCK_REQUEST_PARAMS: Value = Value::Array(vec![]);
const MOCK_REQUEST_URL: &str = "https://cloudflare-eth.com";
const MOCK_REQUEST_PAYLOAD: &str =
    r#"{"id":1,"jsonrpc":"2.0","method":"eth_gasPrice","params":[]}"#;
const MOCK_REQUEST_RESPONSE: &str = r#"{"jsonrpc":"2.0","id":1,"result":"0x00112233"}"#;
const MOCK_REQUEST_RESPONSE_BYTES: u64 = 1000;
const MOCK_API_KEY: &str = "mock-api-key";

const MOCK_TRANSACTION: Bytes = bytes!("0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83");
const MOCK_TRANSACTION_HASH: B256 =
    b256!("0x33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788");

const MOCK_ADDRESS: Address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const MOCK_INPUT_DATA: Bytes =
    bytes!("0x70a08231000000000000000000000000b25eA1D493B49a1DeD42aC5B1208cC618f9A9B80");

const RPC_SERVICES: &[RpcServices] = &[
    RpcServices::EthMainnet(None),
    RpcServices::EthSepolia(None),
    RpcServices::ArbitrumOne(None),
    RpcServices::BaseMainnet(None),
    RpcServices::OptimismMainnet(None),
];

const ANKR_HOSTNAME: &str = "rpc.ankr.com";
const ALCHEMY_ETH_MAINNET_HOSTNAME: &str = "eth-mainnet.g.alchemy.com";
const BLOCKPI_ETH_HOSTNAME: &str = "ethereum.blockpi.network";
const PUBLICNODE_ETH_MAINNET_HOSTNAME: &str = "ethereum-rpc.publicnode.com";

#[tokio::test]
async fn should_canonicalize_request_endpoint_response() {
    let responses = [
        r#"{"id":1,"jsonrpc":"2.0","result":"0x00112233"}"#,
        r#"{"result":"0x00112233","id":1,"jsonrpc":"2.0"}"#,
        r#"{"result":"0x00112233","jsonrpc":"2.0","id":1}"#,
    ];

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let mut results = Vec::with_capacity(3);
    for response in responses {
        let mocks = MockHttpOutcallsBuilder::new()
            .given(
                JsonRpcRequestMatcher::with_method(MOCK_REQUEST_METHOD)
                    .with_params(MOCK_REQUEST_PARAMS)
                    .with_raw_id(MOCK_REQUEST_ID),
            )
            .respond_with(JsonRpcResponse::from(response));
        let result = setup
            .request(
                &setup.new_mock_http_runtime_with_wallet(mocks),
                (
                    RpcService::Custom(RpcApi {
                        url: MOCK_REQUEST_URL.to_string(),
                        headers: None,
                    }),
                    MOCK_REQUEST_PAYLOAD,
                    MOCK_REQUEST_RESPONSE_BYTES,
                ),
                1_000_000_000,
            )
            .await;
        results.push(result);
    }

    assert!(results.windows(2).all(|w| w[0] == w[1]));
}

#[tokio::test]
async fn should_not_modify_json_rpc_request_from_request_endpoint() {
    let mock_request = r#"{"id":123,"jsonrpc":"2.0","method":"eth_gasPrice"}"#;
    let mock_response = r#"{"jsonrpc":"2.0","id":123,"result":"0x00112233"}"#;
    let mocks = MockHttpOutcallsBuilder::new()
        .given(JsonRpcRequestMatcher::with_method("eth_gasPrice").with_raw_id(Id::Number(123)))
        .respond_with(JsonRpcResponse::from(mock_response));

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let response = setup
        .request(
            &setup.new_mock_http_runtime_with_wallet(mocks),
            (
                RpcService::Custom(RpcApi {
                    url: MOCK_REQUEST_URL.to_string(),
                    headers: None,
                }),
                mock_request,
                MOCK_REQUEST_RESPONSE_BYTES,
            ),
            1_000_000_000,
        )
        .await;

    assert_eq!(response, Ok(mock_response.to_string()));
}

#[tokio::test]
async fn multi_request_should_succeed() {
    fn mocks(offset: u64) -> MockHttpOutcallsBuilder {
        let [response_0, response_1, response_2] = [
            r#"{"id":0,"jsonrpc":"2.0","result":"0x00112233"}"#,
            r#"{"result":"0x00112233","id":0,"jsonrpc":"2.0"}"#,
            r#"{"result":"0x00112233","jsonrpc":"2.0","id":0}"#,
        ];
        MockHttpOutcallsBuilder::new()
            .given(JsonRpcRequestMatcher::with_method("eth_gasPrice").with_id(offset))
            .respond_with(JsonRpcResponse::from(response_0).with_id(offset))
            .given(JsonRpcRequestMatcher::with_method("eth_gasPrice").with_id(offset + 1))
            .respond_with(JsonRpcResponse::from(response_1).with_id(offset + 1))
            .given(JsonRpcRequestMatcher::with_method("eth_gasPrice").with_id(offset + 2))
            .respond_with(JsonRpcResponse::from(response_2).with_id(offset + 2))
    }

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let mut offsets = (0..).step_by(3);

    for source in RPC_SERVICES {
        let candid_result = setup
            .client(mocks(offsets.next().unwrap()))
            .with_rpc_sources(source.clone())
            .with_candid()
            .build()
            .multi_request(json!({
                "id" : ConstantSizeId::ZERO.to_string(),
                "jsonrpc": "2.0",
                "method": "eth_gasPrice",
            }))
            .send()
            .await
            .expect_consistent();
        assert_eq!(candid_result, Ok("0x00112233".to_string()));

        let alloy_result = setup
            .client(mocks(offsets.next().unwrap()))
            .with_rpc_sources(source.clone())
            .build()
            .multi_request(json!({
                "id" : ConstantSizeId::ZERO.to_string(),
                "jsonrpc": "2.0",
                "method": "eth_gasPrice",
            }))
            .send()
            .await
            .expect_consistent();
        assert_eq!(alloy_result, Ok("0x00112233".to_string()));
    }
}

#[tokio::test]
async fn eth_get_logs_should_succeed() {
    fn mocks(
        from_block: BlockNumberOrTag,
        to_block: BlockNumberOrTag,
        offset: u64,
    ) -> MockHttpOutcallsBuilder {
        MockHttpOutcallsBuilder::new()
            .given(get_logs_request(from_block, to_block).with_id(offset))
            .respond_with(get_logs_response().with_id(offset))
            .given(get_logs_request(from_block, to_block).with_id(1 + offset))
            .respond_with(get_logs_response().with_id(1 + offset))
            .given(get_logs_request(from_block, to_block).with_id(2 + offset))
            .respond_with(get_logs_response().with_id(2 + offset))
    }

    fn candid_expected_logs() -> Vec<evm_rpc_types::LogEntry> {
        vec![evm_rpc_types::LogEntry {
            address: address!("0xdac17f958d2ee523a2206206994597c13d831ec7").into(),
            topics: vec![
                b256!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef").into(),
                b256!("0x000000000000000000000000a9d1e08c7793af67e9d92fe308d5697fb81d3e43").into(),
                b256!("0x00000000000000000000000078cccfb3d517cd4ed6d045e263e134712288ace2").into(),
            ],
            data: bytes!("0x000000000000000000000000000000000000000000000000000000003b9c6433")
                .into(),
            block_number: Some(0x11dc77e_u64.into()),
            transaction_hash: Some(
                b256!("0xf3ed91a03ddf964281ac7a24351573efd535b80fc460a5c2ad2b9d23153ec678").into(),
            ),
            transaction_index: Some(0x65_u64.into()),
            block_hash: Some(
                b256!("0xd5c72ad752b2f0144a878594faf8bd9f570f2f72af8e7f0940d3545a6388f629").into(),
            ),
            log_index: Some(0xe8_u64.into()),
            removed: false,
        }]
    }

    fn alloy_expected_logs() -> Vec<alloy_rpc_types::Log> {
        candid_expected_logs()
            .into_iter()
            .map(alloy_rpc_types::Log::try_from)
            .collect::<RpcResult<Vec<alloy_rpc_types::Log>>>()
            .unwrap()
    }

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let mut offsets = (0..).step_by(3);

    for source in RPC_SERVICES {
        for (config, from_block, to_block) in [
            // default block range
            (
                GetLogsRpcConfig::default(),
                BlockNumberOrTag::Number(0_u8.into()),
                BlockNumberOrTag::Number(500_u16.into()),
            ),
            // large block range
            (
                GetLogsRpcConfig {
                    max_block_range: Some(1_000),
                    ..Default::default()
                },
                BlockNumberOrTag::Number(0_u8.into()),
                BlockNumberOrTag::Number(501_u16.into()),
            ),
        ] {
            let candid_result = setup
                .client(mocks(from_block, to_block, offsets.next().unwrap()))
                .with_rpc_sources(source.clone())
                .with_candid()
                .build()
                .get_logs(vec![address!("0xdac17f958d2ee523a2206206994597c13d831ec7")])
                .with_from_block(from_block)
                .with_to_block(to_block)
                .with_rpc_config(config.clone())
                .send()
                .await
                .expect_consistent();
            assert_eq!(candid_result, Ok(candid_expected_logs()));

            let alloy_result = setup
                .client(mocks(from_block, to_block, offsets.next().unwrap()))
                .with_rpc_sources(source.clone())
                .build()
                .get_logs(vec![address!("0xdac17f958d2ee523a2206206994597c13d831ec7")])
                .with_from_block(from_block)
                .with_to_block(to_block)
                .with_rpc_config(config)
                .send()
                .await
                .expect_consistent();
            assert_eq!(alloy_result, Ok(alloy_expected_logs()));
        }
    }
}

#[tokio::test]
async fn eth_get_logs_should_fail_when_block_range_too_large() {
    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let error_msg_regex =
        regex::Regex::new("Requested [0-9_]+ blocks; limited to [0-9_]+").unwrap();

    for source in RPC_SERVICES {
        for (config, from_block, to_block) in [
            // default block range
            (
                GetLogsRpcConfig::default(),
                BlockTag::Number(0_u8.into()),
                BlockTag::Number(501_u16.into()),
            ),
            // large block range
            (
                GetLogsRpcConfig {
                    max_block_range: Some(1_000),
                    ..Default::default()
                },
                BlockTag::Number(0_u8.into()),
                BlockTag::Number(1001_u16.into()),
            ),
        ] {
            let client = setup
                .client(MockHttpOutcalls::never())
                .with_rpc_sources(source.clone())
                .build();

            let response = client
                .get_logs(vec![address!("0xdAC17F958D2ee523a2206206994597C13D831ec7")])
                .with_from_block(from_block)
                .with_to_block(to_block)
                .with_rpc_config(config)
                .send()
                .await
                .expect_consistent()
                .unwrap_err();

            assert_matches!(
                response,
                RpcError::ValidationError(ValidationError::Custom(s)) if error_msg_regex.is_match(&s)
            )
        }
    }
}

#[tokio::test]
async fn eth_get_block_by_number_should_succeed() {
    fn mocks(offset: u64) -> MockHttpOutcallsBuilder {
        MockHttpOutcallsBuilder::new()
            .given(get_block_by_number_request().with_id(offset))
            .respond_with(get_block_by_number_response().with_id(offset))
            .given(get_block_by_number_request().with_id(1 + offset))
            .respond_with(get_block_by_number_response().with_id(1 + offset))
            .given(get_block_by_number_request().with_id(2 + offset))
            .respond_with(get_block_by_number_response().with_id(2 + offset))
    }

    fn candid_expected_block() -> evm_rpc_types::Block {
        evm_rpc_types::Block {
            base_fee_per_gas: Some(57_750_497_844_u64.into()),
            number: 18_722_845_u64.into(),
            difficulty: Some(Nat256::ZERO),
            extra_data: bytes!("0x546974616e2028746974616e6275696c6465722e78797a29").into(),
            gas_limit: 0x1c9c380_u64.into(),
            gas_used: 0xa768c4_u64.into(),
            hash: b256!("0xc3674be7b9d95580d7f23c03d32e946f2b453679ee6505e3a778f003c5a3cfae").into(),
            logs_bloom: bloom!("0x3e6b8420e1a13038902c24d6c2a9720a7ad4860cdc870cd5c0490011e43631134f608935bd83171247407da2c15d85014f9984608c03684c74aad48b20bc24022134cdca5f2e9d2dee3b502a8ccd39eff8040b1d96601c460e119c408c620b44fa14053013220847045556ea70484e67ec012c322830cf56ef75e09bd0db28a00f238adfa587c9f80d7e30d3aba2863e63a5cad78954555966b1055a4936643366a0bb0b1bac68d0e6267fc5bf8304d404b0c69041125219aa70562e6a5a6362331a414a96d0716990a10161b87dd9568046a742d4280014975e232b6001a0360970e569d54404b27807d7a44c949ac507879d9d41ec8842122da6772101bc8b").into(),
            miner: address!("0x388c818ca8b9251b393131c08a736a67ccb19297").into(),
            mix_hash: b256!("0x516a58424d4883a3614da00a9c6f18cd5cd54335a08388229a993a8ecf05042f").into(),
            nonce: Nat256::ZERO,
            parent_hash: b256!("0x43325027f6adf9befb223f8ae80db057daddcd7b48e41f60cd94bfa8877181ae").into(),
            receipts_root: b256!("0x66934c3fd9c547036fe0e56ad01bc43c84b170be7c4030a86805ddcdab149929").into(),
            sha3_uncles: b256!("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
            size: 0xcd35_u64.into(),
            state_root: b256!("0x13552447dd62f11ad885f21a583c4fa34144efe923c7e35fb018d6710f06b2b6").into(),
            timestamp: 0x656f96f3_u64.into(),
            total_difficulty: None,
            transactions: vec![],
            transactions_root: Some(b256!("0x93a1ad3d067009259b508cc95fde63b5efd7e9d8b55754314c173fdde8c0826a").into()),
            uncles: vec![],
        }
    }

    fn alloy_expected_block() -> alloy_rpc_types::Block {
        alloy_rpc_types::Block::try_from(candid_expected_block()).unwrap()
    }

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let mut offsets = (0..).step_by(3);

    for source in RPC_SERVICES {
        let candid_result = setup
            .client(mocks(offsets.next().unwrap()))
            .with_rpc_sources(source.clone())
            .with_candid()
            .build()
            .get_block_by_number(BlockNumberOrTag::Latest)
            .send()
            .await
            .expect_consistent();
        assert_eq!(candid_result, Ok(candid_expected_block()));

        let alloy_result = setup
            .client(mocks(offsets.next().unwrap()))
            .with_rpc_sources(source.clone())
            .build()
            .get_block_by_number(BlockNumberOrTag::Latest)
            .send()
            .await
            .expect_consistent();
        assert_eq!(alloy_result, Ok(alloy_expected_block()));
    }
}

#[tokio::test]
async fn eth_get_block_by_number_pre_london_fork_should_succeed() {
    fn mock_response() -> JsonRpcResponse {
        JsonRpcResponse::from(json!({
           "jsonrpc":"2.0",
           "id":0,
           "result":{
              "number":"0x0",
              "hash":"0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
              "transactions":[],
              "totalDifficulty":"0x400000000",
              "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
              "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
              "extraData":"0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa",
              "nonce":"0x0000000000000042",
              "miner":"0x0000000000000000000000000000000000000000",
              "difficulty":"0x400000000",
              "gasLimit":"0x1388",
              "gasUsed":"0x0",
              "uncles":[],
              "sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
              "size":"0x21c",
              "transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
              "stateRoot":"0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544",
              "mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
              "parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
              "timestamp":"0x0"
           }
        }))
    }

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    for (source, offset) in iter::zip(RPC_SERVICES, (0..).step_by(3)) {
        let mocks = MockHttpOutcallsBuilder::new()
            .given(get_block_by_number_request().with_id(offset))
            .respond_with(mock_response().with_id(offset))
            .given(get_block_by_number_request().with_id(1 + offset))
            .respond_with(mock_response().with_id(1 + offset))
            .given(get_block_by_number_request().with_id(2 + offset))
            .respond_with(mock_response().with_id(2 + offset));

        let response = setup
            .client(mocks)
            .with_rpc_sources(source.clone())
            .build()
            .get_block_by_number(BlockNumberOrTag::Latest)
            .send()
            .await
            .expect_consistent()
            .unwrap();

        assert_eq!(response, alloy_rpc_types::Block {
            header: alloy_rpc_types::Header {
                hash: b256!("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
                inner: alloy_consensus::Header {
                    parent_hash: b256!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                    ommers_hash: b256!("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
                    beneficiary: address!("0x0000000000000000000000000000000000000000"),
                    state_root: b256!("0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544"),
                    transactions_root: b256!("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
                    receipts_root: b256!("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
                    logs_bloom: bloom!("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                    difficulty: U256::from(0x400000000_u64),
                    number: 0_u64,
                    gas_limit: 0x1388_u64,
                    gas_used: 0_u64,
                    timestamp: 0_u64,
                    extra_data: bytes!("0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"),
                    mix_hash: b256!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                    nonce: B64::from(0x0000000000000042_u64),
                    base_fee_per_gas: None,
                    withdrawals_root: None,
                    blob_gas_used: None,
                    excess_blob_gas: None,
                    parent_beacon_block_root: None,
                    requests_hash: None,
                },
                total_difficulty: None,
                size: Some(U256::from(0x21c_u64)),
            },
            uncles: vec![],
            transactions: BlockTransactions::Hashes(vec![]),
            withdrawals: None,
        });
    }
}

#[tokio::test]
async fn eth_get_block_by_number_should_be_consistent_when_total_difficulty_inconsistent() {
    fn mock_response(total_difficulty: Option<&str>) -> JsonRpcResponse {
        let mut body = json!({
           "jsonrpc":"2.0",
           "result":{
              "baseFeePerGas":"0xd7232aa34",
              "difficulty":"0x0",
              "extraData":"0x546974616e2028746974616e6275696c6465722e78797a29",
              "gasLimit":"0x1c9c380",
              "gasUsed":"0xa768c4",
              "hash":"0xc3674be7b9d95580d7f23c03d32e946f2b453679ee6505e3a778f003c5a3cfae",
              "logsBloom":"0x3e6b8420e1a13038902c24d6c2a9720a7ad4860cdc870cd5c0490011e43631134f608935bd83171247407da2c15d85014f9984608c03684c74aad48b20bc24022134cdca5f2e9d2dee3b502a8ccd39eff8040b1d96601c460e119c408c620b44fa14053013220847045556ea70484e67ec012c322830cf56ef75e09bd0db28a00f238adfa587c9f80d7e30d3aba2863e63a5cad78954555966b1055a4936643366a0bb0b1bac68d0e6267fc5bf8304d404b0c69041125219aa70562e6a5a6362331a414a96d0716990a10161b87dd9568046a742d4280014975e232b6001a0360970e569d54404b27807d7a44c949ac507879d9d41ec8842122da6772101bc8b",
              "miner":"0x388c818ca8b9251b393131c08a736a67ccb19297",
              "mixHash":"0x516a58424d4883a3614da00a9c6f18cd5cd54335a08388229a993a8ecf05042f",
              "nonce":"0x0000000000000000",
              "number":"0x11db01d",
              "parentHash":"0x43325027f6adf9befb223f8ae80db057daddcd7b48e41f60cd94bfa8877181ae",
              "receiptsRoot":"0x66934c3fd9c547036fe0e56ad01bc43c84b170be7c4030a86805ddcdab149929",
              "sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
              "size":"0xcd35",
              "stateRoot":"0x13552447dd62f11ad885f21a583c4fa34144efe923c7e35fb018d6710f06b2b6",
              "timestamp":"0x656f96f3",
              "withdrawalsRoot":"0xecae44b2c53871003c5cc75285995764034c9b5978a904229d36c1280b141d48",
              "transactionsRoot":"0x93a1ad3d067009259b508cc95fde63b5efd7e9d8b55754314c173fdde8c0826a",
           },
           "id":0
        });
        if let Some(total_difficulty) = total_difficulty {
            body.get_mut("result").unwrap()["totalDifficulty"] =
                Value::String(total_difficulty.to_string());
        }
        JsonRpcResponse::from(body)
    }

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    let mocks = MockHttpOutcallsBuilder::new()
        .given(get_block_by_number_request().with_id(0))
        .respond_with(mock_response(Some("0xc70d815d562d3cfa955")).with_id(0))
        .given(get_block_by_number_request().with_id(1))
        .respond_with(mock_response(None).with_id(1));

    let response = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Ankr,
            EthMainnetService::PublicNode,
        ])))
        .build()
        .get_block_by_number(BlockNumberOrTag::Latest)
        .send()
        .await
        .expect_consistent()
        .unwrap();

    assert_eq!(response.number(), 18_722_845_u64);
    assert_eq!(response.header.total_difficulty, None);
}

#[tokio::test]
async fn eth_get_transaction_receipt_should_succeed() {
    fn mocks(
        tx_hash: FixedBytes<32>,
        response: &JsonRpcResponse,
        offset: u64,
    ) -> MockHttpOutcallsBuilder {
        fn request(tx_hash: impl ToString) -> JsonRpcRequestMatcher {
            JsonRpcRequestMatcher::with_method("eth_getTransactionReceipt")
                .with_params(json!([tx_hash.to_string()]))
        }
        MockHttpOutcallsBuilder::new()
            .given(request(tx_hash).with_id(offset))
            .respond_with(response.clone().with_id(offset))
            .given(request(tx_hash).with_id(offset + 1))
            .respond_with(response.clone().with_id(offset + 1))
            .given(request(tx_hash).with_id(offset + 2))
            .respond_with(response.clone().with_id(offset + 2))
    }

    let test_cases = [
        (
            b256!("0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f"),
            JsonRpcResponse::from(json!({
               "jsonrpc":"2.0",
               "id":0,
               "result":{
                  "blockHash":"0x5115c07eb1f20a9d6410db0916ed3df626cfdab161d3904f45c8c8b65c90d0be",
                  "blockNumber":"0x11a85ab",
                  "contractAddress":null,
                  "cumulativeGasUsed":"0xf02aed",
                  "effectiveGasPrice":"0x63c00ee76",
                  "from":"0x0aa8ebb6ad5a8e499e550ae2c461197624c6e667",
                  "gasUsed":"0x7d89",
                  "logs":[],
                  "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                  "status":"0x1",
                  "to":"0x356cfd6e6d0000400000003900b415f80669009e",
                  "transactionHash":"0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f",
                  "transactionIndex":"0xd9",
                  "type":"0x2"
               }
            })),
            evm_rpc_types::TransactionReceipt {
                block_hash: b256!("0x5115c07eb1f20a9d6410db0916ed3df626cfdab161d3904f45c8c8b65c90d0be").into(),
                block_number: 0x11a85ab_u64.into(),
                effective_gas_price: 0x63c00ee76_u64.into(),
                gas_used: 0x7d89_u64.into(),
                cumulative_gas_used: 0xf02aed_u64.into(),
                status: Some(0x1_u64.into()),
                root: None,
                transaction_hash: b256!("0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f").into(),
                contract_address: None,
                from: address!("0x0aa8ebb6ad5a8e499e550ae2c461197624c6e667").into(),
                logs: vec![],
                logs_bloom: bloom!("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").into(),
                to: Some(address!("0x356cfd6e6d0000400000003900b415f80669009e").into()),
                transaction_index: 0xd9_u64.into(),
                tx_type: 0x2_u8.into(),
            },
        ),
        // first transaction after genesis
        (
            b256!("0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060"),
            JsonRpcResponse::from(json!({
               "jsonrpc":"2.0",
               "id":0,
               "result":{
                  "transactionHash":"0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060",
                  "blockHash":"0x4e3a3754410177e6937ef1f84bba68ea139e8d1a2258c5f85db9f1cd715a1bdd",
                  "blockNumber":"0xb443",
                  "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                  "gasUsed":"0x5208",
                  "root":"0x96a8e009d2b88b1483e6941e6812e32263b05683fac202abc622a3e31aed1957",
                  "contractAddress":null,
                  "cumulativeGasUsed":"0x5208",
                  "transactionIndex":"0x0",
                  "from":"0xa1e4380a3b1f749673e270229993ee55f35663b4",
                  "to":"0x5df9b87991262f6ba471f09758cde1c0fc1de734",
                  "type":"0x0",
                  "effectiveGasPrice":"0x2d79883d2000",
                  "logs":[],
               }
            })),
            evm_rpc_types::TransactionReceipt {
                block_hash: b256!("0x4e3a3754410177e6937ef1f84bba68ea139e8d1a2258c5f85db9f1cd715a1bdd").into(),
                block_number: 0xb443_u64.into(),
                effective_gas_price: 0x2d79883d2000_u64.into(),
                gas_used: 0x5208_u64.into(),
                cumulative_gas_used: 0x5208_u64.into(),
                status: None,
                root: Some(b256!("0x96a8e009d2b88b1483e6941e6812e32263b05683fac202abc622a3e31aed1957").into()),
                transaction_hash: b256!("0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060").into(),
                contract_address: None,
                from: address!("0xa1e4380a3b1f749673e270229993ee55f35663b4").into(),
                logs: vec![],
                logs_bloom: bloom!("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").into(),
                to: Some(address!("0x5df9b87991262f6ba471f09758cde1c0fc1de734").into()),
                transaction_index: 0x0_u64.into(),
                tx_type: 0x0_u8.into(),
            },
        ),
        // contract creation
        (
            b256!("0x2b8e12d42a187ace19c64b47fae0955def8859bf966c345102c6d3a52f28308b"),
            JsonRpcResponse::from(json!({
               "jsonrpc":"2.0",
               "id":0,
               "result":{
                  "transactionHash":"0x2b8e12d42a187ace19c64b47fae0955def8859bf966c345102c6d3a52f28308b",
                  "blockHash":"0xd050426a753a7cc4833ba15a5dfcef761fd983f5277230ea8dc700eadd307363",
                  "blockNumber":"0x12e64fd",
                  "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                  "gasUsed":"0x69892",
                  "contractAddress":"0x6abda0438307733fc299e9c229fd3cc074bd8cc0",
                  "cumulativeGasUsed":"0x3009d2",
                  "transactionIndex":"0x17",
                  "from":"0xe12e9a6661aeaf57abf95fd060bebb223fbee7dd",
                  "to":null,
                  "type":"0x2",
                  "effectiveGasPrice":"0x17c01a135",
                  "logs":[],
                  "status":"0x1"
               }
            })),
            evm_rpc_types::TransactionReceipt {
                block_hash: b256!("0xd050426a753a7cc4833ba15a5dfcef761fd983f5277230ea8dc700eadd307363").into(),
                block_number: 0x12e64fd_u64.into(),
                effective_gas_price: 0x17c01a135_u128.into(),
                gas_used: 0x69892_u64.into(),
                cumulative_gas_used: 0x3009d2_u64.into(),
                status: Some(0x1_u64.into()),
                root: None,
                transaction_hash: b256!("0x2b8e12d42a187ace19c64b47fae0955def8859bf966c345102c6d3a52f28308b").into(),
                contract_address: Some(address!("0x6abda0438307733fc299e9c229fd3cc074bd8cc0").into()),
                from: address!("0xe12e9a6661aeaf57abf95fd060bebb223fbee7dd").into(),
                logs: vec![],
                logs_bloom: bloom!("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").into(),
                to: None,
                transaction_index: 0x17_u64.into(),
                tx_type: 0x2_u8.into(),
            },
        )
    ];

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let mut offsets = (0..).step_by(3);

    for (tx_hash, response, candid_receipt) in test_cases {
        for source in RPC_SERVICES {
            let candid_result = setup
                .client(mocks(tx_hash, &response, offsets.next().unwrap()))
                .with_rpc_sources(source.clone())
                .with_candid()
                .build()
                .get_transaction_receipt(tx_hash)
                .send()
                .await
                .expect_consistent();
            assert_eq!(candid_result, Ok(Some(candid_receipt.clone())));

            let alloy_result = setup
                .client(mocks(tx_hash, &response, offsets.next().unwrap()))
                .with_rpc_sources(source.clone())
                .build()
                .get_transaction_receipt(tx_hash)
                .send()
                .await
                .expect_consistent();
            assert_eq!(
                alloy_result,
                Ok(Some(
                    alloy_rpc_types::TransactionReceipt::try_from(candid_receipt.clone()).unwrap()
                ))
            );
        }
    }
}

#[tokio::test]
async fn eth_get_transaction_count_should_succeed() {
    fn mocks(offset: u64) -> MockHttpOutcallsBuilder {
        MockHttpOutcallsBuilder::new()
            .given(get_transaction_count_request().with_id(offset))
            .respond_with(get_transaction_count_response().with_id(offset))
            .given(get_transaction_count_request().with_id(offset + 1))
            .respond_with(get_transaction_count_response().with_id(offset + 1))
            .given(get_transaction_count_request().with_id(offset + 2))
            .respond_with(get_transaction_count_response().with_id(offset + 2))
    }

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let mut offsets = (0..).step_by(3);

    for source in RPC_SERVICES {
        let candid_result = setup
            .client(mocks(offsets.next().unwrap()))
            .with_rpc_sources(source.clone())
            .with_candid()
            .build()
            .get_transaction_count((
                address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
                BlockNumberOrTag::Latest,
            ))
            .send()
            .await
            .expect_consistent();
        assert_eq!(candid_result, Ok(Nat256::from(1_u64)));

        let alloy_result = setup
            .client(mocks(offsets.next().unwrap()))
            .with_rpc_sources(source.clone())
            .build()
            .get_transaction_count((
                address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
                BlockNumberOrTag::Latest,
            ))
            .send()
            .await
            .expect_consistent();
        assert_eq!(alloy_result, Ok(U256::ONE));
    }
}

#[tokio::test]
async fn eth_fee_history_should_succeed() {
    fn mocks(offset: u64) -> MockHttpOutcallsBuilder {
        MockHttpOutcallsBuilder::new()
            .given(fee_history_request().with_id(offset))
            .respond_with(fee_history_response().with_id(offset))
            .given(fee_history_request().with_id(1 + offset))
            .respond_with(fee_history_response().with_id(1 + offset))
            .given(fee_history_request().with_id(2 + offset))
            .respond_with(fee_history_response().with_id(2 + offset))
    }

    fn candid_expected_fee_history() -> evm_rpc_types::FeeHistory {
        evm_rpc_types::FeeHistory {
            oldest_block: 0x11e57f5_u64.into(),
            base_fee_per_gas: vec![
                0x9cf6c61b9_u64.into(),
                0x97d853982_u64.into(),
                0x9ba55a0b0_u64.into(),
                0x9543bf98d_u64.into(),
            ],
            gas_used_ratio: vec![],
            reward: vec![vec![0x0123_u64.into()]],
        }
    }

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let mut offsets = (0..).step_by(3);

    for source in RPC_SERVICES {
        let candid_result = setup
            .client(mocks(offsets.next().unwrap()))
            .with_rpc_sources(source.clone())
            .with_candid()
            .build()
            .fee_history((3_u64, BlockNumberOrTag::Latest))
            .send()
            .await
            .expect_consistent();
        assert_eq!(candid_result, Ok(candid_expected_fee_history()));

        let alloy_result = setup
            .client(mocks(offsets.next().unwrap()))
            .with_rpc_sources(source.clone())
            .build()
            .fee_history((3_u64, BlockNumberOrTag::Latest))
            .send()
            .await
            .expect_consistent();
        assert_eq!(
            alloy_result,
            Ok(alloy_rpc_types::FeeHistory::try_from(candid_expected_fee_history()).unwrap())
        );
    }
}

#[tokio::test]
async fn eth_send_raw_transaction_should_succeed() {
    fn mocks(offset: u64) -> MockHttpOutcallsBuilder {
        MockHttpOutcallsBuilder::new()
            .given(send_raw_transaction_request().with_id(offset))
            .respond_with(send_raw_transaction_response().with_id(offset))
            .given(send_raw_transaction_request().with_id(1 + offset))
            .respond_with(send_raw_transaction_response().with_id(1 + offset))
            .given(send_raw_transaction_request().with_id(2 + offset))
            .respond_with(send_raw_transaction_response().with_id(2 + offset))
    }

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let mut offsets = (0..).step_by(3);

    for source in RPC_SERVICES {
        let candid_result = setup
            .client(mocks(offsets.next().unwrap()))
            .with_rpc_sources(source.clone())
            .with_candid()
            .build()
            .send_raw_transaction(MOCK_TRANSACTION)
            .send()
            .await
            .expect_consistent();
        assert_eq!(
            candid_result,
            Ok(evm_rpc_types::SendRawTransactionStatus::Ok(Some(
                Hex32::from(MOCK_TRANSACTION_HASH)
            )))
        );

        let alloy_result = setup
            .client(mocks(offsets.next().unwrap()))
            .with_rpc_sources(source.clone())
            .build()
            .send_raw_transaction(MOCK_TRANSACTION)
            .send()
            .await
            .expect_consistent();
        assert_eq!(alloy_result, Ok(MOCK_TRANSACTION_HASH));
    }
}

#[tokio::test]
async fn eth_call_should_succeed() {
    fn mocks(offset: u64) -> MockHttpOutcallsBuilder {
        MockHttpOutcallsBuilder::new()
            .given(call_request().with_id(offset))
            .respond_with(call_response().with_id(offset))
            .given(call_request().with_id(offset + 1))
            .respond_with(call_response().with_id(offset + 1))
            .given(call_request().with_id(offset + 2))
            .respond_with(call_response().with_id(offset + 2))
    }

    fn expected_candid_call_result() -> Hex {
        Hex::from(bytes!(
            "0x0000000000000000000000000000000000000000000000000000013c3ee36e89"
        ))
    }

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let mut offsets = (0..).step_by(3);

    for block in [
        Some(BlockTag::Latest),
        None, //should be same as specifying Latest
    ] {
        for source in RPC_SERVICES {
            let mut request = setup
                .client(mocks(offsets.next().unwrap()))
                .with_rpc_sources(source.clone())
                .with_candid()
                .build()
                .call(
                    alloy_rpc_types::TransactionRequest::default()
                        .to(MOCK_ADDRESS)
                        .input(alloy_rpc_types::TransactionInput::from(MOCK_INPUT_DATA)),
                );
            if let Some(block) = block.clone() {
                request = request.with_block(block)
            }
            let candid_result = request.send().await.expect_consistent();
            assert_eq!(candid_result, Ok(expected_candid_call_result()));

            let mut request = setup
                .client(mocks(offsets.next().unwrap()))
                .with_rpc_sources(source.clone())
                .build()
                .call(
                    alloy_rpc_types::TransactionRequest::default()
                        .to(MOCK_ADDRESS)
                        .input(alloy_rpc_types::TransactionInput::from(MOCK_INPUT_DATA)),
                );
            if let Some(block) = block.clone() {
                request = request.with_block(block)
            }
            let alloy_result = request.send().await.expect_consistent();
            assert_eq!(alloy_result, Ok(Bytes::from(expected_candid_call_result())));
        }
    }
}

#[tokio::test]
async fn candid_rpc_should_allow_unexpected_response_fields() {
    fn mock_response() -> JsonRpcResponse {
        JsonRpcResponse::from(json!({
            "jsonrpc":"2.0",
            "id" : ConstantSizeId::ZERO.to_string(),
            "result":{
                "unexpectedKey":"unexpectedValue",
                "blockHash": "0x5115c07eb1f20a9d6410db0916ed3df626cfdab161d3904f45c8c8b65c90d0be",
                "blockNumber": "0x11a85ab",
                "contractAddress": null,
                "cumulativeGasUsed": "0xf02aed",
                "effectiveGasPrice": "0x63c00ee76",
                "from": "0x0aa8ebb6ad5a8e499e550ae2c461197624c6e667",
                "gasUsed": "0x7d89",
                "logs": [],
                "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "status": "0x1",
                "to": "0x356cfd6e6d0000400000003900b415f80669009e",
                "transactionHash": "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f",
                "transactionIndex": "0xd9",
                "type": "0x2"
            }
        }))
    }

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    let mocks = MockHttpOutcallsBuilder::new()
        .given(get_transaction_receipt_request().with_id(0))
        .respond_with(mock_response().with_id(0))
        .given(get_transaction_receipt_request().with_id(1))
        .respond_with(mock_response().with_id(1))
        .given(get_transaction_receipt_request().with_id(2))
        .respond_with(mock_response().with_id(2));

    let response = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(None))
        .build()
        .get_transaction_receipt(b256!(
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f"
        ))
        .send()
        .await
        .expect_consistent()
        .unwrap()
        .expect("receipt was None");
    assert_eq!(
        response.block_hash,
        Some(b256!(
            "0x5115c07eb1f20a9d6410db0916ed3df626cfdab161d3904f45c8c8b65c90d0be"
        ))
    );
}

#[tokio::test]
async fn candid_rpc_should_err_without_cycles() {
    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    let result = setup
        .client(MockHttpOutcalls::never())
        .with_rpc_sources(RpcServices::EthMainnet(None))
        .build()
        .get_transaction_receipt(b256!(
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f"
        ))
        .with_cycles(0)
        .send()
        .await
        .expect_inconsistent();
    // Because the expected cycles are different for each provider, the results are inconsistent
    // but should all be `TooFewCycles` error.
    for (_, err) in result {
        assert_matches!(
            err,
            Err(RpcError::ProviderError(ProviderError::TooFewCycles {
                expected: _,
                received: 0,
            }))
        )
    }
}

#[tokio::test]
async fn candid_rpc_should_err_when_service_unavailable() {
    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let mocks = MockHttpOutcallsBuilder::new()
        .given(get_transaction_receipt_request().with_id(0))
        .respond_with(CanisterHttpReply::with_status(503).with_body("Service unavailable"))
        .given(get_transaction_receipt_request().with_id(1))
        .respond_with(CanisterHttpReply::with_status(503).with_body("Service unavailable"))
        .given(get_transaction_receipt_request().with_id(2))
        .respond_with(CanisterHttpReply::with_status(503).with_body("Service unavailable"));
    let result = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(None))
        .build()
        .get_transaction_receipt(b256!(
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f"
        ))
        .send()
        .await
        .expect_consistent();
    assert_eq!(
        result,
        Err(RpcError::HttpOutcallError(
            HttpOutcallError::InvalidHttpJsonRpcResponse {
                status: 503,
                body: "\"Service unavailable\"".to_string(),
                parsing_error: None
            }
        ))
    );

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionReceipt",host="ethereum.blockpi.network",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionReceipt",host="rpc.ankr.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionReceipt",host="ethereum-rpc.publicnode.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionReceipt",host="ethereum.blockpi.network",is_supported_provider="true",status="503"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionReceipt",host="rpc.ankr.com",is_supported_provider="true",status="503"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionReceipt",host="ethereum-rpc.publicnode.com",is_supported_provider="true",status="503"} 1 \d+"#);
}

#[tokio::test]
async fn candid_rpc_should_recognize_json_error() {
    fn mock_response() -> JsonRpcResponse {
        JsonRpcResponse::from(json!({
            "jsonrpc":"2.0",
            "id":0,
            "error": {
                "code":123,
                "message":"Error message"
            }
        }))
    }

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let mocks = MockHttpOutcallsBuilder::new()
        .given(get_transaction_receipt_request().with_id(0))
        .respond_with(mock_response().with_id(0))
        .given(get_transaction_receipt_request().with_id(1))
        .respond_with(mock_response().with_id(1));
    let result = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthSepolia(Some(vec![
            EthSepoliaService::Ankr,
            EthSepoliaService::BlockPi,
        ])))
        .build()
        .get_transaction_receipt(b256!(
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f"
        ))
        .send()
        .await
        .expect_consistent();
    assert_eq!(
        result,
        Err(RpcError::JsonRpcError(JsonRpcError {
            code: 123,
            message: "Error message".to_string(),
        }))
    );

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionReceipt",host="rpc.ankr.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionReceipt",host="ethereum-sepolia.blockpi.network",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionReceipt",host="rpc.ankr.com",is_supported_provider="true",status="200"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionReceipt",host="ethereum-sepolia.blockpi.network",is_supported_provider="true",status="200"} 1 \d+"#);
}

#[tokio::test]
async fn candid_rpc_should_reject_empty_service_list() {
    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let result = setup
        .client(MockHttpOutcalls::never())
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![])))
        .build()
        .get_transaction_receipt(b256!(
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f"
        ))
        .send()
        .await
        .expect_consistent();
    assert_eq!(
        result,
        Err(RpcError::ProviderError(ProviderError::ProviderNotFound))
    );
}

#[tokio::test]
async fn candid_rpc_should_return_inconsistent_results() {
    let mocks = MockHttpOutcallsBuilder::new()
        .given(send_raw_transaction_request().with_id(0))
        .respond_with(JsonRpcResponse::from(json!({
                "id": ConstantSizeId::from(0_u64).to_string(),
                "jsonrpc": "2.0",
                "result": MOCK_TRANSACTION_HASH
        })))
        .given(send_raw_transaction_request().with_id(1))
        .respond_with(JsonRpcResponse::from(json!({
            "id": ConstantSizeId::from(1_u64).to_string(),
            "jsonrpc": "2.0",
            "result": "NonceTooLow"
        })));

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let results = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Ankr,
            EthMainnetService::Cloudflare,
        ])))
        .build()
        .send_raw_transaction(MOCK_TRANSACTION)
        .send()
        .await
        .expect_inconsistent();
    assert_eq!(
        results,
        vec![
            (
                RpcService::EthMainnet(EthMainnetService::Ankr),
                Ok(MOCK_TRANSACTION_HASH)
            ),
            (
                RpcService::EthMainnet(EthMainnetService::Cloudflare),
                Err(RpcError::JsonRpcError(JsonRpcError {
                    code: -32_000,
                    message: "Nonce too low".to_string()
                }))
            )
        ]
    );

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_sendRawTransaction",host="rpc.ankr.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_sendRawTransaction",host="cloudflare-eth.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_sendRawTransaction",host="rpc.ankr.com",is_supported_provider="true",status="200"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_sendRawTransaction",host="cloudflare-eth.com",is_supported_provider="true",status="200"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_inconsistent_responses\{method="eth_sendRawTransaction",host="rpc.ankr.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_inconsistent_responses\{method="eth_sendRawTransaction",host="cloudflare-eth.com",is_supported_provider="true"} 1 \d+"#);
}

#[tokio::test]
async fn candid_rpc_should_return_3_out_of_4_transaction_count() {
    fn get_transaction_count_response(result: u64) -> JsonRpcResponse {
        JsonRpcResponse::from(json!({
            "jsonrpc": "2.0",
            "id" : ConstantSizeId::ZERO.to_string(),
            "result" : format!("0x{result:x}")
        }))
    }

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    async fn eth_get_transaction_count_with_3_out_of_4(
        setup: &EvmRpcSetup,
        offset: u64,
        [response0, response1, response2, response3]: [CanisterHttpResponse; 4],
    ) -> MultiRpcResult<U256> {
        let mocks = MockHttpOutcallsBuilder::new()
            .given(get_transaction_count_request().with_id(offset))
            .respond_with(response0)
            .given(get_transaction_count_request().with_id(offset + 1))
            .respond_with(response1)
            .given(get_transaction_count_request().with_id(offset + 2))
            .respond_with(response2)
            .given(get_transaction_count_request().with_id(offset + 3))
            .respond_with(response3);

        setup
            .client(mocks)
            .with_rpc_sources(RpcServices::EthMainnet(None))
            .build()
            .get_transaction_count((
                address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
                BlockNumberOrTag::Latest,
            ))
            .with_response_consensus(ConsensusStrategy::Threshold {
                total: Some(4),
                min: 3,
            })
            .send()
            .await
    }

    for (successful_mocks, offset) in [
        [
            get_transaction_count_response(1).with_id(0).into(),
            get_transaction_count_response(1).with_id(1).into(),
            get_transaction_count_response(1).with_id(2).into(),
            get_transaction_count_response(1).with_id(3).into(),
        ],
        [
            get_transaction_count_response(1).with_id(4).into(),
            CanisterHttpReply::with_status(500)
                .with_body("OFFLINE")
                .into(),
            get_transaction_count_response(1).with_id(6).into(),
            get_transaction_count_response(1).with_id(7).into(),
        ],
        [
            get_transaction_count_response(1).with_id(8).into(),
            get_transaction_count_response(1).with_id(9).into(),
            get_transaction_count_response(2).with_id(10).into(),
            get_transaction_count_response(1).with_id(11).into(),
        ],
    ]
    .into_iter()
    .zip((0..).step_by(4))
    {
        let result = eth_get_transaction_count_with_3_out_of_4(&setup, offset, successful_mocks)
            .await
            .expect_consistent()
            .unwrap();

        assert_eq!(result, U256::ONE);
    }

    for (error_mocks, offset) in [
        [
            get_transaction_count_response(1).with_id(12).into(),
            CanisterHttpReply::with_status(500)
                .with_body("OFFLINE")
                .into(),
            get_transaction_count_response(2).into(),
            get_transaction_count_response(1).with_id(15).into(),
        ],
        [
            CanisterHttpReply::with_status(500)
                .with_body("FORBIDDEN")
                .into(),
            CanisterHttpReply::with_status(500)
                .with_body("OFFLINE")
                .into(),
            get_transaction_count_response(1).with_id(18).into(),
            get_transaction_count_response(1).with_id(19).into(),
        ],
        [
            get_transaction_count_response(1).with_id(20).into(),
            get_transaction_count_response(3).with_id(21).into(),
            get_transaction_count_response(2).with_id(22).into(),
            get_transaction_count_response(1).with_id(23).into(),
        ],
    ]
    .into_iter()
    .zip((12..).step_by(4))
    {
        let result = eth_get_transaction_count_with_3_out_of_4(&setup, offset, error_mocks)
            .await
            .expect_inconsistent();

        assert_eq!(result.len(), 4);
    }
}

#[tokio::test]
async fn candid_rpc_should_return_inconsistent_results_with_error() {
    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    let mocks = MockHttpOutcallsBuilder::new()
        .given(get_transaction_count_request().with_id(0))
        .respond_with(get_transaction_count_response().with_id(0))
        .given(get_transaction_count_request().with_id(1))
        .respond_with(JsonRpcResponse::from(json!({
            "jsonrpc": "2.0",
            "id": ConstantSizeId::from(1_u64).to_string(),
            "error" : { "code": 123, "message": "Unexpected"}
        })));

    let result = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Alchemy,
            EthMainnetService::Ankr,
        ])))
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_inconsistent();

    assert_eq!(
        result,
        vec![
            (
                RpcService::EthMainnet(EthMainnetService::Alchemy),
                Ok(U256::ONE)
            ),
            (
                RpcService::EthMainnet(EthMainnetService::Ankr),
                Err(RpcError::JsonRpcError(JsonRpcError {
                    code: 123,
                    message: "Unexpected".to_string(),
                }))
            ),
        ]
    );

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionCount",host="eth-mainnet.g.alchemy.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionCount",host="rpc.ankr.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionCount",host="eth-mainnet.g.alchemy.com",is_supported_provider="true",status="200"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionCount",host="rpc.ankr.com",is_supported_provider="true",status="200"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_inconsistent_responses\{method="eth_getTransactionCount",host="eth-mainnet.g.alchemy.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_inconsistent_responses\{method="eth_getTransactionCount",host="rpc.ankr.com",is_supported_provider="true"} 1 \d+"#);
}

#[tokio::test]
async fn candid_rpc_should_return_inconsistent_results_with_consensus_error() {
    const CONSENSUS_ERROR: &str =
        "No consensus could be reached. Replicas had different responses.";

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    let mocks = MockHttpOutcallsBuilder::new()
        .given(get_transaction_count_request().with_id(0))
        .respond_with(
            CanisterHttpReject::with_reject_code(RejectCode::SysTransient)
                .with_message(CONSENSUS_ERROR),
        )
        .given(get_transaction_count_request().with_id(1))
        .respond_with(get_transaction_count_response().with_id(1))
        .given(get_transaction_count_request().with_id(2))
        .respond_with(
            CanisterHttpReject::with_reject_code(RejectCode::SysTransient)
                .with_message(CONSENSUS_ERROR),
        );

    let result = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(None))
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .with_response_consensus(ConsensusStrategy::Threshold {
            total: Some(3),
            min: 2,
        })
        .send()
        .await
        .expect_inconsistent();

    assert_eq!(
        result,
        vec![
            (
                RpcService::EthMainnet(EthMainnetService::BlockPi),
                Ok(U256::ONE)
            ),
            (
                RpcService::EthMainnet(EthMainnetService::Ankr),
                Err(RpcError::HttpOutcallError(HttpOutcallError::IcError {
                    code: LegacyRejectionCode::SysTransient,
                    message: CONSENSUS_ERROR.to_string()
                }))
            ),
            (
                RpcService::EthMainnet(EthMainnetService::PublicNode),
                Err(RpcError::HttpOutcallError(HttpOutcallError::IcError {
                    code: LegacyRejectionCode::SysTransient,
                    message: CONSENSUS_ERROR.to_string()
                }))
            ),
        ]
    );

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_err_no_consensus\{method="eth_getTransactionCount",host="rpc.ankr.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_err_no_consensus\{method="eth_getTransactionCount",host="ethereum-rpc.publicnode.com",is_supported_provider="true"} 1 \d+"#)
        .assert_does_not_contain_metric_matching(r#"evmrpc_err_http_outcall.*"#);
}

#[tokio::test]
async fn should_have_metrics_for_request_endpoint() {
    let [mock_request_payload_1, mock_request_payload_2] = [
        r#"{"id":1,"jsonrpc":"2.0","method":"eth_gasPrice","params":[]}"#,
        r#"{"id":2,"jsonrpc":"2.0","method":"eth_gasPrice","params":[]}"#,
    ];
    let [mock_request_response_1, mock_request_response_2] = [
        r#"{"jsonrpc":"2.0","id":1,"result":"0x00112233"}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":"0x00112233"}"#,
    ];
    let mocks = MockHttpOutcallsBuilder::new()
        .given(JsonRpcRequestMatcher::with_method(MOCK_REQUEST_METHOD).with_raw_id(Id::Number(1)))
        .respond_with(JsonRpcResponse::from(mock_request_response_1))
        .given(JsonRpcRequestMatcher::with_method(MOCK_REQUEST_METHOD).with_raw_id(Id::Number(2)))
        .respond_with(JsonRpcResponse::from(mock_request_response_2));

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let runtime = setup.new_mock_http_runtime_with_wallet(mocks);

    // Send one request with a supported RPC provider
    let response = setup
        .request(
            &runtime,
            (
                RpcService::Provider(0),
                mock_request_payload_1,
                MOCK_REQUEST_RESPONSE_BYTES,
            ),
            1_000_000_000,
        )
        .await;
    assert_eq!(response, Ok(mock_request_response_1.to_string()));

    // Send one request with a custom RPC provider
    let response = setup
        .request(
            &runtime,
            (
                RpcService::Custom(RpcApi {
                    url: MOCK_REQUEST_URL.to_string(),
                    headers: None,
                }),
                mock_request_payload_2,
                MOCK_REQUEST_RESPONSE_BYTES,
            ),
            1_000_000_000,
        )
        .await;
    assert_eq!(response, Ok(mock_request_response_2.to_string()));

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="request",is_manual_request="true",host="cloudflare-eth.com"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="request",is_manual_request="true",host="cloudflare-eth.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="request",is_manual_request="true",host="cloudflare-eth.com",status="200"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="request",is_manual_request="true",host="cloudflare-eth.com",is_supported_provider="true",status="200"} 1 \d+"#)
        .assert_does_not_contain_metric_matching(r#"evmrpc_err_http_outcall.*"#);
}

#[tokio::test]
async fn should_have_metrics_for_consensus_errors() {
    let mocks = MockHttpOutcallsBuilder::new()
        .given(get_transaction_count_request())
        .respond_with(CanisterHttpReject::with_reject_code(RejectCode::SysTransient)
            .with_message("No consensus could be reached. Replicas had different responses. Details: request_id: 21114231, timeout: 1761906996398580080, hashes: [2f66337c4e46bad3b26f3271d7def54b1b9632dee3146a993bf968ac9fb5bbd5: 15], [6ca1037eb29b619e387de330bc8e248a619b66b04cba26eab59723eddba12d1c: 14], [8ebeb0f2e2390b2e8c63f1ae24d416e6f90e4ddddc47c3df23c40ac03c7d3835: 2], [4fce8e9722ab59f92be2f4a65c5ae7d1f3b69f2b2993287c0795bbfe17d9ed51: 1]")
        );

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let result = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Cloudflare,
        ])))
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent();
    assert_matches!(
        result,
        Err(RpcError::HttpOutcallError(HttpOutcallError::IcError {
            code: LegacyRejectionCode::SysTransient,
            ..
        }))
    );

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionCount",host="cloudflare-eth.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_err_no_consensus\{method="eth_getTransactionCount",host="cloudflare-eth.com",is_supported_provider="true"} 1 \d+"#)
        .assert_does_not_contain_metric_matching(r#"evmrpc_responses.*"#)
        .assert_does_not_contain_metric_matching(r#"evmrpc_err_http_outcall.*"#);
}

#[tokio::test]
async fn should_have_metrics_for_multi_request_endpoint() {
    let mocks = MockHttpOutcallsBuilder::new()
        .given(JsonRpcRequestMatcher::with_method("eth_gasPrice").with_id(0))
        .respond_with(JsonRpcResponse::from(MOCK_REQUEST_RESPONSE).with_id(0));

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let response = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Cloudflare,
        ])))
        .build()
        .multi_request(json!({
            "id" : ConstantSizeId::ZERO.to_string(),
            "jsonrpc": "2.0",
            "method": "eth_gasPrice",
        }))
        .send()
        .await;
    assert_eq!(
        response,
        MultiRpcResult::Consistent(Ok("0x00112233".into()))
    );

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_gasPrice",is_manual_request="true",host="cloudflare-eth.com",is_supported_provider="true"\} 1 \d+"#, )
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_gasPrice",is_manual_request="true",host="cloudflare-eth.com",is_supported_provider="true",status="200"\} 1 \d+"#, );
}

#[tokio::test]
async fn should_have_metrics_for_custom_providers() {
    let mocks = MockHttpOutcallsBuilder::new()
        .given(get_transaction_count_request().with_id(0))
        .respond_with(get_transaction_count_response().with_id(0))
        .given(get_transaction_count_request().with_id(1))
        .respond_with(get_transaction_count_response().with_id(1))
        .given(get_transaction_count_request().with_id(2))
        .respond_with(get_transaction_count_response().with_id(2));

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let request = setup.client(mocks).build().get_transaction_count((
        address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
        BlockNumberOrTag::Latest,
    ));

    for rpc_source in [
        RpcServices::Custom {
            chain_id: 1,
            services: vec![RpcApi {
                url: "https://cloudflare-eth.com".to_string(),
                headers: None,
            }],
        },
        RpcServices::Custom {
            chain_id: 1,
            services: vec![RpcApi {
                url: "https://blockchain.googleapis.com/v1/".to_string(),
                headers: None,
            }],
        },
        RpcServices::EthMainnet(Some(vec![EthMainnetService::Cloudflare])),
    ] {
        let response = request.clone().with_rpc_sources(rpc_source).send().await;
        assert_eq!(response, MultiRpcResult::Consistent(Ok(U256::ONE)));
    }

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionCount",host="cloudflare-eth.com",is_supported_provider="true"\} 1 \d+"#, )
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionCount",host="cloudflare-eth.com"\} 1 \d+"#, )
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionCount",host="blockchain.googleapis.com"\} 1 \d+"#, )
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionCount",host="cloudflare-eth.com",is_supported_provider="true",status="200"\} 1 \d+"#, )
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionCount",host="cloudflare-eth.com",status="200"\} 1 \d+"#, )
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionCount",host="blockchain.googleapis.com",status="200"\} 1 \d+"#, );
}

#[tokio::test]
async fn candid_rpc_should_return_inconsistent_results_with_unexpected_http_status() {
    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    let mocks = MockHttpOutcallsBuilder::new()
        .given(get_transaction_count_request().with_id(0))
        .respond_with(get_transaction_count_response().with_id(0))
        .given(get_transaction_count_request().with_id(1))
        .respond_with(CanisterHttpReply::with_status(400).with_body(
            json!({"jsonrpc": "2.0", "id": 1, "error": {"code": 123, "message": "Error message"}}),
        ));

    let result = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Alchemy,
            EthMainnetService::Ankr,
        ])))
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_inconsistent();
    assert_eq!(
            result,
            vec![
                (
                    RpcService::EthMainnet(EthMainnetService::Alchemy),
                    Ok(U256::ONE)
                ),
                (
                    RpcService::EthMainnet(EthMainnetService::Ankr),
                    Err(RpcError::HttpOutcallError(HttpOutcallError::InvalidHttpJsonRpcResponse {
                        status: 400,
                        body: "{\"error\":{\"code\":123,\"message\":\"Error message\"},\"id\":1,\"jsonrpc\":\"2.0\"}".to_string(),
                        parsing_error: None,
                    })),
                ),
            ]
        );

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionCount",host="eth-mainnet.g.alchemy.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionCount",host="rpc.ankr.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionCount",host="eth-mainnet.g.alchemy.com",is_supported_provider="true",status="200"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionCount",host="rpc.ankr.com",is_supported_provider="true",status="400"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_inconsistent_responses\{method="eth_getTransactionCount",host="eth-mainnet.g.alchemy.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_inconsistent_responses\{method="eth_getTransactionCount",host="rpc.ankr.com",is_supported_provider="true"} 1 \d+"#);
}

#[tokio::test]
async fn candid_rpc_should_handle_already_known() {
    let mocks = MockHttpOutcallsBuilder::new()
        .given(send_raw_transaction_request().with_id(0))
        .respond_with(JsonRpcResponse::from(json!({
            "id": ConstantSizeId::from(0_u64).to_string(),
            "jsonrpc": "2.0",
            "result": MOCK_TRANSACTION_HASH
        })))
        .given(send_raw_transaction_request().with_id(1))
        .respond_with(JsonRpcResponse::from(json!({
            "id": ConstantSizeId::from(1_u64).to_string(),
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": "already known"}
        })));

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let result = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Ankr,
            EthMainnetService::Cloudflare,
        ])))
        .build()
        .send_raw_transaction(MOCK_TRANSACTION)
        .send()
        .await
        .expect_consistent();
    assert_eq!(result, Ok(MOCK_TRANSACTION_HASH));

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_sendRawTransaction",host="rpc.ankr.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_sendRawTransaction",host="cloudflare-eth.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_sendRawTransaction",host="rpc.ankr.com",is_supported_provider="true",status="200"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_sendRawTransaction",host="cloudflare-eth.com",is_supported_provider="true",status="200"} 1 \d+"#);
}

#[tokio::test]
async fn candid_rpc_should_recognize_rate_limit() {
    let mocks = MockHttpOutcallsBuilder::new()
        .given(send_raw_transaction_request().with_id(0))
        .respond_with(CanisterHttpReply::with_status(429).with_body("(Rate limit error message)"))
        .given(send_raw_transaction_request().with_id(1))
        .respond_with(CanisterHttpReply::with_status(429).with_body("(Rate limit error message)"));

    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let result = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Ankr,
            EthMainnetService::Cloudflare,
        ])))
        .build()
        .send_raw_transaction(MOCK_TRANSACTION)
        .send()
        .await
        .expect_consistent();

    assert_eq!(
        result,
        Err(RpcError::HttpOutcallError(
            HttpOutcallError::InvalidHttpJsonRpcResponse {
                status: 429,
                body: "\"(Rate limit error message)\"".to_string(),
                parsing_error: None
            }
        ))
    );

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_sendRawTransaction",host="rpc.ankr.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_sendRawTransaction",host="cloudflare-eth.com",is_supported_provider="true"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_sendRawTransaction",host="rpc.ankr.com",is_supported_provider="true",status="429"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_sendRawTransaction",host="cloudflare-eth.com",is_supported_provider="true",status="429"} 1 \d+"#);
}

#[tokio::test]
async fn should_use_custom_response_size_estimate() {
    let setup = EvmRpcSetup::new().await.mock_api_keys().await;
    let [max_response_bytes_1, max_response_bytes_2] = [1234_u64, 5678];

    let mocks = MockHttpOutcallsBuilder::new()
        .given(
            get_logs_request(BlockNumberOrTag::Latest, BlockNumberOrTag::Latest)
                .with_max_response_bytes(max_response_bytes_1)
                .with_id(0),
        )
        .respond_with(get_logs_response().with_id(0))
        .given(
            get_logs_request(BlockNumberOrTag::Latest, BlockNumberOrTag::Latest)
                .with_max_response_bytes(max_response_bytes_2)
                .with_id(1),
        )
        .respond_with(get_logs_response().with_id(1));

    let client = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Cloudflare,
        ])))
        .with_response_size_estimate(max_response_bytes_1)
        .build();

    let response = client
        .get_logs(vec![address!("0xdAC17F958D2ee523a2206206994597C13D831ec7")])
        .send()
        .await
        .expect_consistent();
    assert_matches!(response, Ok(_));

    let response = client
        .get_logs(vec![address!("0xdAC17F958D2ee523a2206206994597C13D831ec7")])
        .with_response_size_estimate(max_response_bytes_2)
        .send()
        .await
        .expect_consistent();
    assert_matches!(response, Ok(_));
}

#[tokio::test]
async fn should_use_fallback_public_url() {
    let setup = EvmRpcSetup::new().await;
    let response = setup
        .client(
            MockHttpOutcallsBuilder::new()
                .given(get_transaction_count_request().with_url("https://rpc.ankr.com/eth"))
                .respond_with(get_transaction_count_response()),
        )
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![EthMainnetService::Ankr])))
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent()
        .unwrap();
    assert_eq!(response, U256::ONE);
}

#[tokio::test]
async fn should_insert_api_keys() {
    let setup = EvmRpcSetup::with_args(InstallArgs {
        manage_api_keys: Some(vec![DEFAULT_CALLER_TEST_ID]),
        ..Default::default()
    })
    .await;
    let provider_id = 1;
    let api_keys = &[(provider_id, Some("test-api-key".to_string()))];
    setup
        .update_api_keys(api_keys, DEFAULT_CALLER_TEST_ID)
        .await;
    let response = setup
        .client(
            MockHttpOutcallsBuilder::new()
                .given(
                    get_transaction_count_request()
                        .with_url("https://rpc.ankr.com/eth/test-api-key"),
                )
                .respond_with(get_transaction_count_response()),
        )
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![EthMainnetService::Ankr])))
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent()
        .unwrap();
    assert_eq!(response, U256::ONE);
}

#[tokio::test]
async fn should_update_api_key() {
    let setup = EvmRpcSetup::with_args(InstallArgs {
        manage_api_keys: Some(vec![DEFAULT_CALLER_TEST_ID]),
        ..Default::default()
    })
    .await;
    let provider_id = 1; // Ankr / mainnet
    let api_key = "test-api-key";

    let api_keys = &[(provider_id, Some(api_key.to_string()))];
    setup
        .update_api_keys(api_keys, DEFAULT_CALLER_TEST_ID)
        .await;
    let response = setup
        .client(
            MockHttpOutcallsBuilder::new()
                .given(
                    get_transaction_count_request()
                        .with_id(0)
                        .with_url(&format!("https://rpc.ankr.com/eth/{api_key}")),
                )
                .respond_with(get_transaction_count_response().with_id(0)),
        )
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![EthMainnetService::Ankr])))
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent()
        .unwrap();
    assert_eq!(response, U256::ONE);

    let api_keys = &[(provider_id, None)];
    setup
        .update_api_keys(api_keys, DEFAULT_CALLER_TEST_ID)
        .await;
    let response = setup
        .client(
            MockHttpOutcallsBuilder::new()
                .given(
                    get_transaction_count_request()
                        .with_id(1)
                        .with_url("https://rpc.ankr.com/eth"),
                )
                .respond_with(get_transaction_count_response().with_id(1)),
        )
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![EthMainnetService::Ankr])))
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent()
        .unwrap();
    assert_eq!(response, U256::ONE);
}

#[tokio::test]
async fn should_update_bearer_token() {
    let setup = EvmRpcSetup::with_args(InstallArgs {
        manage_api_keys: Some(vec![DEFAULT_CALLER_TEST_ID]),
        ..Default::default()
    })
    .await;
    let provider_id = 8; // Alchemy / mainnet
    let api_key = "test-api-key";
    let api_keys = &[(provider_id, Some(api_key.to_string()))];
    setup
        .update_api_keys(api_keys, DEFAULT_CALLER_TEST_ID)
        .await;
    let response = setup
        .client(
            MockHttpOutcallsBuilder::new()
                .given(
                    get_transaction_count_request()
                        .with_url("https://eth-mainnet.g.alchemy.com/v2")
                        .with_request_headers(vec![
                            ("Content-Type", "application/json"),
                            ("Authorization", &format!("Bearer {api_key}")),
                        ]),
                )
                .respond_with(get_transaction_count_response()),
        )
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Alchemy,
        ])))
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent()
        .unwrap();
    assert_eq!(response, U256::ONE);
}

#[tokio::test]
#[should_panic(expected = "You are not authorized")]
async fn should_prevent_unauthorized_update_api_keys() {
    let setup = EvmRpcSetup::new().await;
    setup
        .update_api_keys(
            &[(0, Some("unauthorized-api-key".to_string()))],
            setup.caller,
        )
        .await;
}

#[tokio::test]
#[should_panic(expected = "Trying to set API key for unauthenticated provider")]
async fn should_prevent_unauthenticated_update_api_keys() {
    let setup = EvmRpcSetup::new().await;
    setup
        .update_api_keys(
            &[(
                2, /* PublicNode / mainnet */
                Some("invalid-api-key".to_string()),
            )],
            setup.controller,
        )
        .await;
}

#[tokio::test]
#[should_panic(expected = "Provider not found")]
async fn should_prevent_unknown_provider_update_api_keys() {
    let setup = EvmRpcSetup::new().await;
    setup
        .update_api_keys(
            &[(5555, Some("unknown-provider-api-key".to_string()))],
            setup.controller,
        )
        .await;
}

#[tokio::test]
async fn should_get_nodes_in_subnet() {
    let setup = EvmRpcSetup::new().await;
    let nodes_in_subnet = setup.get_nodes_in_subnet().await;
    assert_eq!(nodes_in_subnet, 34);
}

#[tokio::test]
async fn should_get_providers_and_get_service_provider_map_be_consistent() {
    let setup = EvmRpcSetup::new().await;
    let providers = setup.get_providers().await;
    let service_provider_map = setup.get_service_provider_map().await;
    assert_eq!(providers.len(), service_provider_map.len());

    for (service, provider_id) in service_provider_map {
        let found_provider = providers
            .iter()
            .find(|p| p.provider_id == provider_id)
            .unwrap();
        assert_eq!(found_provider.alias, Some(service));
    }
}

#[tokio::test]
async fn upgrade_should_keep_api_keys() {
    let setup = EvmRpcSetup::with_args(InstallArgs {
        manage_api_keys: Some(vec![DEFAULT_CALLER_TEST_ID]),
        ..Default::default()
    })
    .await;
    let provider_id = 1; // Ankr / mainnet
    let api_key = "test-api-key";
    let api_keys = &[(provider_id, Some(api_key.to_string()))];
    setup
        .update_api_keys(api_keys, DEFAULT_CALLER_TEST_ID)
        .await;
    let response = setup
        .client(
            MockHttpOutcallsBuilder::new()
                .given(
                    get_transaction_count_request()
                        .with_url(&format!("https://rpc.ankr.com/eth/{api_key}")),
                )
                .respond_with(get_transaction_count_response()),
        )
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![EthMainnetService::Ankr])))
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent()
        .unwrap();
    assert_eq!(response, U256::ONE);

    setup.upgrade_canister(InstallArgs::default()).await;

    let response_post_upgrade = setup
        .client(
            MockHttpOutcallsBuilder::new()
                .given(
                    get_transaction_count_request()
                        .with_url(&format!("https://rpc.ankr.com/eth/{api_key}")),
                )
                .respond_with(get_transaction_count_response()),
        )
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![EthMainnetService::Ankr])))
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent()
        .unwrap();
    assert_eq!(response_post_upgrade, U256::ONE);
}

#[tokio::test]
async fn upgrade_should_keep_demo() {
    let setup = EvmRpcSetup::with_args(InstallArgs {
        demo: Some(true),
        ..Default::default()
    })
    .await;
    assert_eq!(
        setup
            .request_cost(
                RpcService::EthMainnet(EthMainnetService::PublicNode),
                r#"{"jsonrpc":"2.0","id":0,"method":"test"}"#,
                1000
            )
            .await
            .unwrap(),
        0_u128
    );
    setup.upgrade_canister(InstallArgs::default()).await;
    assert_eq!(
        setup
            .request_cost(
                RpcService::EthMainnet(EthMainnetService::PublicNode),
                r#"{"jsonrpc":"2.0","id":0,"method":"test"}"#,
                1000
            )
            .await
            .unwrap(),
        0_u128
    );
}

#[tokio::test]
async fn upgrade_should_change_demo() {
    let setup = EvmRpcSetup::with_args(InstallArgs {
        demo: Some(true),
        ..Default::default()
    })
    .await;
    assert_eq!(
        setup
            .request_cost(
                RpcService::EthMainnet(EthMainnetService::PublicNode),
                r#"{"jsonrpc":"2.0","id":0,"method":"test"}"#,
                1000
            )
            .await
            .unwrap(),
        0_u128
    );
    setup
        .upgrade_canister(InstallArgs {
            demo: Some(false),
            ..Default::default()
        })
        .await;
    assert_ne!(
        setup
            .request_cost(
                RpcService::EthMainnet(EthMainnetService::PublicNode),
                r#"{"jsonrpc":"2.0","id":0,"method":"test"}"#,
                1000
            )
            .await
            .unwrap(),
        0_u128
    );
}

#[tokio::test]
async fn upgrade_should_keep_manage_api_key_principals() {
    let setup = EvmRpcSetup::with_args(InstallArgs {
        manage_api_keys: Some(vec![ADDITIONAL_TEST_ID]),
        ..Default::default()
    })
    .await;
    setup
        .upgrade_canister(InstallArgs {
            manage_api_keys: None,
            ..Default::default()
        })
        .await;
    setup
        .update_api_keys(
            &[(0, Some("authorized-api-key".to_string()))],
            ADDITIONAL_TEST_ID,
        )
        .await;
}

#[tokio::test]
#[should_panic(expected = "You are not authorized")]
async fn upgrade_should_change_manage_api_key_principals() {
    let setup = EvmRpcSetup::with_args(InstallArgs {
        manage_api_keys: Some(vec![ADDITIONAL_TEST_ID]),
        ..Default::default()
    })
    .await;
    setup
        .upgrade_canister(InstallArgs {
            manage_api_keys: Some(vec![]),
            ..Default::default()
        })
        .await;
    setup
        .update_api_keys(
            &[(0, Some("unauthorized-api-key".to_string()))],
            ADDITIONAL_TEST_ID,
        )
        .await;
}

#[tokio::test]
async fn should_reject_http_request_in_replicated_mode() {
    let request = HttpRequest {
        method: "".to_string(),
        url: "/nonexistent".to_string(),
        headers: vec![],
        body: serde_bytes::ByteBuf::new(),
    };
    let setup = EvmRpcSetup::new().await;
    assert_matches!(
        setup
        .env
        .update_call(
            setup.evm_rpc_canister_id,
            Principal::anonymous(),
            "http_request",
            Encode!(&request).unwrap(),
        ).await,
        Err(e) if e.error_code == ErrorCode::CanisterCalledTrap && e.reject_message.contains("Update call rejected")
    );
}

#[tokio::test]
async fn should_retrieve_logs() {
    let setup = EvmRpcSetup::new().await;
    assert_eq!(setup.http_get_logs("DEBUG").await, vec![]);
    assert_eq!(setup.http_get_logs("INFO").await, vec![]);

    let setup = setup.mock_api_keys().await;

    assert_eq!(setup.http_get_logs("DEBUG").await, vec![]);
    assert!(setup.http_get_logs("INFO").await[0]
        .message
        .contains("Updating API keys"));
}

#[tokio::test]
async fn should_retry_when_response_too_large() {
    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    let rpc_services = RpcServices::EthMainnet(Some(vec![EthMainnetService::Cloudflare]));

    // around 600 bytes per log
    // we need at least 3334 logs to reach the 2MB limit
    let response_body = multi_logs_for_single_transaction(3_500);
    let max_response_bytes = iter::once(1_u64)
        .chain((1..=10).map(|i| 1024_u64 << i))
        .chain(iter::once(2_000_000_u64));

    let mut mocks = MockHttpOutcallsBuilder::new();
    for (id, max_response_bytes) in max_response_bytes.enumerate() {
        mocks = mocks
            .given(
                JsonRpcRequestMatcher::with_method("eth_getLogs")
                    .with_id(id as u64)
                    .with_params(json!([{
                        "address" : ["0xdac17f958d2ee523a2206206994597c13d831ec7"],
                        "fromBlock": "latest",
                        "toBlock": "latest",
                    }]))
                    .with_max_response_bytes(max_response_bytes),
            )
            .respond_with(JsonRpcResponse::from(&response_body).with_id(id as u64));
    }

    let response = setup
        .client(mocks)
        .with_rpc_sources(rpc_services.clone())
        .with_response_size_estimate(1)
        .build()
        .get_logs(vec![address!("0xdAC17F958D2ee523a2206206994597C13D831ec7")])
        .with_cycles(1_000_000_000_000)
        .send()
        .await
        .expect_consistent();

    assert_matches!(
        response,
        Err(RpcError::HttpOutcallError(HttpOutcallError::IcError { code, message }))
        if code == LegacyRejectionCode::SysFatal && message.contains("body exceeds size limit")
    );

    let response_body = multi_logs_for_single_transaction(1_000);
    let max_response_bytes = iter::once(1_u64).chain((1..=10).map(|i| 1024_u64 << i));

    let mut mocks = MockHttpOutcallsBuilder::new();
    for (id, max_response_bytes) in max_response_bytes.enumerate() {
        mocks = mocks
            .given(
                JsonRpcRequestMatcher::with_method("eth_getLogs")
                    .with_id(id as u64 + 12)
                    .with_params(json!([{
                        "address" : ["0xdac17f958d2ee523a2206206994597c13d831ec7"],
                        "fromBlock": "latest",
                        "toBlock": "latest",
                    }]))
                    .with_max_response_bytes(max_response_bytes),
            )
            .respond_with(JsonRpcResponse::from(&response_body).with_id(id as u64 + 12));
    }

    let response = setup
        .client(mocks)
        .with_rpc_sources(rpc_services.clone())
        .with_response_size_estimate(1)
        .build()
        .get_logs(vec![address!("0xdAC17F958D2ee523a2206206994597C13D831ec7")])
        .with_cycles(1_000_000_000_000)
        .send()
        .await
        .expect_consistent();

    assert_matches!(
        response,
        Ok(logs) if logs.len() == 1_000
    );
}

#[tokio::test]
async fn should_retry_with_increasingly_more_cycles() {
    const INITIAL_NUM_CYCLES: u128 = 100_000_000;

    let setup = EvmRpcSetup::new().await;

    // Should fail without retrying
    let response = setup
        .client(MockHttpOutcalls::never())
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Cloudflare,
        ])))
        .with_retry_strategy(NoRetry)
        .build()
        .get_transaction_count((
            address!("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .with_cycles(INITIAL_NUM_CYCLES)
        .send()
        .await
        .expect_consistent();
    assert_matches!(
        response,
        Err(RpcError::ProviderError(ProviderError::TooFewCycles { .. }))
    );

    let response = setup
        .client(
            // This mock must have the correct ID for the retry with sufficiently many cycles
            MockHttpOutcallsBuilder::new()
                .given(get_transaction_count_request().with_id(4))
                .respond_with(get_transaction_count_response().with_id(4)),
        )
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Cloudflare,
        ])))
        .with_retry_strategy(DoubleCycles::with_max_num_retries(5))
        .build()
        .get_transaction_count((
            address!("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .with_cycles(INITIAL_NUM_CYCLES)
        .send()
        .await
        .expect_consistent();
    assert_eq!(response, Ok(U256::ONE));
}

#[tokio::test]
async fn should_have_different_request_ids_when_retrying_because_response_too_big() {
    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    let mocks = MockHttpOutcallsBuilder::new()
        .given(
            get_transaction_count_request()
                .with_id(0)
                .with_max_response_bytes(1_u64),
        )
        .respond_with(get_transaction_count_response().with_id(0))
        .given(
            get_transaction_count_request()
                .with_id(1)
                .with_max_response_bytes(2048_u64),
        )
        .respond_with(get_transaction_count_response().with_id(1));

    let response = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Cloudflare,
        ])))
        .with_response_size_estimate(1)
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent();

    assert_eq!(response, Ok(U256::ONE));

    setup
        .check_metrics()
        .await
        .assert_contains_metric_matching(r#"evmrpc_requests\{method="eth_getTransactionCount",host="cloudflare-eth.com",is_supported_provider="true"} 2 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_responses\{method="eth_getTransactionCount",host="cloudflare-eth.com",is_supported_provider="true",status="200"} 1 \d+"#)
        .assert_contains_metric_matching(r#"evmrpc_err_max_response_size_exceeded\{method="eth_getTransactionCount",host="cloudflare-eth.com",is_supported_provider="true"} 1 \d+"#);
}

#[tokio::test]
async fn should_fail_when_response_id_inconsistent_with_request_id() {
    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    let request_id = 0;
    let response_id = 1;
    assert_ne!(request_id, response_id);

    let error = setup
        .client(
            MockHttpOutcallsBuilder::new()
                .given(get_transaction_count_request().with_id(request_id))
                .respond_with(get_transaction_count_response().with_id(response_id)),
        )
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Cloudflare,
        ])))
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent()
        .expect_err("should fail when ID mismatch");

    assert!(
        error
            .to_string()
            .to_ascii_lowercase()
            .contains("unexpected identifier"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn should_log_request() {
    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    let mocks = MockHttpOutcallsBuilder::new()
        .given(fee_history_request())
        .respond_with(fee_history_response());

    let response = setup
        .client(mocks)
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Alchemy,
        ])))
        .build()
        .fee_history((3_u64, BlockNumberOrTag::Latest))
        .send()
        .await
        .expect_consistent()
        .unwrap();

    assert_eq!(
        response,
        alloy_rpc_types::FeeHistory {
            oldest_block: 0x11e57f5_u64,
            base_fee_per_gas: vec![0x9cf6c61b9_u128, 0x97d853982, 0x9ba55a0b0, 0x9543bf98d],
            gas_used_ratio: vec![],
            reward: Some(vec![vec![0x0123_u128]]),
            base_fee_per_blob_gas: vec![],
            blob_gas_used_ratio: vec![],
        }
    );

    let logs = setup.http_get_logs("TRACE_HTTP").await;
    assert_eq!(logs.len(), 2, "Unexpected amount of logs {logs:?}");
    assert!(logs[0].message.contains("JSON-RPC request with id `00000000000000000000` to eth-mainnet.g.alchemy.com: JsonRpcRequest { jsonrpc: V2, method: \"eth_feeHistory\""));
    assert!(logs[1].message.contains("response for request with id `00000000000000000000`. Response with status 200 OK: JsonRpcResponse { jsonrpc: V2, id: String(\"00000000000000000000\"), result: Ok(FeeHistory"));
}

#[tokio::test]
async fn should_change_default_provider_when_one_keeps_failing() {
    let setup = EvmRpcSetup::new().await.mock_api_keys().await;

    let response = setup
        .client(
            MockHttpOutcallsBuilder::new()
                .given(
                    get_transaction_count_request()
                        .with_id(0)
                        .with_host(ANKR_HOSTNAME),
                )
                .respond_with(get_transaction_count_response().with_id(0))
                .given(
                    get_transaction_count_request()
                        .with_id(1)
                        .with_host(BLOCKPI_ETH_HOSTNAME),
                )
                .respond_with(CanisterHttpReply::with_status(500).with_body("Error!"))
                .given(
                    get_transaction_count_request()
                        .with_id(2)
                        .with_host(PUBLICNODE_ETH_MAINNET_HOSTNAME),
                )
                .respond_with(get_transaction_count_response().with_id(2)),
        )
        .with_rpc_sources(RpcServices::EthMainnet(None))
        .with_consensus_strategy(ConsensusStrategy::Threshold {
            total: Some(3),
            min: 2,
        })
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent()
        .unwrap();
    assert_eq!(response, U256::ONE);

    let response = setup
        .client(
            MockHttpOutcallsBuilder::new()
                .given(
                    get_transaction_count_request()
                        .with_id(3)
                        .with_host(ALCHEMY_ETH_MAINNET_HOSTNAME),
                )
                .respond_with(get_transaction_count_response().with_id(3))
                .given(
                    get_transaction_count_request()
                        .with_id(4)
                        .with_host(ANKR_HOSTNAME),
                )
                .respond_with(get_transaction_count_response().with_id(4)),
        )
        .with_rpc_sources(RpcServices::EthMainnet(Some(vec![
            EthMainnetService::Ankr,
            EthMainnetService::Alchemy,
        ])))
        .with_consensus_strategy(ConsensusStrategy::Equality)
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent()
        .unwrap();
    assert_eq!(response, U256::ONE);

    let response = setup
        .client(
            MockHttpOutcallsBuilder::new()
                .given(
                    get_transaction_count_request()
                        .with_id(5)
                        .with_host(ALCHEMY_ETH_MAINNET_HOSTNAME),
                )
                .respond_with(get_transaction_count_response().with_id(5))
                .given(
                    get_transaction_count_request()
                        .with_id(6)
                        .with_host(ANKR_HOSTNAME),
                )
                .respond_with(get_transaction_count_response().with_id(6))
                .given(
                    get_transaction_count_request()
                        .with_id(7)
                        .with_host(PUBLICNODE_ETH_MAINNET_HOSTNAME),
                )
                .respond_with(get_transaction_count_response().with_id(7)),
        )
        .with_rpc_sources(RpcServices::EthMainnet(None))
        .with_consensus_strategy(ConsensusStrategy::Threshold {
            total: Some(3),
            min: 2,
        })
        .build()
        .get_transaction_count((
            address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            BlockNumberOrTag::Latest,
        ))
        .send()
        .await
        .expect_consistent()
        .unwrap();
    assert_eq!(response, U256::ONE);
}

mod cycles_cost_tests {
    use super::*;

    #[tokio::test]
    async fn should_be_idempotent() {
        async fn check<Converter, Config, Params, CandidOutput, Output>(
            request: RequestBuilder<
                CyclesWalletRuntime<PocketIcRuntime<'_>>,
                Converter,
                NoRetry,
                Config,
                Params,
                CandidOutput,
                Output,
            >,
        ) where
            Config: CandidType + Clone + Send,
            Params: CandidType + Clone + Send,
        {
            let cycles_cost_1 = request.clone().request_cost().send().await.unwrap();
            let cycles_cost_2 = request.request_cost().send().await.unwrap();
            assert_eq!(cycles_cost_1, cycles_cost_2);
            assert!(cycles_cost_1 > 0);
        }

        let setup = EvmRpcSetup::with_args(InstallArgs {
            demo: Some(false),
            ..Default::default()
        })
        .await
        .mock_api_keys()
        .await;
        let client = setup.client(MockHttpOutcalls::never()).build();

        for endpoint in EvmRpcEndpoint::iter() {
            match endpoint {
                EvmRpcEndpoint::Call => {
                    check(
                        client.call(
                            alloy_rpc_types::TransactionRequest::default()
                                .to(MOCK_ADDRESS)
                                .input(alloy_rpc_types::TransactionInput::from(MOCK_INPUT_DATA)),
                        ),
                    )
                    .await;
                }
                EvmRpcEndpoint::FeeHistory => {
                    check(client.fee_history((3_u64, BlockNumberOrTag::Latest))).await
                }
                EvmRpcEndpoint::GetBlockByNumber => {
                    check(client.get_block_by_number(BlockNumberOrTag::Latest)).await
                }
                EvmRpcEndpoint::GetLogs => check(client.get_logs(vec![MOCK_ADDRESS])).await,
                EvmRpcEndpoint::GetTransactionCount => {
                    check(client.get_transaction_count((MOCK_ADDRESS, BlockNumberOrTag::Latest)))
                        .await
                }
                EvmRpcEndpoint::GetTransactionReceipt => {
                    check(client.get_transaction_receipt(MOCK_TRANSACTION_HASH)).await
                }
                EvmRpcEndpoint::MultiRequest => {
                    check(client.multi_request(json!({
                        "id" : ConstantSizeId::from(0_u64).to_string(),
                        "jsonrpc": "2.0",
                        "method": "eth_gasPrice",
                    })))
                    .await
                }
                EvmRpcEndpoint::SendRawTransaction => {
                    check(client.send_raw_transaction(MOCK_TRANSACTION)).await
                }
            }
        }
    }

    #[tokio::test]
    async fn should_be_zero_when_in_demo_mode() {
        async fn check<Converter, Config, Params, CandidOutput, Output>(
            request: RequestBuilder<
                CyclesWalletRuntime<PocketIcRuntime<'_>>,
                Converter,
                NoRetry,
                Config,
                Params,
                CandidOutput,
                Output,
            >,
        ) where
            Config: CandidType + Clone + Send,
            Params: CandidType + Clone + Send,
        {
            let cycles_cost = request.request_cost().send().await;
            assert_eq!(cycles_cost, Ok(0));
        }

        let setup = EvmRpcSetup::with_args(InstallArgs {
            demo: Some(true),
            ..Default::default()
        })
        .await
        .mock_api_keys()
        .await;
        let client = setup.client(MockHttpOutcalls::never()).build();

        for endpoint in EvmRpcEndpoint::iter() {
            match endpoint {
                EvmRpcEndpoint::Call => {
                    check(
                        client.call(
                            alloy_rpc_types::TransactionRequest::default()
                                .to(MOCK_ADDRESS)
                                .input(alloy_rpc_types::TransactionInput::from(MOCK_INPUT_DATA)),
                        ),
                    )
                    .await;
                }
                EvmRpcEndpoint::FeeHistory => {
                    check(client.fee_history((3_u64, BlockNumberOrTag::Latest))).await
                }
                EvmRpcEndpoint::GetBlockByNumber => {
                    check(client.get_block_by_number(BlockNumberOrTag::Latest)).await
                }
                EvmRpcEndpoint::GetLogs => check(client.get_logs(vec![MOCK_ADDRESS])).await,
                EvmRpcEndpoint::GetTransactionCount => {
                    check(client.get_transaction_count((MOCK_ADDRESS, BlockNumberOrTag::Latest)))
                        .await
                }
                EvmRpcEndpoint::GetTransactionReceipt => {
                    check(client.get_transaction_receipt(MOCK_TRANSACTION_HASH)).await
                }
                EvmRpcEndpoint::MultiRequest => {
                    check(client.multi_request(json!({
                        "id" : ConstantSizeId::from(0_u64).to_string(),
                        "jsonrpc": "2.0",
                        "method": "eth_gasPrice",
                    })))
                    .await
                }
                EvmRpcEndpoint::SendRawTransaction => {
                    check(client.send_raw_transaction(MOCK_TRANSACTION)).await
                }
            }
        }
    }

    #[tokio::test]
    async fn should_get_exact_cycles_cost() {
        async fn check<Config, Converter, Params, CandidOutput, Output>(
            setup: &EvmRpcSetup,
            request: RequestBuilder<
                CyclesWalletRuntime<PocketIcRuntime<'_>>,
                Converter,
                NoRetry,
                Config,
                Params,
                MultiRpcResult<CandidOutput>,
                MultiRpcResult<Output>,
            >,
            expected_cycles_cost: u128,
        ) where
            Config: CandidType + Clone + Send,
            Params: CandidType + Clone + Send,
            CandidOutput: CandidType + DeserializeOwned,
            Output: Debug,
            MultiRpcResult<CandidOutput>: Into<MultiRpcResult<Output>>,
        {
            let five_percents = 5_u8;

            let cycles_cost = request.clone().request_cost().send().await.unwrap();
            assert_within(cycles_cost, expected_cycles_cost, five_percents);

            let cycles_before = setup.evm_rpc_canister_cycles_balance().await;
            // Request with exact cycles amount should succeed
            let result = request
                .clone()
                .with_cycles(cycles_cost)
                .send()
                .await
                .expect_consistent();
            if let Err(RpcError::ProviderError(ProviderError::TooFewCycles { .. })) = result {
                panic!("BUG: estimated cycles cost was insufficient!: {result:?}");
            }
            let cycles_after = setup.evm_rpc_canister_cycles_balance().await;
            let cycles_consumed = cycles_before + cycles_cost - cycles_after;

            assert!(
                    cycles_after > cycles_before,
                    "BUG: not enough cycles requested. Requested {cycles_cost} cycles, but consumed {cycles_consumed} cycles"
                );

            // The same request with fewer cycles should fail.
            let results = request
                .with_cycles(cycles_cost - 1)
                .send()
                .await
                .expect_inconsistent();

            assert!(
                results.iter().any(|(_provider, result)| matches!(
                    result,
                    &Err(RpcError::ProviderError(ProviderError::TooFewCycles {
                        expected: _,
                        received: _
                    }))
                )),
                "BUG: Expected at least one TooFewCycles error, but got {results:?}"
            );
        }

        let setup = EvmRpcSetup::new().await.mock_api_keys().await;
        // The exact cycles cost of an HTTPs outcall is independent of the response,
        // so we always return a dummy response so that individual responses
        // do not need to be mocked.
        let mut mocks = MockHttpOutcallsBuilder::new();
        let mut ids = 0_u64..;
        for endpoint in EvmRpcEndpoint::iter() {
            let rpc_method = if endpoint == EvmRpcEndpoint::MultiRequest {
                MOCK_REQUEST_METHOD
            } else {
                endpoint.rpc_method()
            };
            for id in ids.by_ref().take(5) {
                mocks = mocks
                    .given(JsonRpcRequestMatcher::with_method(rpc_method).with_id(id))
                    .respond_with(CanisterHttpReply::with_status(403));
            }
            // Advance ID by 1 to account for the call with insufficient cycles, for which only the
            // call to the last provider does not result in an HTTP outcall
            for _ in ids.by_ref().take(1) {}
        }

        let client = setup.client(mocks).build();

        for endpoint in EvmRpcEndpoint::iter() {
            // To find out the expected_cycles_cost for a new endpoint, set the amount to 0
            // and run the test. It should fail and report the amount of cycles needed.
            match endpoint {
                EvmRpcEndpoint::Call => {
                    check(
                        &setup,
                        client.call(
                            alloy_rpc_types::TransactionRequest::default()
                                .to(MOCK_ADDRESS)
                                .input(alloy_rpc_types::TransactionInput::from(MOCK_INPUT_DATA)),
                        ),
                        1_734_639_200,
                    )
                    .await;
                }
                EvmRpcEndpoint::FeeHistory => {
                    check(
                        &setup,
                        client.fee_history((3_u64, BlockNumberOrTag::Latest)),
                        1_750_673_600,
                    )
                    .await
                }
                EvmRpcEndpoint::GetBlockByNumber => {
                    check(
                        &setup,
                        client.get_block_by_number(BlockNumberOrTag::Latest),
                        3_714_418_400,
                    )
                    .await
                }
                EvmRpcEndpoint::GetLogs => {
                    check(&setup, client.get_logs(vec![MOCK_ADDRESS]), 1_795_635_200).await
                }
                EvmRpcEndpoint::GetTransactionCount => {
                    check(
                        &setup,
                        client.get_transaction_count((MOCK_ADDRESS, BlockNumberOrTag::Latest)),
                        1_714_688_000,
                    )
                    .await
                }
                EvmRpcEndpoint::GetTransactionReceipt => {
                    check(
                        &setup,
                        client.get_transaction_receipt(MOCK_TRANSACTION_HASH),
                        1_768_421_600,
                    )
                    .await
                }
                EvmRpcEndpoint::MultiRequest => {
                    check(
                        &setup,
                        client.multi_request(json!({
                            "id" : ConstantSizeId::from(0_u64).to_string(),
                            "jsonrpc": "2.0",
                            "method": "eth_gasPrice",
                        })),
                        1_729_090_400,
                    )
                    .await
                }
                EvmRpcEndpoint::SendRawTransaction => {
                    check(
                        &setup,
                        client.send_raw_transaction(MOCK_TRANSACTION),
                        1_738_556_000,
                    )
                    .await
                }
            }
        }
    }
}

fn call_request() -> JsonRpcRequestMatcher {
    JsonRpcRequestMatcher::with_method("eth_call")
        .with_params(json!([
            {
                "to": MOCK_ADDRESS,
                "input": MOCK_INPUT_DATA
            },
            "latest"
        ]))
        .with_id(0)
}

mod request_cost_tests {
    use super::*;

    #[tokio::test]
    async fn should_be_idempotent() {
        let setup = EvmRpcSetup::new().await.mock_api_keys().await;

        let cycles_cost_1 = setup
            .request_cost(
                RpcService::EthMainnet(EthMainnetService::PublicNode),
                MOCK_REQUEST_PAYLOAD,
                MOCK_REQUEST_RESPONSE_BYTES,
            )
            .await
            .unwrap();

        let cycles_cost_2 = setup
            .request_cost(
                RpcService::EthMainnet(EthMainnetService::PublicNode),
                MOCK_REQUEST_PAYLOAD,
                MOCK_REQUEST_RESPONSE_BYTES,
            )
            .await
            .unwrap();

        assert_eq!(cycles_cost_1, cycles_cost_2);
        assert!(cycles_cost_1 > 0_u128);
    }

    #[tokio::test]
    async fn should_be_zero_when_in_demo_mode() {
        let setup = EvmRpcSetup::with_args(InstallArgs {
            demo: Some(true),
            ..Default::default()
        })
        .await
        .mock_api_keys()
        .await;

        let cycles_cost = setup
            .request_cost(
                RpcService::EthMainnet(EthMainnetService::PublicNode),
                MOCK_REQUEST_PAYLOAD,
                MOCK_REQUEST_RESPONSE_BYTES,
            )
            .await
            .unwrap();

        assert_eq!(cycles_cost, 0_u128);
    }

    #[tokio::test]
    async fn should_get_exact_cycles_cost() {
        const EXPECTED_CYCLES_COST: u128 = 540_518_400;

        let five_percents = 5_u8;
        let setup = EvmRpcSetup::new().await.mock_api_keys().await;
        let mocks = MockHttpOutcallsBuilder::new()
            .given(
                JsonRpcRequestMatcher::with_method(MOCK_REQUEST_METHOD)
                    .with_params(MOCK_REQUEST_PARAMS)
                    .with_raw_id(MOCK_REQUEST_ID),
            )
            .respond_with(JsonRpcResponse::from(MOCK_REQUEST_RESPONSE));

        let cycles_cost = setup
            .request_cost(
                RpcService::EthMainnet(EthMainnetService::PublicNode),
                MOCK_REQUEST_PAYLOAD,
                MOCK_REQUEST_RESPONSE_BYTES,
            )
            .await
            .unwrap();
        assert_within(cycles_cost, EXPECTED_CYCLES_COST, five_percents);

        let cycles_before = setup.evm_rpc_canister_cycles_balance().await;
        // Request with exact cycles amount should succeed
        let result = setup
            .request(
                &setup.new_mock_http_runtime_with_wallet(mocks),
                (
                    RpcService::EthMainnet(EthMainnetService::PublicNode),
                    MOCK_REQUEST_PAYLOAD,
                    MOCK_REQUEST_RESPONSE_BYTES,
                ),
                cycles_cost,
            )
            .await;
        if let Err(RpcError::ProviderError(ProviderError::TooFewCycles { .. })) = result {
            panic!("BUG: estimated cycles cost was insufficient!: {result:?}");
        }
        let cycles_after = setup.evm_rpc_canister_cycles_balance().await;
        let cycles_consumed = cycles_before + cycles_cost - cycles_after;

        assert!(
                cycles_after > cycles_before,
                "BUG: not enough cycles requested. Requested {cycles_cost} cycles, but consumed {cycles_consumed} cycles"
            );

        // Same request with fewer cycles should fail.
        let result = setup
            .request(
                &setup.new_mock_http_runtime_with_wallet(MockHttpOutcalls::never()),
                (
                    RpcService::EthMainnet(EthMainnetService::PublicNode),
                    MOCK_REQUEST_PAYLOAD,
                    MOCK_REQUEST_RESPONSE_BYTES,
                ),
                cycles_cost - 1,
            )
            .await;

        assert_matches!(
            result,
            Err(RpcError::ProviderError(ProviderError::TooFewCycles {
                expected: _,
                received: _
            })),
            "BUG: Expected TooFewCycles error, but got {result:?}"
        );
    }
}

fn assert_within(actual: u128, expected: u128, percentage_error: u8) {
    assert!(percentage_error <= 100);
    let error_margin = expected.saturating_mul(percentage_error as u128) / 100;
    let lower_bound = expected.saturating_sub(error_margin);
    let upper_bound = expected.saturating_add(error_margin);
    assert!(
        lower_bound <= actual && actual <= upper_bound,
        "Expected {} <= {} <= {}",
        lower_bound,
        actual,
        upper_bound
    );
}

fn fee_history_request() -> JsonRpcRequestMatcher {
    JsonRpcRequestMatcher::with_method("eth_feeHistory")
        .with_params(json!(["0x3", "latest", []]))
        .with_id(0)
}

fn get_block_by_number_request() -> JsonRpcRequestMatcher {
    JsonRpcRequestMatcher::with_method("eth_getBlockByNumber")
        .with_params(json!(["latest", false]))
        .with_id(0)
}

fn get_logs_request(
    from_block: BlockNumberOrTag,
    to_block: BlockNumberOrTag,
) -> JsonRpcRequestMatcher {
    JsonRpcRequestMatcher::with_method("eth_getLogs").with_params(json!([{
        "address" : ["0xdac17f958d2ee523a2206206994597c13d831ec7"],
        "fromBlock" : from_block,
        "toBlock" : to_block,
    }]))
}

fn get_transaction_count_request() -> JsonRpcRequestMatcher {
    JsonRpcRequestMatcher::with_method("eth_getTransactionCount")
        .with_params(json!([
            "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "latest"
        ]))
        .with_id(0)
}

fn get_transaction_receipt_request() -> JsonRpcRequestMatcher {
    JsonRpcRequestMatcher::with_method("eth_getTransactionReceipt")
        .with_params(json!([
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f"
        ]))
        .with_id(0)
}

fn send_raw_transaction_request() -> JsonRpcRequestMatcher {
    JsonRpcRequestMatcher::with_method("eth_sendRawTransaction")
        .with_params(json!([MOCK_TRANSACTION.to_string()]))
        .with_id(0)
}

fn call_response() -> JsonRpcResponse {
    JsonRpcResponse::from(json!({
        "jsonrpc": "2.0",
        "id" : ConstantSizeId::ZERO.to_string(),
        "result": "0x0000000000000000000000000000000000000000000000000000013c3ee36e89"
    }))
}

fn fee_history_response() -> JsonRpcResponse {
    JsonRpcResponse::from(json!({
        "id" : ConstantSizeId::ZERO.to_string(),
        "jsonrpc" : "2.0",
        "result" : {
            "oldestBlock" : "0x11e57f5",
            "baseFeePerGas" : ["0x9cf6c61b9", "0x97d853982", "0x9ba55a0b0", "0x9543bf98d"],
            "reward" : [["0x0123"]]
        }
    }))
}

fn get_block_by_number_response() -> JsonRpcResponse {
    JsonRpcResponse::from(json!({
        "jsonrpc": "2.0",
        "result": {
            "baseFeePerGas": "0xd7232aa34",
            "difficulty": "0x0",
            "extraData": "0x546974616e2028746974616e6275696c6465722e78797a29",
            "gasLimit": "0x1c9c380",
            "gasUsed": "0xa768c4",
            "hash": "0xc3674be7b9d95580d7f23c03d32e946f2b453679ee6505e3a778f003c5a3cfae",
            "logsBloom": "0x3e6b8420e1a13038902c24d6c2a9720a7ad4860cdc870cd5c0490011e43631134f608935bd83171247407da2c15d85014f9984608c03684c74aad48b20bc24022134cdca5f2e9d2dee3b502a8ccd39eff8040b1d96601c460e119c408c620b44fa14053013220847045556ea70484e67ec012c322830cf56ef75e09bd0db28a00f238adfa587c9f80d7e30d3aba2863e63a5cad78954555966b1055a4936643366a0bb0b1bac68d0e6267fc5bf8304d404b0c69041125219aa70562e6a5a6362331a414a96d0716990a10161b87dd9568046a742d4280014975e232b6001a0360970e569d54404b27807d7a44c949ac507879d9d41ec8842122da6772101bc8b",
            "miner": "0x388c818ca8b9251b393131c08a736a67ccb19297",
            "mixHash": "0x516a58424d4883a3614da00a9c6f18cd5cd54335a08388229a993a8ecf05042f",
            "nonce": "0x0000000000000000",
            "number": "0x11db01d",
            "parentHash": "0x43325027f6adf9befb223f8ae80db057daddcd7b48e41f60cd94bfa8877181ae",
            "receiptsRoot": "0x66934c3fd9c547036fe0e56ad01bc43c84b170be7c4030a86805ddcdab149929",
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "size": "0xcd35",
            "stateRoot": "0x13552447dd62f11ad885f21a583c4fa34144efe923c7e35fb018d6710f06b2b6",
            "timestamp": "0x656f96f3",
            "withdrawalsRoot": "0xecae44b2c53871003c5cc75285995764034c9b5978a904229d36c1280b141d48",
            "transactionsRoot": "0x93a1ad3d067009259b508cc95fde63b5efd7e9d8b55754314c173fdde8c0826a",
        },
        "id" : ConstantSizeId::ZERO.to_string(),
    }))
}

fn get_logs_response() -> JsonRpcResponse {
    JsonRpcResponse::from(json!({
        "id" : ConstantSizeId::ZERO.to_string(),
        "jsonrpc" : "2.0",
        "result" : [
            {
                "address" : "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "topics" : [
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                    "0x000000000000000000000000a9d1e08c7793af67e9d92fe308d5697fb81d3e43",
                    "0x00000000000000000000000078cccfb3d517cd4ed6d045e263e134712288ace2"
                ],
                "data" : "0x000000000000000000000000000000000000000000000000000000003b9c6433",
                "blockNumber" : "0x11dc77e",
                "transactionHash" : "0xf3ed91a03ddf964281ac7a24351573efd535b80fc460a5c2ad2b9d23153ec678",
                "transactionIndex" : "0x65",
                "blockHash" : "0xd5c72ad752b2f0144a878594faf8bd9f570f2f72af8e7f0940d3545a6388f629",
                "logIndex" : "0xe8",
                "removed" : false
            }
        ]
    }))
}

fn get_transaction_count_response() -> JsonRpcResponse {
    JsonRpcResponse::from(json!({
        "jsonrpc": "2.0",
        "id": ConstantSizeId::ZERO.to_string(),
        "result": "0x1"
    }))
}

fn send_raw_transaction_response() -> JsonRpcResponse {
    JsonRpcResponse::from(json!({
        "jsonrpc": "2.0",
        "id": ConstantSizeId::ZERO.to_string(),
        "result": MOCK_TRANSACTION_HASH
    }))
}

pub fn multi_logs_for_single_transaction(num_logs: usize) -> Value {
    let mut logs = Vec::with_capacity(num_logs);
    for log_index in 0..num_logs {
        let mut log = single_log();
        log.log_index = Some(log_index.into());
        logs.push(log);
    }
    json!({"jsonrpc":"2.0","result": logs,"id":0})
}

fn single_log() -> ethers_core::types::Log {
    let json_value = json!({
       "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
        "blockHash": "0xc5e46f4f529cfd2abf1c5dfaad4c4ea8d297795c8632b5056bc6f9eed1f5a7eb",
        "blockNumber": "0x47b133",
        "data": "0x00000000000000000000000000000000000000000000000000038d7ea4c68000",
        "logIndex": "0x2e",
        "removed": false,
        "topics": [
            "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
            "0x000000000000000000000000c8a1bc416c8498af8dc03b253a513d379d3e4ee8",
            "0x1d9facb184cbe453de4841b6b9d9cc95bfc065344e485789b550544529020000"
        ],
        "transactionHash": "0x42826e03a51e735a1adc6ed026796d9044d6942c8de660017289cdc4787f3983",
        "transactionIndex": "0x20"
    });
    serde_json::from_value(json_value).expect("BUG: invalid log entry")
}
