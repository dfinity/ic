/* tag::catalog[]
end::catalog[] */

use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::GetFirstHealthyNodeSnapshot;
use crate::driver::test_env_api::HasPublicApiUrl;
use crate::driver::test_env_api::HasTopologySnapshot;
use crate::driver::test_env_api::IcNodeContainer;
use crate::util::*;
use candid::Encode;
use ic_agent::agent::RejectCode;
use ic_agent::export::Principal;
use ic_agent::AgentError::CertificateNotAuthorized;
use ic_btc_interface::GetUtxosRequest;
use ic_btc_interface::{Address, GetBalanceRequest, NetworkInRequest};
use ic_config::execution_environment::BITCOIN_MAINNET_CANISTER_ID;
use ic_config::execution_environment::BITCOIN_TESTNET_CANISTER_ID;
use ic_types::Cycles;
use ic_utils::interfaces::ManagementCanister;
use std::str::FromStr;

/// Tests that query replies can be larger than update replies.
pub fn query_reply_sizes(env: TestEnv) {
    // A wasm that exports a query function that has a 3MiB reply.
    let wasm = wat::parse_str(
        r#"(module
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32) (param i32)))

              (func $hi
                (call $msg_reply_data_append (i32.const 0) (i32.const 3145728))
                (call $msg_reply))

              (memory $memory 48)
              (export "memory" (memory $memory))
              (export "canister_query hi" (func $hi)))"#,
    )
    .unwrap();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on({
        async move {
            let mgr = ManagementCanister::create(&agent);

            let canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(app_node.effective_canister_id())
                .call_and_wait()
                .await
                .expect("Couldn't create canister with provisional API.")
                .0;
            mgr.install_code(&canister_id, &wasm)
                .call_and_wait()
                .await
                .unwrap();

            // Calling the query function as a query succeeds.
            agent.query(&canister_id, "hi").call().await.unwrap();
            // Calling the query function as an update fails because the reply
            // is too big.
            let res = agent.update(&canister_id, "hi").call_and_wait().await;
            assert_reject(res, RejectCode::CanisterError);
        }
    })
}

// Wasm for a canister that represents Bitcoin canister
const BITCOIN_CANISTER_MOCK: &str = r#"(module
    (import "ic0" "msg_reply" (func $msg_reply))
    (import "ic0" "msg_reply_data_append"
      (func $msg_reply_data_append (param i32) (param i32)))

    (func $get_balance
      (call $msg_reply_data_append (i32.const 0) (i32.const 314))
      (call $msg_reply))
    (func $get_utxos
        (call $msg_reply_data_append (i32.const 0) (i32.const 315))
        (call $msg_reply))
    (memory $memory 48)
      (export "memory" (memory $memory))
    (export "canister_query bitcoin_get_balance_query" (func $get_balance))
    (export "canister_query bitcoin_get_utxos_query" (func $get_utxos))
)"#;

const INITIAL_CYCLES: Cycles = Cycles::new(5_000_000_000_000);

// Test Bitcoin canister query APIs.
pub fn test_bitcoin_query_apis(env: TestEnv) {
    let node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    node.await_status_is_healthy().unwrap();
    let agent = node.build_default_agent();
    block_on({
        async move {
            for (principal, network) in [
                (BITCOIN_MAINNET_CANISTER_ID, NetworkInRequest::Mainnet),
                (BITCOIN_TESTNET_CANISTER_ID, NetworkInRequest::Testnet),
            ] {
                let wasm = wat::parse_str(BITCOIN_CANISTER_MOCK).unwrap();
                let bitcoin_canister_principal = Principal::from_str(principal).unwrap();
                let actual_bitcoin_canister_principal: Principal =
                    create_and_install_with_cycles_and_specified_id(
                        &agent,
                        bitcoin_canister_principal.into(),
                        wasm.as_slice(),
                        INITIAL_CYCLES,
                    )
                    .await;

                assert_eq!(
                    actual_bitcoin_canister_principal,
                    bitcoin_canister_principal
                );

                let management_canister_id = Principal::from_text("aaaaa-aa").unwrap();
                for (method_name, vec_size, request) in [
                    (
                        "bitcoin_get_balance_query",
                        314,
                        Encode!(&GetBalanceRequest {
                            address: Address::from_str("38XnPvu9PmonFU9WouPXUjYbW91wa5MerL")
                                .unwrap(),
                            network,
                            min_confirmations: None,
                        })
                        .unwrap(),
                    ),
                    (
                        "bitcoin_get_utxos_query",
                        315,
                        Encode!(&GetUtxosRequest {
                            address: Address::from_str("38XnPvu9PmonFU9WouPXUjYbW91wa5MerL")
                                .unwrap(),
                            network,
                            filter: None,
                        })
                        .unwrap(),
                    ),
                ] {
                    let res = agent
                        .query(&management_canister_id, method_name)
                        .with_arg(request)
                        .call()
                        .await
                        .unwrap();
                    assert_eq!(res, vec![0; vec_size]);
                }
            }
        }
    })
}

// Test that Bitcoin query call to non-Bitcoin subnet is rejected.
pub fn test_bitcoin_query_calls_to_application_subnet(env: TestEnv) {
    let root_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    root_node.await_status_is_healthy().unwrap();
    let root_agent = root_node.build_default_agent();

    let app_node: crate::driver::test_env_api::IcNodeSnapshot =
        env.get_first_healthy_application_node_snapshot();
    app_node.await_status_is_healthy().unwrap();
    let app_agent = app_node.build_default_agent();

    block_on({
        async move {
            let wasm = wat::parse_str(BITCOIN_CANISTER_MOCK).unwrap();
            let bitcoin_canister_principal =
                Principal::from_str(BITCOIN_MAINNET_CANISTER_ID).unwrap();
            let actual_bitcoin_canister_principal: Principal =
                create_and_install_with_cycles_and_specified_id(
                    &root_agent,
                    bitcoin_canister_principal.into(),
                    wasm.as_slice(),
                    INITIAL_CYCLES,
                )
                .await;

            assert_eq!(
                actual_bitcoin_canister_principal,
                bitcoin_canister_principal
            );

            let management_canister_id = Principal::from_text("aaaaa-aa").unwrap();
            let res = app_agent
                .query(&management_canister_id, "bitcoin_get_balance_query")
                .with_arg(
                    Encode!(&GetBalanceRequest {
                        address: Address::from_str("38XnPvu9PmonFU9WouPXUjYbW91wa5MerL").unwrap(),
                        network: NetworkInRequest::Mainnet,
                        min_confirmations: None,
                    })
                    .unwrap(),
                )
                .call()
                .await;
            assert_eq!(res, Err(CertificateNotAuthorized()));
        }
    })
}
