use candid::{Decode, Encode};
use ic_nns_test_utils::common::build_node_rewards_wasm;
use ic_nns_test_utils::state_test_helpers::query;
use ic_state_machine_tests::StateMachine;
use node_rewards_canister_api::lifecycle_args::InitArgs;

#[test]
fn test_hello_endpoint() {
    let state_machine = StateMachine::new();

    let wasm = build_node_rewards_wasm();

    let canister_id = state_machine
        .install_canister(wasm.bytes(), Encode!(&InitArgs {}).unwrap(), None)
        .unwrap();

    let response = query(&state_machine, canister_id, "hello", Encode!().unwrap()).unwrap();

    let decoded = Decode!(&response, String).unwrap();

    assert_eq!(decoded, "Hello, world!");
}
