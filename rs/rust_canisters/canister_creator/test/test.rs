use canister_test::*;
use ic_state_machine_tests::StateMachine;

#[test]
fn creating_canisters_works() {
    let env = StateMachine::new();

    let features = [];
    let wasm = Project::cargo_bin_maybe_from_env("canister_creator_canister", &features);

    let initial_cycles = Cycles::from(u128::MAX);
    let canister_id = env
        .install_canister_with_cycles(wasm.bytes(), vec![], None, initial_cycles)
        .unwrap();

    let payload = r#"1000"#.as_bytes().to_vec();
    let result = env
        .execute_ingress(canister_id, "create_canisters", payload)
        .unwrap();
    assert_eq!(result, WasmResult::Reply("null".as_bytes().to_vec()));

    assert!(env.cycle_balance(canister_id) <= initial_cycles.get() - (1000 * 1_000_000_000_000));
}
