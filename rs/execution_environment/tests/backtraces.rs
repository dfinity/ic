use candid::Encode;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_types::{CanisterId, Cycles};

const B: u128 = 1_000 * 1_000 * 1_000;

fn env_with_backtrace_canister() -> (StateMachine, CanisterId) {
    let wasm = canister_test::Project::cargo_bin_maybe_from_env("backtrace_canister", &[]);

    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let initial_cycles = Cycles::new(1_000_000 * B);
    let canister_id = env
        .install_canister_with_cycles(wasm.bytes(), vec![], None, initial_cycles)
        .unwrap();

    (env, canister_id)
}

#[test]
fn backtrace_test_unreachable() {
    let (env, canister_id) = env_with_backtrace_canister();
    assert!(env
        .execute_ingress(canister_id, "unreachable", Encode!(&()).unwrap())
        .is_err());
}

#[test]
fn backtrace_test_oob() {
    let (env, canister_id) = env_with_backtrace_canister();
    assert!(env
        .execute_ingress(canister_id, "oob", Encode!(&()).unwrap())
        .is_err());
}

#[test]
fn backtrace_test_ic0_trap() {
    let (env, canister_id) = env_with_backtrace_canister();
    assert!(env
        .execute_ingress(canister_id, "ic0_trap", Encode!(&()).unwrap())
        .is_err());
}
