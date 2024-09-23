use candid::Encode;
use ic_config::{
    execution_environment::Config as HypervisorConfig, flag_status::FlagStatus,
    subnet_config::SubnetConfig,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{ErrorCode, StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_types::{CanisterId, Cycles};

const B: u128 = 1_000 * 1_000 * 1_000;

fn env_with_backtrace_canister(feature_enabled: FlagStatus) -> (StateMachine, CanisterId) {
    let wasm = canister_test::Project::cargo_bin_maybe_from_env("backtrace_canister", &[]);
    let mut hypervisor_config = HypervisorConfig::default();
    hypervisor_config
        .embedders_config
        .feature_flags
        .canister_backtrace = feature_enabled;
    let subnet_type = SubnetType::Application;

    let env = StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            SubnetConfig::new(subnet_type),
            hypervisor_config,
        )))
        .with_subnet_type(subnet_type)
        .build();

    let initial_cycles = Cycles::new(1_000_000 * B);
    let canister_id = env
        .install_canister_with_cycles(wasm.bytes(), vec![], None, initial_cycles)
        .unwrap();

    (env, canister_id)
}

#[test]
fn unreachable_instr_backtrace() {
    let (env, canister_id) = env_with_backtrace_canister(FlagStatus::Enabled);
    let result = env
        .execute_ingress(canister_id, "unreachable", Encode!(&()).unwrap())
        .unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterTrapped,
        r#"Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister trapped: unreachable
Canister Backtrace:
_wasm_backtrace_canister::unreachable_bar
_wasm_backtrace_canister::unreachable_foo
_wasm_backtrace_canister::__canister_method_unreachable::{{closure}}
canister_update unreachable
.
"#,
    )
}

#[test]
fn no_backtrace_without_feature() {
    let (env, canister_id) = env_with_backtrace_canister(FlagStatus::Disabled);
    let result = env
        .execute_ingress(canister_id, "unreachable", Encode!(&()).unwrap())
        .unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterTrapped,
        "Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister trapped: unreachable",
    );
    let result = std::panic::catch_unwind(|| {
        result.assert_contains(ErrorCode::CanisterTrapped, "Canister Backtrace")
    });
    assert!(result.is_err(), "Expected error, but got {:?}", result);
}

#[test]
fn oob_backtrace() {
    let (env, canister_id) = env_with_backtrace_canister(FlagStatus::Enabled);
    let result = env
        .execute_ingress(canister_id, "oob", Encode!(&()).unwrap())
        .unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterTrapped,
        r#"Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister trapped: heap out of bounds
Canister Backtrace:
_wasm_backtrace_canister::oob_foo
_wasm_backtrace_canister::__canister_method_oob::{{closure}}
canister_update oob
.
"#,
    )
}

#[test]
fn backtrace_test_ic0_trap() {
    let (env, canister_id) = env_with_backtrace_canister(FlagStatus::Enabled);
    assert!(env
        .execute_ingress(canister_id, "ic0_trap", Encode!(&()).unwrap())
        .is_err());
}
