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
_wasm_backtrace_canister::unreachable::inner_2
_wasm_backtrace_canister::unreachable::inner
_wasm_backtrace_canister::unreachable::outer
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
_wasm_backtrace_canister::oob::inner_2
_wasm_backtrace_canister::oob::inner
_wasm_backtrace_canister::oob::outer
canister_update oob
."#,
    )
}

#[test]
fn backtrace_test_ic0_trap() {
    let (env, canister_id) = env_with_backtrace_canister(FlagStatus::Enabled);
    let result = env
        .execute_ingress(canister_id, "ic0_trap", Encode!(&()).unwrap())
        .unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterCalledTrap,
        r#"Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister called `ic0.trap` with message: Panicked at 'uh oh', rs/rust_canisters/backtrace_canister/src/main.rs:47:5
Canister Backtrace:
ic_cdk::api::trap
ic_cdk::printer::set_panic_hook::{{closure}}
std::panicking::rust_panic_with_hook
std::panicking::begin_panic_handler::{{closure}}
std::sys_common::backtrace::__rust_end_short_backtrace
rust_begin_unwind
core::panicking::panic_fmt
_wasm_backtrace_canister::ic0_trap::inner_2
_wasm_backtrace_canister::ic0_trap::inner
_wasm_backtrace_canister::ic0_trap::outer
_wasm_backtrace_canister::__canister_method_ic0_trap::{{closure}}
canister_update ic0_trap
.
"#,
    )
}

#[test]
fn backtrace_test_stable_oob() {
    let (env, canister_id) = env_with_backtrace_canister(true);
    let result = env
        .execute_ingress(canister_id, "stable_oob", Encode!(&()).unwrap())
        .unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterTrapped,
        r#"Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister trapped: stable memory out of bounds
Canister Backtrace:
ic0::ic0::stable_write
_wasm_backtrace_canister::stable_oob::inner_2
_wasm_backtrace_canister::stable_oob::inner
_wasm_backtrace_canister::stable_oob::outer
canister_update stable_oob
.
"#,
    )
}
