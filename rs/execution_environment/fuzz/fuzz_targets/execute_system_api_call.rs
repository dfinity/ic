#![no_main]
use ic_management_canister_types::{CanisterInstallMode, CanisterSettingsArgsBuilder};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{CanisterId, StateMachine, StateMachineBuilder};
use ic_types::Cycles;
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use wasm_fuzzers::ic_wasm::ICWasmModule;

thread_local! {
    static ENV: RefCell<(StateMachine, CanisterId)> = RefCell::new(setup_env());
}

fn with_env<F, R>(f: F) -> R
where
    F: FnOnce(&StateMachine, &CanisterId) -> R,
{
    ENV.with(|env| {
        let env_ref = env.borrow();
        f(&env_ref.0, &env_ref.1) // Pass references to the closure
    })
}

const HELLO_WORLD_WAT: &str = r#"
(module
    (func $hi)
    (export "canister_query hi" (func $hi))
)"#;

fn setup_env() -> (StateMachine, CanisterId) {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .no_dts() // Disable DTS to avoid sandbox_launcher binary dependency (which does not work well with fuzz tests).
        .with_checkpoints_enabled(false)
        .build();
    let canister_id = env.create_canister_with_cycles(
        None,
        Cycles::from(100_000_000_000_u128),
        Some(CanisterSettingsArgsBuilder::new().build()),
    );
    let wasm = wat::parse_str(HELLO_WORLD_WAT).unwrap();
    env.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, wasm, vec![])
        .unwrap();
    (env, canister_id)
}

// This fuzz tries to execute system API call.
//
// The fuzz test is only compiled but not executed by CI.
//
// To execute the fuzzer run
// bazel run --config=fuzzing //rs/execution_environment/fuzz:execute_system_api_call

fuzz_target!(|module: ICWasmModule| {
    let wasm = module.module.to_bytes();

    with_env(|env, canister_id| {
        env.install_wasm_in_mode(*canister_id, CanisterInstallMode::Reinstall, wasm, vec![])
            .unwrap();

        // For determinism, all methods are executed
        for wasm_method in module.exported_functions.iter() {
            let _ = env.execute_ingress(*canister_id, wasm_method.name(), vec![]);
        }
    });
});
