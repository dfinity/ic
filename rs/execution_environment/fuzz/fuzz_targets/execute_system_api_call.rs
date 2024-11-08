use ic_config::{
    embedders::Config as EmbeddersConfig, embedders::FeatureFlags,
    execution_environment::Config as ExecutionConfig, flag_status::FlagStatus,
    subnet_config::SubnetConfig,
};
use ic_management_canister_types::{CanisterInstallMode, CanisterSettingsArgsBuilder};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_types::{CanisterId, Cycles, NumBytes};

use libfuzzer_sys::fuzz_target;
use slog::Level;
use std::cell::RefCell;
use wasm_fuzzers::ic_wasm::ICWasmModule;

thread_local! {
    static ENV: RefCell<(StateMachine, CanisterId)> = RefCell::new(setup_env());
}

const HELLO_WORLD_WAT: &str = r#"
(module
    (func $hi)
    (export "canister_query hi" (func $hi))
)"#;

// To run the fuzzer,
// ASAN_OPTIONS="detect_leaks=0:allow_user_segv_handler=1:handle_segv=1:handle_sigfpe=1:handle_sigill=0:quarantine_size_mb=16"
// LSAN_OPTIONS="handle_sigill=0"
// ASAN_OPTIONS=$ASAN_OPTIONS LSAN_OPTIONS=$LSAN_OPTIONS bazel run --config=fuzzing //rs/execution_environment/fuzz:execute_with_wasm_executor_system_api_call

fn main() {
    fuzzer_sandbox::fuzzer_main();
}

fuzz_target!(|data: ICWasmModule| {
    with_env(|env, canister_id| {
        let wasm = data.module.to_bytes();
        if env
            .install_wasm_in_mode(*canister_id, CanisterInstallMode::Reinstall, wasm, vec![])
            .is_ok()
        {
            // For determinism, all methods are executed.
            for wasm_method in &data.exported_functions {
                let _ = env.execute_ingress(*canister_id, wasm_method.name(), vec![]);
            }
        }
    });
});

fn with_env<F, R>(f: F) -> R
where
    F: FnOnce(&StateMachine, &CanisterId) -> R,
{
    ENV.with(|env| {
        let env_ref = env.borrow();
        f(&env_ref.0, &env_ref.1) // Pass references to the closure
    })
}

// A setup function to initialize StateMachine with a dummy canister and expose the cansiter_id.
// The same canister_id and StateMachine reference is used in the fuzzing runs, where the
// canister is reinstalled under the same canister_id
fn setup_env() -> (StateMachine, CanisterId) {
    let exec_config = ExecutionConfig {
        embedders_config: EmbeddersConfig {
            feature_flags: FeatureFlags {
                write_barrier: FlagStatus::Enabled,
                wasm64: FlagStatus::Enabled, // Enable wasm64 to match generated ICWasmModule.
                ..Default::default()
            },
            ..Default::default()
        },
        max_compilation_cache_size: NumBytes::new(10 * 1024 * 1024), // 10MiB
        ..Default::default()
    };
    let subnet_type = SubnetType::System;
    let config = StateMachineConfig::new(SubnetConfig::new(subnet_type), exec_config);
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(subnet_type)
        .with_checkpoints_enabled(false)
        .with_log_level(Some(Level::Critical))
        .build();
    let canister_id = env.create_canister_with_cycles(
        None,
        Cycles::from(u128::MAX / 2),
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_wasm_memory_limit(100 * 1024 * 1024)
                .build(),
        ),
    );
    let wasm = wat::parse_str(HELLO_WORLD_WAT).unwrap();
    env.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, wasm, vec![])
        .expect("Failed to install valid wasm");
    (env, canister_id)
}
