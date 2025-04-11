use ic_config::execution_environment::Config as ExecutionConfig;
use ic_management_canister_types_private::CanisterSettingsArgsBuilder;
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_types::{CanisterId, Cycles, NumBytes};

use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use wasm_fuzzers::ic_wasm::{ic_embedders_config, SystemApiModule};

thread_local! {
    static ENV_32: RefCell<(ExecutionTest, CanisterId)> = RefCell::new(setup_env(false));
    static ENV_64: RefCell<(ExecutionTest, CanisterId)> = RefCell::new(setup_env(true));
}

const HELLO_WORLD_WAT: &str = r#"
(module
    (func $hi)
    (export "canister_query hi" (func $hi))
)"#;

// To run the fuzzer,
// bazel run --config=sandbox_fuzzing //rs/execution_environment/fuzz:execute_with_wasm_executor_system_api_call

fn main() {
    let features = fuzzer_sandbox::SandboxFeatures {
        syscall_tracing: false,
    };
    fuzzer_sandbox::fuzzer_main(features);
}

fuzz_target!(|data: SystemApiModule| {
    with_env(data.memory64_enabled, |env, canister_id| {
        let wasm = data.module;
        if env.reinstall_canister(*canister_id, wasm).is_ok() {
            // For determinism, all methods are executed.
            for wasm_method in &data.exported_functions {
                let _ = env.ingress(*canister_id, wasm_method.name(), vec![]);
            }
        }
    });
});

fn with_env<F, R>(memory64_enabled: bool, f: F) -> R
where
    F: FnOnce(&mut ExecutionTest, &CanisterId) -> R,
{
    if memory64_enabled {
        ENV_64.with(|env| {
            let canister_id = env.borrow().1;
            let execution_test = &mut env.borrow_mut().0;
            f(execution_test, &canister_id)
        })
    } else {
        ENV_32.with(|env| {
            let canister_id = env.borrow().1;
            let execution_test = &mut env.borrow_mut().0;
            f(execution_test, &canister_id)
        })
    }
}

// A setup function to initialize ExecutionTest with a dummy canister and expose the cansiter_id.
// The same canister_id and ExecutionTest reference is used in the fuzzing runs, where the
// canister is reinstalled under the same canister_id.
fn setup_env(memory64_enabled: bool) -> (ExecutionTest, CanisterId) {
    let exec_config = ExecutionConfig {
        embedders_config: ic_embedders_config(memory64_enabled),
        max_compilation_cache_size: NumBytes::new(10 * 1024 * 1024), // 10MiB
        ..Default::default()
    };
    let mut env = ExecutionTestBuilder::new()
        .with_execution_config(exec_config)
        .with_precompiled_universal_canister(false)
        .build();

    let canister_id = env
        .create_canister_with_settings(
            Cycles::from(u128::MAX / 2),
            CanisterSettingsArgsBuilder::new()
                .with_wasm_memory_limit(100 * 1024 * 1024)
                .build(),
        )
        .unwrap();

    let wasm = wat::parse_str(HELLO_WORLD_WAT).unwrap();
    env.install_canister(canister_id, wasm)
        .expect("Failed to install valid wasm");
    (env, canister_id)
}
