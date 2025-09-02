use ic_config::{
    embedders::Config as EmbeddersConfig, execution_environment::Config as ExecutionConfig,
};
use ic_management_canister_types_private::CanisterSettingsArgsBuilder;
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_types::{CanisterId, Cycles, NumBytes};

use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use wasm_fuzzers::ic_wasm::ICWasmModule;

thread_local! {
    static ENV: RefCell<(ExecutionTest, CanisterId)> = RefCell::new(setup_env());
}

// r#"
// (module
//     (func $hi)
//     (export "canister_query hi" (func $hi))
// )"#;
const HELLO_WORLD_WAT: [u8; 61] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02,
    0x01, 0x00, 0x07, 0x15, 0x01, 0x11, 0x63, 0x61, 0x6E, 0x69, 0x73, 0x74, 0x65, 0x72, 0x5F, 0x71,
    0x75, 0x65, 0x72, 0x79, 0x20, 0x68, 0x69, 0x00, 0x00, 0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B, 0x00,
    0x0C, 0x04, 0x6E, 0x61, 0x6D, 0x65, 0x01, 0x05, 0x01, 0x00, 0x02, 0x68, 0x69,
];

// To run the fuzzer,
// bazel run --config=sandbox_fuzzing //rs/execution_environment/fuzz:execute_with_wasm_executor_system_api_call

fn main() {
    let features = fuzzer_sandbox::SandboxFeatures {
        syscall_tracing: true,
    };
    fuzzer_sandbox::fuzzer_main(features);
}

fuzz_target!(|data: ICWasmModule| {
    ENV.with(|env| {
        let canister_id = env.borrow().1;
        let execution_test = &mut env.borrow_mut().0;
        let wasm = data.module.to_bytes();
        if execution_test.reinstall_canister(canister_id, wasm).is_ok() {
            // For determinism, all methods are executed.
            for wasm_method in &data.exported_functions {
                let _ = execution_test.ingress(canister_id, wasm_method.name(), vec![]);
            }
        }
    });
});

// A setup function to initialize ExecutionTest with a dummy canister and expose the canister_id.
// The same canister_id and ExecutionTest reference is used in the fuzzing runs, where the
// canister is reinstalled under the same canister_id.
fn setup_env() -> (ExecutionTest, CanisterId) {
    let exec_config = ExecutionConfig {
        embedders_config: EmbeddersConfig::default(),
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

    env.install_canister(canister_id, HELLO_WORLD_WAT.to_vec())
        .expect("Failed to install valid wasm");
    (env, canister_id)
}
