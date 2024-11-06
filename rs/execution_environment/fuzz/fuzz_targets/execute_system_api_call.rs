use ic_canister_sandbox_backend_lib::{
    canister_sandbox_main, compiler_sandbox::compiler_sandbox_main,
    launcher::sandbox_launcher_main, RUN_AS_CANISTER_SANDBOX_FLAG, RUN_AS_COMPILER_SANDBOX_FLAG,
    RUN_AS_SANDBOX_LAUNCHER_FLAG,
};
use ic_config::{
    embedders::Config as EmbeddersConfig, embedders::FeatureFlags,
    execution_environment::Config as ExecutionConfig, flag_status::FlagStatus,
    subnet_config::SubnetConfig,
};
use ic_management_canister_types::{CanisterInstallMode, CanisterSettingsArgsBuilder};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_types::CanisterId;
use ic_types::Cycles;

use libfuzzer_sys::{fuzz_target, test_input_wrap};
use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::c_char;
use wasm_fuzzers::ic_wasm::ICWasmModule;

thread_local! {
    static ENV: RefCell<(StateMachine, CanisterId)> = RefCell::new(setup_env());
}

const HELLO_WORLD_WAT: &str = r#"
(module
    (func $hi)
    (export "canister_query hi" (func $hi))
)"#;

#[allow(improper_ctypes)]
extern "C" {
    fn LLVMFuzzerRunDriver(
        argc: *const isize,
        argv: *const *const *const u8,
        UserCb: fn(data: *const u8, size: usize) -> i32,
    ) -> i32;
}

// In general, fuzzers don't include `main()` and the initialisation logic is deferred to libfuzzer.
// However, to enable canister sandboxing, we override the initialisation by providing our own `main()`
// which acts as a dispatcher for different sandboxed under certain arguments.
//
// The default case invokes `LLVMFuzzerRunDriver` which invokes a callback with similar signature as
// `LLVMFuzzerTestOneInput`. For more details, see https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library
//
// We provide `libfuzzer_sys::test_input_wrap` as callback for `LLVMFuzzerRunDriver` since libfuzzer_sys
// already exports `LLVMFuzzerTestOneInput` and we can't override it. `test_input_wrap` internally calls
// `rust_fuzzer_test_input`, which is generated via the macro `fuzz_target!`.
// See https://github.com/rust-fuzz/libfuzzer/blob/c8275d1517933765b56a6de61a371bb1cc4268cb/src/lib.rs#L62

// To run the fuzzer,
// ASAN_OPTIONS="detect_leaks=0:allow_user_segv_handler=1:handle_segv=1:handle_sigfpe=1:handle_sigill=0"
// LSAN_OPTIONS="handle_sigill=0"
// ASAN_OPTIONS=$ASAN_OPTIONS LSAN_OPTIONS=$LSAN_OPTIONS bazel run --config=fuzzing //rs/execution_environment/fuzz:execute_with_wasm_executor_system_api_call

fn main() {
    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        #[cfg(not(fuzzing))]
        canister_sandbox_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_SANDBOX_LAUNCHER_FLAG) {
        #[cfg(not(fuzzing))]
        sandbox_launcher_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_COMPILER_SANDBOX_FLAG) {
        #[cfg(not(fuzzing))]
        compiler_sandbox_main();
    } else {
        // Collect command-line arguments
        let args: Vec<CString> = std::env::args()
            .map(|arg| CString::new(arg).unwrap())
            .collect();

        // Prepare argc as *const isize
        let argc = args.len() as isize;
        let argc: *const isize = &argc;

        // Prepare argv as *const *const *const u8
        let argv: Vec<*const c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
        let argv_ptr: *const *const u8 = argv.as_ptr() as *const *const u8;
        let argv: *const *const *const u8 = &argv_ptr;

        unsafe {
            LLVMFuzzerRunDriver(argc, argv, test_input_wrap);
        }
    }
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
        ..Default::default()
    };
    let subnet_type = SubnetType::System;
    let config = StateMachineConfig::new(SubnetConfig::new(subnet_type), exec_config);
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(subnet_type)
        .with_checkpoints_enabled(false)
        .build();
    let canister_id = env.create_canister_with_cycles(
        None,
        Cycles::from(u128::MAX / 2),
        Some(CanisterSettingsArgsBuilder::new().build()),
    );
    let wasm = wat::parse_str(HELLO_WORLD_WAT).unwrap();
    env.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, wasm, vec![])
        .expect("Failed to install valid wasm");
    (env, canister_id)
}
