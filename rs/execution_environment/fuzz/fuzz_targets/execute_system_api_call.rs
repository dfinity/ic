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
use libfuzzer_sys::test_input_wrap;
use std::cell::RefCell;
use wasm_fuzzers::ic_wasm::ICWasmModule;

use arbitrary::{Arbitrary, Unstructured};
use std::env;
use std::ffi::CString;
use std::os::raw::c_char;

#[allow(improper_ctypes)]
extern "C" {
    fn LLVMFuzzerRunDriver(
        argc: *const isize,
        argv: *const *const *const u8,
        UserCb: fn(data: *const u8, size: usize) -> i32,
    ) -> i32;
}

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
        .no_dts() // Disable DTS to avoid sandbox_launcher binary dependency (which does not work well with fuzz tests).
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

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn rust_fuzzer_test_input(bytes: &[u8]) -> i32 {
    if bytes.len() < <ICWasmModule as Arbitrary>::size_hint(0).0 {
        return -1;
    }

    let u = Unstructured::new(bytes);
    let data = <ICWasmModule as Arbitrary>::arbitrary_take_rest(u);

    let data = match data {
        Ok(d) => d,
        Err(_) => return -1,
    };

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

    0
}

fn main() {
    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        canister_sandbox_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_SANDBOX_LAUNCHER_FLAG) {
        sandbox_launcher_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_COMPILER_SANDBOX_FLAG) {
        compiler_sandbox_main();
    } else {
        // Collect command-line arguments
        let args: Vec<CString> = env::args().map(|arg| CString::new(arg).unwrap()).collect();

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
