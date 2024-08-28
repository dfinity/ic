use std::rc::Rc;
use std::sync::Arc;

use super::{system_api, StoreData, INSTRUCTIONS_COUNTER_GLOBAL_NAME};
use crate::{wasm_utils::validate_and_instrument_for_testing, WasmtimeEmbedder};
use ic_base_types::NumSeconds;
use ic_config::flag_status::FlagStatus;
use ic_config::{embedders::Config as EmbeddersConfig, subnet_config::SchedulerConfig};
use ic_cycles_account_manager::ResourceSaturation;
use ic_interfaces::execution_environment::{ExecutionMode, SubnetAvailableMemory};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::page_map::TestPageAllocatorFileDescriptorImpl;
use ic_replicated_state::{Memory, NetworkTopology, SystemState};
use ic_system_api::{
    sandbox_safe_system_state::SandboxSafeSystemState, ApiType, DefaultOutOfInstructionsHandler,
    ExecutionParameters, InstructionLimits, SystemApiImpl,
};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_types::ids::canister_test_id;
use ic_types::{
    messages::RequestMetadata, time::UNIX_EPOCH, ComputeAllocation, Cycles, MemoryAllocation,
    NumBytes, NumInstructions,
};
use ic_wasm_types::BinaryEncodedWasm;

use lazy_static::lazy_static;
use wasmtime::{Engine, Module, Store, StoreLimits, Val};

const SUBNET_MEMORY_CAPACITY: i64 = i64::MAX / 2;

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory = SubnetAvailableMemory::new(
        SUBNET_MEMORY_CAPACITY,
        SUBNET_MEMORY_CAPACITY,
        SUBNET_MEMORY_CAPACITY
    );
}
const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);

#[test]
fn test_wasmtime_system_api() {
    let engine = Engine::new(&WasmtimeEmbedder::wasmtime_execution_config(
        &EmbeddersConfig::default(),
    ))
    .expect("Failed to initialize Wasmtime engine");
    let canister_id = canister_test_id(53);
    let system_state = SystemState::new_running(
        canister_id,
        canister_id.get(),
        Cycles::zero(),
        NumSeconds::from(0),
        Arc::new(TestPageAllocatorFileDescriptorImpl),
    );
    let api_type = ApiType::start(UNIX_EPOCH);
    let sandbox_safe_system_state = SandboxSafeSystemState::new(
        &system_state,
        CyclesAccountManagerBuilder::new().build(),
        &NetworkTopology::default(),
        SchedulerConfig::application_subnet().dirty_page_overhead,
        ComputeAllocation::default(),
        RequestMetadata::new(0, UNIX_EPOCH),
        api_type.caller(),
        api_type.call_context_id(),
    );
    let canister_memory_limit = NumBytes::from(4 << 30);
    let canister_current_memory_usage = NumBytes::from(0);
    let canister_current_message_memory_usage = NumBytes::from(0);
    let system_api = SystemApiImpl::new(
        api_type,
        sandbox_safe_system_state,
        canister_current_memory_usage,
        canister_current_message_memory_usage,
        ExecutionParameters {
            instruction_limits: InstructionLimits::new(
                FlagStatus::Disabled,
                MAX_NUM_INSTRUCTIONS,
                MAX_NUM_INSTRUCTIONS,
            ),
            canister_memory_limit,
            wasm_memory_limit: None,
            memory_allocation: MemoryAllocation::default(),
            compute_allocation: ComputeAllocation::default(),
            subnet_type: SubnetType::Application,
            execution_mode: ExecutionMode::Replicated,
            subnet_memory_saturation: ResourceSaturation::default(),
        },
        *MAX_SUBNET_AVAILABLE_MEMORY,
        EmbeddersConfig::default()
            .feature_flags
            .wasm_native_stable_memory,
        EmbeddersConfig::default().max_sum_exported_function_name_lengths,
        Memory::new_for_testing(),
        Rc::new(DefaultOutOfInstructionsHandler::default()),
        no_op_logger(),
    );
    let mut store = Store::new(
        &engine,
        StoreData {
            system_api: Some(system_api),
            num_instructions_global: None,
            log: no_op_logger(),
            num_stable_dirty_pages_from_non_native_writes: ic_types::NumOsPages::from(0),
            limits: StoreLimits::default(),
        },
    );

    let wat = r#"
    (module
      (import "ic0" "debug_print" (func $debug_print (param i32) (param i32)))

      (func $test
        (call $debug_print (i32.const 5) (i32.const 3)))

      (memory $memory 1)
      (export "memory" (memory $memory))
      (export "test" (func $test))
      (data (i32.const 5) "Hi!")
    )"#;
    let wasm_binary =
        BinaryEncodedWasm::new(wat::parse_str(wat).expect("failed to compile Wasm source"));
    // Exports the global `counter_instructions`.
    let config = EmbeddersConfig::default();
    let (_, instrumentation_output) = validate_and_instrument_for_testing(
        &WasmtimeEmbedder::new(config.clone(), no_op_logger()),
        &wasm_binary,
    )
    .unwrap();
    let module = Module::new(&engine, instrumentation_output.binary.as_slice())
        .expect("failed to instantiate module");

    let mut linker: wasmtime::Linker<StoreData> = wasmtime::Linker::new(&engine);

    system_api::syscalls::<u32>(
        &mut linker,
        config.feature_flags,
        config.stable_memory_dirty_page_limit,
        config.stable_memory_accessed_page_limit,
        crate::wasmtime_embedder::WasmMemoryType::Wasm32,
    );
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("failed to instantiate instance");

    let global = instance
        .get_global(&mut store, INSTRUCTIONS_COUNTER_GLOBAL_NAME)
        .unwrap();
    store.data_mut().num_instructions_global = Some(global);
    global
        .set(&mut store, Val::I64(MAX_NUM_INSTRUCTIONS.get() as i64))
        .expect("Failed to set global");

    instance
        .get_export(&mut store, "test")
        .expect("export not found")
        .into_func()
        .expect("export is not a function")
        .call(&mut store, &[], &mut [])
        .expect("call failed");
}

#[test]
fn test_initial_wasmtime_config() {
    // The following proposals should be disabled: tail_call, simd, relaxed_simd,
    // threads, multi_memory, exceptions, memory64, extended_const, component_model,
    // function_references, memory_control, gc
    for (proposal, _url, wat, expected_err_msg) in [
        (
            "tail_call",
            "https://github.com/WebAssembly/tail-call/",
            "(module (func $f1 return_call $f2) (func $f2))",
            "tail calls support is not enabled",
        ),
        (
            "relaxed_simd",
            "https://github.com/WebAssembly/relaxed-simd/",
            "(module (func $f (param v128) (drop (f64x2.relaxed_madd (local.get 0) (local.get 0) (local.get 0)))))",
            "relaxed SIMD support is not enabled",
        ),
        (
            "threads",
            "https://github.com/WebAssembly/threads/",
            r#"(module (import "env" "memory" (memory 1 1 shared)))"#,
            "threads must be enabled",
        ),
        (
            "multi_memory",
            "https://github.com/WebAssembly/multi-memory/",
            "(module (memory $m1 1 1) (memory $m2 1 1))",
            "failed with multiple memories",
        ),
        // Exceptions
        (
            "memory64",
            "https://github.com/WebAssembly/memory64/",
            "(module (memory $m i64 1 1))",
            "memory64 must be enabled",
        ),
        (
            "extended_const",
            "https://github.com/WebAssembly/extended-const/",
            "(module (global i32 (i32.add (i32.const 0) (i32.const 0))))",
            "constant expression required",
        ),
        (
            "component_model",
            "https://github.com/WebAssembly/component-model/",
            "(component (core module (func $f)))",
            "component model feature is not enabled",
        ),
        (
            "function_references",
            "https://github.com/WebAssembly/function-references/",
            "(module (type $t (func (param i32))) (func $fn (param $f (ref $t))))",
            "function references required for index reference types",
        ),
        // Memory control
        // GC
    ] {
        let wasm_binary = BinaryEncodedWasm::new(wat::parse_str(wat).unwrap_or_else(|err| {
            panic!("Error parsing proposal `{proposal}` code snippet: {err}")
        }));
        let err = validate_and_instrument_for_testing(
            &WasmtimeEmbedder::new(EmbeddersConfig::default(), no_op_logger()),
            &wasm_binary,
        )
        .err()
        .unwrap_or_else(|| {
            panic!("Error having `{proposal}` proposal enabled in the `wasmtime` config.")
        });
        // Format error message with cause using '{:?}'
        let err_msg = format!("{:?}", err);
        // Make sure the error is because of the feature being disabled.
        assert!(
            err_msg.contains(expected_err_msg),
            "Error expecting `{expected_err_msg}`, but got `{err_msg}`"
        );
    }
}
