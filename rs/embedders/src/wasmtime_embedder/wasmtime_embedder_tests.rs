use std::sync::Arc;

use super::{system_api, StoreData, NUM_INSTRUCTION_GLOBAL_NAME};
use crate::{wasm_utils::validate_and_instrument_for_testing, WasmtimeEmbedder};
use ic_config::flag_status::FlagStatus;
use ic_config::{embedders::Config as EmbeddersConfig, subnet_config::SchedulerConfig};
use ic_interfaces::execution_environment::{ExecutionMode, SubnetAvailableMemory};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{Memory, NetworkTopology, SystemState};
use ic_system_api::{
    sandbox_safe_system_state::SandboxSafeSystemState, ApiType, DefaultOutOfInstructionsHandler,
    ExecutionParameters, InstructionLimits, SystemApiImpl,
};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder, types::ids::canister_test_id,
};
use ic_types::{ComputeAllocation, NumBytes, NumInstructions};
use ic_wasm_types::BinaryEncodedWasm;

use lazy_static::lazy_static;
use wasmtime::{Engine, Module, Store, Val};

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        SubnetAvailableMemory::new(i64::MAX / 2, i64::MAX / 2);
}
const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);

#[test]
fn test_wasmtime_system_api() {
    let engine = Engine::new(&WasmtimeEmbedder::initial_wasmtime_config(
        &EmbeddersConfig::default(),
    ))
    .expect("Failed to initialize Wasmtime engine");
    let canister_id = canister_test_id(53);
    let system_state = SystemState::new_for_start(canister_id);
    let sandbox_safe_system_state = SandboxSafeSystemState::new(
        &system_state,
        CyclesAccountManagerBuilder::new().build(),
        &NetworkTopology::default(),
        SchedulerConfig::application_subnet().dirty_page_overhead,
    );
    let canister_memory_limit = NumBytes::from(4 << 30);
    let canister_current_memory_usage = NumBytes::from(0);
    let system_api = SystemApiImpl::new(
        ApiType::start(),
        sandbox_safe_system_state,
        canister_current_memory_usage,
        ExecutionParameters {
            instruction_limits: InstructionLimits::new(
                FlagStatus::Disabled,
                MAX_NUM_INSTRUCTIONS,
                MAX_NUM_INSTRUCTIONS,
            ),
            canister_memory_limit,
            compute_allocation: ComputeAllocation::default(),
            subnet_type: SubnetType::Application,
            execution_mode: ExecutionMode::Replicated,
        },
        *MAX_SUBNET_AVAILABLE_MEMORY,
        Memory::default(),
        Arc::new(DefaultOutOfInstructionsHandler {}),
        no_op_logger(),
    );
    let mut store = Store::new(
        &engine,
        StoreData {
            system_api,
            num_instructions_global: None,
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
        BinaryEncodedWasm::new(wabt::wat2wasm(&wat).expect("failed to compile Wasm source"));
    // Exports the global `counter_instructions`.
    let config = EmbeddersConfig::default();
    let (_, instrumentation_output) = validate_and_instrument_for_testing(
        &WasmtimeEmbedder::new(config.clone(), no_op_logger()),
        &wasm_binary,
    )
    .unwrap();
    let module = Module::new(&engine, instrumentation_output.binary.as_slice())
        .expect("failed to instantiate module");

    let linker = system_api::syscalls(
        no_op_logger(),
        canister_id,
        &store,
        FlagStatus::Enabled,
        config.stable_memory_dirty_page_limit,
    );
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("failed to instantiate instance");

    let global = instance
        .get_global(&mut store, NUM_INSTRUCTION_GLOBAL_NAME)
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
