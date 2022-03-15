use std::sync::Arc;

use super::{system_api, StoreData, NUM_INSTRUCTION_GLOBAL_NAME};
use crate::wasm_utils::instrumentation::{instrument, InstructionCostTable};
use ic_interfaces::execution_environment::{
    AvailableMemory, ExecutionMode, ExecutionParameters, SubnetAvailableMemory,
};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{Memory, SystemState};
use ic_system_api::{
    sandbox_safe_system_state::SandboxSafeSystemState, ApiType, DefaultOutOfInstructionsHandler,
    SystemApiImpl,
};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder, types::ids::canister_test_id,
};
use ic_types::{ComputeAllocation, NumBytes, NumInstructions};
use ic_wasm_types::BinaryEncodedWasm;

use lazy_static::lazy_static;
use wasmtime::{Config, Engine, Module, Store, Val};

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        AvailableMemory::new(i64::MAX / 2, i64::MAX / 2).into();
}
const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);

#[test]
fn test_wasmtime_system_api() {
    let config = Config::default();
    let engine = Engine::new(&config).expect("Failed to initialize Wasmtime engine");
    let canister_id = canister_test_id(53);
    let system_state = SystemState::new_for_start(canister_id);
    let sandbox_safe_system_state =
        SandboxSafeSystemState::new(&system_state, CyclesAccountManagerBuilder::new().build());
    let canister_memory_limit = NumBytes::from(4 << 30);
    let canister_current_memory_usage = NumBytes::from(0);
    let system_api = SystemApiImpl::new(
        ApiType::start(),
        sandbox_safe_system_state,
        canister_current_memory_usage,
        ExecutionParameters {
            instruction_limit: MAX_NUM_INSTRUCTIONS,
            canister_memory_limit,
            subnet_available_memory: MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            compute_allocation: ComputeAllocation::default(),
            subnet_type: SubnetType::Application,
            execution_mode: ExecutionMode::Replicated,
        },
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
    let output_instrumentation = instrument(&wasm_binary, &InstructionCostTable::new()).unwrap();
    let module = Module::new(&engine, output_instrumentation.binary.as_slice())
        .expect("failed to instantiate module");

    let linker = system_api::syscalls(no_op_logger(), canister_id, &store);
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
