use super::system_api;
use ic_interfaces::execution_environment::SubnetAvailableMemory;
use ic_replicated_state::SystemState;
use ic_system_api::{ApiType, SystemApiImpl};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder, types::ids::canister_test_id,
};
use ic_types::{ComputeAllocation, NumBytes, NumInstructions};
use lazy_static::lazy_static;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use wasmtime::{Config, Engine, Module, Store};

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        SubnetAvailableMemory::new(NumBytes::new(std::u64::MAX));
}

#[test]
fn test_wasmtime_system_api() {
    let config = Config::default();
    let engine = Engine::new(&config);
    let store = Store::new(&engine);
    let system_api_handle = system_api::SystemApiHandle::new();
    let max_num_instructions = NumInstructions::new(1_000_000_000);
    let canister_memory_limit = NumBytes::from(4 << 30);
    let canister_current_memory_usage = NumBytes::from(0);

    let system_state = SystemState::new_for_start(canister_test_id(53));
    let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
    let system_state_accessor =
        ic_system_api::SystemStateAccessorDirect::new(system_state, cycles_account_manager);
    let mut system_api = SystemApiImpl::new(
        ApiType::start(),
        system_state_accessor,
        max_num_instructions,
        canister_memory_limit,
        canister_current_memory_usage,
        MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        ComputeAllocation::default(),
        ic_test_utilities::system_api::dummy_pause_handler(),
    );
    system_api_handle.replace(&mut system_api);
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
    let wasm_binary = wabt::wat2wasm(wat).expect("failed to compile Wasm source");
    let module =
        Module::new(&engine, wasm_binary.as_slice()).expect("failed to instantiate module");
    let cycles_glob = Rc::new(RefCell::new(None));
    let linker = system_api::syscalls(&store, system_api_handle, Rc::downgrade(&cycles_glob));
    let instance = linker
        .instantiate(&module)
        .expect("failed to instantiate instance");
    instance
        .get_export("test")
        .expect("export not found")
        .into_func()
        .expect("export is not a function")
        .call(&[])
        .expect("call failed");
}
