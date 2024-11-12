use std::rc::Rc;
use std::sync::Arc;

use ic_base_types::NumSeconds;
use ic_config::flag_status::FlagStatus;
use ic_config::{embedders::Config as EmbeddersConfig, subnet_config::SchedulerConfig};
use ic_cycles_account_manager::ResourceSaturation;
use ic_embedders::wasmtime_embedder::{system_api, StoreData};
use ic_embedders::WasmtimeEmbedder;
use ic_interfaces::execution_environment::{ExecutionMode, SubnetAvailableMemory};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::page_map::TestPageAllocatorFileDescriptorImpl;
use ic_replicated_state::NumWasmPages;
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
use lazy_static::lazy_static;
use std::collections::HashMap;
use wasm_encoder::{
    EntityType, FuncType, ImportSection, Module, TypeSection, ValType as EncodedValType,
};
use wasmtime::{Engine, Extern, Store, StoreLimits, ValType};

const SUBNET_MEMORY_CAPACITY: i64 = i64::MAX / 2;

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory = SubnetAvailableMemory::new(
        SUBNET_MEMORY_CAPACITY,
        SUBNET_MEMORY_CAPACITY,
        SUBNET_MEMORY_CAPACITY
    );
}
const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);

pub(crate) fn system_api_imports() -> Vec<u8> {
    let config = EmbeddersConfig::default();
    let engine = Engine::new(&WasmtimeEmbedder::wasmtime_execution_config(&config))
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
    let sandbox_safe_system_state = SandboxSafeSystemState::new_for_testing(
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
        EmbeddersConfig::default().feature_flags.canister_backtrace,
        EmbeddersConfig::default().max_sum_exported_function_name_lengths,
        Memory::new_for_testing(),
        NumWasmPages::from(0),
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
            canister_backtrace: config.feature_flags.canister_backtrace,
        },
    );
    let mut linker: wasmtime::Linker<StoreData> = wasmtime::Linker::new(&engine);
    system_api::syscalls::<u32>(
        &mut linker,
        config.feature_flags,
        config.stable_memory_dirty_page_limit,
        config.stable_memory_accessed_page_limit,
        ic_embedders::wasm_utils::instrumentation::WasmMemoryType::Wasm32,
    );

    // to avoid store move
    let mut system_api_imports: Vec<(&str, &str, wasmtime::Func)> = vec![];
    for (module_name, item_name, item) in linker.iter(&mut store) {
        if let Extern::Func(func) = item {
            if module_name == "ic0" {
                system_api_imports.push((module_name, item_name, func));
            }
        }
    }

    let mut types = TypeSection::new();
    let mut imports = ImportSection::new();
    let mut type_mapping: HashMap<FuncType, usize> = HashMap::new();

    for (module_name, item_name, func) in system_api_imports.iter() {
        let ty = func.ty(&store);
        let mut params = vec![];
        let mut results = vec![];
        for param in ty.params() {
            params.push(vtype(param));
        }
        for result in ty.results() {
            results.push(vtype(result));
        }

        let func_type = FuncType::new(params, results);
        if !type_mapping.contains_key(&func_type) {
            type_mapping.insert(func_type.clone(), type_mapping.len());
            types.func_type(&func_type);
        }
        let func_index = type_mapping.get(&func_type).unwrap();
        imports.import(
            module_name,
            item_name,
            EntityType::Function(*func_index as u32),
        );
    }

    let mut module = Module::new();
    module.section(&types);
    module.section(&imports);
    module.finish()
}

fn vtype(valtype: ValType) -> EncodedValType {
    match valtype {
        ValType::I32 => EncodedValType::I32,
        ValType::I64 => EncodedValType::I64,
        ValType::F32 => EncodedValType::F32,
        ValType::F64 => EncodedValType::F64,
        _ => unimplemented!("Other types are not implemented yet"),
    }
}
