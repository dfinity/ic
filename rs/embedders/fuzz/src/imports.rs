use std::rc::Rc;

use crate::wasm_executor::{
    get_execution_parameters, get_system_state, MAX_SUBNET_AVAILABLE_MEMORY,
};
use ic_config::embedders::Config as EmbeddersConfig;
use ic_config::flag_status::FlagStatus;
use ic_embedders::wasm_utils::instrumentation::WasmMemoryType;
use ic_embedders::wasmtime_embedder::{system_api, StoreData};
use ic_embedders::WasmtimeEmbedder;
use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::Memory;
use ic_replicated_state::NumWasmPages;
use ic_system_api::{ApiType, DefaultOutOfInstructionsHandler, SystemApiImpl};
use ic_test_utilities_types::ids::user_test_id;
use ic_types::{time::UNIX_EPOCH, NumBytes};
use std::collections::HashMap;
use wasm_encoder::{
    EntityType, FuncType, ImportSection, Module, TypeSection, ValType as EncodedValType,
};
use wasmtime::{Engine, Extern, Store, StoreLimits, ValType};

pub(crate) fn system_api_imports() -> Vec<u8> {
    let system_api_type = WasmMemoryType::Wasm64;
    let mut config = EmbeddersConfig::default();
    config.feature_flags.write_barrier = FlagStatus::Enabled;
    config.feature_flags.wasm64 = FlagStatus::Enabled;

    let engine = Engine::new(&WasmtimeEmbedder::wasmtime_execution_config(&config))
        .expect("Failed to initialize Wasmtime engine");
    let api_type = ApiType::init(UNIX_EPOCH, vec![], user_test_id(24).get());

    let canister_current_memory_usage = NumBytes::from(0);
    let canister_current_message_memory_usage = NumBytes::from(0);
    let system_api = SystemApiImpl::new(
        api_type.clone(),
        get_system_state(api_type),
        canister_current_memory_usage,
        canister_current_message_memory_usage,
        get_execution_parameters(),
        *MAX_SUBNET_AVAILABLE_MEMORY,
        config.feature_flags.wasm_native_stable_memory,
        config.feature_flags.canister_backtrace,
        config.max_sum_exported_function_name_lengths,
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
        system_api_type,
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
