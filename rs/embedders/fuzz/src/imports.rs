use std::rc::Rc;

use crate::wasm_executor::{
    MAX_SUBNET_AVAILABLE_MEMORY, get_execution_parameters, get_system_state,
};
use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::{
    wasm_utils::instrumentation::WasmMemoryType,
    wasmtime_embedder::{
        StoreData, WasmtimeEmbedder, linker,
        system_api::{ApiType, DefaultOutOfInstructionsHandler, SystemApiImpl},
    },
};
use ic_interfaces::execution_environment::MessageMemoryUsage;
use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::{Memory, NumWasmPages};
use ic_test_utilities_types::ids::user_test_id;
use ic_types::{NumBytes, time::UNIX_EPOCH};
use std::collections::{BTreeMap, HashMap};
use wasm_encoder::{
    EntityType, FuncType, ImportSection, Module, TypeSection, ValType as EncodedValType,
};
use wasmtime::{Engine, Extern, Store, StoreLimits, ValType};

pub struct SystemApiImportStore {
    pub module: Vec<u8>,
    pub type_section: TypeSection,
    pub import_section: ImportSection,
    pub import_mapping: BTreeMap<usize, FuncType>,
}

pub(crate) fn system_api_imports(config: EmbeddersConfig) -> SystemApiImportStore {
    let engine = Engine::new(&WasmtimeEmbedder::wasmtime_execution_config(&config))
        .expect("Failed to initialize Wasmtime engine");
    let api_type = ApiType::init(UNIX_EPOCH, vec![], user_test_id(24).get());

    let canister_current_memory_usage = NumBytes::from(0);
    let canister_current_message_memory_usage = MessageMemoryUsage::ZERO;
    let system_api = SystemApiImpl::new(
        api_type.clone(),
        get_system_state(api_type),
        canister_current_memory_usage,
        canister_current_message_memory_usage,
        get_execution_parameters(),
        *MAX_SUBNET_AVAILABLE_MEMORY,
        &config,
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
            limits: StoreLimits::default(),
            canister_backtrace: config.feature_flags.canister_backtrace,
        },
    );
    let mut linker: wasmtime::Linker<StoreData> = wasmtime::Linker::new(&engine);

    linker::syscalls::<u64>(
        &mut linker,
        config.feature_flags,
        config.stable_memory_dirty_page_limit,
        config.stable_memory_accessed_page_limit,
        WasmMemoryType::Wasm64,
    );

    // to avoid store move
    let mut system_api_imports: Vec<(&str, &str, wasmtime::Func)> = linker
        .iter(&mut store)
        .filter(|(module_name, _, item)| *module_name == "ic0" && matches!(item, Extern::Func(_)))
        .map(|(module_name, item_name, item)| (module_name, item_name, item.into_func().unwrap()))
        .collect();
    system_api_imports.sort_by(|a, b| a.1.cmp(b.1));

    let mut types = TypeSection::new();
    let mut imports = ImportSection::new();
    let mut type_mapping: HashMap<FuncType, usize> = HashMap::new();
    let mut import_mapping: BTreeMap<usize, FuncType> = BTreeMap::new();

    // Inject type () -> ()
    let params = vec![];
    let results = vec![];
    types.ty().function(params.clone(), results.clone());
    type_mapping.insert(FuncType::new(params, results), 0);

    for (index, (module_name, item_name, func)) in system_api_imports.iter().enumerate() {
        let ty = func.ty(&store);
        let params: Vec<EncodedValType> = ty.params().map(vtype).collect();
        let results: Vec<EncodedValType> = ty.results().map(vtype).collect();
        let func_type = FuncType::new(params, results);
        if !type_mapping.contains_key(&func_type) {
            type_mapping.insert(func_type.clone(), type_mapping.len());
            types.ty().func_type(&func_type);
        }
        let func_index = type_mapping.get(&func_type).unwrap();
        imports.import(
            module_name,
            item_name,
            EntityType::Function(*func_index as u32),
        );
        import_mapping.insert(index, func_type);
    }

    let mut module = Module::new();
    module.section(&types);
    module.section(&imports);

    SystemApiImportStore {
        module: module.finish(),
        type_section: types,
        import_section: imports,
        import_mapping,
    }
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
