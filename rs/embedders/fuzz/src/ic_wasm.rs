use crate::imports::{SystemApiImportStore, system_api_imports};
use crate::special_int::SpecialInt;
use arbitrary::{Arbitrary, Result, Unstructured};
use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::wasm_utils::validation::{
    RESERVED_SYMBOLS, WASM_FUNCTION_SIZE_LIMIT, WASM_VALID_SYSTEM_FUNCTIONS,
};
use ic_management_canister_types_private::Global;
use ic_types::methods::WasmMethod;
use lazy_static::lazy_static;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fmt::Write;
use wasm_encoder::{
    CodeSection, ExportKind, ExportSection, Function, FunctionSection, GlobalSection, GlobalType,
    Instruction, MemorySection, MemoryType, Module as WasmModule, TypeSection,
    ValType as EncodedValType,
};
use wasm_smith::{Config, Module};
use wasmparser::*;

lazy_static! {
    static ref SYSTEM_API_IMPORTS_WASM32: SystemApiImportStore =
        system_api_imports(EmbeddersConfig::default());
    static ref SYSTEM_API_IMPORTS_WASM64: SystemApiImportStore =
        system_api_imports(EmbeddersConfig::default());
}

const CANISTER_EXPORT_FUNCTION_PREFIX: &[&str] = &[
    "canister_query",
    "canister_update",
    "canister_composite_query",
];

#[derive(Debug)]
pub struct ICWasmModule {
    pub module: Module,
    // TODO: Create a config for fuzzing
    // for clippy to not complain.
    #[allow(dead_code)]
    pub config: Config,
    #[allow(dead_code)]
    pub exported_globals: Vec<Global>,
    #[allow(dead_code)]
    pub exported_functions: BTreeSet<WasmMethod>,
}

impl<'a> Arbitrary<'a> for ICWasmModule {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let embedder_config = EmbeddersConfig::default();
        let exports = generate_exports(embedder_config.clone(), u)?;
        let is_wasm64 = u.ratio(2, 3)?;
        let mut config = ic_wasm_config(embedder_config, is_wasm64);
        config.exports = exports;
        Ok(ICWasmModule::new(config.clone(), Module::new(config, u)?))
    }
}

#[derive(Debug)]
pub struct SystemApiModule {
    pub module: Vec<u8>,
    pub is_wasm64: bool,
    pub exported_functions: BTreeSet<WasmMethod>,
}

impl<'a> Arbitrary<'a> for SystemApiModule {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        const FUNCTIONS: usize = 2;
        const SYSTEM_API_PER_FUNCTION: usize = 20;

        // memory pages are bound to 100
        let memory_minimum = u.int_in_range(0..=50)?;
        let memory_maximum = u.int_in_range(memory_minimum..=100)?;
        let is_wasm64 = u.ratio(2, 3)?;

        let store: &'static SystemApiImportStore = if is_wasm64 {
            &SYSTEM_API_IMPORTS_WASM64
        } else {
            &SYSTEM_API_IMPORTS_WASM32
        };

        let mut module = WasmModule::new();

        module.section(&store.type_section);
        module.section(&store.import_section);

        let mut functions = FunctionSection::new();
        for _ in 0..FUNCTIONS {
            functions.function(0);
        }
        module.section(&functions);

        let mut memories = MemorySection::new();
        memories.memory(MemoryType {
            minimum: memory_minimum,
            maximum: Some(memory_maximum),
            memory64: is_wasm64,
            shared: false,
            page_size_log2: None,
        });
        module.section(&memories);

        // Export section
        let mut exports = ExportSection::new();
        let choice = u.choose_index(CANISTER_EXPORT_FUNCTION_PREFIX.len())?;
        let name = format!("{} test", CANISTER_EXPORT_FUNCTION_PREFIX[choice]);
        exports.export(name.as_str(), ExportKind::Func, store.import_section.len());

        let choice = u.choose_index(WASM_VALID_SYSTEM_FUNCTIONS.len())?;
        exports.export(
            WASM_VALID_SYSTEM_FUNCTIONS[choice],
            ExportKind::Func,
            store.import_section.len() + 1,
        );

        module.section(&exports);

        let mut codes = CodeSection::new();
        assert!(store.import_section.len() == store.import_mapping.len() as u32);
        for _ in 0..FUNCTIONS {
            let mut function = Function::new(vec![]);
            for _ in 0..SYSTEM_API_PER_FUNCTION {
                let call_index = u.int_in_range(0..=(store.import_section.len() - 1))?;
                let func_type = store.import_mapping.get(&(call_index as usize)).unwrap();

                for param in func_type.params() {
                    let instruction = match param {
                        EncodedValType::I32 => {
                            Instruction::I32Const(SpecialInt::<i32>::arbitrary(u)?.0)
                        }
                        EncodedValType::I64 => {
                            Instruction::I64Const(SpecialInt::<i64>::arbitrary(u)?.0)
                        }
                        _ => unimplemented!(),
                    };
                    function.instruction(&instruction);
                }
                function.instruction(&Instruction::Call(call_index));
                for _result in func_type.results() {
                    function.instruction(&Instruction::Drop);
                }
            }
            function.instruction(&Instruction::End);
            codes.function(&function);
        }

        module.section(&codes);

        let wasm_bytes = module.finish();

        assert!(wasmparser::validate(&wasm_bytes).is_ok());
        let wasm_method = WasmMethod::try_from(name.to_string()).unwrap();

        Ok(SystemApiModule {
            module: wasm_bytes,
            is_wasm64,
            exported_functions: BTreeSet::from([wasm_method]),
        })
    }
}

impl ICWasmModule {
    fn new(config: Config, module: Module) -> Self {
        let module_bytes = module.to_bytes();
        let mut wasm_methods: BTreeSet<WasmMethod> = BTreeSet::new();
        let mut exported_globals_index: Vec<u32> = vec![];
        let mut global_section: Vec<wasmparser::Global> = vec![];
        let mut persisted_globals: Vec<Global> = vec![];

        for payload in wasmparser::Parser::new(0).parse_all(&module_bytes) {
            match payload.expect("Failed to parse wasm-smith generated module") {
                wasmparser::Payload::ExportSection(export_reader) => {
                    for export in export_reader.into_iter() {
                        let export = export.expect("Failed to read export");
                        match export.kind {
                            ExternalKind::Func => {
                                let func_name = export.name;
                                if let Ok(wasm_method) = WasmMethod::try_from(func_name.to_string())
                                {
                                    match wasm_method {
                                        WasmMethod::Query(_)
                                        | WasmMethod::CompositeQuery(_)
                                        | WasmMethod::Update(_) => {
                                            wasm_methods.insert(wasm_method);
                                        }
                                        _ => (),
                                    }
                                }
                            }
                            ExternalKind::Global => {
                                exported_globals_index.push(export.index);
                            }
                            _ => (),
                        }
                    }
                }
                wasmparser::Payload::GlobalSection(global_reader) => {
                    for global in global_reader.into_iter() {
                        // Temporarily collect globals since we need the exported
                        // index of globals to construct the persisted globals
                        global_section.push(global.expect("Failed to read global"));
                    }
                }
                _ => (),
            }
        }
        for index in &exported_globals_index {
            if let Some(global) =
                get_persisted_global(global_section.get(*index as usize).unwrap().clone())
            {
                persisted_globals.push(global);
            }
        }

        persisted_globals.extend(
            global_section
                .iter()
                .enumerate()
                .filter(|(i, _)| !exported_globals_index.contains(&(*i as u32)))
                .filter(|(_, global)| global.ty.mutable)
                .filter_map(|(_, global)| get_persisted_global(global.clone()))
                .collect::<Vec<Global>>(),
        );

        // An extra global is added for instruction counter.
        // On the exporting logic, two other globals must be exported
        // but they are not persisted across ExecutionState.
        // const TO_IGNORE: &[&str] = &[
        //     DIRTY_PAGES_COUNTER_GLOBAL_NAME,
        //     ACCESSED_PAGES_COUNTER_GLOBAL_NAME,
        // ];
        //
        // Instruction counter shouldn't be persisted as well since
        // it's overwritten with instruction limit every round.
        // However, this is currently not done in the embedders library
        // and we have to persist it to pass a validation check.
        // It can be removed once instruction counter isn't persisted
        // in our library.
        persisted_globals.push(Global::I64(i64::MAX));

        Self {
            config,
            module,
            exported_globals: persisted_globals,
            exported_functions: wasm_methods,
        }
    }
}

pub fn ic_wasm_config(embedder_config: EmbeddersConfig, is_wasm64: bool) -> Config {
    Config {
        min_funcs: 10,
        min_exports: 10,
        max_globals: embedder_config.max_globals,
        max_funcs: embedder_config.max_functions,
        max_instructions: WASM_FUNCTION_SIZE_LIMIT,

        min_data_segments: 2,
        max_data_segments: 10,

        allow_start_export: true,
        export_everything: true,
        generate_custom_sections: true,
        bulk_memory_enabled: true,
        reference_types_enabled: true,
        simd_enabled: true,
        memory64_enabled: is_wasm64,

        threads_enabled: false,
        relaxed_simd_enabled: false,
        canonicalize_nans: false,
        exceptions_enabled: false,

        available_imports: Some(if is_wasm64 {
            SYSTEM_API_IMPORTS_WASM64.module.to_vec()
        } else {
            SYSTEM_API_IMPORTS_WASM32.module.to_vec()
        }),
        ..Default::default()
    }
}

fn get_persisted_global(g: wasmparser::Global) -> Option<Global> {
    match (
        g.ty.content_type,
        g.init_expr
            .get_operators_reader()
            .read()
            .expect("Unable to read operator for ConstExpr"),
    ) {
        (ValType::I32, Operator::I32Const { value }) => Some(Global::I32(value)),
        (ValType::I64, Operator::I64Const { value }) => Some(Global::I64(value)),
        (ValType::F32, Operator::F32Const { value }) => {
            Some(Global::F32(f32::from_bits(value.bits())))
        }
        (ValType::F64, Operator::F64Const { value }) => {
            Some(Global::F64(f64::from_bits(value.bits())))
        }
        (ValType::V128, Operator::V128Const { value }) => {
            Some(Global::V128(u128::from_le_bytes(*value.bytes())))
        }
        (_, _) => None,
    }
}

pub fn generate_exports(
    embedder_config: EmbeddersConfig,
    u: &mut Unstructured,
) -> Result<Option<Vec<u8>>> {
    let mut module = WasmModule::new();

    // Type section
    // Inject type () -> ()
    let mut types = TypeSection::new();
    let params = vec![];
    let results = vec![];
    types.ty().function(params, results);
    module.section(&types);
    let type_index = 0;

    // Function Section
    let mut exported_names: HashSet<String> = HashSet::new();
    let export_func_count = u.int_in_range(10..=embedder_config.max_number_exported_functions)?;
    let mut functions = FunctionSection::new();
    for _ in 0..export_func_count {
        functions.function(type_index);
    }
    module.section(&functions);

    // Global Section (dummy values)
    let global_export_count = u.int_in_range(10..=embedder_config.max_globals)?;
    let mut globals = GlobalSection::new();
    for _ in 0..global_export_count {
        globals.global(
            GlobalType {
                val_type: wasm_encoder::ValType::I32,
                mutable: u.ratio(2, 3)?,
                shared: false,
            },
            &wasm_encoder::ConstExpr::i32_const(0_i32),
        );
    }
    module.section(&globals);

    // Export Section
    let mut exports = ExportSection::new();
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    for i in 0..global_export_count {
        let name = unique_string(1_000, &mut exported_names, u)?;
        exports.export(name.as_str(), ExportKind::Global, i as u32);
    }
    for i in 0..export_func_count {
        let name = export_name(u, &mut exported_names, &mut visited)?;
        exports.export(name.as_str(), ExportKind::Func, i as u32);
    }
    module.section(&exports);

    // Code Section (dummy values)
    let mut codes = CodeSection::new();
    let mut function = Function::new(vec![]);
    function.instruction(&Instruction::End);
    for _ in 0..export_func_count {
        codes.function(&function);
    }
    module.section(&codes);

    let wasm_bytes = module.finish();
    assert!(wasmparser::validate(&wasm_bytes).is_ok());
    Ok(Some(wasm_bytes))
}

fn export_name(
    u: &mut Unstructured,
    exported_names: &mut HashSet<String>,
    visited: &mut BTreeSet<usize>,
) -> Result<String> {
    let mut name = unique_string(1_000, exported_names, u)?;
    if u.ratio(1, 2)? && WASM_VALID_SYSTEM_FUNCTIONS.len() != visited.len() {
        let index_choice: Vec<usize> = (0..WASM_VALID_SYSTEM_FUNCTIONS.len())
            .filter(|index| !visited.contains(index))
            .collect();
        let choice = u.choose(&index_choice)?;
        visited.insert(*choice);
        return Ok(WASM_VALID_SYSTEM_FUNCTIONS[*choice].to_string());
    }

    let choice = u.choose_index(CANISTER_EXPORT_FUNCTION_PREFIX.len())?;
    name = format!("{} {}", CANISTER_EXPORT_FUNCTION_PREFIX[choice], name);
    exported_names.insert(name.clone());

    Ok(name)
}

// Functions below are duplicated from wasm-smith

fn unique_string(
    max_size: usize,
    names: &mut HashSet<String>,
    u: &mut Unstructured,
) -> Result<String> {
    let disallowed_export_func: Vec<String> = RESERVED_SYMBOLS
        .iter()
        .map(|name| name.to_string())
        .collect();
    let disallowed_export_func_prefix: Vec<String> =
        vec!["canister_".to_string(), "canister".to_string()];
    let mut name = limited_string(max_size, u)?;
    for prefix in disallowed_export_func_prefix.iter() {
        name = name.replace(prefix, "");
    }
    while names.contains(&name) || disallowed_export_func.contains(&name) {
        write!(&mut name, "{}", names.len()).unwrap();
    }
    names.insert(name.clone());
    Ok(name)
}

fn limited_string(max_size: usize, u: &mut Unstructured) -> Result<String> {
    Ok(limited_str(max_size, u)?.into())
}

// Mirror what happens in `Arbitrary for String`, but do so with a clamped size.
fn limited_str<'a>(max_size: usize, u: &mut Unstructured<'a>) -> Result<&'a str> {
    let size = u.arbitrary_len::<u8>()?;
    let size = std::cmp::min(size, max_size);
    match std::str::from_utf8(u.peek_bytes(size).unwrap()) {
        Ok(s) => {
            u.bytes(size).unwrap();
            Ok(s)
        }
        Err(e) => {
            let i = e.valid_up_to();
            let valid = u.bytes(i).unwrap();
            let s = std::str::from_utf8(valid).unwrap();
            Ok(s)
        }
    }
}
