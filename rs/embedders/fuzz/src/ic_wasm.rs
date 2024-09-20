use arbitrary::{Arbitrary, Result, Unstructured};
use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::wasm_utils::decoding::decode_wasm;
use ic_embedders::wasm_utils::validation::{RESERVED_SYMBOLS, WASM_FUNCTION_SIZE_LIMIT};
use ic_replicated_state::Global;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_types::methods::WasmMethod;
use ic_wasm_types::BinaryEncodedWasm;
use lazy_static::lazy_static;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fmt::Write;
use std::sync::Arc;
use wasm_encoder::{
    CodeSection, ExportKind, ExportSection, Function, FunctionSection, GlobalSection, GlobalType,
    Instruction, Module as WasmModule, TypeSection,
};
use wasm_smith::{Config, Module};
use wasmparser::*;

lazy_static! {
    static ref UNIVERSAL_CANISTER_WASM_BYTES : BinaryEncodedWasm = {
        // Universal canister wasm is gzipped
        decode_wasm(EmbeddersConfig::new().wasm_max_size, Arc::new(UNIVERSAL_CANISTER_WASM.to_vec())).expect("Unable to decode universal canister wasm")
    };
}

#[derive(Debug)]
pub struct ICWasmModule {
    pub module: Module,
    // TODO: Create a config for fuzzing
    // for clippy to not complain.
    #[allow(dead_code)]
    pub config: Config,
    #[allow(dead_code)]
    pub exoported_globals: Vec<Global>,
    #[allow(dead_code)]
    pub exported_functions: BTreeSet<WasmMethod>,
}

impl<'a> Arbitrary<'a> for ICWasmModule {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let embedder_config = EmbeddersConfig::new();
        let exports = generate_exports(embedder_config.clone(), u)?;
        let mut config = ic_wasm_config(embedder_config);
        config.exports = exports;
        Ok(ICWasmModule::new(config.clone(), Module::new(config, u)?))
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
            exoported_globals: persisted_globals,
            exported_functions: wasm_methods,
        }
    }
}

fn ic_wasm_config(embedder_config: EmbeddersConfig) -> Config {
    Config {
        min_funcs: 10,
        min_exports: 10,
        max_globals: embedder_config.max_globals,
        max_funcs: embedder_config.max_functions,
        max_instructions: WASM_FUNCTION_SIZE_LIMIT,

        // TODO: Ignore data segments for now
        min_data_segments: 0,
        max_data_segments: 0,

        allow_start_export: true,
        export_everything: true,
        generate_custom_sections: true,
        bulk_memory_enabled: true,
        reference_types_enabled: true,
        simd_enabled: true,
        memory64_enabled: true,

        threads_enabled: false,
        relaxed_simd_enabled: false,
        canonicalize_nans: false,
        exceptions_enabled: false,

        available_imports: Some(UNIVERSAL_CANISTER_WASM_BYTES.as_slice().to_vec()),
        ..Default::default()
    }
}

fn get_persisted_global(g: wasmparser::Global) -> Option<Global> {
    match g.ty.content_type {
        ValType::I32 => Some(Global::I32(
            g.init_expr
                .get_binary_reader()
                .read_var_i32()
                .expect("Failed to parse GlobalType i32"),
        )),
        ValType::I64 => Some(Global::I64(
            g.init_expr
                .get_binary_reader()
                .read_var_i64()
                .expect("Failed to parse GlobalType i64"),
        )),
        ValType::F32 => Some(Global::F32(f32::from_bits(
            g.init_expr
                .get_binary_reader()
                .read_f32()
                .expect("Failed to parse GlobalType f32")
                .bits(),
        ))),
        ValType::F64 => Some(Global::F64(f64::from_bits(
            g.init_expr
                .get_binary_reader()
                .read_f64()
                .expect("Failed to parse GlobalType f64")
                .bits(),
        ))),
        ValType::V128 => Some(Global::V128(u128::from_le_bytes(
            g.init_expr
                .get_binary_reader()
                .read_bytes(16)
                .expect("Failed to parse GlobalType v128")[..]
                .try_into()
                .unwrap(),
        ))),
        _ => None,
    }
}

fn generate_exports(
    embedder_config: EmbeddersConfig,
    u: &mut Unstructured,
) -> Result<Option<Vec<u8>>> {
    let mut module = WasmModule::new();

    // Type section
    // Inject type () -> ()
    let mut types = TypeSection::new();
    let params = vec![];
    let results = vec![];
    types.function(params, results);
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

    // Global Section (dummy values)
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
    let export_func_once: Vec<String> = vec![
        "canister_init".to_string(),
        "canister_inspect_message".to_string(),
        "canister_pre_upgrade".to_string(),
        "canister_post_upgrade".to_string(),
        "canister_heartbeat".to_string(),
        "canister_global_timer".to_string(),
    ];

    let export_func_prefix: Vec<String> = vec![
        "canister_query".to_string(),
        "canister_update".to_string(),
        "canister_composite_query".to_string(),
    ];

    let mut name = unique_string(1_000, exported_names, u)?;

    if u.ratio(1, 2)? && export_func_once.len() != visited.len() {
        let index_choice: Vec<usize> = (0..export_func_once.len())
            .filter(|index| !visited.contains(index))
            .collect();
        let choice = u.choose(&index_choice)?;
        name.clone_from(&export_func_once[*choice]);
        visited.insert(*choice);
        return Ok(name);
    }

    let choice = u.choose_index(export_func_prefix.len())?;
    name = format!("{} {}", export_func_prefix[choice], name);
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
