#![allow(unused)]

use std::collections::HashMap;

use wasmtime::{Config, Engine, Instance, Module, Store};

use ic_wasm_types::BinaryEncodedWasm;

/// Helper function to instantiate Wasm module in Wasmtime and call "run"
/// function. The goal is to use plain Wasmtime, without any of our additions.
pub fn wasmtime_instantiate_and_call_run(wasm: &BinaryEncodedWasm) -> Vec<wasmtime::Val> {
    // check that instrumented module instantiates correctly
    let wasmtime = WasmtimeSimple::new();

    let (imports_module_instance, imports_module_exports) = {
        let imports_wasm = wabt::wat2wasm(
            r#"
            (module
                (func (export "out_of_instructions"))
                (func (export "update_available_memory") (param i32 i32) (result i32)
                    i32.const 42
                )
            )"#,
        )
        .unwrap();
        let i = wasmtime.instantiate(&HashMap::new(), &imports_wasm);
        let mut e = HashMap::new();
        e.insert("out_of_instructions".to_string(), 0);
        e.insert("update_available_memory".to_string(), 1);
        (i, e)
    };

    let mut registry = HashMap::new();
    registry.insert(
        "__".to_string(),
        (imports_module_instance, imports_module_exports),
    );

    let instance = wasmtime.instantiate(&registry, wasm.as_slice());
    invoke(&instance, "run", &[])
}

pub struct WasmtimeSimple {
    engine: Engine,
    store: Store,
}

/// Used to resolve module imports during instantiation.
/// Example:
///
/// ```
/// let wasm = wabt::wat2wasm(
///     r#"(module
///       (import "__" "magic_number" (func $magic_number (result i32)))
///       (func (export "run") (result i32) (call $magic_number))
///     )"#,
/// )
/// .unwrap();
/// let wasmtime = ic_test_utilities::wasmtime_simple::WasmtimeSimple::new();
///
/// let (imports_module_instance, imports_module_exports) = {
///     let imports_wasm = wabt::wat2wasm(
///         r#"(module
///           (func (export "magic_number") (result i32) (i32.const 42))
///         )"#,
///     )
///     .unwrap();
///     let i = wasmtime.instantiate(&std::collections::HashMap::new(), &imports_wasm);
///     let mut e = std::collections::HashMap::new();
///     e.insert("magic_number".to_string(), 0);
///     (i, e)
/// };
///
/// let mut registry = std::collections::HashMap::new();
/// registry.insert(
///     "__".to_string(),
///     (imports_module_instance, imports_module_exports),
/// );
///
/// let instance = wasmtime.instantiate(&registry, wasm.as_slice());
/// let result = ic_test_utilities::wasmtime_simple::invoke(&instance, "run", &[]);
/// assert_eq!(result[0].i32().unwrap(), 42);
/// ```
pub type ModuleRegistry = HashMap<String, (Instance, HashMap<String, usize>)>;

#[allow(clippy::new_without_default)]
impl WasmtimeSimple {
    pub fn new() -> Self {
        let config = Config::default();
        let engine = Engine::new(&config).expect("Failed to initialize Wasmtime engine");
        let store = Store::new(&engine);
        Self { engine, store }
    }

    pub fn instantiate(&self, module_registry: &ModuleRegistry, wasm_binary: &[u8]) -> Instance {
        instantiate_module(&self.engine, &self.store, module_registry, &wasm_binary).unwrap()
    }
}

pub fn get_globals(instance: &Instance) -> Vec<wasmtime::Val> {
    instance
        .exports()
        .filter_map(|e| e.into_global())
        .map(|g| match g.ty().content() {
            wasmtime::ValType::I32 => g.get(),
            wasmtime::ValType::I64 => g.get(),
            _ => panic!("unexpected global value type"),
        })
        .collect()
}

pub fn invoke(instance: &Instance, func_name: &str, args: &[wasmtime::Val]) -> Vec<wasmtime::Val> {
    instance
        .get_export(func_name)
        .unwrap()
        .into_func()
        .unwrap_or_else(|| panic!("{} export is not a function", func_name))
        .call(args)
        .unwrap()
        .to_vec()
}

fn instantiate_module(
    engine: &Engine,
    store: &Store,
    module_registry: &ModuleRegistry,
    wasm_binary: &[u8],
) -> Result<Instance, Box<dyn std::error::Error>> {
    let module = Module::new(&engine, &wasm_binary)?;
    // Resolve import using module_registry.
    let imports: Vec<wasmtime::Extern> = module
        .imports()
        .map(|i| {
            let module_name = i.module().to_string();
            if let Some((instance, map)) = module_registry.get(&module_name) {
                let field_name = i.name().unwrap().to_string();
                if let Some(export_index) = map.get(&field_name) {
                    instance
                        .exports()
                        .nth(*export_index)
                        .unwrap()
                        .clone()
                        .into_extern()
                } else {
                    panic!(
                        "Import {} was not found in module {}",
                        field_name, module_name
                    )
                }
            } else {
                panic!("Import module {} was not found", module_name)
            }
        })
        .collect();

    let mut instance = Instance::new(&store, &module, &imports)?;
    Ok(instance)
}
