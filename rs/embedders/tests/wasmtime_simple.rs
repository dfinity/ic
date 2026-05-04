#![allow(unused)]

use std::collections::HashMap;

use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::WasmtimeEmbedder;
use wasmtime::{Config, Engine, Instance, Module, Store};

use ic_wasm_types::BinaryEncodedWasm;

/// Helper function to instantiate Wasm module in Wasmtime and call "run"
/// function. The goal is to use plain Wasmtime, without any of our additions.
pub fn wasmtime_instantiate_and_call_run(wasm: &BinaryEncodedWasm) {
    // check that instrumented module instantiates correctly
    let mut wasmtime = WasmtimeSimple::new();

    let (imports_module_instance, imports_module_exports) = {
        let imports_wasm = wat::parse_str(
            r#"
            (module
                (func (export "out_of_instructions"))
                (func (export "try_grow_wasm_memory") (param i32 i32) (result i32)
                    i32.const 42
                )
                (func (export "try_grow_stable_memory") (param i64 i64 i32) (result i64)
                    i64.const 0
                )
                (func (export "deallocate_pages") (param i64))
                (func (export "internal_trap") (param i32))
                (func (export "stable_read_first_access") (param i64 i64 i64))
            )"#,
        )
        .unwrap();
        let i = wasmtime.instantiate(&HashMap::new(), &imports_wasm);
        let mut e = HashMap::new();
        e.insert("out_of_instructions".to_string(), 0);
        e.insert("try_grow_wasm_memory".to_string(), 1);
        e.insert("try_grow_stable_memory".to_string(), 2);
        e.insert("deallocate_pages".to_string(), 3);
        e.insert("internal_trap".to_string(), 4);
        e.insert("stable_read_first_access".to_string(), 5);
        (i, e)
    };

    let mut registry = HashMap::new();
    registry.insert(
        "__".to_string(),
        (imports_module_instance, imports_module_exports),
    );

    let instance = wasmtime.instantiate(&registry, wasm.as_slice());
    invoke(wasmtime.store, &instance, "run", &[])
}

pub struct WasmtimeSimple {
    engine: Engine,
    store: Store<()>,
}

/// Used to resolve module imports during instantiation.
/// Example:
///
/// ```
/// let wasm = wat::parse_str(
///     r#"(module
///       (import "__" "magic_number" (func $magic_number (result i32)))
///       (func (export "run") (result i32) (call $magic_number))
///     )"#,
/// )
/// .unwrap();
/// let wasmtime = ic_test_utilities::wasmtime_simple::WasmtimeSimple::new();
///
/// let (imports_module_instance, imports_module_exports) = {
///     let imports_wasm = wat::parse_str(
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
        let engine = Engine::new(&WasmtimeEmbedder::wasmtime_execution_config(
            &EmbeddersConfig::default(),
        ))
        .expect("Failed to initialize Wasmtime engine");
        let store = Store::new(&engine, ());
        Self { engine, store }
    }

    pub fn instantiate(
        &mut self,
        module_registry: &ModuleRegistry,
        wasm_binary: &[u8],
    ) -> Instance {
        instantiate_module(&self.engine, &mut self.store, module_registry, wasm_binary).unwrap()
    }
}

pub fn get_globals(mut store: Store<()>, instance: &Instance) -> Vec<wasmtime::Val> {
    let globals: Vec<_> = instance
        .exports(&mut store)
        .filter_map(|e| e.into_global())
        .collect();
    globals
        .iter()
        .map(|g| match g.ty(&store).content() {
            wasmtime::ValType::I32 => g.get(&mut store),
            wasmtime::ValType::I64 => g.get(&mut store),
            _ => panic!("unexpected global value type"),
        })
        .collect()
}

pub fn invoke(mut store: Store<()>, instance: &Instance, func_name: &str, args: &[wasmtime::Val]) {
    instance
        .get_export(&mut store, func_name)
        .unwrap()
        .into_func()
        .unwrap_or_else(|| panic!("{func_name} export is not a function"))
        .call(&mut store, args, &mut [])
        .unwrap()
}

fn instantiate_module(
    engine: &Engine,
    mut store: &mut Store<()>,
    module_registry: &ModuleRegistry,
    wasm_binary: &[u8],
) -> Result<Instance, Box<dyn std::error::Error>> {
    let module = Module::new(engine, wasm_binary)?;
    // Resolve import using module_registry.
    let mut imports = vec![];
    for i in module.imports() {
        let module_name = i.module().to_string();
        if let Some((instance, map)) = module_registry.get(&module_name) {
            let field_name = i.name().to_string();
            if let Some(export_index) = map.get(&field_name) {
                imports.push(
                    instance
                        .exports(&mut store)
                        .nth(*export_index)
                        .unwrap()
                        .clone()
                        .into_extern(),
                );
            } else {
                panic!("Import {field_name} was not found in module {module_name}")
            }
        } else {
            panic!("Import module {module_name} was not found")
        }
    }

    let mut instance = Instance::new(store, &module, &imports)?;
    Ok(instance)
}
