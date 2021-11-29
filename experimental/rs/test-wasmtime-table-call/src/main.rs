#![allow(unused)]

use anyhow::{bail, Error};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use wasmtime::{Config, Engine, HostRef, Instance, Limits, MemoryType, Module, Store};
use wasmtime_interface_types::ModuleData;

struct Wasmtime {
    engine: HostRef<Engine>,
    store: HostRef<Store>,
    module_registry: HashMap<String, (Instance, HashMap<String, usize>)>,
    instance: HostRef<Instance>,
    wasm_binary: Vec<u8>,
}

impl Wasmtime {
    fn new(config: Config, module_wat: &str) -> Result<Self, Error> {
        let engine = HostRef::new(Engine::new(&config));
        let store = HostRef::new(Store::new(&engine));
        let mut module_registry = HashMap::new();
        let wasm_binary = wabt::wat2wasm(module_wat)?;
        let instance = instantiate_module(&store, &module_registry, &wasm_binary).unwrap();
        Ok(Self {
            engine,
            store,
            module_registry,
            instance,
            wasm_binary,
        })
    }
}

#[allow(clippy::type_complexity)]
fn instantiate_module(
    store: &HostRef<Store>,
    module_registry: &HashMap<String, (Instance, HashMap<String, usize>)>,
    wasm_binary: &[u8],
) -> Result<HostRef<Instance>, Error> {
    let module = HostRef::new(Module::new(&store, &wasm_binary)?);
    // Resolve import using module_registry.
    let imports = module
        .borrow()
        .imports()
        .iter()
        .map(|i| {
            let module_name = i.module().to_string();
            if let Some((instance, map)) = module_registry.get(&module_name) {
                let field_name = i.name().to_string();
                if let Some(export_index) = map.get(&field_name) {
                    Ok(instance.exports()[*export_index].clone())
                } else {
                    bail!(
                        "Import {} was not found in module {}",
                        field_name,
                        module_name
                    )
                }
            } else {
                bail!("Import module {} was not found", module_name)
            }
        })
        .collect::<Result<Vec<_>, anyhow::Error>>()?;

    let mut instance = HostRef::new(Instance::new(&store, &module, &imports)?);
    Ok(instance)
}

fn main() {
    let config = Config::default();
    let mut wasmtime = Wasmtime::new(
        config,
        r#"
            (module
              (func $f (result i32)
                (i32.const 123)
              )
              (table funcref (elem $f))
            )
        "#,
    )
    .unwrap();

    for i in 0..10 {
        let store = &wasmtime.store.borrow();
        let sig = store.lookup_wasmtime_signature(wasmtime_runtime::VMSharedSignatureIndex::new(i));
        println!("sig {}: {:?}", i, sig);
    };


    let table_index = 0;

    let inst = wasmtime.instance.borrow();

    let anyfunc = inst
        .handle()
        .table_get(cranelift_wasm::DefinedTableIndex::from_u32(0), table_index)
        .unwrap();

    println!("anyfunc: {:?}", anyfunc);

    let result = match wasmtime::from_checked_anyfunc(anyfunc, &wasmtime.store) {
        wasmtime::Val::FuncRef(func) => {
            println!("func: {:?}", func);
            func.borrow()
                .call(&[])
                .map_err(|trap_ref| panic!("{}", &trap_ref.borrow()))
                .unwrap()
                .to_vec()
        }
        _ => {
            panic!("function not found");
        }
    };

    println!("result: {:?}", result);
}
