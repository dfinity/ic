#![allow(unused)]

use anyhow::{bail, Error};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use wasmtime::{Config, Engine, HostRef, Instance, Module, Store, MemoryType, Limits};
use wasmtime_interface_types::ModuleData;

use memory_area::Area;

use slog::{debug, o};

struct Wasmtime<'a> {
    engine: HostRef<Engine>,
    store: HostRef<Store>,
    module_registry: HashMap<String, (Instance, HashMap<String, usize>)>,
    instance: HostRef<Instance>,
    wasm_binary: Vec<u8>,
    area: Option<Area<'a>>,
    log: slog::Logger,
}

impl<'a> Wasmtime<'a> {
    fn new(config: Config, module_wat: &str) -> Result<Self, Error> {
        let log = slog_scope::logger().new(o!("component" => "Wasmtime"));
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
            area: None,
            log,
        })
    }

    fn invoke(&self, name: &str) -> Result<Vec<wasmtime_interface_types::Value>, Error> {
        let data = ModuleData::new(&self.wasm_binary)?;
        invoke_export(&self.store, &self.instance, &data, name, vec![])
    }

    fn invoke_and_print(&self, name: &str) {
        for value in self.invoke(name).unwrap() {
            println!("{}(): {}", name, value);
        }
    }

    fn with_persistent_memory(&mut self, file_name: impl Into<String>) {
        // TODO: this requires memory to be exported as "memory"
        let mem_export = self
            .instance
            .borrow()
            .get_wasmtime_memory()
            .expect("Wasm module has memory");
        if let wasmtime_runtime::Export::Memory {
            definition,
            vmctx,
            memory,
        } = mem_export
        {
            let (base, current_length): (*mut u8, usize) = unsafe {
                // definition: *mut VMMemoryDefinition
                let definition = std::ptr::read(definition);
                (definition.base, definition.current_length)
            };
            debug!(
                self.log,
                "Memory: base addr = {:?}, current_size = {}", base, current_length
            );
            let num_pages = current_length / 4096;
            debug!(
                self.log,
                "Registering Area(addr={:?}, num_pages={})", base, num_pages
            );
            let area = Area::register(
                base as *mut libc::c_void,
                num_pages,
                Some(file_name.into()),
                self.log.clone(),
            );

            assert_eq!(area.addr() as *mut u8, base);

            self.instance.borrow_mut().set_signal_handler({
                // cast the pointer to c_void to avoid invalid lifetime error; unfortunately the
                // signal handler closure requires 'static lifetime
                let area_args = area.register_args();
                move |signum, siginfo, _context| {
                    println!("Hello from instance signal handler!");
                    // Only interested in SIGSEGV.
                    if libc::SIGSEGV == signum {
                        let si_addr: *mut libc::c_void = unsafe { (*siginfo).si_addr() };
                        // Call *our* signal handler. Returns true if the signal has been handled.
                        if memory_area::memory_tracker_sigsegv_fault_handler(si_addr, area_args) {
                            println!("signal has been handled");
                            true
                        } else {
                            println!("signal has not been handled");
                            false
                        }
                    // Forward any other signal.
                    } else {
                        false
                    }
                }
            });

            self.area = Some(area);
        } else {
            panic!("expected Memory export");
        }
    }

    fn commit_persistent_memory(self) {
        if let Some(area) = self.area {
            area.commit();
        };
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

fn invoke_export(
    store: &HostRef<Store>,
    instance: &HostRef<Instance>,
    data: &ModuleData,
    func_name: &str,
    func_args: Vec<wasmtime_interface_types::Value>,
) -> Result<Vec<wasmtime_interface_types::Value>, Error> {
    // use wasm_webidl_bindings::ast;
    use wasmtime_interface_types::Value;

    // Invoke the function and then afterwards print all the results that came
    // out, if there are any.
    let results = data
        .invoke_export(&instance, func_name, &func_args).expect(&format!("failed to invoke `{}`", func_name));
        // .with_context(|_| format!("failed to invoke `{}`", func_name))?;

    Ok(results)
}

const COUNTER_MODULE_WAT: &str = r#"
    (module
      (func $read (export "read") (result i32)
        (i32.load (i32.const 0))
      )
      (func $incr (export "incr") (result i32)
        ;; increment the counter
        (i32.store
          (i32.const 0)
          (i32.add (i32.load (i32.const 0)) (i32.const 1))
        )
        ;; return the current value
        (i32.load (i32.const 0))
      )
      (func $read_out_of_bounds (export "read_out_of_bounds") (result i32)
        (i32.load
          (i32.mul
            ;; memory size in Wasm pages
            (memory.size)
            ;; Wasm page size
            (i32.const 65536)
          )
        )
      )
      (memory (export "memory") 1 4)
    )
"#;

fn main() -> Result<(), anyhow::Error> {
    let _guard = init_logger();
    let config = Config::default();
    let mut wasmtime = Wasmtime::new(config, COUNTER_MODULE_WAT)?;
    // Set up persistent memory using SIGSEGV handler
    wasmtime.with_persistent_memory("memory.bin");
    // Expect `read` and `incr` to succeed
    wasmtime.invoke_and_print("read");
    for _ in 0..4 {
        wasmtime.invoke_and_print("incr");
    }
    wasmtime.invoke_and_print("read");
    // Expect `read_out_of_bounds` to trap
    println!("read_out_of_bounds()");
    match wasmtime.invoke("read_out_of_bounds") {
        Ok(_) => panic!("expected out of bounds memory access error"),
        Err(err) => {
            debug!(wasmtime.log, "{}; {}", err.to_string(), err.root_cause());
            assert!(format!("{}", err.root_cause())
                .starts_with("trapped: wasm trap: out of bounds memory access"));
        }
    };
    // Done! Persist memory
    wasmtime.commit_persistent_memory();
    Ok(())
}

pub fn init_logger() -> (slog_scope::GlobalLoggerGuard, slog_async::AsyncGuard) {
    // Drain for .fuse()
    use slog::{slog_o, Drain};
    use slog_scope::info;
    let drain =
        slog_term::CompactFormat::new(slog_term::PlainSyncDecorator::new(std::io::stderr()))
            .build();
    // use async_guard to guarantee the log is flushed before exiting
    let (async_log, async_guard) = slog_async::Async::new(drain.fuse())
        .chan_size(100)
        .overflow_strategy(slog_async::OverflowStrategy::Block)
        .build_with_guard();
    let root_logger = slog::Logger::root(async_log.fuse(), slog_o!());
    let log_guard = slog_scope::set_global_logger(root_logger);
    (log_guard, async_guard)
}
