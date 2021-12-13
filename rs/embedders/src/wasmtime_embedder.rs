pub mod host_memory;
mod signal_stack;
mod system_api;
pub mod system_api_charges;

use std::convert::TryInto;
use std::sync::{Arc, Mutex};
use std::{collections::HashMap, convert::TryFrom};

use ic_system_api::ModificationTracking;
use wasmtime::{unix::StoreExt, Memory, Mutability, Store, Val, ValType};

use host_memory::MmapMemoryCreator;
pub use host_memory::WasmtimeMemoryCreator;
use ic_config::embedders::{Config as EmbeddersConfig, PersistenceType};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, InstanceStats, SystemApi, TrapCode,
};
use ic_logger::{debug, error, fatal, ReplicaLogger};
use ic_replicated_state::{EmbedderCache, Global, NumWasmPages, PageIndex, PageMap};
use ic_sys::PAGE_SIZE;
use ic_types::{
    methods::{FuncRef, WasmMethod},
    CanisterId, NumInstructions,
};
use ic_wasm_types::{BinaryEncodedWasm, WasmEngineError};
use memory_tracker::{DirtyPageTracking, SigsegvMemoryTracker};
use signal_stack::WasmtimeSignalStack;

use crate::wasm_utils::validation::ensure_determinism;

use crate::cow_memory_creator::{CowMemoryCreator, CowMemoryCreatorProxy};

use super::InstanceRunResult;

use self::host_memory::{MemoryPageSize, MemoryStart};

#[cfg(test)]
mod wasmtime_embedder_tests;

const NUM_INSTRUCTION_GLOBAL_NAME: &str = "canister counter_instructions";

fn trap_to_error(err: anyhow::Error) -> HypervisorError {
    let message = {
        // We cannot use `format!` here because displaying `err` may fail.
        let mut output = String::new();
        match std::fmt::write(&mut output, format_args!("{}", err)) {
            Ok(()) => output,
            Err(_) => "Conversion of Wasmtime error to string failed.".to_string(),
        }
    };
    let re_signature_mismatch =
        regex::Regex::new("expected \\d+ arguments, got \\d+").expect("signature mismatch regex");
    if message.contains("wasm trap: call stack exhausted") {
        HypervisorError::Trapped(TrapCode::StackOverflow)
    } else if message.contains("wasm trap: out of bounds memory access") {
        HypervisorError::Trapped(TrapCode::HeapOutOfBounds)
    } else if message.contains("wasm trap: integer divide by zero") {
        HypervisorError::Trapped(TrapCode::IntegerDivByZero)
    } else if message.contains("wasm trap: unreachable") {
        HypervisorError::Trapped(TrapCode::Unreachable)
    } else if message.contains("wasm trap: undefined element: out of bounds") {
        HypervisorError::Trapped(TrapCode::TableOutOfBounds)
    } else if message.contains("argument type mismatch") || re_signature_mismatch.is_match(&message)
    {
        HypervisorError::ContractViolation(
            "function invocation does not match its signature".to_string(),
        )
    } else {
        HypervisorError::Trapped(TrapCode::Other)
    }
}

pub struct WasmtimeEmbedder {
    log: ReplicaLogger,
    max_wasm_stack_size: usize,
    // Each time a new memory is created it is added to this map.  Each time a
    // `SigsegvMemoryTracker` is created it will look up the corresponding memory in the map
    // and remove it. So memories will only be in this map for the time between module
    // instatiation and creation of the corresponding `SigsegvMemoryTracker`.
    created_memories: Arc<Mutex<HashMap<MemoryStart, MemoryPageSize>>>,
}

impl WasmtimeEmbedder {
    pub fn new(config: EmbeddersConfig, log: ReplicaLogger) -> Self {
        let EmbeddersConfig {
            max_wasm_stack_size,
            ..
        } = config;

        WasmtimeEmbedder {
            log,
            max_wasm_stack_size,
            created_memories: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn compile(
        &self,
        persistence_type: PersistenceType,
        wasm_binary: &BinaryEncodedWasm,
    ) -> HypervisorResult<EmbedderCache> {
        let mut config = wasmtime::Config::default();
        ensure_determinism(&mut config);
        let cached_mem_creator = match persistence_type {
            PersistenceType::Sigsegv => {
                let raw_creator = MmapMemoryCreator {};
                let mem_creator = Arc::new(WasmtimeMemoryCreator::new(raw_creator, Arc::clone(&self.created_memories)));
                config.with_host_memory(mem_creator);
                None
            }
            _ /*Pagemap*/ => {
                let raw_creator = CowMemoryCreatorProxy::new(Arc::new(CowMemoryCreator::new_uninitialized()));
                let mem_creator = Arc::new(WasmtimeMemoryCreator::new(raw_creator.clone(), Arc::clone(&self.created_memories)));
                config.with_host_memory(mem_creator);
                Some(raw_creator)
            }
        };

        config
            // maximum size in bytes where a linear memory is considered
            // static. setting this to maximum Wasm memory size will guarantee
            // the memory is always static.
            .static_memory_maximum_size(
                wasmtime_environ::WASM_PAGE_SIZE as u64 * wasmtime_environ::WASM_MAX_PAGES as u64,
            )
            .max_wasm_stack(self.max_wasm_stack_size)
            .map_err(|_| HypervisorError::WasmEngineError(WasmEngineError::FailedToSetWasmStack))?;

        let engine = wasmtime::Engine::new(&config).map_err(|_| {
            HypervisorError::WasmEngineError(WasmEngineError::FailedToInitializeEngine)
        })?;
        let module = wasmtime::Module::new(&engine, wasm_binary.as_slice()).map_err(|_| {
            HypervisorError::WasmEngineError(WasmEngineError::FailedToInstantiateModule)
        })?;
        // Note that a wasmtime::Module object is cheaply clonable (just doing
        // a bit of reference counting, i.e. it is a "shallow copy"). This is
        // important because EmbedderCache is cloned frequently, and that must
        // not be an expensive operation.
        Ok(EmbedderCache::new((module, cached_mem_creator)))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_instance<S: SystemApi>(
        &self,
        canister_id: CanisterId,
        cache: &EmbedderCache,
        exported_globals: &[Global],
        heap_size: NumWasmPages,
        memory_creator: Option<Arc<CowMemoryCreator>>,
        page_map: Option<PageMap>,
        modification_tracking: ModificationTracking,
        system_api: S,
    ) -> Result<WasmtimeInstance<S>, (HypervisorError, S)> {
        let (module, memory_creator_proxy) = cache
            .downcast::<(wasmtime::Module, Option<CowMemoryCreatorProxy>)>()
            .expect("incompatible embedder cache, expected BinaryEncodedWasm");

        let mut store = Store::new(
            module.engine(),
            StoreData {
                system_api,
                num_instructions_global: None,
            },
        );

        let linker = system_api::syscalls(self.log.clone(), canister_id, &store);

        let (instance, persistence_type) = match (memory_creator, memory_creator_proxy) {
            (Some(memory_creator), Some(cow_mem_creator_proxy)) => {
                // If we have the CowMemoryCreator we want to ensure it is used
                // atomically
                let _lock = cow_mem_creator_proxy.memory_creator_lock.lock().unwrap();

                cow_mem_creator_proxy.replace(memory_creator);

                let instance = match linker.instantiate(&mut store, module) {
                    Ok(instance) => instance,
                    Err(err) => {
                        error!(
                            self.log,
                            "Failed to instantiate module for {}: {}", canister_id, err
                        );
                        return Err((
                            HypervisorError::WasmEngineError(
                                WasmEngineError::FailedToInstantiateModule,
                            ),
                            store.into_data().system_api,
                        ));
                    }
                };

                // After the Wasm module instance and its corresponding memory
                // are created we want to ensure that this particular
                // MemoryCreator can't be reused
                cow_mem_creator_proxy
                    .replace(std::sync::Arc::new(CowMemoryCreator::new_uninitialized()));
                (instance, PersistenceType::Pagemap)
            }
            (None, None) => {
                let instance = match linker.instantiate(&mut store, module) {
                    Ok(instance) => instance,
                    Err(err) => {
                        error!(
                            self.log,
                            "Failed to instantiate module for {}: {}", canister_id, err
                        );
                        return Err((
                            HypervisorError::WasmEngineError(
                                WasmEngineError::FailedToInstantiateModule,
                            ),
                            store.into_data().system_api,
                        ));
                    }
                };
                (instance, PersistenceType::Sigsegv)
            }
            (None, Some(_)) | (Some(_), None) => {
                fatal!(
                    self.log,
                    "We are caching mem creator if and only if mem_creator argument is not None,
                            and both happen if persistence type is Pagemap"
                );
            }
        };

        store.data_mut().num_instructions_global =
            instance.get_global(&mut store, NUM_INSTRUCTION_GLOBAL_NAME);

        // in wasmtime only exported globals are accessible
        let instance_globals: Vec<_> = instance
            .exports(&mut store)
            .filter_map(|e| e.into_global())
            .collect();

        if exported_globals.len() > instance_globals.len() {
            fatal!(
                self.log,
                "Given exported globals length {} is more than instance exported globals length {}",
                exported_globals.len(),
                instance_globals.len()
            );
        }

        // set the globals to persisted values
        for ((ix, v), instance_global) in exported_globals
            .iter()
            .enumerate()
            .zip(instance_globals.iter())
        {
            if instance_global.ty(&mut store).mutability() == Mutability::Var {
                instance_global
                    .set(
                        &mut store,
                        match v {
                            Global::I32(val) => Val::I32(*val),
                            Global::I64(val) => Val::I64(*val),
                            Global::F32(val) => Val::F32((val).to_bits()),
                            Global::F64(val) => Val::F64((val).to_bits()),
                        },
                    )
                    .unwrap_or_else(|e| {
                        let v = match v {
                            Global::I32(val) => (val).to_string(),
                            Global::I64(val) => (val).to_string(),
                            Global::F32(val) => (val).to_string(),
                            Global::F64(val) => (val).to_string(),
                        };
                        fatal!(
                            self.log,
                            "error while setting exported global {} to {}: {}",
                            ix,
                            v,
                            e
                        )
                    })
            } else {
                debug!(
                    self.log,
                    "skipping initialization of immutable global {}", ix
                );
            }
        }

        let instance_memory = instance
            .get_memory(&mut store, "memory")
            .map(|instance_memory| {
                let current_heap_size = instance_memory.size(&store);
                // TODO(EXC-650): Remove panic on wasmtime upgrade.
                let requested_size: u32 = heap_size
                    .get()
                    .try_into()
                    .expect("Couldn't convert requested heap size to u32");

                if current_heap_size < requested_size {
                    let delta = requested_size - current_heap_size;
                    // TODO(DFN-1305): It is OK to panic here. `requested_size` is
                    // value we store only after we've successfully grown module memory in some
                    // previous execution.
                    // Example: module starts with (memory 1 2) and calls (memory.grow 1). Then
                    // requested_size will be 2.
                    instance_memory
                        .grow(&mut store, delta)
                        .expect("memory grow failed");
                }
                instance_memory
            });

        let dirty_page_tracking = match modification_tracking {
            ModificationTracking::Ignore => DirtyPageTracking::Ignore,
            ModificationTracking::Track => DirtyPageTracking::Track,
        };

        // if `wasmtime::Instance` does not have memory we don't need a memory tracker
        let memory_tracker = match instance_memory {
            None => None,
            Some(instance_memory) => {
                let page_map = match persistence_type {
                    PersistenceType::Sigsegv => page_map,
                    PersistenceType::Pagemap => None,
                };
                let start = MemoryStart(instance_memory.data_ptr(&store) as usize);
                match self
                    .created_memories
                    .lock()
                    .ok()
                    .and_then(|mut mems| mems.remove(&start))
                {
                    None => {
                        error!(
                            self.log,
                            "Unable to find memory for canister {} when instantiating", canister_id
                        );
                        return Err((
                            HypervisorError::WasmEngineError(
                                WasmEngineError::FailedToInstantiateModule,
                            ),
                            store.into_data().system_api,
                        ));
                    }
                    Some(current_memory_size_in_pages) => Some(sigsegv_memory_tracker(
                        persistence_type,
                        &instance_memory,
                        current_memory_size_in_pages,
                        &mut store,
                        page_map,
                        self.log.clone(),
                        dirty_page_tracking,
                    )),
                }
            }
        };
        let signal_stack = WasmtimeSignalStack::new();

        Ok(WasmtimeInstance {
            instance,
            memory_tracker,
            signal_stack,
            log: self.log.clone(),
            instance_stats: InstanceStats {
                accessed_pages: 0,
                dirty_pages: 0,
            },
            store,
        })
    }
}

struct StoreRef(*mut wasmtime::Store<()>);

/// SAFETY: The users of `StoreRef` are required to only dereference the pointer
/// when it is know that nothing else is using the `Store`. When the signal
/// handler runs we dereference the pointer even though wasmtime may still be
/// using it, but we don't modify it in any way. EXC-535 should make this
/// unnecessary.
unsafe impl Sync for StoreRef {}
unsafe impl Send for StoreRef {}

fn sigsegv_memory_tracker<S>(
    persistence_type: PersistenceType,
    instance_memory: &wasmtime::Memory,
    current_memory_size_in_pages: MemoryPageSize,
    store: &mut wasmtime::Store<S>,
    page_map: Option<PageMap>,
    log: ReplicaLogger,
    dirty_page_tracking: DirtyPageTracking,
) -> Arc<Mutex<SigsegvMemoryTracker>> {
    let base = instance_memory.data_ptr(&store);
    let size = instance_memory.data_size(&store);

    let sigsegv_memory_tracker = {
        // For both SIGSEGV and in the future UFFD memory tracking we need
        // the base address of the heap and its size
        let base = base as *mut libc::c_void;
        if base as usize % PAGE_SIZE != 0 {
            fatal!(log, "[EXC-BUG] Memory tracker - Heap must be page aligned.");
        }
        if size % PAGE_SIZE != 0 {
            fatal!(
                log,
                "[EXC-BUG] Memory tracker - Heap size must be a multiple of page size."
            );
        }

        Arc::new(Mutex::new(
            SigsegvMemoryTracker::new(
                persistence_type,
                base,
                size,
                log,
                dirty_page_tracking,
                page_map,
            )
            .expect("failed to instantiate SIGSEGV memory tracker"),
        ))
    };

    let handler = crate::signal_handler::sigsegv_memory_tracker_handler(
        Arc::clone(&sigsegv_memory_tracker),
        current_memory_size_in_pages,
    );
    // http://man7.org/linux/man-pages/man7/signal-safety.7.html
    unsafe {
        store.set_signal_handler(handler);
    };
    sigsegv_memory_tracker
}

/// Additional types that need to be owned by the `wasmtime::Store`.
pub struct StoreData<S> {
    pub system_api: S,
    pub num_instructions_global: Option<wasmtime::Global>,
}

/// Encapsulates a Wasmtime instance on the Internet Computer.
pub struct WasmtimeInstance<S: SystemApi> {
    instance: wasmtime::Instance,
    memory_tracker: Option<Arc<Mutex<SigsegvMemoryTracker>>>,
    signal_stack: WasmtimeSignalStack,
    log: ReplicaLogger,
    instance_stats: InstanceStats,
    store: wasmtime::Store<StoreData<S>>,
}

impl<S: SystemApi> WasmtimeInstance<S> {
    pub fn into_store_data(self) -> StoreData<S> {
        self.store.into_data()
    }

    pub fn store_data_mut(&mut self) -> &mut StoreData<S> {
        self.store.data_mut()
    }

    fn invoke_export(&mut self, export: &str, args: &[Val]) -> HypervisorResult<Vec<Val>> {
        Ok(self
            .instance
            .get_export(&mut self.store, export)
            .ok_or_else(|| {
                HypervisorError::MethodNotFound(WasmMethod::try_from(export.to_string()).unwrap())
            })?
            .into_func()
            .ok_or_else(|| {
                HypervisorError::ContractViolation("export is not a function".to_string())
            })?
            .call(&mut self.store, args)
            .map_err(trap_to_error)?
            .to_vec())
    }

    fn dirty_pages(&self) -> Vec<PageIndex> {
        if let Some(memory_tracker) = self.memory_tracker.as_ref() {
            let memory_tracker = memory_tracker.lock().unwrap();
            let speculatively_dirty_pages = memory_tracker.take_speculatively_dirty_pages();
            let dirty_pages = memory_tracker.take_dirty_pages();
            dirty_pages
                .into_iter()
                .chain(speculatively_dirty_pages.into_iter())
                .filter_map(|p| memory_tracker.validate_speculatively_dirty_page(p))
                .collect::<Vec<PageIndex>>()
        } else {
            debug!(
                self.log,
                "Memory tracking disabled. Returning empty list of dirty pages"
            );
            vec![]
        }
    }

    fn memory(&mut self) -> HypervisorResult<Memory> {
        match self.instance.get_export(&mut self.store, "memory") {
            Some(export) => export.into_memory().ok_or_else(|| {
                HypervisorError::ContractViolation("export 'memory' is not a memory".to_string())
            }),
            None => Err(HypervisorError::ContractViolation(
                "export 'memory' not found".to_string(),
            )),
        }
    }

    /// Executes first exported method on an embedder instance, whose name
    /// consists of one of the prefixes and method_name.
    pub fn run(&mut self, func_ref: FuncRef) -> HypervisorResult<InstanceRunResult> {
        let _alt_sig_stack = unsafe { self.signal_stack.register() };

        let result = match &func_ref {
            FuncRef::Method(wasm_method) => self.invoke_export(&wasm_method.to_string(), &[]),
            FuncRef::QueryClosure(closure) | FuncRef::UpdateClosure(closure) => self
                .instance
                .get_export(&mut self.store, "table")
                .ok_or_else(|| HypervisorError::ContractViolation("table not found".to_string()))?
                .into_table()
                .ok_or_else(|| {
                    HypervisorError::ContractViolation("export 'table' is not a table".to_string())
                })?
                .get(&mut self.store, closure.func_idx)
                .ok_or(HypervisorError::FunctionNotFound(0, closure.func_idx))?
                .funcref()
                .ok_or_else(|| {
                    HypervisorError::ContractViolation("not a function reference".to_string())
                })?
                .ok_or_else(|| {
                    HypervisorError::ContractViolation(
                        "unexpected null function reference".to_string(),
                    )
                })?
                .call(&mut self.store, &[Val::I32(closure.env as i32)])
                .map_err(trap_to_error)
                .map(|boxed_slice| boxed_slice.to_vec()),
        }
        .map_err(|e| {
            self.store
                .data_mut()
                .system_api
                .get_execution_error()
                .cloned()
                .unwrap_or(e)
        });

        let dirty_pages = self.dirty_pages();
        let num_accessed_pages = self
            .memory_tracker
            .as_ref()
            .map_or(0, |tracker| tracker.lock().unwrap().num_accessed_pages());
        self.instance_stats.accessed_pages += num_accessed_pages;
        self.instance_stats.dirty_pages += dirty_pages.len();

        let stable_memory_dirty_pages: Vec<_> = self
            .store
            .data()
            .system_api
            .stable_memory_dirty_pages()
            .into_iter()
            .map(|(i, p)| (i, *p))
            .collect();
        let stable_memory_size =
            NumWasmPages::from(self.store.data().system_api.stable_memory_size());
        self.instance_stats.dirty_pages += stable_memory_dirty_pages.len();

        match result {
            Ok(_) => Ok(InstanceRunResult {
                exported_globals: self.get_exported_globals(),
                dirty_pages,
                stable_memory_size,
                stable_memory_dirty_pages,
            }),
            Err(err) => Err(err),
        }
    }

    /// Sets the number of instructions for a method execution.
    pub fn set_num_instructions(&mut self, num_instructions: NumInstructions) {
        match self.store.data().num_instructions_global {
            Some(num_instructions_global) => {
                match num_instructions_global
                    .set(&mut self.store, Val::I64(num_instructions.get() as i64))
                {
                    Ok(_) => (),
                    Err(e) => panic!("couldn't set the num_instructions counter: {:?}", e),
                }
            }
            None => panic!("couldn't find the num_instructions counter in the canister globals"),
        }
    }

    /// Returns the number of instructions left.
    pub fn get_num_instructions(&mut self) -> NumInstructions {
        match self.store.data().num_instructions_global {
            Some(num_instructions) => match num_instructions.get(&mut self.store) {
                Val::I64(num_instructions_i64) => {
                    NumInstructions::from(num_instructions_i64.max(0) as u64)
                }
                _ => panic!("invalid num_instructions counter type"),
            },
            None => panic!("couldn't find the num_instructions counter in the canister globals"),
        }
    }

    /// Returns the heap size.
    /// Result is guaranteed to fit in a `u32`.
    pub fn heap_size(&mut self) -> NumWasmPages {
        NumWasmPages::from(self.memory().map_or(0, |mem| mem.size(&self.store)) as usize)
    }

    /// Returns a list of exported globals.
    pub fn get_exported_globals(&mut self) -> Vec<Global> {
        let globals: Vec<_> = self
            .instance
            .exports(&mut self.store)
            .filter_map(|e| e.into_global())
            .collect();
        globals
            .iter()
            .map(|g| match g.ty(&self.store).content() {
                ValType::I32 => Global::I32(g.get(&mut self.store).i32().expect("global i32")),
                ValType::I64 => Global::I64(g.get(&mut self.store).i64().expect("global i64")),
                ValType::F32 => Global::F32(g.get(&mut self.store).f32().expect("global f32")),
                ValType::F64 => Global::F64(g.get(&mut self.store).f64().expect("global f64")),
                _ => panic!("unexpected global value type"),
            })
            .collect()
    }

    /// Return the heap address. If the Instance does not contain any memory,
    /// the pointer is null.
    ///
    /// # Safety
    /// This function returns a pointer to Instance's memory. The pointer is
    /// only valid while the Instance object is kept alive.
    pub unsafe fn heap_addr(&mut self) -> *const u8 {
        self.memory()
            .map(|mem| mem.data(&self.store).as_ptr())
            .unwrap_or_else(|_| std::ptr::null())
    }

    /// Returns execution statistics for this instance.
    ///
    /// Note that stats must be available even if this instance trapped.
    pub fn get_stats(&self) -> InstanceStats {
        self.instance_stats.clone()
    }
}
