pub mod host_memory;
mod signal_stack;
mod system_api;
pub mod system_api_complexity;

use std::{
    collections::HashMap,
    convert::TryFrom,
    sync::{Arc, Mutex},
};

use ic_system_api::ModificationTracking;
use wasmtime::{unix::StoreExt, Engine, Memory, Module, Mutability, OptLevel, Store, Val, ValType};

pub use host_memory::WasmtimeMemoryCreator;
use ic_config::embedders::Config as EmbeddersConfig;
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, InstanceStats, SystemApi, TrapCode,
};
use ic_logger::{debug, error, fatal, ReplicaLogger};
use ic_replicated_state::{
    canister_state::execution_state, EmbedderCache, Global, NumWasmPages, PageIndex, PageMap,
};
use ic_sys::PAGE_SIZE;
use ic_types::{
    methods::{FuncRef, WasmMethod},
    CanisterId,
};
use ic_wasm_types::{BinaryEncodedWasm, WasmEngineError};
use memory_tracker::{DirtyPageTracking, SigsegvMemoryTracker};
use signal_stack::WasmtimeSignalStack;

use crate::{serialized_module::SerializedModuleBytes, wasm_utils::validation::ensure_determinism};

use super::InstanceRunResult;

use self::host_memory::{MemoryPageSize, MemoryStart};

#[cfg(test)]
mod wasmtime_embedder_tests;

const NUM_INSTRUCTION_GLOBAL_NAME: &str = "canister counter_instructions";

const BAD_SIGNATURE_MESSAGE: &str = "function invocation does not match its signature";

fn wasmtime_error_to_hypervisor_error(err: anyhow::Error) -> HypervisorError {
    match err.downcast::<wasmtime::Trap>() {
        Ok(trap) => match trap.trap_code() {
            Some(trap_code) => trap_code_to_hypervisor_error(trap_code),
            None => HypervisorError::Trapped(TrapCode::Other),
        },
        Err(err) => {
            // The error could be either a compile error or some other error.
            // We have to inspect the error message to distingiush these cases.
            let message = {
                // We cannot use `format!` here because displaying `err` may fail.
                let mut output = String::new();
                match std::fmt::write(&mut output, format_args!("{}", err)) {
                    Ok(()) => output,
                    Err(_) => "Conversion of Wasmtime error to string failed.".to_string(),
                }
            };
            // Check if the message contains one of:
            // - "expected ... arguments, got ..."
            // - "expected ... results, got ..."
            let arguments_or_results_mismatch = message
                .find("expected ")
                .and_then(|i| {
                    message
                        .get(i..)
                        .map(|s| s.contains(" arguments, got ") || s.contains(" results, got "))
                })
                .unwrap_or(false);
            if message.contains("argument type mismatch") || arguments_or_results_mismatch {
                return HypervisorError::ContractViolation(BAD_SIGNATURE_MESSAGE.to_string());
            }
            HypervisorError::Trapped(TrapCode::Other)
        }
    }
}

fn trap_code_to_hypervisor_error(trap_code: wasmtime::TrapCode) -> HypervisorError {
    match trap_code {
        wasmtime::TrapCode::StackOverflow => HypervisorError::Trapped(TrapCode::StackOverflow),
        wasmtime::TrapCode::MemoryOutOfBounds => {
            HypervisorError::Trapped(TrapCode::HeapOutOfBounds)
        }
        wasmtime::TrapCode::TableOutOfBounds => {
            HypervisorError::Trapped(TrapCode::TableOutOfBounds)
        }
        wasmtime::TrapCode::BadSignature => {
            HypervisorError::ContractViolation(BAD_SIGNATURE_MESSAGE.to_string())
        }
        wasmtime::TrapCode::IntegerDivisionByZero => {
            HypervisorError::Trapped(TrapCode::IntegerDivByZero)
        }
        wasmtime::TrapCode::UnreachableCodeReached => {
            HypervisorError::Trapped(TrapCode::Unreachable)
        }
        _ => {
            // The `wasmtime::TrapCode` enum is marked as #[non_exhaustive]
            // so we have to use the wildcard matching here.
            HypervisorError::Trapped(TrapCode::Other)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CanisterMemoryType {
    Heap,
}

pub struct WasmtimeEmbedder {
    log: ReplicaLogger,
    config: EmbeddersConfig,
    // Each time a new memory is created it is added to this map.  Each time a
    // `SigsegvMemoryTracker` is created it will look up the corresponding memory in the map
    // and remove it. So memories will only be in this map for the time between module
    // instatiation and creation of the corresponding `SigsegvMemoryTracker`.
    created_memories: Arc<Mutex<HashMap<MemoryStart, MemoryPageSize>>>,
}

impl WasmtimeEmbedder {
    pub fn new(config: EmbeddersConfig, log: ReplicaLogger) -> Self {
        WasmtimeEmbedder {
            log,
            config,
            created_memories: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn create_engine(&self) -> HypervisorResult<Engine> {
        let mut config = wasmtime::Config::default();
        config.cranelift_opt_level(OptLevel::None);
        ensure_determinism(&mut config);
        let mem_creator = Arc::new(WasmtimeMemoryCreator::new(Arc::clone(
            &self.created_memories,
        )));
        config.with_host_memory(mem_creator);

        config
            // maximum size in bytes where a linear memory is considered
            // static. setting this to maximum Wasm memory size will guarantee
            // the memory is always static.
            .static_memory_maximum_size(
                wasmtime_environ::WASM_PAGE_SIZE as u64 * wasmtime_environ::WASM32_MAX_PAGES as u64,
            )
            .max_wasm_stack(self.config.max_wasm_stack_size);

        wasmtime::Engine::new(&config).map_err(|_| {
            HypervisorError::WasmEngineError(WasmEngineError::FailedToInitializeEngine)
        })
    }

    pub fn compile(&self, wasm_binary: &BinaryEncodedWasm) -> HypervisorResult<Module> {
        let module = wasmtime::Module::new(&self.create_engine()?, wasm_binary.as_slice())
            .map_err(|_| {
                HypervisorError::WasmEngineError(WasmEngineError::FailedToInstantiateModule)
            })?;
        // Note that a wasmtime::Module object is cheaply clonable (just doing
        // a bit of reference counting, i.e. it is a "shallow copy"). This is
        // important because EmbedderCache is cloned frequently, and that must
        // not be an expensive operation.
        Ok(module)
    }

    pub fn deserialize_module(
        &self,
        serialized_module: &SerializedModuleBytes,
    ) -> HypervisorResult<Module> {
        // SAFETY: `SerializedModuleBytes` guarantees that `as_slice` returns a
        // sequence of bytes generated by serializing a `wasmtime::Module`. This
        // is precisely what is needed for `deserialize` to be safe.
        unsafe {
            Module::deserialize(&self.create_engine()?, serialized_module.as_slice()).map_err(
                |err| {
                    HypervisorError::WasmEngineError(WasmEngineError::FailedToDeserializeModule(
                        format!("{:?}", err),
                    ))
                },
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_instance<S: SystemApi>(
        &self,
        canister_id: CanisterId,
        cache: &EmbedderCache,
        exported_globals: &[Global],
        heap_memory: &execution_state::Memory,
        _stable_memory: &execution_state::Memory,
        modification_tracking: ModificationTracking,
        system_api: S,
    ) -> Result<WasmtimeInstance<S>, (HypervisorError, S)> {
        let module = match cache
            .downcast::<HypervisorResult<wasmtime::Module>>()
            .expect("incompatible embedder cache, expected HypervisorResult<wasmtime::Module>")
        {
            Ok(module) => module,
            Err(err) => return Err((err.clone(), system_api)),
        };

        let mut store = Store::new(
            module.engine(),
            StoreData {
                system_api,
                num_instructions_global: None,
            },
        );

        let linker = system_api::syscalls(
            self.log.clone(),
            canister_id,
            &store,
            self.config.feature_flags.rate_limiting_of_debug_prints,
            self.config.stable_memory_dirty_page_limit,
        );

        let instance = match linker.instantiate(&mut store, module) {
            Ok(instance) => instance,
            Err(err) => {
                error!(
                    self.log,
                    "Failed to instantiate module for {}: {}", canister_id, err
                );
                return Err((
                    HypervisorError::WasmEngineError(WasmEngineError::FailedToInstantiateModule),
                    store.into_data().system_api,
                ));
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

        let instance_heap_memory =
            instance
                .get_memory(&mut store, "memory")
                .map(|instance_memory| {
                    let current_heap_size = instance_memory.size(&store);
                    let requested_size = heap_memory.size.get() as u64;

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
        let memory_trackers = match instance_heap_memory {
            None => HashMap::new(),
            Some(instance_memory) => {
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
                    Some(current_memory_size_in_pages) => sigsegv_memory_tracker(
                        [(
                            CanisterMemoryType::Heap,
                            (
                                instance_memory,
                                current_memory_size_in_pages,
                                heap_memory.page_map.clone(),
                            ),
                        )]
                        .into_iter()
                        .collect(),
                        &mut store,
                        self.log.clone(),
                        dirty_page_tracking,
                    ),
                }
            }
        };
        let signal_stack = WasmtimeSignalStack::new();

        Ok(WasmtimeInstance {
            instance,
            memory_trackers,
            signal_stack,
            log: self.log.clone(),
            instance_stats: InstanceStats {
                accessed_pages: 0,
                dirty_pages: 0,
            },
            store,
        })
    }

    pub fn config(&self) -> &EmbeddersConfig {
        &self.config
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
    memories: HashMap<CanisterMemoryType, (wasmtime::Memory, MemoryPageSize, PageMap)>,
    store: &mut wasmtime::Store<S>,
    log: ReplicaLogger,
    dirty_page_tracking: DirtyPageTracking,
) -> HashMap<CanisterMemoryType, Arc<Mutex<SigsegvMemoryTracker>>> {
    let mut tracked_memories = vec![];
    let mut result = HashMap::new();
    for (mem_type, (instance_memory, current_memory_size_in_pages, page_map)) in memories {
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
                SigsegvMemoryTracker::new(base, size, log.clone(), dirty_page_tracking, page_map)
                    .expect("failed to instantiate SIGSEGV memory tracker"),
            ))
        };
        result.insert(mem_type, Arc::clone(&sigsegv_memory_tracker));
        tracked_memories.push((sigsegv_memory_tracker, current_memory_size_in_pages));
    }

    let handler = crate::signal_handler::sigsegv_memory_tracker_handler(tracked_memories);
    // http://man7.org/linux/man-pages/man7/signal-safety.7.html
    unsafe {
        store.set_signal_handler(handler);
    };
    result
}

/// Additional types that need to be owned by the `wasmtime::Store`.
pub struct StoreData<S> {
    pub system_api: S,
    pub num_instructions_global: Option<wasmtime::Global>,
}

pub struct PageAccessResults {
    pub dirty_pages: Vec<PageIndex>,
    pub num_accessed_pages: usize,
}

/// Encapsulates a Wasmtime instance on the Internet Computer.
pub struct WasmtimeInstance<S: SystemApi> {
    instance: wasmtime::Instance,
    memory_trackers: HashMap<CanisterMemoryType, Arc<Mutex<SigsegvMemoryTracker>>>,
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

    pub fn store_data(&self) -> &StoreData<S> {
        self.store.data()
    }

    fn invoke_export(&mut self, export: &str, args: &[Val]) -> HypervisorResult<()> {
        self.instance
            .get_export(&mut self.store, export)
            .ok_or_else(|| {
                HypervisorError::MethodNotFound(WasmMethod::try_from(export.to_string()).unwrap())
            })?
            .into_func()
            .ok_or_else(|| {
                HypervisorError::ContractViolation("export is not a function".to_string())
            })?
            .call(&mut self.store, args, &mut [])
            .map_err(wasmtime_error_to_hypervisor_error)
    }

    fn dirty_pages(&self) -> HashMap<CanisterMemoryType, PageAccessResults> {
        if self.memory_trackers.is_empty() {
            debug!(
                self.log,
                "Memory tracking disabled. Returning empty list of dirty pages"
            );
            return HashMap::new();
        }
        self.memory_trackers
            .iter()
            .map(|(ty, tracker)| {
                let memory_tracker = tracker.lock().unwrap();
                let speculatively_dirty_pages = memory_tracker.take_speculatively_dirty_pages();
                let dirty_pages = memory_tracker.take_dirty_pages();
                let dirty_pages = dirty_pages
                    .into_iter()
                    .chain(speculatively_dirty_pages.into_iter())
                    .filter_map(|p| memory_tracker.validate_speculatively_dirty_page(p))
                    .collect::<Vec<PageIndex>>();
                (
                    *ty,
                    PageAccessResults {
                        dirty_pages,
                        num_accessed_pages: memory_tracker.num_accessed_pages(),
                    },
                )
            })
            .collect()
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
                .call(&mut self.store, &[Val::I32(closure.env as i32)], &mut [])
                .map_err(wasmtime_error_to_hypervisor_error),
        }
        .map_err(|e| {
            self.store
                .data_mut()
                .system_api
                .get_execution_error()
                .cloned()
                .unwrap_or(e)
        });

        let mut accesses = self.dirty_pages();
        let dirty_pages = if let Some(PageAccessResults {
            dirty_pages,
            num_accessed_pages,
        }) = accesses.remove(&CanisterMemoryType::Heap)
        {
            self.instance_stats.accessed_pages += num_accessed_pages;
            self.instance_stats.dirty_pages += dirty_pages.len();
            dirty_pages
        } else {
            vec![]
        };

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

    /// Sets the instruction counter to the given value.
    pub fn set_instruction_counter(&mut self, instruction_counter: i64) {
        match self.store.data().num_instructions_global {
            Some(num_instructions_global) => {
                match num_instructions_global.set(&mut self.store, Val::I64(instruction_counter)) {
                    Ok(_) => (),
                    Err(e) => panic!("couldn't set the instruction counter: {:?}", e),
                }
            }
            None => panic!("couldn't find the instruction counter in the canister globals"),
        }
    }

    /// Returns the current instruction counter.
    pub fn instruction_counter(&mut self) -> i64 {
        match self.store.data().num_instructions_global {
            Some(num_instructions) => match num_instructions.get(&mut self.store) {
                Val::I64(instruction_counter) => instruction_counter,
                _ => panic!("invalid instruction counter type"),
            },
            None => panic!("couldn't find the instruction counter in the canister globals"),
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
