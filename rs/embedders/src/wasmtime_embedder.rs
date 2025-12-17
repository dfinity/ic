use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fs::File,
    mem::size_of,
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};

use ic_management_canister_types_private::Global;
use wasmtime::{
    Engine, Instance, InstancePre, Linker, Memory, Module, Mutability, Store, StoreLimits,
    StoreLimitsBuilder, Val, ValType, unix::StoreExt,
};

pub use host_memory::WasmtimeMemoryCreator;
use ic_config::{embedders::Config as EmbeddersConfig, flag_status::FlagStatus};
use ic_interfaces::execution_environment::{
    CanisterBacktrace, HypervisorError, HypervisorResult, InstanceStats, SystemApi, TrapCode,
};
use ic_logger::{ReplicaLogger, debug, error, fatal};
use ic_replicated_state::{
    EmbedderCache, NumWasmPages, PageIndex, PageMap,
    canister_state::{WASM_PAGE_SIZE_IN_BYTES, execution_state},
};
use ic_sys::PAGE_SIZE;
use ic_types::{
    CanisterId, NumBytes, NumInstructions, NumOsPages,
    methods::{FuncRef, WasmMethod},
};
use ic_wasm_types::{BinaryEncodedWasm, WasmEngineError};
use memory_tracker::{DirtyPageTracking, MemoryLimits, SigsegvMemoryTracker};
use signal_stack::WasmtimeSignalStack;

use crate::wasm_utils::instrumentation::{
    ACCESSED_PAGES_COUNTER_GLOBAL_NAME, DIRTY_PAGES_COUNTER_GLOBAL_NAME,
    INSTRUCTIONS_COUNTER_GLOBAL_NAME, WasmMemoryType,
};
use crate::{
    serialized_module::SerializedModuleBytes, wasm_utils::validation::wasmtime_validation_config,
};

use super::InstanceRunResult;

use self::host_memory::{MemoryPageSize, MemoryStart};

pub mod host_memory;
/// pub for usage in fuzzing
#[doc(hidden)]
pub mod linker;
mod signal_handler;
mod signal_stack;
pub mod system_api;
pub mod system_api_complexity;

use system_api::{ModificationTracking, SystemApiImpl};

#[cfg(test)]
mod tests;

const BAD_SIGNATURE_MESSAGE: &str = "function invocation does not match its signature";
pub(crate) const WASM_HEAP_MEMORY_NAME: &str = "memory";
pub(crate) const STABLE_MEMORY_NAME: &str = "stable_memory";
pub(crate) const STABLE_BYTEMAP_MEMORY_NAME: &str = "stable_bytemap_memory";

pub(crate) const MAX_STORE_TABLES: usize = 1;
pub(crate) const MAX_STORE_TABLE_ELEMENTS: usize = 1_000_000;

fn demangle(func_name: &str) -> String {
    if let Ok(name) = rustc_demangle::try_demangle(func_name) {
        format!("{name:#}")
    } else {
        func_name.to_string()
    }
}

/// Convert a backtrace to our internal representation. Returns `None` if we
/// can't get function names for any of the frames. This likely indicates that
/// the `name` section is not present and the user won't want an error
/// cluttered with a useless backtrace anyway.
fn convert_backtrace(wasm: &wasmtime::WasmBacktrace) -> Option<CanisterBacktrace> {
    let funcs: Vec<_> = wasm
        .frames()
        .iter()
        .map(|f| (f.func_index(), f.func_name().map(demangle)))
        .collect();
    if funcs.iter().all(|(_, name)| name.is_none()) {
        None
    } else {
        Some(CanisterBacktrace(funcs))
    }
}

fn wasmtime_error_to_hypervisor_error(err: anyhow::Error) -> HypervisorError {
    let backtrace = err
        .downcast_ref::<wasmtime::WasmBacktrace>()
        .and_then(convert_backtrace);
    match err.downcast::<wasmtime::Trap>() {
        Ok(trap) => trap_code_to_hypervisor_error(trap, backtrace),
        Err(err) => {
            // The error could be either a compile error or some other error.
            // We have to inspect the error message to distinguish these cases.
            let message = {
                // We cannot use `format!` here because displaying `err` may fail.
                let mut output = String::new();
                match std::fmt::write(&mut output, format_args!("{}", err.root_cause())) {
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
                return HypervisorError::ToolchainContractViolation {
                    error: BAD_SIGNATURE_MESSAGE.to_string(),
                };
            }
            HypervisorError::Trapped {
                trap_code: TrapCode::Other,
                backtrace,
            }
        }
    }
}

fn trap_code_to_hypervisor_error(
    trap: wasmtime::Trap,
    backtrace: Option<CanisterBacktrace>,
) -> HypervisorError {
    if trap == wasmtime::Trap::BadSignature {
        return HypervisorError::ToolchainContractViolation {
            error: BAD_SIGNATURE_MESSAGE.to_string(),
        };
    };
    let trap_code = match trap {
        wasmtime::Trap::StackOverflow => TrapCode::StackOverflow,
        wasmtime::Trap::MemoryOutOfBounds => TrapCode::HeapOutOfBounds,
        wasmtime::Trap::TableOutOfBounds => TrapCode::TableOutOfBounds,
        wasmtime::Trap::IntegerDivisionByZero => TrapCode::IntegerDivByZero,
        wasmtime::Trap::UnreachableCodeReached => TrapCode::Unreachable,
        // The `wasmtime::TrapCode` enum is marked as #[non_exhaustive]
        // so we have to use the wildcard matching here.
        _ => TrapCode::Other,
    };
    HypervisorError::Trapped {
        trap_code,
        backtrace,
    }
}

fn get_exported_globals<T>(instance: &Instance, store: &mut Store<T>) -> Vec<wasmtime::Global> {
    const TO_IGNORE: &[&str] = &[
        DIRTY_PAGES_COUNTER_GLOBAL_NAME,
        ACCESSED_PAGES_COUNTER_GLOBAL_NAME,
    ];

    instance
        .exports(store)
        .filter_map(|e| {
            if TO_IGNORE.contains(&e.name()) {
                None
            } else {
                e.into_global()
            }
        })
        .collect()
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum CanisterMemoryType {
    Heap,
    Stable,
}

impl std::fmt::Display for CanisterMemoryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Information needed to instantiate a Wasm memory.
struct WasmMemoryInfo {
    /// The exported name of the memory.
    name: &'static str,
    /// The exported name of the associated dirty page bytemap memory (if it exists).
    bytemap_name: Option<&'static str>,
    /// The initial memory state.
    memory: execution_state::Memory,
    /// The type of this memory.
    memory_type: CanisterMemoryType,
    /// Indicates whether dirty page tracking should be enabled.
    dirty_page_tracking: DirtyPageTracking,
}

pub struct WasmtimeEmbedder {
    log: ReplicaLogger,
    config: EmbeddersConfig,
    // Each time a new memory is created it is added to this map.  Each time a
    // `SigsegvMemoryTracker` is created it will look up the corresponding memory in the map
    // and remove it. So memories will only be in this map for the time between module
    // instantiation and creation of the corresponding `SigsegvMemoryTracker`.
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

    /// Only public for use in tests that create their own wasmtime engine. This
    /// contains all the wasmtime configuration used to actually run the
    /// canisters __except__ the `host_memory`.
    #[doc(hidden)]
    pub fn wasmtime_execution_config(embedder_config: &EmbeddersConfig) -> wasmtime::Config {
        let mut config = wasmtime_validation_config(embedder_config);

        config.wasm_multi_memory(true);
        config.wasm_memory64(true);
        config
    }

    fn create_engine(&self) -> HypervisorResult<Engine> {
        let mut config = Self::wasmtime_execution_config(&self.config);
        let mem_creator = Arc::new(WasmtimeMemoryCreator::new(Arc::clone(
            &self.created_memories,
        )));
        config.with_host_memory(mem_creator);

        wasmtime::Engine::new(&config).map_err(|_| {
            HypervisorError::WasmEngineError(WasmEngineError::FailedToInitializeEngine)
        })
    }

    pub fn compile(&self, wasm_binary: &BinaryEncodedWasm) -> HypervisorResult<Module> {
        let module = wasmtime::Module::new(&self.create_engine()?, wasm_binary.as_slice())
            .map_err(|e| {
                HypervisorError::WasmEngineError(WasmEngineError::FailedToInstantiateModule(
                    format!("{e:?}"),
                ))
            })?;
        Ok(module)
    }

    pub fn pre_instantiate(&self, module: &Module) -> HypervisorResult<InstancePre<StoreData>> {
        let mut linker: wasmtime::Linker<StoreData> = Linker::new(module.engine());
        let mut main_memory_type = WasmMemoryType::Wasm32;

        if let Some(export) = module.get_export(WASM_HEAP_MEMORY_NAME)
            && let Some(mem) = export.memory()
            && mem.is_64()
        {
            main_memory_type = WasmMemoryType::Wasm64;
        }

        match main_memory_type {
            WasmMemoryType::Wasm32 => {
                linker::syscalls::<u32>(
                    &mut linker,
                    self.config.feature_flags,
                    self.config.stable_memory_dirty_page_limit,
                    self.config.stable_memory_accessed_page_limit,
                    main_memory_type,
                );
            }
            WasmMemoryType::Wasm64 => {
                linker::syscalls::<u64>(
                    &mut linker,
                    self.config.feature_flags,
                    self.config.stable_memory_dirty_page_limit,
                    self.config.stable_memory_accessed_page_limit,
                    main_memory_type,
                );
            }
        }

        let instance_pre = linker.instantiate_pre(module).map_err(|e| {
            HypervisorError::WasmEngineError(WasmEngineError::FailedToInstantiateModule(format!(
                "{e:?}"
            )))
        })?;

        // Note that a wasmtime::InstancePre object is cheaply clonable (just doing
        // a bit of reference counting, i.e. it is a "shallow copy"). This is
        // important because EmbedderCache is cloned frequently, and that must
        // not be an expensive operation.
        Ok(instance_pre)
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
                        format!("{err:?}"),
                    ))
                },
            )
        }
    }

    pub fn deserialize_module_and_pre_instantiate(
        &self,
        serialized_module: &SerializedModuleBytes,
    ) -> HypervisorResult<InstancePre<StoreData>> {
        let module = self.deserialize_module(serialized_module)?;
        self.pre_instantiate(&module)
    }

    fn deserialize_from_file(&self, serialized_module: File) -> HypervisorResult<Module> {
        // SAFETY: The compilation cache setup guarantees that this file is a
        // valid serialized module and will not be modified after initial
        // creation.
        unsafe {
            Module::deserialize_open_file(&self.create_engine()?, serialized_module).map_err(
                |err| {
                    HypervisorError::WasmEngineError(WasmEngineError::FailedToDeserializeModule(
                        format!("{err:?}"),
                    ))
                },
            )
        }
    }

    pub fn read_file_and_pre_instantiate(
        &self,
        serialized_module: File,
    ) -> HypervisorResult<InstancePre<StoreData>> {
        let module = self.deserialize_from_file(serialized_module)?;
        self.pre_instantiate(&module)
    }

    fn list_memory_infos(
        &self,
        modification_tracking: ModificationTracking,
        heap_memory: &execution_state::Memory,
        stable_memory: &execution_state::Memory,
    ) -> Vec<WasmMemoryInfo> {
        let dirty_page_tracking = match modification_tracking {
            ModificationTracking::Ignore => DirtyPageTracking::Ignore,
            ModificationTracking::Track => DirtyPageTracking::Track,
        };

        let mut result = vec![WasmMemoryInfo {
            name: WASM_HEAP_MEMORY_NAME,
            bytemap_name: None,
            memory: heap_memory.clone(),
            memory_type: CanisterMemoryType::Heap,
            dirty_page_tracking,
        }];

        result.push(WasmMemoryInfo {
            name: STABLE_MEMORY_NAME,
            bytemap_name: Some(STABLE_BYTEMAP_MEMORY_NAME),
            memory: stable_memory.clone(),
            memory_type: CanisterMemoryType::Stable,
            // Wasm native stable memory will always be tracked by a
            // bytemap within the wasm module.
            dirty_page_tracking: DirtyPageTracking::Ignore,
        });

        result
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::result_large_err)]
    pub fn new_instance(
        &self,
        canister_id: CanisterId,
        cache: &EmbedderCache,
        exported_globals: Option<&[Global]>,
        heap_memory: &execution_state::Memory,
        stable_memory: &execution_state::Memory,
        modification_tracking: ModificationTracking,
        system_api: Option<SystemApiImpl>,
    ) -> Result<WasmtimeInstance, (HypervisorError, Option<SystemApiImpl>)> {
        let instance_pre = match cache
            .downcast::<HypervisorResult<InstancePre<StoreData>>>()
            .expect("incompatible embedder cache, expected HypervisorResult<wasmtime::InstancePre<StoreData>>>")
        {
            Ok(x) => x,
            Err(err) => return Err((err.clone(), system_api)),
        };

        // Compute dirty page limit and access page limit based on the message type.
        let (current_dirty_page_limit, current_accessed_limit) = match system_api {
            Some(ref system_api) => (
                system_api.get_page_limit(&self.config.stable_memory_dirty_page_limit),
                system_api.get_page_limit(&self.config.stable_memory_accessed_page_limit),
            ),

            // If system api is not present, then this function has been called from
            // get_initial_globals_and_memory(). In this case, the number of
            // dirty pages does not matter as the canister is not running.
            None => (
                self.config.stable_memory_dirty_page_limit.message,
                self.config.stable_memory_accessed_page_limit.message,
            ),
        };

        let stable_memory_limits = MemoryLimits {
            max_memory_size: self.config.max_stable_memory_size,
            max_accessed_pages: current_accessed_limit,
            max_dirty_pages: current_dirty_page_limit,
        };
        let max_heap_memory_size = self
            .config
            .max_wasm_memory_size
            .max(self.config.max_wasm64_memory_size);
        let heap_memory_limits = MemoryLimits {
            max_memory_size: max_heap_memory_size,
            max_accessed_pages: NumOsPages::new(max_heap_memory_size.get() / PAGE_SIZE as u64),
            max_dirty_pages: NumOsPages::new(max_heap_memory_size.get() / PAGE_SIZE as u64),
        };

        let mut store = Store::new(
            instance_pre.module().engine(),
            StoreData {
                system_api,
                num_instructions_global: None,
                log: self.log.clone(),
                limits: StoreLimitsBuilder::new()
                    .memory_size(self.config.max_stable_memory_size.get() as usize)
                    .tables(MAX_STORE_TABLES)
                    .table_elements(MAX_STORE_TABLE_ELEMENTS)
                    .build(),
                canister_backtrace: self.config.feature_flags.canister_backtrace,
            },
        );
        store.limiter(|state| &mut state.limits);

        let instance = match instance_pre.instantiate(&mut store) {
            Ok(instance) => instance,
            Err(err) => {
                error!(
                    self.log,
                    "Failed to instantiate module for {}: {}", canister_id, err
                );
                return Err((
                    HypervisorError::WasmEngineError(WasmEngineError::FailedToInstantiateModule(
                        format!("{err:?}"),
                    )),
                    store.into_data().system_api,
                ));
            }
        };

        store.data_mut().num_instructions_global =
            instance.get_global(&mut store, INSTRUCTIONS_COUNTER_GLOBAL_NAME);

        if let Some(exported_globals) = exported_globals {
            let instance_globals = get_exported_globals(&instance, &mut store);

            if exported_globals.len() != instance_globals.len() {
                fatal!(
                    self.log,
                    "Given number of exported globals {} is not equal to the number of instance exported globals {}",
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
                                Global::V128(val) => Val::V128((*val).into()),
                            },
                        )
                        .unwrap_or_else(|e| {
                            let v = match v {
                                Global::I32(val) => (val).to_string(),
                                Global::I64(val) => (val).to_string(),
                                Global::F32(val) => (val).to_string(),
                                Global::F64(val) => (val).to_string(),
                                Global::V128(val) => (val).to_string(),
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
        }

        instance
            .get_global(&mut store, DIRTY_PAGES_COUNTER_GLOBAL_NAME)
            .expect(
                "Counter for dirty pages global should have been added \
                with native stable memory enabled.",
            )
            .set(&mut store, Val::I64(current_dirty_page_limit.get() as i64))
            .expect("Couldn't set dirty page counter global");
        instance
            .get_global(&mut store, ACCESSED_PAGES_COUNTER_GLOBAL_NAME)
            .expect(
                "Counter for accessed pages global should have been added \
                with native stable memory enabled.",
            )
            .set(&mut store, Val::I64(current_accessed_limit.get() as i64))
            .expect("Couldn't set dirty page counter global");

        let mut memories = HashMap::new();
        for mem_info in self.list_memory_infos(modification_tracking, heap_memory, stable_memory) {
            let memory_limits = match mem_info.memory_type {
                CanisterMemoryType::Heap => &heap_memory_limits,
                CanisterMemoryType::Stable => &stable_memory_limits,
            };
            if let Err(e) = self.instantiate_memory(
                mem_info,
                &instance,
                &mut store,
                &mut memories,
                canister_id,
                memory_limits,
            ) {
                return Err((e, store.into_data().system_api));
            }
        }

        let memory_trackers = sigsegv_memory_tracker(memories, &mut store, self.log.clone());

        let signal_stack = WasmtimeSignalStack::new();
        let mut main_memory_type = WasmMemoryType::Wasm32;
        if let Some(mem) = instance.get_memory(&mut store, WASM_HEAP_MEMORY_NAME)
            && mem.ty(&store).is_64()
        {
            main_memory_type = WasmMemoryType::Wasm64;
        }
        let dirty_page_overhead = match main_memory_type {
            WasmMemoryType::Wasm32 => self.config.dirty_page_overhead,
            WasmMemoryType::Wasm64 => NumInstructions::from(
                self.config.dirty_page_overhead.get()
                    * self.config.wasm64_dirty_page_overhead_multiplier,
            ),
        };

        Ok(WasmtimeInstance {
            instance,
            memory_trackers,
            signal_stack,
            log: self.log.clone(),
            instance_stats: InstanceStats::default(),
            store,
            canister_backtrace: self.config.feature_flags.canister_backtrace,
            modification_tracking,
            dirty_page_overhead,
            #[cfg(debug_assertions)]
            stable_memory_dirty_page_limit: current_dirty_page_limit,
            stable_memory_page_access_limit: current_accessed_limit,
            main_memory_type,
        })
    }

    fn instantiate_memory(
        &self,
        memory_info: WasmMemoryInfo,
        instance: &Instance,
        mut store: &mut Store<StoreData>,
        memories_to_track: &mut HashMap<CanisterMemoryType, MemorySigSegvInfo>,
        canister_id: CanisterId,
        memory_limits: &MemoryLimits,
    ) -> HypervisorResult<()> {
        if let Some(instance_memory) = instance.get_memory(&mut store, memory_info.name) {
            let current_size = instance_memory.size(&store);
            let requested_size = memory_info.memory.size.get() as u64;

            if current_size < requested_size {
                let delta = requested_size - current_size;
                instance_memory
                    .grow(&mut store, delta)
                    .expect("memory grow failed");
            }
            let start = MemoryStart(instance_memory.data_ptr(&store) as usize);
            let mut created_memories = self.created_memories.lock().unwrap();
            let current_size = match created_memories.remove(&start) {
                None => {
                    error!(
                        self.log,
                        "Unable to find memory for canister {} when instantiating", canister_id
                    );
                    return Err(HypervisorError::WasmEngineError(
                        WasmEngineError::FailedToInstantiateModule(
                            "Unable to find memory when instantiating".to_string(),
                        ),
                    ));
                }
                Some(current_memory_size_in_pages) => current_memory_size_in_pages,
            };
            memories_to_track.insert(
                memory_info.memory_type,
                MemorySigSegvInfo {
                    instance_memory,
                    current_memory_size_in_pages: current_size,
                    page_map: memory_info.memory.page_map.clone(),
                    dirty_page_tracking: memory_info.dirty_page_tracking,
                    memory_limits: memory_limits.clone(),
                },
            );

            if let Some(bytemap_name) = memory_info.bytemap_name {
                self.bytemap_protect_read_write(
                    bytemap_name,
                    instance,
                    store,
                    &mut created_memories,
                    canister_id,
                )?;
            }
        }
        Ok(())
    }

    /// We don't need to track changes to the bytemap so it can
    /// be immediately read/write permissioned and we don't have
    /// to register it with the sigsegv tracker.
    fn bytemap_protect_read_write(
        &self,
        bytemap_name: &str,
        instance: &Instance,
        mut store: &mut Store<StoreData>,
        created_memories: &mut HashMap<MemoryStart, MemoryPageSize>,
        canister_id: CanisterId,
    ) -> HypervisorResult<()> {
        let memory =
            instance
                .get_memory(&mut store, bytemap_name)
                .and_then(|bytemap_instance_memory| {
                    let start = MemoryStart(bytemap_instance_memory.data_ptr(&store) as usize);
                    created_memories
                        .remove(&start)
                        .map(|s| (bytemap_instance_memory, s))
                });
        match memory {
            None => {
                error!(
                    self.log,
                    "Unable to find memory bytemap for canister {} when instantiating", canister_id
                );
                Err(HypervisorError::WasmEngineError(
                    WasmEngineError::FailedToInstantiateModule(
                        "Unable to find bytemap memory when instantiating".to_string(),
                    ),
                ))
            }
            Some((instance_memory, current_memory_size_in_pages)) => {
                let addr = instance_memory.data_ptr(store) as usize;
                let size_in_bytes =
                    current_memory_size_in_pages.load(Ordering::SeqCst) * WASM_PAGE_SIZE_IN_BYTES;
                use nix::sys::mman;
                // SAFETY: This is the array we created in the host_memory creator, so we know it is a valid memory region that we own.
                unsafe {
                    mman::mprotect(
                        addr as *mut _,
                        size_in_bytes,
                        mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                    )
                    .unwrap();
                }
                Ok(())
            }
        }
    }

    pub fn config(&self) -> &EmbeddersConfig {
        &self.config
    }
}

pub struct MemorySigSegvInfo {
    instance_memory: wasmtime::Memory,
    current_memory_size_in_pages: MemoryPageSize,
    page_map: PageMap,
    dirty_page_tracking: DirtyPageTracking,
    memory_limits: MemoryLimits,
}

fn sigsegv_memory_tracker<S>(
    memories: HashMap<CanisterMemoryType, MemorySigSegvInfo>,
    store: &mut wasmtime::Store<S>,
    log: ReplicaLogger,
) -> HashMap<CanisterMemoryType, Arc<Mutex<SigsegvMemoryTracker>>> {
    let mut tracked_memories = vec![];
    let mut result = HashMap::new();
    for (
        mem_type,
        MemorySigSegvInfo {
            instance_memory,
            current_memory_size_in_pages,
            page_map,
            dirty_page_tracking,
            memory_limits,
        },
    ) in memories
    {
        let base = instance_memory.data_ptr(&store);
        let size = instance_memory.data_size(&store);

        let sigsegv_memory_tracker = {
            // For both SIGSEGV and in the future UFFD memory tracking we need
            // the base address of the heap and its size
            let base = base as *mut libc::c_void;
            if !(base as usize).is_multiple_of(PAGE_SIZE) {
                fatal!(log, "[EXC-BUG] Memory tracker - Heap must be page aligned.");
            }
            if !size.is_multiple_of(PAGE_SIZE) {
                fatal!(
                    log,
                    "[EXC-BUG] Memory tracker - Heap size must be a multiple of page size."
                );
            }

            Arc::new(Mutex::new(
                memory_tracker::new(
                    base,
                    NumBytes::new(size as u64),
                    log.clone(),
                    dirty_page_tracking,
                    page_map,
                    memory_limits,
                )
                .expect("failed to instantiate SIGSEGV memory tracker"),
            ))
        };
        result.insert(mem_type, Arc::clone(&sigsegv_memory_tracker));
        tracked_memories.push((sigsegv_memory_tracker, current_memory_size_in_pages));
    }

    let handler = signal_handler::sigsegv_memory_tracker_handler(tracked_memories);
    // http://man7.org/linux/man-pages/man7/signal-safety.7.html
    unsafe {
        store.set_signal_handler(handler);
    };
    result
}

/// Additional types that need to be owned by the `wasmtime::Store`.
pub struct StoreData {
    pub system_api: Option<SystemApiImpl>,
    pub num_instructions_global: Option<wasmtime::Global>,
    pub log: ReplicaLogger,
    pub limits: StoreLimits,
    pub canister_backtrace: FlagStatus,
}

impl StoreData {
    pub fn system_api(&self) -> HypervisorResult<&SystemApiImpl> {
        self.system_api.as_ref().ok_or_else(|| {
            HypervisorError::WasmEngineError(WasmEngineError::Other(
                "System api not present in data store".to_string(),
            ))
        })
    }

    pub fn system_api_mut(&mut self) -> HypervisorResult<&mut SystemApiImpl> {
        self.system_api.as_mut().ok_or_else(|| {
            HypervisorError::WasmEngineError(WasmEngineError::Other(
                "System api not present in data store".to_string(),
            ))
        })
    }

    pub fn system_api_mut_log(&mut self) -> HypervisorResult<(&mut SystemApiImpl, &ReplicaLogger)> {
        let api = self.system_api.as_mut().ok_or_else(|| {
            HypervisorError::WasmEngineError(WasmEngineError::Other(
                "System api not present in data store".to_string(),
            ))
        })?;
        Ok((api, &self.log))
    }
}

#[derive(Debug, Default)]
pub struct PageAccessResults {
    pub wasm_dirty_pages: Vec<PageIndex>,
    pub wasm_num_accessed_pages: usize,
    /// Non-deterministic number of dirty OS (4 KiB) pages (write).
    pub wasm_dirty_os_pages_count: usize,
    /// Non-deterministic number of dirty Wasm (64 KiB) pages (write).
    pub wasm_dirty_wasm_pages_count: usize,
    /// Non-deterministic number of accessed OS (4 KiB) pages (read + write).
    pub wasm_accessed_os_pages_count: usize,
    /// Non-deterministic number of accessed Wasm (64 KiB) pages (read + write).
    pub wasm_accessed_wasm_pages_count: usize,
    pub wasm_read_before_write_count: usize,
    pub wasm_direct_write_count: usize,
    pub wasm_sigsegv_count: usize,
    pub wasm_mmap_count: usize,
    pub wasm_mprotect_count: usize,
    pub wasm_copy_page_count: usize,
    pub wasm_sigsegv_handler_duration: Duration,
    pub stable_dirty_pages: Vec<PageIndex>,
    pub stable_accessed_pages: usize,
    pub stable_read_before_write_count: usize,
    pub stable_direct_write_count: usize,
    pub stable_sigsegv_count: usize,
    pub stable_mmap_count: usize,
    pub stable_mprotect_count: usize,
    pub stable_copy_page_count: usize,
    pub stable_sigsegv_handler_duration: Duration,
}

/// Encapsulates a Wasmtime instance on the Internet Computer.
pub struct WasmtimeInstance {
    instance: wasmtime::Instance,
    memory_trackers: HashMap<CanisterMemoryType, Arc<Mutex<SigsegvMemoryTracker>>>,
    signal_stack: WasmtimeSignalStack,
    log: ReplicaLogger,
    instance_stats: InstanceStats,
    store: wasmtime::Store<StoreData>,
    #[allow(unused)]
    canister_backtrace: FlagStatus,
    modification_tracking: ModificationTracking,
    dirty_page_overhead: NumInstructions,
    #[cfg(debug_assertions)]
    #[allow(dead_code)]
    stable_memory_dirty_page_limit: ic_types::NumOsPages,
    stable_memory_page_access_limit: ic_types::NumOsPages,
    main_memory_type: WasmMemoryType,
}

impl WasmtimeInstance {
    pub fn into_store_data(self) -> StoreData {
        self.store.into_data()
    }

    pub fn store_data_mut(&mut self) -> &mut StoreData {
        self.store.data_mut()
    }

    pub fn store_data(&self) -> &StoreData {
        self.store.data()
    }

    fn invoke_export(&mut self, export: &str, args: &[Val]) -> HypervisorResult<()> {
        self.instance
            .get_export(&mut self.store, export)
            .ok_or_else(|| {
                HypervisorError::MethodNotFound(WasmMethod::try_from(export.to_string()).unwrap())
            })?
            .into_func()
            .ok_or_else(|| HypervisorError::ToolchainContractViolation {
                error: "export is not a function".to_string(),
            })?
            .call(&mut self.store, args, &mut [])
            .map_err(wasmtime_error_to_hypervisor_error)
    }

    fn page_accesses(&mut self) -> HypervisorResult<PageAccessResults> {
        let stable_dirty_pages = self.stable_dirty_pages_from_bytemap()?;

        // Get stable accessed pages from the global counter.
        let stable_accessed_pages = (self.stable_memory_page_access_limit.get() as i64
            - self
                .instance
                .get_global(&mut self.store, ACCESSED_PAGES_COUNTER_GLOBAL_NAME)
                .unwrap()
                .get(&mut self.store)
                .i64()
                .unwrap()) as usize;

        if !self.memory_trackers.contains_key(&CanisterMemoryType::Heap) {
            debug!(
                self.log,
                "Memory tracking disabled. Returning empty list of dirty pages"
            );
            Ok(PageAccessResults {
                stable_dirty_pages,
                stable_accessed_pages,
                ..PageAccessResults::default()
            })
        } else {
            let wasm_tracker = self
                .memory_trackers
                .get(&CanisterMemoryType::Heap)
                .unwrap()
                .lock()
                .unwrap();

            let speculatively_dirty_pages = wasm_tracker.take_speculatively_dirty_pages();
            let dirty_pages = wasm_tracker.take_dirty_pages();
            let (wasm_dirty_os_pages_count, wasm_dirty_wasm_pages_count) =
                dirty_os_and_wasm_pages(&speculatively_dirty_pages, &dirty_pages);

            let accessed_pages = wasm_tracker.take_accessed_pages();
            let (wasm_accessed_os_pages_count, wasm_accessed_wasm_pages_count) =
                accessed_os_and_wasm_pages(&accessed_pages);

            let wasm_dirty_pages = match self.modification_tracking {
                ModificationTracking::Track => dirty_pages
                    .into_iter()
                    .chain(speculatively_dirty_pages)
                    .filter_map(|p| wasm_tracker.validate_speculatively_dirty_page(p))
                    .collect::<Vec<PageIndex>>(),
                ModificationTracking::Ignore => vec![],
            };

            let wasm_sigsegv_handler_duration = wasm_tracker.metrics().sigsegv_handler_duration();

            // We don't have a tracker for stable memory.
            if !self
                .memory_trackers
                .contains_key(&CanisterMemoryType::Stable)
            {
                return Ok(PageAccessResults {
                    wasm_dirty_pages,
                    wasm_num_accessed_pages: wasm_tracker.num_accessed_pages(),
                    wasm_dirty_os_pages_count,
                    wasm_dirty_wasm_pages_count,
                    wasm_accessed_os_pages_count,
                    wasm_accessed_wasm_pages_count,
                    wasm_read_before_write_count: wasm_tracker.metrics().read_before_write_count(),
                    wasm_direct_write_count: wasm_tracker.metrics().direct_write_count(),
                    wasm_sigsegv_count: wasm_tracker.metrics().sigsegv_count(),
                    wasm_mmap_count: wasm_tracker.metrics().mmap_count(),
                    wasm_mprotect_count: wasm_tracker.metrics().mprotect_count(),
                    wasm_copy_page_count: wasm_tracker.metrics().copy_page_count(),
                    wasm_sigsegv_handler_duration,
                    stable_dirty_pages,
                    stable_accessed_pages,
                    ..Default::default()
                });
            }

            let stable_tracker = self
                .memory_trackers
                .get(&CanisterMemoryType::Stable)
                .unwrap()
                .lock()
                .unwrap();

            let stable_sigsegv_handler_duration =
                stable_tracker.metrics().sigsegv_handler_duration();

            Ok(PageAccessResults {
                wasm_dirty_pages,
                wasm_num_accessed_pages: wasm_tracker.num_accessed_pages(),
                wasm_dirty_os_pages_count,
                wasm_dirty_wasm_pages_count,
                wasm_accessed_os_pages_count,
                wasm_accessed_wasm_pages_count,
                wasm_read_before_write_count: wasm_tracker.metrics().read_before_write_count(),
                wasm_direct_write_count: wasm_tracker.metrics().direct_write_count(),
                wasm_sigsegv_count: wasm_tracker.metrics().sigsegv_count(),
                wasm_mmap_count: wasm_tracker.metrics().mmap_count(),
                wasm_mprotect_count: wasm_tracker.metrics().mprotect_count(),
                wasm_copy_page_count: wasm_tracker.metrics().copy_page_count(),
                wasm_sigsegv_handler_duration,
                stable_dirty_pages,
                stable_accessed_pages,
                stable_read_before_write_count: stable_tracker.metrics().read_before_write_count(),
                stable_direct_write_count: stable_tracker.metrics().direct_write_count(),
                stable_sigsegv_count: stable_tracker.metrics().sigsegv_count(),
                stable_mmap_count: stable_tracker.metrics().mmap_count(),
                stable_mprotect_count: stable_tracker.metrics().mprotect_count(),
                stable_copy_page_count: stable_tracker.metrics().copy_page_count(),
                stable_sigsegv_handler_duration,
            })
        }
    }

    fn get_memory(&mut self, name: &str) -> HypervisorResult<Memory> {
        match self.instance.get_export(&mut self.store, name) {
            Some(export) => {
                export
                    .into_memory()
                    .ok_or_else(|| HypervisorError::ToolchainContractViolation {
                        error: format!("export '{name}' is not a memory"),
                    })
            }
            None => Err(HypervisorError::ToolchainContractViolation {
                error: format!("export '{name}' not found"),
            }),
        }
    }

    fn set_instance_stats(&mut self, res: &PageAccessResults) {
        self.instance_stats = InstanceStats {
            wasm_accessed_pages: res.wasm_num_accessed_pages,
            wasm_accessed_os_pages_count: res.wasm_accessed_os_pages_count,
            wasm_accessed_wasm_pages_count: res.wasm_accessed_wasm_pages_count,
            wasm_dirty_pages: res.wasm_dirty_pages.len(),
            wasm_dirty_os_pages_count: res.wasm_dirty_os_pages_count,
            wasm_dirty_wasm_pages_count: res.wasm_dirty_wasm_pages_count,
            wasm_read_before_write_count: res.wasm_read_before_write_count,
            wasm_direct_write_count: res.wasm_direct_write_count,
            wasm_sigsegv_count: res.wasm_sigsegv_count,
            wasm_mmap_count: res.wasm_mmap_count,
            wasm_mprotect_count: res.wasm_mprotect_count,
            wasm_copy_page_count: res.wasm_copy_page_count,
            wasm_sigsegv_handler_duration: res.wasm_sigsegv_handler_duration,
            stable_accessed_pages: res.stable_accessed_pages,
            stable_dirty_pages: res.stable_dirty_pages.len(),
            stable_read_before_write_count: res.stable_read_before_write_count,
            stable_direct_write_count: res.stable_direct_write_count,
            stable_sigsegv_count: res.stable_sigsegv_count,
            stable_mmap_count: res.stable_mmap_count,
            stable_mprotect_count: res.stable_mprotect_count,
            stable_copy_page_count: res.stable_copy_page_count,
            stable_sigsegv_handler_duration: res.stable_sigsegv_handler_duration,
        };
    }

    /// Executes first exported method on an embedder instance, whose name
    /// consists of one of the prefixes and method_name.
    pub fn run(&mut self, func_ref: FuncRef) -> HypervisorResult<InstanceRunResult> {
        let _alt_sig_stack = unsafe { self.signal_stack.register() };

        let result = match &func_ref {
            FuncRef::Method(wasm_method) => self.invoke_export(&wasm_method.to_string(), &[]),
            FuncRef::QueryClosure(closure) | FuncRef::UpdateClosure(closure) => {
                let call_args = match self.main_memory_type {
                    WasmMemoryType::Wasm32 => {
                        // Wasm32 closure should hold a value which fits in u32
                        let Ok(env32): Result<u32, _> = closure.env.try_into() else {
                            return Err(HypervisorError::ToolchainContractViolation {
                                error: format!(
                                    "error converting additional value {} to u32",
                                    closure.env
                                ),
                            });
                        };
                        [Val::I32(env32 as i32)]
                    }
                    WasmMemoryType::Wasm64 => [Val::I64(closure.env as i64)],
                };

                self.instance
                    .get_export(&mut self.store, "table")
                    .ok_or_else(|| HypervisorError::ToolchainContractViolation {
                        error: "table not found".to_string(),
                    })?
                    .into_table()
                    .ok_or_else(|| HypervisorError::ToolchainContractViolation {
                        error: "export 'table' is not a table".to_string(),
                    })?
                    .get(&mut self.store, closure.func_idx as u64)
                    .ok_or(HypervisorError::FunctionNotFound(0, closure.func_idx))?
                    .as_func()
                    .ok_or_else(|| HypervisorError::ToolchainContractViolation {
                        error: "not a function reference".to_string(),
                    })?
                    .ok_or_else(|| HypervisorError::ToolchainContractViolation {
                        error: "unexpected null function reference".to_string(),
                    })?
                    .call(&mut self.store, &call_args, &mut [])
                    .map_err(wasmtime_error_to_hypervisor_error)
            }
        }
        .map_err(|e| {
            let exec_err = self
                .store
                .data()
                .system_api()
                .map(|api| api.get_execution_error().cloned());
            match exec_err {
                Ok(Some(HypervisorError::WasmEngineError(WasmEngineError::Unexpected(err)))) => {
                    // safe to unwrap because previous line succeeded
                    let cid = self.store.data().system_api().unwrap().canister_id();
                    error!(self.log, "[EXC-BUG] Canister {}: {}", cid, err);
                    HypervisorError::WasmEngineError(WasmEngineError::Unexpected(err))
                }
                Ok(Some(err)) => err,
                Ok(None) => e,
                Err(_) => e,
            }
        });

        if let Err(HypervisorError::Aborted) = result {
            // The replica process has aborted the execution and the memory may
            // have already been dropped. Return early instead of trying to
            // compute instance stats because they will not be used anyway.
            return Err(HypervisorError::Aborted);
        }

        let access = self.page_accesses()?;
        self.set_instance_stats(&access);

        // Charge for dirty wasm heap pages.
        let x = self.instruction_counter().saturating_sub_unsigned(
            self.dirty_page_overhead
                .get()
                .saturating_mul(access.wasm_dirty_pages.len() as u64),
        );
        self.set_instruction_counter(x);

        match result {
            Ok(_) => Ok(InstanceRunResult {
                exported_globals: self.get_exported_globals()?,
                wasm_dirty_pages: access.wasm_dirty_pages,
                stable_memory_dirty_pages: access.stable_dirty_pages,
            }),
            Err(err) => Err(err),
        }
    }

    fn stable_dirty_pages_from_bytemap(&mut self) -> HypervisorResult<Vec<PageIndex>> {
        let mut result = vec![];
        if let Ok(heap_memory) = self.get_memory(STABLE_MEMORY_NAME) {
            let bytemap = self
                .get_memory(STABLE_BYTEMAP_MEMORY_NAME)?
                .data(&self.store);
            let tracker = self
                .memory_trackers
                .get(&CanisterMemoryType::Stable)
                .ok_or_else(|| HypervisorError::ToolchainContractViolation {
                    error: "No memory tracker for stable memory".to_string(),
                })?;
            let tracker = tracker.lock().unwrap();
            let heap_memory = heap_memory.data(&self.store);

            fn handle_bytemap_entry(
                previous_page_marked_written: &mut bool,
                result: &mut Vec<PageIndex>,
                page_index: usize,
                heap_memory: &[u8],
                tracker: &SigsegvMemoryTracker,
                written: u8,
            ) -> HypervisorResult<()> {
                let index = PageIndex::new(page_index as u64);
                match written & 0x1 {
                    1 => {
                        result.push(index);
                        *previous_page_marked_written = true;
                        Ok(())
                    }
                    0 => {
                        // We must check that the page was accessed during
                        // execution before trying to read it because if it
                        // wasn't accessed then it will still be mapped
                        // `PROT_NONE` and trying to read it will segfault.
                        if *previous_page_marked_written && tracker.is_accessed(index) {
                            // An unaligned V128 write to the previous page may
                            // have written as many as 15 bytes into this page.
                            // So even if we didn't see a write here we need to
                            // check that the first 15 bytes haven't been
                            // modified to be sure it isn't dirty.
                            let first_bytes = &heap_memory[PAGE_SIZE * page_index
                                ..PAGE_SIZE * page_index + size_of::<u128>() - 1];
                            let previous_bytes = &tracker.get_page(index)[0..size_of::<u128>() - 1];
                            if first_bytes != previous_bytes {
                                result.push(index);
                            }
                        }
                        *previous_page_marked_written = false;
                        Ok(())
                    }
                    _ => Err(HypervisorError::ToolchainContractViolation {
                        error: format!("Bytemap contains invalid value {written}"),
                    }),
                }
            }

            // We only need to scan the bytemap up to and including the last
            // page that is actually used by the existing memory (i.e. the page
            // of the last byte of heap memory).
            let bytemap = &bytemap[0..=(heap_memory.len().saturating_sub(1)) / PAGE_SIZE];
            // SAFETY: It is always safe to transmute a sequence of `u8` to a
            // `u128`. These will then be converted back to `u8` using
            // the native ordering.
            let (prefix, middle, suffix) = unsafe { bytemap.align_to::<u128>() };
            let mut previous_page_marked_written = false;
            let mut page_index: usize = 0;
            for written in prefix {
                handle_bytemap_entry(
                    &mut previous_page_marked_written,
                    &mut result,
                    page_index,
                    heap_memory,
                    &tracker,
                    *written,
                )?;
                page_index += 1;
            }
            for group in middle {
                if *group != 0 {
                    for (group_index, written) in group.to_ne_bytes().iter().enumerate() {
                        handle_bytemap_entry(
                            &mut previous_page_marked_written,
                            &mut result,
                            page_index + group_index,
                            heap_memory,
                            &tracker,
                            *written,
                        )?;
                    }
                }
                page_index += size_of::<u128>();
            }
            for written in suffix {
                handle_bytemap_entry(
                    &mut previous_page_marked_written,
                    &mut result,
                    page_index,
                    heap_memory,
                    &tracker,
                    *written,
                )?;
                page_index += 1;
            }
        }
        Ok(result)
    }

    /// Sets the instruction counter to the given value.
    pub fn set_instruction_counter(&mut self, instruction_counter: i64) {
        match self.store.data().num_instructions_global {
            Some(num_instructions_global) => {
                match num_instructions_global.set(&mut self.store, Val::I64(instruction_counter)) {
                    Ok(_) => (),
                    Err(e) => panic!("couldn't set the instruction counter: {e:?}"),
                }
            }
            None => panic!("couldn't find the instruction counter in the canister globals"),
        }
    }

    /// Returns the current instruction counter.
    pub fn instruction_counter(&mut self) -> i64 {
        let Some(num_instructions) = self.store.data().num_instructions_global else {
            panic!("couldn't find the instruction counter in the canister globals");
        };
        let Val::I64(instruction_counter) = num_instructions.get(&mut self.store) else {
            panic!("invalid instruction counter type");
        };
        instruction_counter
    }

    /// Returns the heap size.
    /// Result is guaranteed to fit in a `u32`.
    pub fn heap_size(&mut self, canister_memory_type: CanisterMemoryType) -> NumWasmPages {
        let name = match canister_memory_type {
            CanisterMemoryType::Heap => WASM_HEAP_MEMORY_NAME,
            CanisterMemoryType::Stable => STABLE_MEMORY_NAME,
        };
        NumWasmPages::from(self.get_memory(name).map_or(0, |mem| mem.size(&self.store)) as usize)
    }

    /// Returns true iff the Wasm memory is 32 bit.
    pub fn is_wasm32(&self) -> bool {
        matches!(self.main_memory_type, WasmMemoryType::Wasm32)
    }

    /// Returns a list of exported globals.
    pub fn get_exported_globals(&mut self) -> HypervisorResult<Vec<Global>> {
        let globals = get_exported_globals(&self.instance, &mut self.store);

        globals
            .iter()
            .map(|g| match g.ty(&self.store).content() {
                ValType::I32 => Ok(Global::I32(
                    g.get(&mut self.store).i32().expect("global i32"),
                )),
                ValType::I64 => Ok(Global::I64(
                    g.get(&mut self.store).i64().expect("global i64"),
                )),
                ValType::F32 => Ok(Global::F32(
                    g.get(&mut self.store).f32().expect("global f32"),
                )),
                ValType::F64 => Ok(Global::F64(
                    g.get(&mut self.store).f64().expect("global f64"),
                )),
                ValType::V128 => Ok(Global::V128(
                    g.get(&mut self.store).v128().expect("global v128").into(),
                )),
                _ => Err(HypervisorError::WasmEngineError(WasmEngineError::Other(
                    "Unexpected global value type".to_string(),
                ))),
            })
            .collect()
    }

    /// Return the heap address. If the Instance does not contain any memory,
    /// the pointer is null.
    ///
    /// # Safety
    /// This function returns a pointer to Instance's memory. The pointer is
    /// only valid while the Instance object is kept alive.
    pub unsafe fn heap_addr(&mut self, canister_memory_type: CanisterMemoryType) -> *const u8 {
        let name = match canister_memory_type {
            CanisterMemoryType::Heap => WASM_HEAP_MEMORY_NAME,
            CanisterMemoryType::Stable => STABLE_MEMORY_NAME,
        };
        self.get_memory(name)
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

const OS_PAGES_PER_WASM_PAGE: usize = WASM_PAGE_SIZE_IN_BYTES / PAGE_SIZE;
fn accessed_os_and_wasm_pages(accessed_pages: &[PageIndex]) -> (usize, usize) {
    let wasm_pages: HashSet<u64> = accessed_pages
        .iter()
        .map(|&os_index| os_index.get() / OS_PAGES_PER_WASM_PAGE as u64)
        .collect();
    (accessed_pages.len(), wasm_pages.len())
}

fn dirty_os_and_wasm_pages(
    speculatively_dirty_pages: &[PageIndex],
    dirty_pages: &[PageIndex],
) -> (usize, usize) {
    let wasm_pages: HashSet<u64> = speculatively_dirty_pages
        .iter()
        .chain(dirty_pages.iter())
        .map(|&os_index| os_index.get() / OS_PAGES_PER_WASM_PAGE as u64)
        .collect();
    (
        dirty_pages.len() + speculatively_dirty_pages.len(),
        wasm_pages.len(),
    )
}
