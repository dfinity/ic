pub mod host_memory;

use host_memory::MmapMemoryCreator;
pub use host_memory::WasmtimeMemoryCreator;

mod signal_stack;
mod system_api;

#[cfg(test)]
mod wasmtime_embedder_tests;

use super::InstanceRunResult;
use crate::cow_memory_creator::{CowMemoryCreator, CowMemoryCreatorProxy};

use ic_config::embedders::{Config, PersistenceType};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, InstanceStats, SystemApi, TrapCode,
};
use ic_logger::{debug, ReplicaLogger};
use ic_replicated_state::{EmbedderCache, Global, NumWasmPages, PageIndex, PageMap};
use ic_types::{
    methods::{FuncRef, WasmMethod},
    CanisterId, NumInstructions,
};
use ic_wasm_types::{BinaryEncodedWasm, WasmEngineError};
use memory_tracker::{DirtyPageTracking, SigsegvMemoryTracker};
use signal_stack::WasmtimeSignalStack;
use std::cell::RefCell;
use std::convert::TryFrom;
use std::rc::Rc;
use std::sync::Arc;
use system_api::SystemApiHandle;
use wasmtime::{unix::StoreExt, Memory, Mutability, Store, Val, ValType};

fn trap_to_error(err: anyhow::Error) -> HypervisorError {
    let message = format!("{}", err);
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
}

impl WasmtimeEmbedder {
    pub fn new(config: Config, log: ReplicaLogger) -> Self {
        let Config {
            max_wasm_stack_size,
            ..
        } = config;

        WasmtimeEmbedder {
            log,
            max_wasm_stack_size,
        }
    }

    pub fn compile(
        &self,
        persistence_type: PersistenceType,
        wasm_binary: &BinaryEncodedWasm,
    ) -> HypervisorResult<EmbedderCache> {
        let mut config = wasmtime::Config::default();
        ic_wasm_utils::ensure_determinism(&mut config);
        let cached_mem_creator = match persistence_type {
            PersistenceType::Sigsegv => {
                let raw_creator = MmapMemoryCreator {};
                let mem_creator = Arc::new(WasmtimeMemoryCreator::new(raw_creator));
                config.with_host_memory(mem_creator);
                None
            }
            _ /*Pagemap*/ => {
                let raw_creator = CowMemoryCreatorProxy::new(Arc::new(CowMemoryCreator::new_uninitialized()));
                let mem_creator = Arc::new(WasmtimeMemoryCreator::new(raw_creator.clone()));
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
            );

        // Wasmtime requires that the async stack is larger than the Wasm stack.
        // Since both `config.async_stack_size()` and `config.max_wasm_stack()` check
        // for that condition and we cannot query the default values, we have to
        // try calling the setters in two different orders and expect that one of them
        // succeeds.
        //
        // Since by default the async stack size is 2x of the wasm stack size,
        // we set the new value for the async stack size correspondingly.
        let async_stack_size = self.max_wasm_stack_size * 2;
        match config.async_stack_size(async_stack_size) {
            Ok(_) => {
                // The new `async_stack_size` is larger than the default `max_wasm_stack`,
                // the following should succeed.
                config
                    .max_wasm_stack(self.max_wasm_stack_size)
                    .map_err(|_| {
                        HypervisorError::WasmEngineError(WasmEngineError::FailedToSetWasmStack)
                    })?
            }
            Err(_) => {
                // The new `async_stack_size` is smaller than `max_wasm_stack`, which in turn
                // is smaller than the default `async_stack_size`. This means that the new
                // `max_wasm_stack` is smaller than the default `async_stack_size`, so the
                // following should succeed.
                config
                    .max_wasm_stack(self.max_wasm_stack_size)
                    .map_err(|_| {
                        HypervisorError::WasmEngineError(WasmEngineError::FailedToSetWasmStack)
                    })?
                    .async_stack_size(async_stack_size)
                    .map_err(|_| {
                        HypervisorError::WasmEngineError(WasmEngineError::FailedToSetAsyncStack)
                    })?
            }
        };

        let engine = wasmtime::Engine::new(&config).map_err(|_| {
            HypervisorError::WasmEngineError(WasmEngineError::FailedToInitializeEngine)
        })?;
        let module = wasmtime::Module::new(&engine, wasm_binary.as_slice()).map_err(|_| {
            HypervisorError::WasmEngineError(WasmEngineError::FailedToInstantiateModule)
        })?;
        Ok(EmbedderCache::new((module, cached_mem_creator)))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_instance(
        &self,
        canister_id: CanisterId,
        cache: &EmbedderCache,
        exported_globals: &[Global],
        heap_size: NumWasmPages,
        memory_creator: Option<Arc<CowMemoryCreator>>,
        page_map: Option<PageMap>,
        dirty_page_tracking: DirtyPageTracking,
    ) -> WasmtimeInstance {
        let (module, memory_creator_proxy) = cache
            .downcast::<(wasmtime::Module, Option<CowMemoryCreatorProxy>)>()
            .expect("incompatible embedder cache, expected BinaryEncodedWasm");

        assert_eq!(
            memory_creator.is_some(),
            memory_creator_proxy.is_some(),
            "We are caching mem creator if and only if mem_creator argument is not None,\
                    and both happen if persistence type is Pagemap"
        );

        let store = Store::new(&module.engine());
        let system_api_handle = SystemApiHandle::new();
        let canister_num_instructions_global = Rc::new(RefCell::new(None));

        // We need to pass a weak pointer to the canister_num_instructions_global,
        // because wasmtime::Global internally references Store and it would
        // create a cyclic reference. Since Store holds both the global and our
        // syscalls, syscalls won't outlive the global
        let linker: wasmtime::Linker = system_api::syscalls(
            self.log.clone(),
            canister_id,
            &store,
            system_api_handle.clone(),
            Rc::downgrade(&canister_num_instructions_global),
        );

        let (instance, persistence_type) = if let Some(cow_mem_creator_proxy) = memory_creator_proxy
        {
            // If we have the CowMemoryCreator we want to ensure it is used
            // atomically
            let _lock = cow_mem_creator_proxy.memory_creator_lock.lock().unwrap();

            cow_mem_creator_proxy.replace(memory_creator.unwrap());

            let instance = linker
                .instantiate(&module)
                .expect("failed to create Wasmtime instance");

            // After the Wasm module instance and its corresponding memory
            // are created we want to ensure that this particular
            // MemoryCreator can't be reused
            cow_mem_creator_proxy
                .replace(std::sync::Arc::new(CowMemoryCreator::new_uninitialized()));
            (instance, PersistenceType::Pagemap)
        } else {
            (
                linker
                    .instantiate(&module)
                    .expect("failed to create Wasmtime instance"),
                PersistenceType::Sigsegv,
            )
        };

        // in wasmtime only exported globals are accessible
        let instance_globals: Vec<_> = instance.exports().filter_map(|e| e.into_global()).collect();

        if exported_globals.len() > instance_globals.len() {
            panic!(
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
            if instance_global.ty().mutability() == Mutability::Var {
                instance_global
                    .set(match v {
                        Global::I32(val) => Val::I32(*val),
                        Global::I64(val) => Val::I64(*val),
                        Global::F32(val) => Val::F32((val).to_bits()),
                        Global::F64(val) => Val::F64((val).to_bits()),
                    })
                    .unwrap_or_else(|e| {
                        let v = match v {
                            Global::I32(val) => (val).to_string(),
                            Global::I64(val) => (val).to_string(),
                            Global::F32(val) => (val).to_string(),
                            Global::F64(val) => (val).to_string(),
                        };
                        panic!("error while setting exported global {} to {}: {}", ix, v, e)
                    })
            } else {
                debug!(
                    self.log,
                    "skipping initialization of immutable global {}", ix
                );
            }
        }

        let instance_memory = instance
            .get_memory("memory")
            .map(|instance_memory| {
                let current_heap_size = instance_memory.size();
                let requested_size = heap_size.get();

                if current_heap_size < requested_size {
                    let delta = requested_size - current_heap_size;
                    // TODO(DFN-1305): It is OK to panic here. `requested_size` is
                    // value we store only after we've successfully grown module memory in some
                    // previous execution.
                    // Example: module starts with (memory 1 2) and calls (memory.grow 1). Then
                    // requested_size will be 2.
                    instance_memory.grow(delta).expect("memory grow failed");
                }
                instance_memory
            })
            .map(Arc::new);

        // if `wasmtime::Instance` does not have memory we don't need a memory tracker
        let memory_tracker = instance_memory.as_ref().map(|instance_memory| {
            let page_map = match persistence_type {
                PersistenceType::Sigsegv => page_map,
                PersistenceType::Pagemap => None,
            };
            sigsegv_memory_tracker(
                persistence_type,
                Arc::downgrade(instance_memory),
                &store,
                page_map,
                self.log.clone(),
                dirty_page_tracking,
            )
        });
        let signal_stack = WasmtimeSignalStack::new();

        // canister_num_instructions_global is an Option because some wasmtime tests
        // invoke this function without exporting the "canister counter_instructions"
        // global
        *canister_num_instructions_global.borrow_mut() =
            instance.get_global("canister counter_instructions");

        WasmtimeInstance {
            system_api_handle,
            instance,
            instance_memory,
            memory_tracker,
            signal_stack,
            canister_num_instructions_global,
            log: self.log.clone(),
            instance_stats: InstanceStats {
                accessed_pages: 0,
                dirty_pages: 0,
            },
        }
    }
}

fn sigsegv_memory_tracker(
    persistence_type: PersistenceType,
    instance_memory: std::sync::Weak<wasmtime::Memory>,
    store: &wasmtime::Store,
    page_map: Option<PageMap>,
    log: ReplicaLogger,
    dirty_page_tracking: DirtyPageTracking,
) -> Rc<SigsegvMemoryTracker> {
    let (base, size) = {
        let memory = instance_memory.upgrade().unwrap();
        (memory.data_ptr(), memory.data_size())
    };

    let sigsegv_memory_tracker = {
        // For both SIGSEGV and in the future UFFD memory tracking we need
        // the base address of the heap and its size
        let base = base as *mut libc::c_void;
        let page_size = *ic_sys::PAGE_SIZE;
        assert!(base as usize % page_size == 0, "heap must be page aligned");
        assert!(
            size % page_size == 0,
            "heap size must be a multiple of page size"
        );
        std::rc::Rc::new(
            SigsegvMemoryTracker::new(
                persistence_type,
                base,
                size,
                log,
                dirty_page_tracking,
                page_map,
            )
            .expect("failed to instantiate SIGSEGV memory tracker"),
        )
    };

    // http://man7.org/linux/man-pages/man7/signal-safety.7.html
    unsafe {
        let current_heap_size = Box::new(move || {
            instance_memory
                .upgrade()
                .map(|x| x.data_size())
                .unwrap_or(0)
        }) as Box<dyn Fn() -> usize>;

        let default_handler = || {
            #[cfg(feature = "sigsegv_handler_debug")]
            eprintln!("> instance signal handler: calling default signal handler");
            false
        };

        let handler = crate::signal_handler::sigsegv_memory_tracker_handler(
            std::rc::Rc::clone(&sigsegv_memory_tracker),
            current_heap_size,
            default_handler,
            || true,
            || false,
        );
        store.set_signal_handler(handler);
    };
    sigsegv_memory_tracker as std::rc::Rc<SigsegvMemoryTracker>
}

/// Encapsulates a Wasmtime instance on the Internet Computer.
pub struct WasmtimeInstance {
    system_api_handle: SystemApiHandle,
    instance: wasmtime::Instance,
    // if instance memory exists we need to keep the Arc alive as long as the
    // Instance is alive. This is because we are sending the Weak pointer to a
    // signal handler.
    #[allow(dead_code)]
    instance_memory: Option<Arc<wasmtime::Memory>>,
    memory_tracker: Option<Rc<SigsegvMemoryTracker>>,
    signal_stack: WasmtimeSignalStack,
    canister_num_instructions_global: Rc<RefCell<Option<wasmtime::Global>>>,
    log: ReplicaLogger,
    instance_stats: InstanceStats,
}

impl WasmtimeInstance {
    fn invoke_export(&mut self, export: &str, args: &[Val]) -> HypervisorResult<Vec<Val>> {
        Ok(self
            .instance
            .get_export(export)
            .ok_or_else(|| {
                HypervisorError::MethodNotFound(WasmMethod::try_from(export.to_string()).unwrap())
            })?
            .into_func()
            .ok_or_else(|| {
                HypervisorError::ContractViolation("export is not a function".to_string())
            })?
            .call(args)
            .map_err(trap_to_error)?
            .to_vec())
    }

    fn dirty_pages(&self) -> Vec<PageIndex> {
        if let Some(memory_tracker) = self.memory_tracker.as_ref() {
            let speculatively_dirty_pages = memory_tracker.take_speculatively_dirty_pages();
            let dirty_pages = memory_tracker.take_dirty_pages();
            dirty_pages
                .into_iter()
                .chain(
                    speculatively_dirty_pages
                        .into_iter()
                        .filter_map(|p| memory_tracker.validate_speculatively_dirty_page(p)),
                )
                .collect::<Vec<PageIndex>>()
        } else {
            debug!(
                self.log,
                "Memory tracking disabled. Returning empty list of dirty pages"
            );
            vec![]
        }
    }

    fn memory(&self) -> HypervisorResult<Memory> {
        match self.instance.get_export("memory") {
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
    pub fn run(
        &mut self,
        system_api: &mut (dyn SystemApi + 'static),
        func_ref: FuncRef,
    ) -> HypervisorResult<InstanceRunResult> {
        self.system_api_handle.replace(system_api);
        let _alt_sig_stack = unsafe { self.signal_stack.register() };

        let result = match &func_ref {
            FuncRef::Method(wasm_method) => self.invoke_export(&wasm_method.to_string(), &[]),
            FuncRef::QueryClosure(closure) | FuncRef::UpdateClosure(closure) => self
                .instance
                .get_export("table")
                .ok_or_else(|| HypervisorError::ContractViolation("table not found".to_string()))?
                .into_table()
                .ok_or_else(|| {
                    HypervisorError::ContractViolation("export 'table' is not a table".to_string())
                })?
                .get(closure.func_idx)
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
                .call(&[Val::I32(closure.env as i32)])
                .map_err(trap_to_error)
                .map(|boxed_slice| boxed_slice.to_vec()),
        }
        .map_err(|e| system_api.get_execution_error().cloned().unwrap_or(e));

        self.system_api_handle.clear();

        let dirty_pages = self.dirty_pages();
        let num_accessed_pages = self
            .memory_tracker
            .as_ref()
            .map_or(0, |tracker| tracker.num_accessed_pages());
        let num_dirty_pages = dirty_pages.len();
        self.instance_stats.accessed_pages += num_accessed_pages;
        self.instance_stats.dirty_pages += num_dirty_pages;
        self.instance_stats.dirty_pages += system_api.get_stable_memory_delta_pages();

        match result {
            Ok(_) => Ok(InstanceRunResult {
                exported_globals: self.get_exported_globals(),
                dirty_pages,
            }),
            Err(err) => Err(err),
        }
    }

    /// Sets the number of instructions for a method execution.
    pub fn set_num_instructions(&mut self, num_instructions: NumInstructions) {
        match &*self.canister_num_instructions_global.borrow_mut() {
            Some(num_instructions_global) => {
                match num_instructions_global.set(Val::I64(num_instructions.get() as i64)) {
                    Ok(_) => (),
                    Err(e) => panic!("couldn't set the num_instructions counter: {:?}", e),
                }
            }
            None => panic!("couldn't find the num_instructions counter in the canister globals"),
        }
    }

    /// Returns the number of instructions left.
    pub fn get_num_instructions(&self) -> NumInstructions {
        match &*self.canister_num_instructions_global.borrow() {
            Some(num_instructions) => match num_instructions.get() {
                Val::I64(num_instructions_i64) => {
                    NumInstructions::from(num_instructions_i64.max(0) as u64)
                }
                _ => panic!("invalid num_instructions counter type"),
            },
            None => panic!("couldn't find the num_instructions counter in the canister globals"),
        }
    }

    /// Returns the heap size.
    pub fn heap_size(&self) -> NumWasmPages {
        NumWasmPages::from(self.memory().map_or(0, |mem| mem.size()))
    }

    /// Returns a list of exported globals.
    pub fn get_exported_globals(&self) -> Vec<Global> {
        self.instance
            .exports()
            .filter_map(|e| e.into_global())
            .map(|g| match g.ty().content() {
                ValType::I32 => Global::I32(g.get().i32().expect("global i32")),
                ValType::I64 => Global::I64(g.get().i64().expect("global i64")),
                ValType::F32 => Global::F32(g.get().f32().expect("global f32")),
                ValType::F64 => Global::F64(g.get().f64().expect("global f64")),
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
    pub unsafe fn heap_addr(&self) -> *const u8 {
        self.memory()
            .map(|mem| mem.data_unchecked().as_ptr())
            .unwrap_or_else(|_| std::ptr::null())
    }

    /// Returns execution statistics for this instance.
    ///
    /// Note that stats must be available even if this instance trapped.
    pub fn get_stats(&self) -> InstanceStats {
        self.instance_stats.clone()
    }
}
