use std::path::PathBuf;
use std::sync::Arc;

use prometheus::{Histogram, IntCounter};

use ic_config::{embedders::Config as EmbeddersConfig, embedders::PersistenceType};
use ic_cow_state::{CowMemoryManager, MappedState};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::execution_environment::{
    ExecutionParameters, HypervisorError, HypervisorResult, InstanceStats, SystemApi,
};
use ic_logger::ReplicaLogger;
use ic_metrics::buckets::decimal_buckets_with_zero;
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{
    canister_state::execution_state::SandboxExecutionState, EmbedderCache, ExecutionState,
    SystemState,
};
use ic_sys::{page_bytes_from_ptr, PageBytes, PageIndex, PAGE_SIZE};
use ic_system_api::{
    ApiType, ModificationTracking, StaticSystemState, SystemApiImpl, SystemStateAccessorDirect,
};
use ic_types::{
    methods::{FuncRef, WasmMethod},
    NumBytes, NumInstructions,
};
use ic_wasm_types::BinaryEncodedWasm;

use crate::cow_memory_creator::CowMemoryCreator;
use crate::{
    wasm_utils::instrumentation::{instrument, InstructionCostTable},
    wasm_utils::validation::{validate_wasm_binary, WasmImportsDetails},
    wasmtime_embedder::WasmtimeInstance,
    WasmExecutionInput, WasmExecutionOutput, WasmtimeEmbedder,
};

struct WasmExecutorMetrics {
    // TODO(EXC-350): Remove this metric once we confirm that no reserved functions are exported.
    reserved_exports: IntCounter,
    // TODO(EXC-365): Remove this metric once we confirm that no module imports `ic0.call_simple`
    // anymore.
    imports_call_simple: IntCounter,
    // TODO(EXC-376): Remove these metrics once we confirm that no module imports these IC0 methods
    // anymore.
    imports_call_cycles_add: IntCounter,
    imports_canister_cycle_balance: IntCounter,
    imports_msg_cycles_available: IntCounter,
    imports_msg_cycles_refunded: IntCounter,
    imports_msg_cycles_accept: IntCounter,
    imports_mint_cycles: IntCounter,
    compile: Histogram,
}

impl WasmExecutorMetrics {
    #[doc(hidden)] // pub for usage in tests
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            reserved_exports: metrics_registry.int_counter(
                "execution_wasm_reserved_exports_total",
                "The number of reserved functions exported from Wasm modules",
            ),
            imports_call_simple: metrics_registry.int_counter(
                "execution_wasm_imports_call_simple_total",
                "The number of Wasm modules that import ic0.call_simple",
            ),
            imports_call_cycles_add: metrics_registry.int_counter(
                "execution_wasm_imports_call_cycles_add",
                "The number of Wasm modules that import ic0.call_cycles_add",
            ),
            imports_canister_cycle_balance: metrics_registry.int_counter(
                "execution_wasm_imports_canister_cycle_balance",
                "The number of Wasm modules that import ic0.canister_cycle_balance",
            ),
            imports_msg_cycles_available: metrics_registry.int_counter(
                "execution_wasm_imports_msg_cycles_available",
                "The number of Wasm modules that import ic0.msg_cycles_available",
            ),
            imports_msg_cycles_refunded: metrics_registry.int_counter(
                "execution_wasm_imports_msg_cycles_refunded",
                "The number of Wasm modules that import ic0.msg_cycles_refunded",
            ),
            imports_msg_cycles_accept: metrics_registry.int_counter(
                "execution_wasm_imports_msg_cycles_accept",
                "The number of Wasm modules that import ic0.msg_cycles_accept",
            ),
            imports_mint_cycles: metrics_registry.int_counter(
                "execution_wasm_imports_mint_cycles",
                "The number of Wasm modules that import ic0.mint_cycles",
            ),
            compile: metrics_registry.histogram(
                "execution_wasm_compile",
                "The duration of Wasm module compilation including validation and instrumentation",
                decimal_buckets_with_zero(-4, 1),
            ),
        }
    }
}

/// An executor that can process any message (query or not).
pub struct WasmExecutor {
    wasm_embedder: WasmtimeEmbedder,
    config: EmbeddersConfig,
    metrics: WasmExecutorMetrics,
    log: ReplicaLogger,
}

impl WasmExecutor {
    pub fn new(
        wasm_embedder: WasmtimeEmbedder,
        metrics_registry: &MetricsRegistry,
        config: EmbeddersConfig,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            wasm_embedder,
            metrics: WasmExecutorMetrics::new(metrics_registry),
            config,
            log,
        }
    }

    pub fn observe_metrics(&self, imports_details: &WasmImportsDetails) {
        if imports_details.imports_call_simple {
            self.metrics.imports_call_simple.inc();
        }
        if imports_details.imports_call_cycles_add {
            self.metrics.imports_call_cycles_add.inc();
        }
        if imports_details.imports_canister_cycle_balance {
            self.metrics.imports_canister_cycle_balance.inc();
        }
        if imports_details.imports_msg_cycles_available {
            self.metrics.imports_msg_cycles_available.inc();
        }
        if imports_details.imports_msg_cycles_accept {
            self.metrics.imports_msg_cycles_accept.inc();
        }
        if imports_details.imports_msg_cycles_refunded {
            self.metrics.imports_msg_cycles_refunded.inc();
        }
        if imports_details.imports_mint_cycles {
            self.metrics.imports_mint_cycles.inc();
        }
    }

    pub fn compile(
        &self,
        wasm_binary: &BinaryEncodedWasm,
        persistence_type: PersistenceType,
    ) -> HypervisorResult<EmbedderCache> {
        let _timer = self.metrics.compile.start_timer();
        validate_wasm_binary(wasm_binary, &self.config)
            .map_err(HypervisorError::from)
            .and_then(|details| {
                if details.reserved_exports > 0 {
                    self.metrics
                        .reserved_exports
                        .inc_by(details.reserved_exports as u64);
                }
                self.observe_metrics(&details.imports_details);
                instrument(wasm_binary, &InstructionCostTable::new()).map_err(HypervisorError::from)
            })
            .and_then(|output| self.wasm_embedder.compile(persistence_type, &output.binary))
    }

    fn get_embedder_cache(
        &self,
        execution_state: &ExecutionState,
    ) -> HypervisorResult<EmbedderCache> {
        let mut guard = execution_state.wasm_binary.embedder_cache.lock().unwrap();
        if let Some(embedder_cache) = &*guard {
            Ok(embedder_cache.clone())
        } else {
            // The wasm_binary stored in the `ExecutionState` is not
            // instrumented so instrument it before compiling. Further, due to
            // IC upgrades, it is possible that the `validate_wasm_binary()`
            // function has changed, so also validate the binary.
            match self.compile(
                &execution_state.wasm_binary.binary,
                execution_state.persistence_type(),
            ) {
                Ok(cache) => {
                    *guard = Some(cache.clone());
                    Ok(cache)
                }
                Err(err) => Err(err),
            }
        }
    }

    pub fn process(
        &self,
        WasmExecutionInput {
            api_type,
            system_state,
            canister_current_memory_usage,
            execution_parameters,
            func_ref,
            mut execution_state,
            cycles_account_manager,
        }: WasmExecutionInput,
    ) -> WasmExecutionOutput {
        let static_system_state =
            StaticSystemState::new(&system_state, cycles_account_manager.subnet_type());
        let canister_id = system_state.canister_id;
        let system_state_accessor =
            SystemStateAccessorDirect::new(system_state, cycles_account_manager);

        let embedder_cache = self.get_embedder_cache(&execution_state);
        match embedder_cache {
            Ok(_) => (),
            Err(err) => {
                return WasmExecutionOutput {
                    wasm_result: Err(err),
                    num_instructions_left: NumInstructions::from(0),
                    system_state: system_state_accessor.release_system_state(),
                    execution_state,
                    instance_stats: InstanceStats {
                        accessed_pages: 0,
                        dirty_pages: 0,
                    },
                };
            }
        }
        // We have verified that it is not an error, so safe to unwrap now.
        let embedder_cache = embedder_cache.unwrap();

        // TODO(EXC-176): we should combine this with the hypervisor so that
        // we make the decision of whether or not to commit modifications in
        // a single place instead.
        let memory_creator = if execution_state.cow_mem_mgr.is_valid() {
            match &func_ref {
                FuncRef::Method(WasmMethod::Update(_))
                | FuncRef::Method(WasmMethod::System(_))
                | FuncRef::UpdateClosure(_) => {
                    let mapped_state = execution_state.cow_mem_mgr.get_map();
                    execution_state.mapped_state = Some(Arc::new(mapped_state));
                }
                _ => (),
            }
            let mapped_state = Arc::as_ref(execution_state.mapped_state.as_ref().unwrap());
            Some(Arc::new(CowMemoryCreator::new(mapped_state)))
        } else {
            None
        };

        let commit_dirty_pages = func_ref.to_commit();
        let modification_tracking = api_type.modification_tracking();

        let instruction_limit = execution_parameters.instruction_limit;
        let system_api = SystemApiImpl::new(
            api_type,
            system_state_accessor,
            static_system_state,
            canister_current_memory_usage,
            execution_parameters,
            execution_state.stable_memory.clone(),
            self.log.clone(),
        );

        let mut instance = match self.wasm_embedder.new_instance(
            canister_id,
            &embedder_cache,
            &execution_state.exported_globals,
            execution_state.wasm_memory.size,
            memory_creator,
            Some(execution_state.wasm_memory.page_map.clone()),
            modification_tracking,
            system_api,
        ) {
            Ok(instance) => instance,
            Err((err, system_api)) => {
                return WasmExecutionOutput {
                    wasm_result: Err(err),
                    num_instructions_left: NumInstructions::from(0),
                    system_state: system_api
                        .release_system_state_accessor()
                        .release_system_state(),
                    execution_state,
                    instance_stats: InstanceStats {
                        accessed_pages: 0,
                        dirty_pages: 0,
                    },
                };
            }
        };

        let (execution_result, available_num_instructions, system_state, instance_stats) = {
            instance.set_num_instructions(instruction_limit);
            let run_result = instance.run(func_ref);
            match run_result {
                Ok(run_result) => {
                    if modification_tracking == ModificationTracking::Track {
                        if execution_state.cow_mem_mgr.is_valid() && commit_dirty_pages {
                            let mapped_state = execution_state.mapped_state.take();
                            let pages: Vec<u64> =
                                run_result.dirty_pages.iter().map(|p| p.get()).collect();
                            mapped_state.unwrap().soft_commit(&pages);
                        } else {
                            let page_delta =
                                compute_page_delta(&mut instance, &run_result.dirty_pages);
                            execution_state.wasm_memory.page_map.update(&page_delta);
                        }
                        execution_state.wasm_memory.size = instance.heap_size();
                        execution_state.stable_memory.page_map.update(
                            &run_result
                                .stable_memory_dirty_pages
                                .iter()
                                .map(|(i, p)| (*i, p))
                                .collect::<Vec<_>>(),
                        );
                        execution_state.stable_memory.size = run_result.stable_memory_size;
                        execution_state.exported_globals = run_result.exported_globals;

                        // TODO(EXC-624): Create delta-based remote state here.
                        execution_state.sandbox_state = SandboxExecutionState::new();
                    }
                }
                Err(err) => {
                    instance
                        .store_data_mut()
                        .system_api
                        .set_execution_error(err);
                }
            };
            let num_instructions = instance.get_num_instructions();
            let stats = instance.get_stats();
            let mut system_api = instance.into_store_data().system_api;
            let execution_result = system_api.take_execution_result();
            let system_state_accessor = system_api.release_system_state_accessor();
            let system_state = system_state_accessor.release_system_state();
            (execution_result, num_instructions, system_state, stats)
        };

        WasmExecutionOutput {
            wasm_result: execution_result,
            num_instructions_left: available_num_instructions,
            system_state,
            execution_state,
            instance_stats,
        }
    }

    pub fn create_execution_state(
        &self,
        wasm_binary: Vec<u8>,
        canister_root: PathBuf,
        system_state: SystemState,
        canister_current_memory_usage: NumBytes,
        execution_parameters: ExecutionParameters,
        cycles_account_manager: Arc<CyclesAccountManager>,
    ) -> HypervisorResult<ExecutionState> {
        // Get new ExecutionState not fully initialized.
        let mut execution_state =
            self.wasm_embedder
                .create_execution_state(wasm_binary, canister_root, &self.config)?;

        let canister_id = system_state.canister_id;
        let static_system_state =
            StaticSystemState::new(&system_state, cycles_account_manager.subnet_type());
        let system_state_accessor =
            SystemStateAccessorDirect::new(system_state, cycles_account_manager);
        let api_type = ApiType::start();
        let modification_tracking = api_type.modification_tracking();
        let system_api = SystemApiImpl::new(
            api_type,
            system_state_accessor,
            static_system_state,
            canister_current_memory_usage,
            execution_parameters,
            execution_state.stable_memory.clone(),
            self.log.clone(),
        );

        let memory_creator = if execution_state.mapped_state.is_some() {
            let mapped_state = Arc::as_ref(execution_state.mapped_state.as_ref().unwrap());
            Some(Arc::new(CowMemoryCreator::new(mapped_state)))
        } else {
            None
        };

        let embedder_cache = self.get_embedder_cache(&execution_state)?;
        let mut instance = match self.wasm_embedder.new_instance(
            canister_id,
            &embedder_cache,
            &execution_state.exported_globals,
            execution_state.wasm_memory.size,
            memory_creator,
            Some(execution_state.wasm_memory.page_map.clone()),
            modification_tracking,
            system_api,
        ) {
            Ok(instance) => instance,
            Err((err, _)) => {
                return Err(err);
            }
        };

        execution_state.wasm_memory.size = instance.heap_size();
        execution_state.exported_globals = instance.get_exported_globals();
        Ok(execution_state)
    }

    pub fn compile_count_for_testing(&self) -> u64 {
        self.metrics.compile.get_sample_count()
    }
}

/// Utility function to compute the page delta. It creates a copy of `Instance`
/// dirty pages. The function is public because it is used in
/// `wasmtime_random_memory_writes` tests.
#[doc(hidden)]
pub fn compute_page_delta<'a, S: SystemApi>(
    instance: &'a mut WasmtimeInstance<S>,
    dirty_pages: &[PageIndex],
) -> Vec<(PageIndex, &'a PageBytes)> {
    // heap pointer is only valid as long as the `Instance` is alive.
    let heap_addr: *const u8 = unsafe { instance.heap_addr() };

    let mut pages = vec![];

    for page_index in dirty_pages {
        let i = page_index.get();
        // SAFETY: All dirty pages are mapped and remain valid for the lifetime of
        // `instance`. Since this function is called after Wasm execution, the dirty
        // pages are not borrowed as mutable.
        let page_ref = unsafe {
            let offset: usize = i as usize * PAGE_SIZE;
            page_bytes_from_ptr(instance, (heap_addr as *const u8).add(offset))
        };
        pages.push((*page_index, page_ref));
    }
    pages
}
