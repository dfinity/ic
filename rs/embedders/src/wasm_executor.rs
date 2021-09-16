use crate::cow_memory_creator::CowMemoryCreator;
use crate::{
    wasmtime_embedder::WasmtimeInstance, WasmExecutionInput, WasmExecutionOutput, WasmtimeEmbedder,
};
use ic_config::embedders::PersistenceType;
use ic_cow_state::{CowMemoryManager, MappedState};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, InstanceStats, SystemApi,
};
use ic_logger::ReplicaLogger;
use ic_metrics::buckets::decimal_buckets_with_zero;
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{EmbedderCache, PageDelta, PageIndex};
use ic_system_api::{ApiType, NonReplicatedQueryKind, SystemApiImpl, SystemStateAccessorDirect};
use ic_types::{
    methods::{FuncRef, SystemMethod, WasmMethod},
    NumInstructions,
};
use ic_wasm_types::BinaryEncodedWasm;
use ic_wasm_utils::validation::WasmImportsDetails;
use ic_wasm_utils::{
    instrumentation::{instrument, InstructionCostTable},
    validation::{validate_wasm_binary, WasmValidationLimits},
};
use memory_tracker::DirtyPageTracking;
use prometheus::{Histogram, IntCounter};
use std::sync::Arc;

struct WasmExecutorConfig {
    max_globals: usize,
    max_functions: usize,
}

impl WasmExecutorConfig {
    pub fn new(max_globals: usize, max_functions: usize) -> Self {
        Self {
            max_globals,
            max_functions,
        }
    }
}

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
    config: WasmExecutorConfig,
    metrics: WasmExecutorMetrics,
    log: ReplicaLogger,
}

impl WasmExecutor {
    pub fn new(
        wasm_embedder: WasmtimeEmbedder,
        max_globals: usize,
        max_functions: usize,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            wasm_embedder,
            config: WasmExecutorConfig::new(max_globals, max_functions),
            metrics: WasmExecutorMetrics::new(metrics_registry),
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
        validate_wasm_binary(
            wasm_binary,
            WasmValidationLimits {
                max_globals: self.config.max_globals,
                max_functions: self.config.max_functions,
            },
        )
        .map_err(HypervisorError::from)
        .and_then(|details| {
            if details.reserved_exports > 0 {
                self.metrics
                    .reserved_exports
                    .inc_by(details.reserved_exports as u64);
            }
            self.observe_metrics(&details.imports_details);
            instrument(&wasm_binary, &InstructionCostTable::new()).map_err(HypervisorError::from)
        })
        .and_then(|output| self.wasm_embedder.compile(persistence_type, &output.binary))
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
        let canister_id = system_state.canister_id;
        let system_state_accessor =
            SystemStateAccessorDirect::new(system_state, cycles_account_manager);
        if execution_state.embedder_cache.is_none() {
            // The wasm_binary stored in the `ExecutionState` is not
            // instrumented so instrument it before compiling. Further, due to
            // IC upgrades, it is possible that the `validate_wasm_binary()`
            // function has changed, so also validate the binary.
            match self.compile(
                &execution_state.wasm_binary,
                execution_state.persistence_type(),
            ) {
                Ok(cache) => execution_state.embedder_cache = Some(cache),
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
        }

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

        let dirty_page_tracking = match &api_type {
            ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery {
                query_kind: NonReplicatedQueryKind::Pure,
                ..
            }
            | ApiType::InspectMessage { .. } => DirtyPageTracking::Ignore,
            _ => DirtyPageTracking::Track,
        };

        let mut instance = self.wasm_embedder.new_instance(
            canister_id,
            &execution_state.embedder_cache.as_ref().unwrap(),
            &execution_state.exported_globals,
            execution_state.heap_size,
            memory_creator,
            Some(execution_state.page_map.clone()),
            dirty_page_tracking,
        );

        if let FuncRef::Method(WasmMethod::System(SystemMethod::Empty)) = func_ref {
            execution_state.heap_size = instance.heap_size();
            execution_state.exported_globals = instance.get_exported_globals();
            return WasmExecutionOutput {
                wasm_result: Ok(None),
                num_instructions_left: NumInstructions::from(0),
                system_state: system_state_accessor.release_system_state(),
                execution_state,
                instance_stats: instance.get_stats(),
            };
        }

        let (execution_result, available_num_instructions, system_state_accessor, instance_stats) = {
            instance.set_num_instructions(execution_parameters.instruction_limit);
            let mut system_api = SystemApiImpl::new(
                api_type,
                system_state_accessor,
                canister_current_memory_usage,
                execution_parameters,
                self.log.clone(),
            );
            let run_result = instance.run(&mut system_api, func_ref);
            match run_result {
                Ok(run_result) => {
                    if dirty_page_tracking == DirtyPageTracking::Track {
                        if execution_state.cow_mem_mgr.is_valid() && commit_dirty_pages {
                            let mapped_state = execution_state.mapped_state.take();
                            let pages: Vec<u64> =
                                run_result.dirty_pages.iter().map(|p| p.get()).collect();
                            mapped_state.unwrap().soft_commit(&pages);
                        } else {
                            let page_delta = compute_page_delta(&instance, &run_result.dirty_pages);
                            execution_state.page_map.update(page_delta);
                        }
                    }
                    execution_state.exported_globals = run_result.exported_globals;
                    execution_state.heap_size = instance.heap_size();
                }
                Err(err) => {
                    system_api.set_execution_error(err);
                }
            };
            (
                system_api.take_execution_result(),
                instance.get_num_instructions(),
                system_api.release_system_state_accessor(),
                instance.get_stats(),
            )
        };

        WasmExecutionOutput {
            wasm_result: execution_result,
            num_instructions_left: available_num_instructions,
            system_state: system_state_accessor.release_system_state(),
            execution_state,
            instance_stats,
        }
    }

    pub fn compile_count_for_testing(&self) -> u64 {
        self.metrics.compile.get_sample_count()
    }
}

/// Utility function to compute the page delta. It creates a copy of `Instance`
/// dirty pages. The function is public because it is used in
/// `wasmtime_random_memory_writes` tests.
#[doc(hidden)]
pub fn compute_page_delta(instance: &WasmtimeInstance, dirty_pages: &[PageIndex]) -> PageDelta {
    // heap pointer is only valid as long as the `Instance` is alive.
    let heap_addr: *const u8 = unsafe { instance.heap_addr() };

    let mut pages = vec![];

    for page_index in dirty_pages {
        let i = page_index.get();
        let page_addr: *const u8 = unsafe {
            let offset: usize = i as usize * *ic_sys::PAGE_SIZE;
            (heap_addr as *mut u8).add(offset)
        };
        let buf = unsafe { std::slice::from_raw_parts(page_addr, *ic_sys::PAGE_SIZE) };
        pages.push((*page_index, buf));
    }

    PageDelta::from(pages.as_slice())
}
