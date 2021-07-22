use crate::cow_memory_creator::CowMemoryCreator;
use crate::{
    wasmtime_embedder::WasmtimeInstance, WasmExecutionInput, WasmExecutionOutput, WasmtimeEmbedder,
};
use ic_config::embedders::PersistenceType;
use ic_cow_state::{CowMemoryManager, MappedState};
use ic_interfaces::execution_environment::{HypervisorError, InstanceStats, SystemApi};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{PageDelta, PageIndex};
use ic_system_api::{SystemApiImpl, SystemStateAccessorDirect};
use ic_types::{
    methods::{FuncRef, SystemMethod, WasmMethod},
    NumInstructions,
};
use ic_wasm_utils::{
    instrumentation::{instrument, InstructionCostTable},
    validation::{validate_wasm_binary, WasmValidationLimits},
};
use prometheus::IntCounter;
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
        }
    }
}

/// An executor that can process any message (query or not).
pub struct WasmExecutor {
    wasm_embedder: WasmtimeEmbedder,
    config: WasmExecutorConfig,
    metrics: WasmExecutorMetrics,
}

impl WasmExecutor {
    pub fn new(
        wasm_embedder: WasmtimeEmbedder,
        max_globals: usize,
        max_functions: usize,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        Self {
            wasm_embedder,
            config: WasmExecutorConfig::new(max_globals, max_functions),
            metrics: WasmExecutorMetrics::new(metrics_registry),
        }
    }

    pub fn process(
        &self,
        WasmExecutionInput {
            api_type,
            system_state,
            instructions_limit,
            canister_memory_limit,
            canister_current_memory_usage,
            subnet_available_memory,
            compute_allocation,
            func_ref,
            mut execution_state,
            cycles_account_manager,
        }: WasmExecutionInput,
    ) -> WasmExecutionOutput {
        let system_state_accessor =
            SystemStateAccessorDirect::new(system_state, cycles_account_manager);
        let persistence_type = if execution_state.cow_mem_mgr.is_valid() {
            PersistenceType::Pagemap
        } else {
            PersistenceType::Sigsegv
        };
        if execution_state.embedder_cache.is_none() {
            // The wasm_binary stored in the `ExecutionState` is not
            // instrumented so instrument it before compiling. Further, due to
            // IC upgrades, it is possible that the `validate_wasm_binary()`
            // function has changed, so also validate the binary.
            match validate_wasm_binary(
                &execution_state.wasm_binary,
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
                if details.imports_call_simple {
                    self.metrics.imports_call_simple.inc();
                }
                instrument(&execution_state.wasm_binary, &InstructionCostTable::new())
                    .map_err(HypervisorError::from)
            })
            .and_then(|output| self.wasm_embedder.compile(persistence_type, &output.binary))
            {
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
        let (memory_creator, commit_dirty_pages) = if execution_state.cow_mem_mgr.is_valid() {
            match &func_ref {
                FuncRef::Method(WasmMethod::Update(_))
                | FuncRef::Method(WasmMethod::System(_))
                | FuncRef::UpdateClosure(_) => {
                    let mapped_state = execution_state.cow_mem_mgr.get_map();
                    execution_state.mapped_state = Some(Arc::new(mapped_state));
                }
                _ => (),
            }

            let commit_dirty_pages = func_ref.to_commit();

            let mapped_state = Arc::as_ref(execution_state.mapped_state.as_ref().unwrap());
            (
                Some(Arc::new(CowMemoryCreator::new(mapped_state))),
                commit_dirty_pages,
            )
        } else {
            (None, false)
        };

        let mut instance = self.wasm_embedder.new_instance(
            &execution_state.embedder_cache.as_ref().unwrap(),
            &execution_state.exported_globals,
            execution_state.heap_size,
            memory_creator,
            Some(execution_state.page_map.clone()),
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
            let mut system_api = SystemApiImpl::new(
                api_type,
                system_state_accessor,
                canister_memory_limit,
                canister_current_memory_usage,
                subnet_available_memory,
                compute_allocation,
            );
            instance.set_num_instructions(instructions_limit);
            let run_result = instance.run(&mut system_api, func_ref);
            match run_result {
                Ok(run_result) => {
                    if execution_state.cow_mem_mgr.is_valid() && commit_dirty_pages {
                        let mapped_state = execution_state.mapped_state.take();
                        let pages: Vec<u64> =
                            run_result.dirty_pages.iter().map(|p| p.get()).collect();
                        mapped_state.unwrap().soft_commit(&pages);
                    } else {
                        let page_delta = compute_page_delta(&instance, &run_result.dirty_pages);
                        execution_state.page_map.update(page_delta);
                    }
                    execution_state.exported_globals = run_result.exported_globals;
                    execution_state.heap_size = instance.heap_size();
                }
                Err(err) => {
                    system_api.set_execution_error(err);
                }
            };
            let mut instance_stats = instance.get_stats();
            instance_stats.dirty_pages += system_api.get_stable_memory_delta_pages();
            (
                system_api.take_execution_result(),
                instance.get_num_instructions(),
                system_api.release_system_state_accessor(),
                instance_stats,
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
}

// Utility function to compute the page delta. It creates a copy of `Instance`
// dirty pages.
fn compute_page_delta(instance: &WasmtimeInstance, dirty_pages: &[PageIndex]) -> PageDelta {
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
