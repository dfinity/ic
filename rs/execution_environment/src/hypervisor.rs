use ic_canister_sandbox_backend_lib::replica_controller::sandboxed_execution_controller::SandboxedExecutionController;
use ic_config::execution_environment::{Config, MAX_COMPILATION_CACHE_SIZE};
use ic_config::flag_status::FlagStatus;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::{
    wasm_executor::{WasmExecutionResult, WasmExecutor, WasmExecutorImpl},
    wasm_utils::decoding::decoded_wasm_size,
    CompilationCache, CompilationResult, WasmExecutionInput, WasmtimeEmbedder,
};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, WasmExecutionOutput,
};
use ic_interfaces_state_manager::StateReader;
use ic_logger::ReplicaLogger;
use ic_management_canister_types::LogVisibilityV2;
use ic_metrics::buckets::decimal_buckets_with_zero;
use ic_metrics::{buckets::exponential_buckets, MetricsRegistry};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{page_map::allocated_pages_count, ExecutionState, SystemState};
use ic_replicated_state::{NetworkTopology, ReplicatedState};
use ic_system_api::ExecutionParameters;
use ic_system_api::{sandbox_safe_system_state::SandboxSafeSystemState, ApiType};
use ic_types::{
    messages::RequestMetadata, methods::FuncRef, CanisterId, MemoryDiskBytes, NumBytes,
    NumInstructions, SubnetId, Time,
};
use ic_wasm_types::CanisterModule;
use prometheus::{Histogram, HistogramVec, IntCounter, IntGauge, IntGaugeVec};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::execution::common::{apply_canister_state_changes, update_round_limits};
use crate::execution_environment::{as_round_instructions, CompilationCostHandling, RoundLimits};
use crate::metrics::CallTreeMetrics;
use ic_replicated_state::page_map::PageAllocatorFileDescriptor;

#[doc(hidden)] // pub for usage in tests
pub struct HypervisorMetrics {
    accessed_pages: HistogramVec,
    dirty_pages: HistogramVec,
    read_before_write_count: HistogramVec,
    direct_write_count: HistogramVec,
    allocated_pages: IntGauge,
    largest_function_instruction_count: Histogram,
    compile: Histogram,
    max_complexity: Histogram,
    sigsegv_count: HistogramVec,
    mmap_count: HistogramVec,
    mprotect_count: HistogramVec,
    copy_page_count: HistogramVec,
    compilation_cache_size: IntGaugeVec,
}

impl HypervisorMetrics {
    #[doc(hidden)] // pub for usage in tests
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            accessed_pages: metrics_registry.histogram_vec(
                "hypervisor_accessed_pages",
                "Number of pages accessed by type of memory (wasm, stable) and api type.",
                // 1 page, 2 pages, …, 2^21 (8GiB worth of) pages
                exponential_buckets(1.0, 2.0, 22),
                &["api_type", "memory_type"]
            ),
            dirty_pages: metrics_registry.histogram_vec(
                "hypervisor_dirty_pages",
                "Number of pages modified (dirtied) by type of memory (wasm, stable) and api type.",
                exponential_buckets(1.0, 2.0, 22),
                &["api_type", "memory_type"]
            ),
            read_before_write_count: metrics_registry.histogram_vec(
                "hypervisor_read_before_write_count",
                "Number of write accesses handled where the page had already been read by type of memory (wasm, stable) and api type.",
                exponential_buckets(1.0, 2.0, 22),
                &["api_type", "memory_type"]
            ),
            direct_write_count: metrics_registry.histogram_vec(
                "hypervisor_direct_write_count",
                "Number of write accesses handled where the page had not yet been read by type of memory (wasm, stable) and api type.",
                exponential_buckets(1.0, 2.0, 22),
                &["api_type", "memory_type"]
            ),
            allocated_pages: metrics_registry.int_gauge(
                "hypervisor_allocated_pages",
                "Total number of currently allocated pages.",
            ),
            largest_function_instruction_count: metrics_registry.histogram(
                "hypervisor_largest_function_instruction_count",
                "Size of the largest compiled wasm function in a canister by number of wasm instructions.",
                decimal_buckets_with_zero(1, 7), // 10 - 10M.
            ),
            compile: metrics_registry.histogram(
                "hypervisor_wasm_compile_time_seconds",
                "The duration of Wasm module compilation including validation and instrumentation.",
                decimal_buckets_with_zero(-4, 1),
            ),
            max_complexity: metrics_registry.histogram(
                "hypervisor_wasm_max_function_complexity",
                "The maximum function complexity in a wasm module.",
                decimal_buckets_with_zero(1, 8), //10 - 100M.
            ),
            sigsegv_count: metrics_registry.histogram_vec(
                "hypervisor_sigsegv_count",
                "Number of signal faults handled during the execution by type of memory (wasm, stable) and api type.",
                decimal_buckets_with_zero(0,8),
                &["api_type", "memory_type"]
            ),
            mmap_count: metrics_registry.histogram_vec(
                "hypervisor_mmap_count",
                "Number of calls to mmap during the execution by type of memory (wasm, stable) and api type.",
                decimal_buckets_with_zero(0,8),
                &["api_type", "memory_type"]
            ),
            mprotect_count: metrics_registry.histogram_vec(
                "hypervisor_mprotect_count",
                "Number of calls to mprotect during the execution by type of memory (wasm, stable) and api type.",
                decimal_buckets_with_zero(0,8),
                &["api_type", "memory_type"]
            ),
            copy_page_count: metrics_registry.histogram_vec(
                "hypervisor_copy_page_count",
                "Number of calls to pages memcopied during the execution by type of memory (wasm, stable) and api type.",
                decimal_buckets_with_zero(0,8),
                &["api_type", "memory_type"]
            ),
            compilation_cache_size: metrics_registry.int_gauge_vec("hypervisor_compilation_cache_size", "Bytes in memory and on disk used by the compilation cache.", &["location"],
            ),
        }
    }

    fn observe(&self, result: &WasmExecutionResult, api_type: &str) {
        if let WasmExecutionResult::Finished(_, output, ..) = result {
            self.accessed_pages
                .with_label_values(&[api_type, "wasm"])
                .observe(output.instance_stats.wasm_accessed_pages as f64);
            self.dirty_pages
                .with_label_values(&[api_type, "wasm"])
                .observe(output.instance_stats.wasm_dirty_pages as f64);
            self.read_before_write_count
                .with_label_values(&[api_type, "wasm"])
                .observe(output.instance_stats.wasm_read_before_write_count as f64);
            self.direct_write_count
                .with_label_values(&[api_type, "wasm"])
                .observe(output.instance_stats.wasm_direct_write_count as f64);
            self.sigsegv_count
                .with_label_values(&[api_type, "wasm"])
                .observe(output.instance_stats.wasm_sigsegv_count as f64);
            self.mmap_count
                .with_label_values(&[api_type, "wasm"])
                .observe(output.instance_stats.wasm_mmap_count as f64);
            self.mprotect_count
                .with_label_values(&[api_type, "wasm"])
                .observe(output.instance_stats.wasm_mprotect_count as f64);
            self.copy_page_count
                .with_label_values(&[api_type, "wasm"])
                .observe(output.instance_stats.wasm_copy_page_count as f64);

            // Additional metrics for the stable memory.
            self.accessed_pages
                .with_label_values(&[api_type, "stable"])
                .observe(output.instance_stats.stable_accessed_pages as f64);
            self.dirty_pages
                .with_label_values(&[api_type, "stable"])
                .observe(output.instance_stats.stable_dirty_pages as f64);
            self.read_before_write_count
                .with_label_values(&[api_type, "stable"])
                .observe(output.instance_stats.stable_read_before_write_count as f64);
            self.direct_write_count
                .with_label_values(&[api_type, "stable"])
                .observe(output.instance_stats.stable_direct_write_count as f64);
            self.sigsegv_count
                .with_label_values(&[api_type, "stable"])
                .observe(output.instance_stats.stable_sigsegv_count as f64);
            self.mmap_count
                .with_label_values(&[api_type, "stable"])
                .observe(output.instance_stats.stable_mmap_count as f64);
            self.mprotect_count
                .with_label_values(&[api_type, "stable"])
                .observe(output.instance_stats.stable_mprotect_count as f64);
            self.copy_page_count
                .with_label_values(&[api_type, "stable"])
                .observe(output.instance_stats.stable_copy_page_count as f64);

            self.allocated_pages.set(allocated_pages_count() as i64);
        }
    }

    fn observe_compilation_metrics(
        &self,
        compilation_result: &CompilationResult,
        cache_memory_size: usize,
        cache_disk_size: usize,
    ) {
        let CompilationResult {
            largest_function_instruction_count,
            compilation_time,
            max_complexity,
        } = compilation_result;
        self.largest_function_instruction_count
            .observe(largest_function_instruction_count.get() as f64);
        self.compile.observe(compilation_time.as_secs_f64());
        self.max_complexity.observe(*max_complexity as f64);
        self.compilation_cache_size
            .with_label_values(&["memory"])
            .set(cache_memory_size as i64);
        self.compilation_cache_size
            .with_label_values(&["disk"])
            .set(cache_disk_size as i64);
    }
}

#[doc(hidden)]
pub struct Hypervisor {
    wasm_executor: Arc<dyn WasmExecutor>,
    metrics: Arc<HypervisorMetrics>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    log: ReplicaLogger,
    cycles_account_manager: Arc<CyclesAccountManager>,
    compilation_cache: Arc<CompilationCache>,
    deterministic_time_slicing: FlagStatus,
    cost_to_compile_wasm_instruction: NumInstructions,
    dirty_page_overhead: NumInstructions,
    canister_guaranteed_callback_quota: usize,
}

impl Hypervisor {
    pub(crate) fn subnet_id(&self) -> SubnetId {
        self.own_subnet_id
    }

    pub fn subnet_type(&self) -> SubnetType {
        self.own_subnet_type
    }

    pub fn create_execution_state(
        &self,
        canister_module: CanisterModule,
        canister_root: PathBuf,
        canister_id: CanisterId,
        round_limits: &mut RoundLimits,
        compilation_cost_handling: CompilationCostHandling,
    ) -> (NumInstructions, HypervisorResult<ExecutionState>) {
        // If a wasm instruction has no arguments then it can be represented as
        // a single byte. So taking the length of the wasm source is a
        // conservative estimate of the number of instructions. If we can't
        // determine the decoded size, take the actual size as an approximation.
        let wasm_size_result = decoded_wasm_size(canister_module.as_slice());
        let wasm_size = match wasm_size_result {
            Ok(size) => std::cmp::max(size, canister_module.len()),
            Err(_) => canister_module.len(),
        };
        let compilation_cost = self.cost_to_compile_wasm_instruction * wasm_size as u64;
        if let Err(err) = wasm_size_result {
            round_limits.instructions -= as_round_instructions(compilation_cost);
            self.compilation_cache
                .insert_err(&canister_module, err.clone().into());
            return (compilation_cost, Err(err.into()));
        }

        let creation_result = self.wasm_executor.create_execution_state(
            canister_module,
            canister_root,
            canister_id,
            Arc::clone(&self.compilation_cache),
        );
        match creation_result {
            Ok((execution_state, compilation_cost, compilation_result)) => {
                if let Some(compilation_result) = compilation_result {
                    self.metrics.observe_compilation_metrics(
                        &compilation_result,
                        self.compilation_cache.memory_bytes(),
                        self.compilation_cache.disk_bytes(),
                    );
                }
                round_limits.instructions -= as_round_instructions(
                    compilation_cost_handling.adjusted_compilation_cost(compilation_cost),
                );
                (compilation_cost, Ok(execution_state))
            }
            Err(err) => {
                round_limits.instructions -= as_round_instructions(compilation_cost);
                (compilation_cost, Err(err))
            }
        }
    }

    pub fn new(
        config: Config,
        metrics_registry: &MetricsRegistry,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        log: ReplicaLogger,
        cycles_account_manager: Arc<CyclesAccountManager>,
        dirty_page_overhead: NumInstructions,
        fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        // TODO(EXC-1821): Create a temp dir in this directory for use in the
        // compilation cache.
        _temp_dir: &Path,
    ) -> Self {
        let mut embedder_config = config.embedders_config.clone();
        embedder_config.subnet_type = own_subnet_type;
        embedder_config.dirty_page_overhead = dirty_page_overhead;

        let wasm_executor: Arc<dyn WasmExecutor> = match config.canister_sandboxing_flag {
            FlagStatus::Enabled => {
                let executor = SandboxedExecutionController::new(
                    log.clone(),
                    metrics_registry,
                    &embedder_config,
                    Arc::clone(&fd_factory),
                    Arc::clone(&state_reader),
                    true,
                )
                .expect("Failed to start sandboxed execution controller");
                Arc::new(executor)
            }
            FlagStatus::Disabled => {
                let executor = WasmExecutorImpl::new(
                    WasmtimeEmbedder::new(embedder_config, log.clone()),
                    metrics_registry,
                    log.clone(),
                    Arc::clone(&fd_factory),
                );
                Arc::new(executor)
            }
        };
        Self {
            wasm_executor,
            metrics: Arc::new(HypervisorMetrics::new(metrics_registry)),
            own_subnet_id,
            own_subnet_type,
            log,
            cycles_account_manager,
            compilation_cache: Arc::new(CompilationCache::new(MAX_COMPILATION_CACHE_SIZE)),
            deterministic_time_slicing: config.deterministic_time_slicing,
            cost_to_compile_wasm_instruction: config
                .embedders_config
                .cost_to_compile_wasm_instruction,
            dirty_page_overhead,
            canister_guaranteed_callback_quota: config.canister_guaranteed_callback_quota,
        }
    }

    #[doc(hidden)]
    pub fn new_for_testing(
        metrics_registry: &MetricsRegistry,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        log: ReplicaLogger,
        cycles_account_manager: Arc<CyclesAccountManager>,
        wasm_executor: Arc<dyn WasmExecutor>,
        deterministic_time_slicing: FlagStatus,
        cost_to_compile_wasm_instruction: NumInstructions,
        dirty_page_overhead: NumInstructions,
        canister_guaranteed_callback_quota: usize,
    ) -> Self {
        Self {
            wasm_executor,
            metrics: Arc::new(HypervisorMetrics::new(metrics_registry)),
            own_subnet_id,
            own_subnet_type,
            log,
            cycles_account_manager,
            compilation_cache: Arc::new(CompilationCache::new(MAX_COMPILATION_CACHE_SIZE)),
            deterministic_time_slicing,
            cost_to_compile_wasm_instruction,
            dirty_page_overhead,
            canister_guaranteed_callback_quota,
        }
    }

    #[cfg(test)]
    pub fn compile_count(&self) -> u64 {
        self.metrics.compile.get_sample_count()
    }

    /// Wrapper around the standalone `execute`.
    /// NOTE: this is public to enable integration testing.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &self,
        api_type: ApiType,
        time: Time,
        mut system_state: SystemState,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: NumBytes,
        execution_parameters: ExecutionParameters,
        func_ref: FuncRef,
        mut execution_state: ExecutionState,
        network_topology: &NetworkTopology,
        round_limits: &mut RoundLimits,
        state_changes_error: &IntCounter,
        call_tree_metrics: &dyn CallTreeMetrics,
        call_context_creation_time: Time,
    ) -> (WasmExecutionOutput, ExecutionState, SystemState) {
        assert_eq!(
            execution_parameters.instruction_limits.message(),
            execution_parameters.instruction_limits.slice()
        );
        let execution_result = self.execute_dts(
            api_type,
            &execution_state,
            &system_state,
            canister_current_memory_usage,
            canister_current_message_memory_usage,
            execution_parameters,
            func_ref,
            RequestMetadata::for_new_call_tree(time),
            round_limits,
            network_topology,
        );
        let (slice, mut output, canister_state_changes) = match execution_result {
            WasmExecutionResult::Finished(slice, output, system_state_changes) => {
                (slice, output, system_state_changes)
            }
            WasmExecutionResult::Paused(_, _) => {
                unreachable!("DTS is not supported");
            }
        };
        update_round_limits(round_limits, &slice);
        apply_canister_state_changes(
            canister_state_changes,
            &mut execution_state,
            &mut system_state,
            &mut output,
            round_limits,
            time,
            network_topology,
            self.own_subnet_id,
            &self.log,
            state_changes_error,
            call_tree_metrics,
            call_context_creation_time,
            &|system_state| std::mem::drop(system_state),
        );
        (output, execution_state, system_state)
    }

    /// Executes the given WebAssembly function with deterministic time slicing.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_dts(
        &self,
        api_type: ApiType,
        execution_state: &ExecutionState,
        system_state: &SystemState,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: NumBytes,
        execution_parameters: ExecutionParameters,
        func_ref: FuncRef,
        request_metadata: RequestMetadata,
        round_limits: &mut RoundLimits,
        network_topology: &NetworkTopology,
    ) -> WasmExecutionResult {
        match self.deterministic_time_slicing {
            FlagStatus::Enabled => assert!(
                execution_parameters.instruction_limits.message()
                    >= execution_parameters.instruction_limits.slice()
            ),
            FlagStatus::Disabled => assert_eq!(
                execution_parameters.instruction_limits.message(),
                execution_parameters.instruction_limits.slice()
            ),
        }
        let caller = api_type.caller();
        let subnet_available_callbacks = round_limits.subnet_available_callbacks.max(0) as u64;
        let remaining_canister_callback_quota = system_state.call_context_manager().map_or(
            // The default is never used (since we would never end up here with no
            // `CallContextManager`) but preferrable to an `unwrap()`.
            self.canister_guaranteed_callback_quota,
            |ccm| {
                self.canister_guaranteed_callback_quota
                    .saturating_sub(ccm.callbacks().len())
            },
        ) as u64;
        // Maximum between remaining canister quota and available subnet shared pool.
        let available_callbacks = subnet_available_callbacks.max(remaining_canister_callback_quota);
        let static_system_state = SandboxSafeSystemState::new(
            system_state,
            *self.cycles_account_manager,
            network_topology,
            self.dirty_page_overhead,
            execution_parameters.compute_allocation,
            available_callbacks,
            request_metadata,
            api_type.caller(),
            api_type.call_context_id(),
            execution_state.is_wasm64,
        );
        let api_type_str = api_type.as_str();
        let (compilation_result, mut execution_result) = Arc::clone(&self.wasm_executor).execute(
            WasmExecutionInput {
                api_type,
                sandbox_safe_system_state: static_system_state,
                canister_current_memory_usage,
                canister_current_message_memory_usage,
                execution_parameters,
                subnet_available_memory: round_limits.subnet_available_memory,
                func_ref,
                compilation_cache: Arc::clone(&self.compilation_cache),
            },
            execution_state,
        );
        if let Some(compilation_result) = compilation_result {
            self.metrics.observe_compilation_metrics(
                &compilation_result,
                self.compilation_cache.memory_bytes(),
                self.compilation_cache.disk_bytes(),
            );
        }
        self.metrics.observe(&execution_result, api_type_str);

        // If the caller does not have permission to view this canister's logs,
        // then it shouldn't get a backtrace either. So in that case we remove
        // the backtrace from the error.
        fn remove_backtrace(err: &mut HypervisorError) {
            match err {
                HypervisorError::Trapped { backtrace, .. }
                | HypervisorError::CalledTrap { backtrace, .. } => *backtrace = None,
                HypervisorError::Cleanup {
                    callback_err,
                    cleanup_err,
                } => {
                    remove_backtrace(callback_err);
                    remove_backtrace(cleanup_err);
                }
                _ => {}
            }
        }
        if let WasmExecutionResult::Finished(_, result, _) = &mut execution_result {
            if let Err(err) = &mut result.wasm_result {
                let can_view = match &system_state.log_visibility {
                    LogVisibilityV2::Controllers => {
                        caller.is_some_and(|c| system_state.controllers.contains(&c))
                    }
                    LogVisibilityV2::Public => true,
                    LogVisibilityV2::AllowedViewers(allowed) => {
                        caller.is_some_and(|c| allowed.get().contains(&c))
                    }
                };
                if !can_view {
                    remove_backtrace(err);
                }
            }
        }

        execution_result
    }

    #[doc(hidden)]
    pub fn clear_compilation_cache_for_testing(&self) {
        self.compilation_cache.clear_for_testing()
    }

    /// Insert a compiled module in the compilation cache speed up tests by
    /// skipping the Wasmtime compilation step.
    #[doc(hidden)]
    pub fn compilation_cache_insert_for_testing(
        &self,
        bytes: Vec<u8>,
        compiled_module: ic_embedders::SerializedModule,
    ) {
        let canister_module = CanisterModule::new(bytes);
        self.compilation_cache
            .insert_ok(&canister_module, compiled_module);
    }
}
