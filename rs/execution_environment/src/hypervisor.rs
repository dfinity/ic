use ic_canister_sandbox_backend_lib::replica_controller::sandboxed_execution_controller::SandboxedExecutionController;
use ic_config::execution_environment::{Config, MAX_COMPILATION_CACHE_SIZE};
use ic_config::flag_status::FlagStatus;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::{
    CompilationCache, CompilationCacheBuilder, CompilationResult, WasmExecutionInput,
    WasmtimeEmbedder,
    wasm_executor::{WasmExecutionResult, WasmExecutor, WasmExecutorImpl},
    wasm_utils::decoding::decoded_wasm_size,
    wasmtime_embedder::system_api::{
        ApiType, ExecutionParameters, sandbox_safe_system_state::SandboxSafeSystemState,
    },
};
use ic_heap_bytes::HeapBytes;
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, MessageMemoryUsage, WasmExecutionOutput,
};
use ic_interfaces_state_manager::StateReader;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_metrics::buckets::{decimal_buckets_with_zero, linear_buckets};
use ic_replicated_state::{ExecutionState, NetworkTopology, ReplicatedState, SystemState};
use ic_types::batch::CanisterCyclesCostSchedule;
use ic_types::{
    CanisterId, DiskBytes, NumBytes, NumInstructions, SubnetId, Time, messages::RequestMetadata,
    methods::FuncRef,
};
use ic_wasm_types::CanisterModule;
use prometheus::{Histogram, IntCounter, IntGaugeVec};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::canister_logs::check_log_visibility_permission;
use crate::execution::common::{apply_canister_state_changes, update_round_limits};
use crate::execution_environment::{CompilationCostHandling, RoundLimits};
use crate::metrics::CallTreeMetrics;
use ic_replicated_state::page_map::PageAllocatorFileDescriptor;

#[doc(hidden)] // pub for usage in tests
pub struct HypervisorMetrics {
    largest_function_instruction_count: Histogram,
    compile: Histogram,
    max_complexity: Histogram,
    compilation_cache_size: IntGaugeVec,
    code_section_size: Histogram,
}

impl HypervisorMetrics {
    #[doc(hidden)] // pub for usage in tests
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            largest_function_instruction_count: metrics_registry.histogram(
                "hypervisor_largest_function_instruction_count",
                "Size of the largest compiled wasm function in a canister \
                    by number of wasm instructions.",
                decimal_buckets_with_zero(1, 7), // 10 - 10M.
            ),
            compile: metrics_registry.histogram(
                "hypervisor_wasm_compile_time_seconds",
                "The duration of Wasm module compilation including validation \
                    and instrumentation.",
                decimal_buckets_with_zero(-4, 1),
            ),
            max_complexity: metrics_registry.histogram(
                "hypervisor_wasm_max_function_complexity",
                "The maximum function complexity in a wasm module.",
                decimal_buckets_with_zero(1, 8), //10 - 100M.
            ),
            compilation_cache_size: metrics_registry.int_gauge_vec(
                "hypervisor_compilation_cache_size",
                "Bytes in memory and on disk used by the compilation cache.",
                &["location"],
            ),
            code_section_size: metrics_registry.histogram(
                "hypervisor_code_section_size",
                "Size of the code section in bytes for a canister Wasm. Only Wasms that \
                    successfully compile are counted (which implies the code sections are below \
                    the current limit).",
                linear_buckets(1024.0 * 1024.0, 1024.0 * 1204.0, 11), // 1MiB, 2MiB, ..., 11 MiB. Current limit is 11 MiB.
            ),
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
            code_section_size,
        } = compilation_result;
        self.largest_function_instruction_count
            .observe(largest_function_instruction_count.get() as f64);
        self.compile.observe(compilation_time.as_secs_f64());
        self.max_complexity.observe(*max_complexity as f64);
        self.code_section_size
            .observe(code_section_size.get() as f64);
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
    log: ReplicaLogger,
    cycles_account_manager: Arc<CyclesAccountManager>,
    compilation_cache: Arc<CompilationCache>,
    cost_to_compile_wasm_instruction: NumInstructions,
    dirty_page_overhead: NumInstructions,
    canister_guaranteed_callback_quota: usize,
}

impl Hypervisor {
    pub(crate) fn subnet_id(&self) -> SubnetId {
        self.own_subnet_id
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
            round_limits.charge_instructions(compilation_cost);
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
                        self.compilation_cache.heap_bytes(),
                        self.compilation_cache.disk_bytes(),
                    );
                }
                let adjusted_compilation_cost =
                    compilation_cost_handling.adjusted_compilation_cost(compilation_cost);
                round_limits.charge_instructions(adjusted_compilation_cost);
                (adjusted_compilation_cost, Ok(execution_state))
            }
            Err(err) => {
                round_limits.charge_instructions(compilation_cost);
                (compilation_cost, Err(err))
            }
        }
    }

    pub(crate) fn new(
        config: Config,
        metrics_registry: &MetricsRegistry,
        own_subnet_id: SubnetId,
        log: ReplicaLogger,
        cycles_account_manager: Arc<CyclesAccountManager>,
        dirty_page_overhead: NumInstructions,
        fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        temp_dir: &Path,
    ) -> Self {
        let mut embedder_config = config.embedders_config.clone();
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
            log,
            cycles_account_manager,
            compilation_cache: Arc::new(
                CompilationCacheBuilder::new()
                    .with_memory_capacity(MAX_COMPILATION_CACHE_SIZE)
                    .with_dir(tempfile::tempdir_in(temp_dir).unwrap())
                    .build(),
            ),
            cost_to_compile_wasm_instruction: config
                .embedders_config
                .cost_to_compile_wasm_instruction,
            dirty_page_overhead,
            canister_guaranteed_callback_quota: config.canister_guaranteed_callback_quota,
        }
    }

    pub(crate) fn new_for_testing(
        metrics_registry: &MetricsRegistry,
        own_subnet_id: SubnetId,
        log: ReplicaLogger,
        cycles_account_manager: Arc<CyclesAccountManager>,
        wasm_executor: Arc<dyn WasmExecutor>,
        cost_to_compile_wasm_instruction: NumInstructions,
        dirty_page_overhead: NumInstructions,
        canister_guaranteed_callback_quota: usize,
    ) -> Self {
        Self {
            wasm_executor,
            metrics: Arc::new(HypervisorMetrics::new(metrics_registry)),
            own_subnet_id,
            log,
            cycles_account_manager,
            compilation_cache: Arc::new(
                CompilationCacheBuilder::new()
                    .with_memory_capacity(MAX_COMPILATION_CACHE_SIZE)
                    .with_dir(tempfile::tempdir().unwrap())
                    .build(),
            ),
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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute(
        &self,
        api_type: ApiType,
        time: Time,
        mut system_state: SystemState,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        execution_parameters: ExecutionParameters,
        func_ref: FuncRef,
        mut execution_state: ExecutionState,
        network_topology: &NetworkTopology,
        round_limits: &mut RoundLimits,
        state_changes_error: &IntCounter,
        call_tree_metrics: &dyn CallTreeMetrics,
        call_context_creation_time: Time,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> (WasmExecutionOutput, ExecutionState, SystemState) {
        assert_eq!(
            execution_parameters.instruction_limits.message(),
            execution_parameters.instruction_limits.slice()
        );
        let is_composite_query = matches!(api_type, ApiType::CompositeQuery { .. });
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
            cost_schedule,
        );
        let (slice, mut output, canister_state_changes) = match execution_result {
            WasmExecutionResult::Finished(slice, output, system_state_modifications) => {
                (slice, output, system_state_modifications)
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
            is_composite_query,
            &|system_state| std::mem::drop(system_state),
        );
        (output, execution_state, system_state)
    }

    /// Executes the given WebAssembly function with deterministic time slicing.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_dts(
        &self,
        api_type: ApiType,
        execution_state: &ExecutionState,
        system_state: &SystemState,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        execution_parameters: ExecutionParameters,
        func_ref: FuncRef,
        request_metadata: RequestMetadata,
        round_limits: &mut RoundLimits,
        network_topology: &NetworkTopology,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> WasmExecutionResult {
        assert!(
            execution_parameters.instruction_limits.message()
                >= execution_parameters.instruction_limits.slice()
        );
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
            execution_state.wasm_execution_mode.is_wasm64(),
            cost_schedule,
        );
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
                self.compilation_cache.heap_bytes(),
                self.compilation_cache.disk_bytes(),
            );
        }

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
            // If execution fails, remove the backtrace when the caller is not allowed to see logs.
            if let (Some(caller), Err(err)) = (caller, &mut result.wasm_result)
                && check_log_visibility_permission(
                    &caller,
                    &system_state.log_visibility,
                    &system_state.controllers,
                )
                .is_err()
            {
                remove_backtrace(err);
            }
        }

        execution_result
    }

    pub(crate) fn clear_compilation_cache_for_testing(&self) {
        self.compilation_cache.clear_for_testing()
    }

    // Insert a compiled module in the compilation cache speed up tests by
    // skipping the Wasmtime compilation step.
    pub(crate) fn compilation_cache_insert_for_testing(
        &self,
        bytes: Vec<u8>,
        compiled_module: ic_embedders::SerializedModule,
    ) {
        let canister_module = CanisterModule::new(bytes);
        self.compilation_cache
            .insert_ok(&canister_module, compiled_module);
    }
}
