use ic_canister_sandbox_replica_controller::sandboxed_execution_controller::SandboxedExecutionController;
use ic_config::embedders::FeatureFlags;
use ic_config::flag_status::FlagStatus;
use ic_config::{embedders::Config as EmbeddersConfig, execution_environment::Config};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::wasm_executor::{WasmExecutionResult, WasmExecutor};
use ic_embedders::{wasm_executor::WasmExecutorImpl, WasmExecutionInput, WasmtimeEmbedder};
use ic_embedders::{CompilationCache, CompilationResult};
use ic_interfaces::execution_environment::{HypervisorResult, WasmExecutionOutput};
use ic_logger::{fatal, ReplicaLogger};
use ic_metrics::buckets::decimal_buckets_with_zero;
use ic_metrics::{buckets::exponential_buckets, MetricsRegistry};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::NetworkTopology;
use ic_replicated_state::{
    page_map::allocated_pages_count, CanisterState, ExecutionState, SchedulerState, SystemState,
};
use ic_sys::PAGE_SIZE;
use ic_system_api::ExecutionParameters;
use ic_system_api::{sandbox_safe_system_state::SandboxSafeSystemState, ApiType};
use ic_types::{
    ingress::WasmResult, methods::FuncRef, CanisterId, NumBytes, NumInstructions, SubnetId, Time,
};
use ic_wasm_types::CanisterModule;
use prometheus::{Histogram, IntCounterVec, IntGauge};
use std::{path::PathBuf, sync::Arc};

use crate::execution::common::update_round_limits;
use crate::execution_environment::{as_round_instructions, RoundLimits};

#[doc(hidden)] // pub for usage in tests
pub struct HypervisorMetrics {
    accessed_pages: Histogram,
    dirty_pages: Histogram,
    allocated_pages: IntGauge,
    executed_messages: IntCounterVec,
    largest_function_instruction_count: Histogram,
    compile: Histogram,
}

impl HypervisorMetrics {
    #[doc(hidden)] // pub for usage in tests
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            accessed_pages: metrics_registry.histogram(
                "hypervisor_accessed_pages",
                "Number of pages accessed per execution round.",
                // 1 page, 2 pages, …, 2^21 (8GiB worth of) pages
                exponential_buckets(1.0, 2.0, 22),
            ),
            dirty_pages: metrics_registry.histogram(
                "hypervisor_dirty_pages",
                "Number of pages modified (dirtied) per execution round.",
                exponential_buckets(1.0, 2.0, 22),
            ),
            allocated_pages: metrics_registry.int_gauge(
                "hypervisor_allocated_pages",
                "Total number of currently allocated pages.",
            ),
            executed_messages: metrics_registry.int_counter_vec(
                "hypervisor_executed_messages_total",
                "Number of messages executed, by type and status.",
                &["api_type", "status"],
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
        }
    }

    fn observe(&self, api_type: &str, result: &WasmExecutionResult) {
        let status = match result {
            WasmExecutionResult::Finished(_, output, ..) => {
                self.accessed_pages
                    .observe(output.instance_stats.accessed_pages as f64);
                self.dirty_pages
                    .observe(output.instance_stats.dirty_pages as f64);
                self.allocated_pages.set(allocated_pages_count() as i64);

                match &output.wasm_result {
                    Ok(Some(WasmResult::Reply(_))) => "success",
                    Ok(Some(WasmResult::Reject(_))) => "Reject",
                    Ok(None) => "NoResponse",
                    Err(e) => e.as_str(),
                }
            }
            WasmExecutionResult::Paused(_, _) => "paused",
        };
        self.executed_messages
            .with_label_values(&[api_type, status])
            .inc();
    }

    fn observe_compilation_metrics(&self, compilation_result: &CompilationResult) {
        let CompilationResult {
            largest_function_instruction_count,
            compilation_time,
        } = compilation_result;
        self.largest_function_instruction_count
            .observe(largest_function_instruction_count.get() as f64);
        self.compile.observe(compilation_time.as_secs_f64());
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
}

impl Hypervisor {
    pub(crate) fn subnet_id(&self) -> SubnetId {
        self.own_subnet_id
    }

    pub fn subnet_type(&self) -> SubnetType {
        self.own_subnet_type
    }

    // A helper that converts a Wasm execution output to an execution
    // result of `execution_canister_*` functions.
    //
    // The components of the resulting `CanisterState` are computed
    // as follows:
    // - `execution_state` is taken from the Wasm output.
    // - `scheduler_state` is taken from the corresponding argument.
    // - `system_state` is taken from the system_state_accessor if the execution
    //   succeeded; otherwise, it is taken from the corresponding argument.
    pub fn system_execution_result(
        &self,
        output: WasmExecutionOutput,
        execution_state: ExecutionState,
        old_system_state: SystemState,
        scheduler_state: SchedulerState,
        output_system_state: SystemState,
    ) -> (CanisterState, NumInstructions, HypervisorResult<NumBytes>) {
        let (system_state, heap_delta) = match output.wasm_result {
            Ok(opt_result) => {
                if opt_result.is_some() {
                    fatal!(self.log, "[EXC-BUG] System methods cannot use msg_reply.");
                }
                let bytes = NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64);
                (output_system_state, Ok(bytes))
            }
            Err(err) => (old_system_state, Err(err)),
        };
        let canister =
            CanisterState::from_parts(Some(execution_state), system_state, scheduler_state);
        (canister, output.num_instructions_left, heap_delta)
    }

    pub fn create_execution_state(
        &self,
        wasm_binary: Vec<u8>,
        canister_root: PathBuf,
        canister_id: CanisterId,
        round_limits: &mut RoundLimits,
    ) -> HypervisorResult<(NumInstructions, ExecutionState)> {
        let canister_module = CanisterModule::new(wasm_binary);
        let (execution_state, compilation_cost, compilation_result) =
            self.wasm_executor.create_execution_state(
                canister_module,
                canister_root,
                canister_id,
                Arc::clone(&self.compilation_cache),
            )?;
        if let Some(compilation_result) = compilation_result {
            self.metrics
                .observe_compilation_metrics(&compilation_result);
        }
        round_limits.instructions -= as_round_instructions(compilation_cost);
        Ok((compilation_cost, execution_state))
    }

    pub fn new(
        config: Config,
        metrics_registry: &MetricsRegistry,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        log: ReplicaLogger,
        cycles_account_manager: Arc<CyclesAccountManager>,
    ) -> Self {
        let mut embedder_config = EmbeddersConfig::new();
        embedder_config.query_execution_threads = config.query_execution_threads;
        embedder_config.feature_flags.rate_limiting_of_debug_prints =
            config.rate_limiting_of_debug_prints;

        let module_sharing_flag = embedder_config.feature_flags.module_sharing;

        let wasm_executor: Arc<dyn WasmExecutor> = match config.canister_sandboxing_flag {
            FlagStatus::Enabled => {
                let executor = SandboxedExecutionController::new(
                    log.clone(),
                    metrics_registry,
                    &embedder_config,
                )
                .expect("Failed to start sandboxed execution controller");
                Arc::new(executor)
            }
            FlagStatus::Disabled => {
                let executor = WasmExecutorImpl::new(
                    WasmtimeEmbedder::new(embedder_config, log.clone()),
                    metrics_registry,
                    log.clone(),
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
            compilation_cache: Arc::new(CompilationCache::new(module_sharing_flag)),
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
    ) -> Self {
        Self {
            wasm_executor,
            metrics: Arc::new(HypervisorMetrics::new(metrics_registry)),
            own_subnet_id,
            own_subnet_type,
            log,
            cycles_account_manager,
            compilation_cache: Arc::new(CompilationCache::new(
                FeatureFlags::default().module_sharing,
            )),
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
        execution_parameters: ExecutionParameters,
        func_ref: FuncRef,
        execution_state: ExecutionState,
        network_topology: &NetworkTopology,
        round_limits: &mut RoundLimits,
    ) -> (WasmExecutionOutput, ExecutionState, SystemState) {
        let api_type_str = api_type.as_str();
        let static_system_state = SandboxSafeSystemState::new(
            &system_state,
            *self.cycles_account_manager,
            network_topology,
        );
        let (compilation_result, execution_state, execution_result) =
            Arc::clone(&self.wasm_executor).execute(WasmExecutionInput {
                api_type,
                sandbox_safe_system_state: static_system_state,
                canister_current_memory_usage,
                execution_parameters,
                subnet_available_memory: round_limits.subnet_available_memory.get(),
                func_ref,
                execution_state,
                compilation_cache: Arc::clone(&self.compilation_cache),
            });
        if let Some(compilation_result) = compilation_result {
            self.metrics
                .observe_compilation_metrics(&compilation_result);
        }
        self.metrics.observe(api_type_str, &execution_result);
        let (slice, output, system_state_changes) = match execution_result {
            WasmExecutionResult::Finished(slice, output, system_state_changes) => {
                (slice, output, system_state_changes)
            }
            WasmExecutionResult::Paused(_, _) => {
                unreachable!("DTS is not enabled yet.");
            }
        };
        // The unwrap is guaranteed to succeed because without DTS the subnet
        // available memory did not change since the start of execution and the
        // Wasm executor must have done all checks.
        round_limits
            .subnet_available_memory
            .try_decrement(output.allocated_bytes, output.allocated_message_bytes)
            .unwrap();
        update_round_limits(round_limits, &slice);
        system_state_changes.apply_changes(
            time,
            &mut system_state,
            network_topology,
            self.own_subnet_id,
            &self.log,
        );
        (output, execution_state, system_state)
    }

    /// Executes the given WebAssembly function with deterministic time slicing.
    /// TODO(RUN-232): Change all callers of `execute()` to call `execute_dts()`
    /// and rename `execute_dts()` to `execute()`.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_dts(
        &self,
        api_type: ApiType,
        system_state: SystemState,
        canister_current_memory_usage: NumBytes,
        execution_parameters: ExecutionParameters,
        func_ref: FuncRef,
        execution_state: ExecutionState,
        round_limits: &mut RoundLimits,
        network_topology: &NetworkTopology,
    ) -> (ExecutionState, WasmExecutionResult) {
        let api_type_str = api_type.as_str();
        let static_system_state = SandboxSafeSystemState::new(
            &system_state,
            *self.cycles_account_manager,
            network_topology,
        );
        let (compilation_result, execution_state, execution_result) =
            Arc::clone(&self.wasm_executor).execute(WasmExecutionInput {
                api_type,
                sandbox_safe_system_state: static_system_state,
                canister_current_memory_usage,
                execution_parameters,
                subnet_available_memory: round_limits.subnet_available_memory.get(),
                func_ref,
                execution_state,
                compilation_cache: Arc::clone(&self.compilation_cache),
            });

        if let Some(compilation_result) = compilation_result {
            self.metrics
                .observe_compilation_metrics(&compilation_result);
        }
        self.metrics.observe(api_type_str, &execution_result);
        (execution_state, execution_result)
    }

    #[doc(hidden)]
    pub fn clear_compilation_cache_for_testing(&self) {
        self.compilation_cache.clear_for_testing()
    }
}
