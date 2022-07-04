use ic_canister_sandbox_replica_controller::sandboxed_execution_controller::SandboxedExecutionController;
use ic_config::flag_status::FlagStatus;
use ic_config::{embedders::Config as EmbeddersConfig, execution_environment::Config};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::wasm_executor::{WasmExecutionResult, WasmExecutor};
use ic_embedders::{wasm_executor::WasmExecutorImpl, WasmExecutionInput, WasmtimeEmbedder};
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::CanisterStatusType;
use ic_interfaces::execution_environment::{
    CompilationResult, ExecutionParameters, HypervisorError, HypervisorResult, WasmExecutionOutput,
};
use ic_logger::{fatal, ReplicaLogger};
use ic_metrics::buckets::decimal_buckets_with_zero;
use ic_metrics::{buckets::exponential_buckets, MetricsRegistry};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::NetworkTopology;
use ic_replicated_state::{
    page_map::allocated_pages_count, CallContextAction, CallOrigin, CanisterState, ExecutionState,
    SchedulerState, SystemState,
};
use ic_sys::PAGE_SIZE;
use ic_system_api::{sandbox_safe_system_state::SandboxSafeSystemState, ApiType};
use ic_types::{
    ingress::WasmResult,
    messages::Payload,
    methods::{Callback, FuncRef, SystemMethod, WasmMethod},
    CanisterId, Cycles, NumBytes, NumInstructions, PrincipalId, SubnetId, Time,
};
use prometheus::{Histogram, IntCounterVec, IntGauge};
use std::{path::PathBuf, sync::Arc};

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
            WasmExecutionResult::Finished(output, ..) => {
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
            WasmExecutionResult::Paused(_) => "paused",
        };
        self.executed_messages
            .with_label_values(&[api_type, status])
            .inc();
    }

    fn observe_compilation_metrics(&self, compilation_result: &CompilationResult) {
        let CompilationResult {
            largest_function_instruction_count,
            compilation_time,
            compilation_cost: _,
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
}

impl Hypervisor {
    pub(crate) fn subnet_id(&self) -> SubnetId {
        self.own_subnet_id
    }

    pub(crate) fn subnet_type(&self) -> SubnetType {
        self.own_subnet_type
    }

    /// Execute a callback.
    ///
    /// Callbacks are executed when a canister receives a response to an
    /// outbound request it had made.
    ///
    /// Returns:
    ///
    /// - The updated `CanisterState` if the execution succeeded, otherwise
    /// the old `CanisterState`.
    ///
    /// - Number of instructions left. This should be <= `instructions_limit`.
    ///
    /// - The size of the heap delta change that the execution produced.
    ///
    /// - A HypervisorResult that on success contains an optional wasm execution
    ///   result or the relevant error if execution failed.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn execute_callback(
        &self,
        mut canister: CanisterState,
        call_origin: &CallOrigin,
        callback: Callback,
        payload: Payload,
        incoming_cycles: Cycles,
        time: Time,
        network_topology: Arc<NetworkTopology>,
        execution_parameters: ExecutionParameters,
    ) -> (CanisterState, NumInstructions, CallContextAction, NumBytes) {
        // Validate that the canister is not stopped.
        if canister.status() == CanisterStatusType::Stopped {
            return (
                canister,
                execution_parameters.total_instruction_limit,
                CallContextAction::Fail {
                    error: HypervisorError::CanisterStopped,
                    refund: Cycles::new(0),
                },
                NumBytes::from(0),
            );
        }

        // Validate that the canister has an `ExecutionState`.
        if canister.execution_state.is_none() {
            let action = canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .on_canister_result(
                    callback.call_context_id,
                    Err(HypervisorError::WasmModuleNotFound),
                );
            return (
                canister,
                execution_parameters.total_instruction_limit,
                action,
                NumBytes::from(0),
            );
        }

        let call_responded = canister
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .call_responded(callback.call_context_id)
            // NOTE: Since we retrieved the `call_origin` earlier, we are now
            // sure that a call context exists and that this unwrap is safe.
            .unwrap();

        let closure = match payload {
            Payload::Data(_) => callback.on_reply,
            Payload::Reject(_) => callback.on_reject,
        };

        let api_type = match payload {
            Payload::Data(payload) => ApiType::reply_callback(
                time,
                payload.to_vec(),
                incoming_cycles,
                callback.call_context_id,
                call_responded,
            ),
            Payload::Reject(context) => ApiType::reject_callback(
                time,
                context,
                incoming_cycles,
                callback.call_context_id,
                call_responded,
            ),
        };

        let func_ref = match call_origin {
            CallOrigin::Ingress(_, _)
            | CallOrigin::CanisterUpdate(_, _)
            | CallOrigin::Heartbeat => FuncRef::UpdateClosure(closure),
            CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => {
                FuncRef::QueryClosure(closure)
            }
        };

        let (output, output_execution_state, output_system_state) = self.execute(
            api_type,
            canister.system_state.clone(),
            canister.memory_usage(self.own_subnet_type),
            execution_parameters.clone(),
            func_ref,
            canister.execution_state.take().unwrap(),
            &network_topology,
        );

        let canister_current_memory_usage = canister.memory_usage(self.own_subnet_type);
        let call_origin = call_origin.clone();

        canister.execution_state = Some(output_execution_state);
        let (num_instr, num_bytes, result) = match output.wasm_result {
            result @ Ok(_) => {
                // Executing the reply/reject closure succeeded.
                canister.system_state = output_system_state;
                let heap_delta =
                    NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64);
                (output.num_instructions_left, heap_delta, result)
            }
            Err(callback_err) => {
                // A trap has occurred when executing the reply/reject closure.
                // Execute the cleanup if it exists.
                match callback.on_cleanup {
                    None => {
                        // No cleanup closure present. Return the callback error as-is.
                        (
                            output.num_instructions_left,
                            NumBytes::from(0),
                            Err(callback_err),
                        )
                    }
                    Some(cleanup_closure) => {
                        let func_ref = match call_origin {
                            CallOrigin::Ingress(_, _)
                            | CallOrigin::CanisterUpdate(_, _)
                            | CallOrigin::Heartbeat => FuncRef::UpdateClosure(cleanup_closure),
                            CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => {
                                FuncRef::QueryClosure(cleanup_closure)
                            }
                        };
                        let (cleanup_output, output_execution_state, output_system_state) = self
                            .execute(
                                ApiType::Cleanup { time },
                                canister.system_state.clone(),
                                canister_current_memory_usage,
                                ExecutionParameters {
                                    total_instruction_limit: output.num_instructions_left,
                                    slice_instruction_limit: output.num_instructions_left,
                                    ..execution_parameters
                                },
                                func_ref,
                                canister.execution_state.take().unwrap(),
                                &network_topology,
                            );

                        canister.execution_state = Some(output_execution_state);
                        match cleanup_output.wasm_result {
                            Ok(_) => {
                                // Executing the cleanup callback has succeeded.
                                canister.system_state = output_system_state;
                                let heap_delta = NumBytes::from(
                                    (cleanup_output.instance_stats.dirty_pages * PAGE_SIZE) as u64,
                                );

                                // Note that, even though the callback has succeeded,
                                // the original callback error is returned.
                                (
                                    cleanup_output.num_instructions_left,
                                    heap_delta,
                                    Err(callback_err),
                                )
                            }
                            Err(cleanup_err) => {
                                // Executing the cleanup call back failed.
                                (
                                    cleanup_output.num_instructions_left,
                                    NumBytes::from(0),
                                    Err(HypervisorError::Cleanup {
                                        callback_err: Box::new(callback_err),
                                        cleanup_err: Box::new(cleanup_err),
                                    }),
                                )
                            }
                        }
                    }
                }
            }
        };
        let action = canister
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .on_canister_result(callback.call_context_id, result);
        (canister, num_instr, action, num_bytes)
    }

    /// Executes the system method `canister_start`.
    ///
    /// Returns:
    ///
    /// - The updated `CanisterState` if the execution succeeded, otherwise
    /// the old `CanisterState`.
    ///
    /// - Number of instructions left. This should be <= `instructions_limit`.
    ///
    /// - A HypervisorResult containing the size of the heap delta change if
    /// execution was successful or the relevant error if execution failed.
    #[allow(clippy::type_complexity)]
    pub fn execute_canister_start(
        &self,
        canister: CanisterState,
        execution_parameters: ExecutionParameters,
        network_topology: &NetworkTopology,
    ) -> (CanisterState, NumInstructions, HypervisorResult<NumBytes>) {
        let method = WasmMethod::System(SystemMethod::CanisterStart);
        let memory_usage = canister.memory_usage(self.own_subnet_type);
        let canister_id = canister.canister_id();
        let (execution_state, system_state, scheduler_state) = canister.into_parts();

        // Validate that the Wasm module is present.
        let execution_state = match execution_state {
            None => {
                return (
                    CanisterState::from_parts(None, system_state, scheduler_state),
                    execution_parameters.total_instruction_limit,
                    Err(HypervisorError::WasmModuleNotFound),
                );
            }
            Some(es) => es,
        };

        // If the Wasm module does not export the method, then this execution
        // succeeds as a no-op.
        if !execution_state.exports_method(&method) {
            return (
                CanisterState::from_parts(Some(execution_state), system_state, scheduler_state),
                execution_parameters.total_instruction_limit,
                Ok(NumBytes::from(0)),
            );
        }

        let (output, output_execution_state, _system_state_accessor) = self.execute(
            ApiType::start(),
            SystemState::new_for_start(canister_id),
            memory_usage,
            execution_parameters,
            FuncRef::Method(method),
            execution_state,
            network_topology,
        );

        self.system_execution_result_with_old_system_state(
            output,
            output_execution_state,
            system_state,
            scheduler_state,
        )
    }

    /// Executes the system method `canister_inspect_message`.
    ///
    /// This method is called pre-consensus to let the canister decide if it
    /// wants to accept the message or not.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_inspect_message(
        &self,
        canister: CanisterState,
        sender: PrincipalId,
        method_name: String,
        method_payload: Vec<u8>,
        time: Time,
        execution_parameters: ExecutionParameters,
        network_topology: &NetworkTopology,
    ) -> (NumInstructions, Result<(), UserError>) {
        let method = WasmMethod::System(SystemMethod::CanisterInspectMessage);
        let memory_usage = canister.memory_usage(self.own_subnet_type);
        let canister_id = canister.canister_id();
        let (execution_state, system_state, _) = canister.into_parts();

        // Validate that the Wasm module is present.
        let execution_state = match execution_state {
            None => {
                return (
                    execution_parameters.total_instruction_limit,
                    Err(UserError::new(
                        ErrorCode::CanisterWasmModuleNotFound,
                        "Requested canister has no wasm module",
                    )),
                );
            }
            Some(execution_state) => execution_state,
        };

        // If the Wasm module does not export the method, then this execution
        // succeeds as a no-op.
        if !execution_state.exports_method(&method) {
            return (execution_parameters.total_instruction_limit, Ok(()));
        }

        let system_api = ApiType::inspect_message(sender, method_name, method_payload, time);
        let log = self.log.clone();
        let (output, _output_execution_state, _system_state_accessor) = self.execute(
            system_api,
            system_state,
            memory_usage,
            execution_parameters,
            FuncRef::Method(method),
            execution_state,
            network_topology,
        );
        match output.wasm_result {
            Ok(maybe_wasm_result) => match maybe_wasm_result {
                None => (output.num_instructions_left, Ok(())),
                Some(_result) => fatal!(
                    log,
                    "SystemApi should guarantee that the canister does not reply"
                ),
            },
            Err(err) => (
                output.num_instructions_left,
                Err(err.into_user_error(&canister_id)),
            ),
        }
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

    // Similar to `system_execution_result` but unconditionally uses
    // the given `old_system_state` for the resulting canister state.
    fn system_execution_result_with_old_system_state(
        &self,
        output: WasmExecutionOutput,
        execution_state: ExecutionState,
        old_system_state: SystemState,
        scheduler_state: SchedulerState,
    ) -> (CanisterState, NumInstructions, HypervisorResult<NumBytes>) {
        let heap_delta = match output.wasm_result {
            Ok(opt_result) => {
                if opt_result.is_some() {
                    fatal!(self.log, "[EXC-BUG] System methods cannot use msg_reply.");
                }
                Ok(NumBytes::from(
                    (output.instance_stats.dirty_pages * PAGE_SIZE) as u64,
                ))
            }
            Err(err) => Err(err),
        };
        let canister =
            CanisterState::from_parts(Some(execution_state), old_system_state, scheduler_state);
        (canister, output.num_instructions_left, heap_delta)
    }

    pub fn create_execution_state(
        &self,
        wasm_binary: Vec<u8>,
        canister_root: PathBuf,
        canister_id: CanisterId,
    ) -> HypervisorResult<(NumInstructions, ExecutionState)> {
        let (compilation_result, execution_state) =
            self.wasm_executor
                .create_execution_state(wasm_binary, canister_root, canister_id)?;
        self.metrics
            .observe_compilation_metrics(&compilation_result);
        Ok((compilation_result.compilation_cost, execution_state))
    }

    #[allow(clippy::too_many_arguments)]
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
        mut system_state: SystemState,
        canister_current_memory_usage: NumBytes,
        execution_parameters: ExecutionParameters,
        func_ref: FuncRef,
        execution_state: ExecutionState,
        network_topology: &NetworkTopology,
    ) -> (WasmExecutionOutput, ExecutionState, SystemState) {
        let api_type_str = api_type.as_str();
        let static_system_state =
            SandboxSafeSystemState::new(&system_state, *self.cycles_account_manager);

        let (compilation_result, execution_state, execution_result) =
            Arc::clone(&self.wasm_executor).execute(WasmExecutionInput {
                api_type,
                sandbox_safe_system_state: static_system_state,
                canister_current_memory_usage,
                execution_parameters,
                func_ref,
                execution_state,
            });
        if let Some(compilation_result) = compilation_result {
            self.metrics
                .observe_compilation_metrics(&compilation_result);
        }
        self.metrics.observe(api_type_str, &execution_result);
        let (output, system_state_changes) = match execution_result {
            WasmExecutionResult::Finished(output, system_state_changes) => {
                (output, system_state_changes)
            }
            WasmExecutionResult::Paused(_) => {
                unreachable!("DTS is not enabled yet.");
            }
        };
        system_state_changes.apply_changes(
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
    ) -> (ExecutionState, WasmExecutionResult) {
        let api_type_str = api_type.as_str();
        let static_system_state =
            SandboxSafeSystemState::new(&system_state, *self.cycles_account_manager);

        let (compilation_result, execution_state, execution_result) =
            Arc::clone(&self.wasm_executor).execute(WasmExecutionInput {
                api_type,
                sandbox_safe_system_state: static_system_state,
                canister_current_memory_usage,
                execution_parameters,
                func_ref,
                execution_state,
            });
        if let Some(compilation_result) = compilation_result {
            self.metrics
                .observe_compilation_metrics(&compilation_result);
        }
        self.metrics.observe(api_type_str, &execution_result);
        (execution_state, execution_result)
    }
}
