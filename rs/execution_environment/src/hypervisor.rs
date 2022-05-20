use crate::{NonReplicatedQueryKind as QueryKind, QueryExecutionType};
use ic_canister_sandbox_replica_controller::sandboxed_execution_controller::SandboxedExecutionController;
use ic_config::flag_status::FlagStatus;
use ic_config::{embedders::Config as EmbeddersConfig, execution_environment::Config};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::{wasm_executor::WasmExecutor, WasmExecutionInput, WasmtimeEmbedder};
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::CanisterStatusType;
use ic_ic00_types::IC_00;
use ic_interfaces::execution_environment::{
    ExecutionParameters, HypervisorError, HypervisorResult, WasmExecutionOutput,
};
use ic_interfaces::messages::RequestOrIngress;
use ic_logger::{debug, fatal, ReplicaLogger};
use ic_metrics::{buckets::exponential_buckets, MetricsRegistry};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::NetworkTopology;
use ic_replicated_state::{
    page_map::allocated_pages_count, CallContextAction, CallOrigin, CanisterState, ExecutionState,
    SchedulerState, SystemState,
};
use ic_sys::PAGE_SIZE;
use ic_system_api::{
    sandbox_safe_system_state::SandboxSafeSystemState, ApiType, NonReplicatedQueryKind,
};
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
        }
    }

    fn observe(&self, api_type: &str, result: &WasmExecutionOutput) {
        self.accessed_pages
            .observe(result.instance_stats.accessed_pages as f64);
        self.dirty_pages
            .observe(result.instance_stats.dirty_pages as f64);
        self.allocated_pages.set(allocated_pages_count() as i64);

        let status = match &result.wasm_result {
            Ok(Some(WasmResult::Reply(_))) => "success",
            Ok(Some(WasmResult::Reject(_))) => "Reject",
            Ok(None) => "NoResponse",
            Err(e) => e.as_str(),
        };
        self.executed_messages
            .with_label_values(&[api_type, status])
            .inc();
    }
}

#[doc(hidden)]
pub struct Hypervisor {
    wasm_executor: Arc<WasmExecutor>,
    sandbox_executor: Option<Arc<SandboxedExecutionController>>,
    metrics: Arc<HypervisorMetrics>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    log: ReplicaLogger,
    cycles_account_manager: Arc<CyclesAccountManager>,
}

impl Hypervisor {
    /// Execute an update call.
    ///
    /// Returns:
    ///
    /// - The updated `CanisterState` if the execution succeeded, otherwise
    /// the old `CanisterState`.
    ///
    /// - Number of instructions left. This should be <= `instructions_limit`.
    ///
    /// - An enum describing the different actions that should be taken based
    /// the current state of the call context associated with the request that
    /// was executed.
    ///
    /// - The size of the heap delta change that the canister produced during
    /// execution. If execution failed, then the value is 0.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_update(
        &self,
        canister: CanisterState,
        mut request: RequestOrIngress,
        time: Time,
        network_topology: Arc<NetworkTopology>,
        execution_parameters: ExecutionParameters,
    ) -> (CanisterState, NumInstructions, CallContextAction, NumBytes) {
        debug!(self.log, "execute_update: method {}", request.method_name());

        let incoming_cycles = request.take_cycles();

        // Validate that the canister is running.
        if CanisterStatusType::Running != canister.status() {
            return (
                canister,
                execution_parameters.total_instruction_limit,
                CallContextAction::Fail {
                    error: HypervisorError::CanisterStopped,
                    refund: incoming_cycles,
                },
                NumBytes::from(0),
            );
        }

        let method = WasmMethod::Update(request.method_name().to_string());
        let memory_usage = canister.memory_usage(self.own_subnet_type);
        let (execution_state, mut system_state, scheduler_state) = canister.into_parts();

        // Validate that the Wasm module is present.
        let execution_state = match execution_state {
            None => {
                return (
                    CanisterState::from_parts(None, system_state, scheduler_state),
                    execution_parameters.total_instruction_limit,
                    CallContextAction::Fail {
                        error: HypervisorError::WasmModuleNotFound,
                        refund: incoming_cycles,
                    },
                    NumBytes::from(0),
                );
            }
            Some(es) => es,
        };

        // Validate that the Wasm module exports the method.
        if !execution_state.exports_method(&method) {
            return (
                CanisterState::from_parts(Some(execution_state), system_state, scheduler_state),
                execution_parameters.total_instruction_limit,
                CallContextAction::Fail {
                    error: HypervisorError::MethodNotFound(method),
                    refund: incoming_cycles,
                },
                NumBytes::from(0),
            );
        }

        let call_context_id = system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(CallOrigin::from(&request), incoming_cycles, time);

        let api_type = ApiType::update(
            time,
            request.method_payload().to_vec(),
            incoming_cycles,
            *request.sender(),
            call_context_id,
            self.own_subnet_id,
            self.own_subnet_type,
            Arc::clone(&network_topology),
        );
        let (output, output_execution_state, output_system_state) = self.execute(
            api_type,
            system_state.clone(),
            memory_usage,
            execution_parameters,
            FuncRef::Method(method),
            execution_state,
            &network_topology,
        );

        let (mut system_state, heap_delta) = if output.wasm_result.is_ok() {
            (
                output_system_state,
                NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64),
            )
        } else {
            // In contrast to other methods, an update methods ignores the
            // Wasm execution error and returns 0 as the heap delta.
            (system_state, NumBytes::from(0))
        };

        let action = system_state
            .call_context_manager_mut()
            .unwrap()
            .on_canister_result(call_context_id, output.wasm_result);

        let canister =
            CanisterState::from_parts(Some(output_execution_state), system_state, scheduler_state);
        (canister, output.num_instructions_left, action, heap_delta)
    }

    /// Execute a query call.
    ///
    /// Query calls are different from update calls as follows:
    /// - A different set of system APIs can be used.
    /// - Any modifications to the canister's state (like Wasm heap, etc.) will
    ///   be rolled back.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_query(
        &self,
        query_execution_type: QueryExecutionType,
        method: &str,
        payload: &[u8],
        caller: PrincipalId,
        canister: CanisterState,
        data_certificate: Option<Vec<u8>>,
        time: Time,
        execution_parameters: ExecutionParameters,
        network_topology: &NetworkTopology,
    ) -> (
        CanisterState,
        NumInstructions,
        HypervisorResult<Option<WasmResult>>,
    ) {
        // Validate that the canister is running.
        if CanisterStatusType::Running != canister.status() {
            return (
                canister,
                execution_parameters.total_instruction_limit,
                Err(HypervisorError::CanisterStopped),
            );
        }

        let method = WasmMethod::Query(method.to_string());
        let memory_usage = canister.memory_usage(self.own_subnet_type);
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
            Some(state) => state,
        };

        // Validate that the Wasm module exports the method.
        if !execution_state.exports_method(&method) {
            return (
                CanisterState::from_parts(Some(execution_state), system_state, scheduler_state),
                execution_parameters.total_instruction_limit,
                Err(HypervisorError::MethodNotFound(method)),
            );
        }

        match query_execution_type {
            QueryExecutionType::Replicated => {
                let api_type =
                    ApiType::replicated_query(time, payload.to_vec(), caller, data_certificate);
                // As we are executing the query in the replicated mode, we do
                // not want to commit updates, i.e. we must return the
                // unmodified version of the canister. Hence, execute on clones
                // of system and execution states so that we have the original
                // versions.
                let (output, _output_execution_state, _system_state_accessor) = self.execute(
                    api_type,
                    system_state.clone(),
                    memory_usage,
                    execution_parameters,
                    FuncRef::Method(method),
                    execution_state.clone(),
                    network_topology,
                );

                let canister =
                    CanisterState::from_parts(Some(execution_state), system_state, scheduler_state);
                (canister, output.num_instructions_left, output.wasm_result)
            }
            QueryExecutionType::NonReplicated {
                call_context_id,
                network_topology,
                query_kind,
            } => {
                let non_replicated_query_kind = match query_kind {
                    QueryKind::Pure => NonReplicatedQueryKind::Pure,
                    QueryKind::Stateful => NonReplicatedQueryKind::Stateful {
                        call_context_id,
                        network_topology: Arc::clone(&network_topology),
                        outgoing_request: None,
                    },
                };
                let api_type = ApiType::non_replicated_query(
                    time,
                    caller,
                    self.own_subnet_id,
                    payload.to_vec(),
                    data_certificate,
                    non_replicated_query_kind,
                );
                // As we are executing the query in non-replicated mode, we can
                // modify the canister as the caller is not going to be able to
                // commit modifications to the canister anyway.
                let (output, output_execution_state, output_system_state) = self.execute(
                    api_type,
                    system_state,
                    memory_usage,
                    execution_parameters,
                    FuncRef::Method(method),
                    execution_state.clone(),
                    &network_topology,
                );

                let new_execution_state = match query_kind {
                    QueryKind::Pure => execution_state,
                    QueryKind::Stateful => output_execution_state,
                };

                let canister = CanisterState::from_parts(
                    Some(new_execution_state),
                    output_system_state,
                    scheduler_state,
                );
                (canister, output.num_instructions_left, output.wasm_result)
            }
        }
    }

    /// Execute a query call that has no caller provided.
    /// This type of query is triggered by the IC only when
    /// there is a need to execute a query call on the provided canister.
    #[allow(clippy::type_complexity)]
    pub fn execute_anonymous_query(
        &self,
        time: Time,
        method: &str,
        payload: &[u8],
        canister: CanisterState,
        data_certificate: Option<Vec<u8>>,
        execution_parameters: ExecutionParameters,
        network_topology: &NetworkTopology,
    ) -> (
        CanisterState,
        NumInstructions,
        HypervisorResult<Option<WasmResult>>,
    ) {
        // Validate that the canister is running.
        if CanisterStatusType::Running != canister.status() {
            return (
                canister,
                execution_parameters.total_instruction_limit,
                Err(HypervisorError::CanisterStopped),
            );
        }

        let method = WasmMethod::Query(method.to_string());
        let memory_usage = canister.memory_usage(self.own_subnet_type);
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
            Some(state) => state,
        };

        // Validate that the Wasm module exports the method.
        if !execution_state.exports_method(&method) {
            return (
                CanisterState::from_parts(Some(execution_state), system_state, scheduler_state),
                execution_parameters.total_instruction_limit,
                Err(HypervisorError::MethodNotFound(method)),
            );
        }

        let api_type = ApiType::non_replicated_query(
            time,
            IC_00.get(),
            self.own_subnet_id,
            payload.to_vec(),
            data_certificate,
            NonReplicatedQueryKind::Pure,
        );
        // We do not want to commit updates. Hence, execute on clones
        // of system and execution states so that we have the original
        // versions.
        let (output, _, _) = self.execute(
            api_type,
            system_state.clone(),
            memory_usage,
            execution_parameters,
            FuncRef::Method(method),
            execution_state.clone(),
            network_topology,
        );

        // We return the unmodified version of the canister.
        let canister =
            CanisterState::from_parts(Some(execution_state), system_state, scheduler_state);
        (canister, output.num_instructions_left, output.wasm_result)
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
                self.own_subnet_id,
                self.own_subnet_type,
                Arc::clone(&network_topology),
            ),
            Payload::Reject(context) => ApiType::reject_callback(
                time,
                context,
                incoming_cycles,
                callback.call_context_id,
                call_responded,
                self.own_subnet_id,
                self.own_subnet_type,
                Arc::clone(&network_topology),
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

    /// Executes the system method `canister_pre_upgrade`.
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
    pub fn execute_canister_pre_upgrade(
        &self,
        canister: CanisterState,
        caller: PrincipalId,
        time: Time,
        execution_parameters: ExecutionParameters,
        network_topology: &NetworkTopology,
    ) -> (CanisterState, NumInstructions, HypervisorResult<NumBytes>) {
        let method = WasmMethod::System(SystemMethod::CanisterPreUpgrade);
        let memory_usage = canister.memory_usage(self.own_subnet_type);
        let (execution_state, old_system_state, scheduler_state) = canister.into_parts();

        // Validate that the Wasm module is present.
        let execution_state = match execution_state {
            None => {
                return (
                    CanisterState::from_parts(None, old_system_state, scheduler_state),
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
                CanisterState::from_parts(Some(execution_state), old_system_state, scheduler_state),
                execution_parameters.total_instruction_limit,
                Ok(NumBytes::from(0)),
            );
        }

        let (output, output_execution_state, output_system_state) = self.execute(
            ApiType::pre_upgrade(time, caller),
            old_system_state.clone(),
            memory_usage,
            execution_parameters,
            FuncRef::Method(method),
            execution_state,
            network_topology,
        );
        self.system_execution_result(
            output,
            output_execution_state,
            old_system_state,
            scheduler_state,
            output_system_state,
        )
    }

    /// Executes the system method `canister_init`.
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
    pub fn execute_canister_init(
        &self,
        canister: CanisterState,
        caller: PrincipalId,
        payload: &[u8],
        time: Time,
        execution_parameters: ExecutionParameters,
        network_topology: &NetworkTopology,
    ) -> (CanisterState, NumInstructions, HypervisorResult<NumBytes>) {
        let method = WasmMethod::System(SystemMethod::CanisterInit);
        let memory_usage = canister.memory_usage(self.own_subnet_type);
        let (execution_state, old_system_state, scheduler_state) = canister.into_parts();

        // Validate that the Wasm module is present.
        let execution_state = match execution_state {
            None => {
                return (
                    CanisterState::from_parts(None, old_system_state, scheduler_state),
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
                CanisterState::from_parts(Some(execution_state), old_system_state, scheduler_state),
                execution_parameters.total_instruction_limit,
                Ok(NumBytes::from(0)),
            );
        }

        let (output, output_execution_state, output_system_state) = self.execute(
            ApiType::init(time, payload.to_vec(), caller),
            old_system_state.clone(),
            memory_usage,
            execution_parameters,
            FuncRef::Method(method),
            execution_state,
            network_topology,
        );
        self.system_execution_result(
            output,
            output_execution_state,
            old_system_state,
            scheduler_state,
            output_system_state,
        )
    }

    /// Executes the system method `canister_post_upgrade`.
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
    pub fn execute_canister_post_upgrade(
        &self,
        canister: CanisterState,
        caller: PrincipalId,
        payload: &[u8],
        time: Time,
        execution_parameters: ExecutionParameters,
        network_topology: &NetworkTopology,
    ) -> (CanisterState, NumInstructions, HypervisorResult<NumBytes>) {
        let method = WasmMethod::System(SystemMethod::CanisterPostUpgrade);
        let memory_usage = canister.memory_usage(self.own_subnet_type);
        let (execution_state, old_system_state, scheduler_state) = canister.into_parts();

        // Validate that the Wasm module is present.
        let execution_state = match execution_state {
            None => {
                return (
                    CanisterState::from_parts(None, old_system_state, scheduler_state),
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
                CanisterState::from_parts(Some(execution_state), old_system_state, scheduler_state),
                execution_parameters.total_instruction_limit,
                Ok(NumBytes::from(0)),
            );
        }

        let (output, output_execution_state, output_system_state) = self.execute(
            ApiType::init(time, payload.to_vec(), caller),
            old_system_state.clone(),
            memory_usage,
            execution_parameters,
            FuncRef::Method(method),
            execution_state,
            network_topology,
        );
        self.system_execution_result(
            output,
            output_execution_state,
            old_system_state,
            scheduler_state,
            output_system_state,
        )
    }

    /// Executes the system method `canister_inspect_message`.
    ///
    /// This method is called pre-consensus to let the canister decide if it
    /// wants to accept the message or not.
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
    ) -> HypervisorResult<ExecutionState> {
        if let Some(sandbox_executor) = self.sandbox_executor.as_ref() {
            sandbox_executor.create_execution_state(wasm_binary, canister_root, canister_id)
        } else {
            self.wasm_executor
                .create_execution_state(wasm_binary, canister_root, canister_id)
        }
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

        let sandbox_executor = match config.canister_sandboxing_flag {
            FlagStatus::Enabled => Some(Arc::new(
                SandboxedExecutionController::new(log.clone(), metrics_registry, &embedder_config)
                    .expect("Failed to start sandboxed execution controller"),
            )),
            FlagStatus::Disabled => None,
        };

        let wasm_embedder = WasmtimeEmbedder::new(embedder_config.clone(), log.clone());
        let wasm_executor = WasmExecutor::new(
            wasm_embedder,
            metrics_registry,
            embedder_config,
            log.clone(),
        );

        Self {
            wasm_executor: Arc::new(wasm_executor),
            sandbox_executor,
            metrics: Arc::new(HypervisorMetrics::new(metrics_registry)),
            own_subnet_id,
            own_subnet_type,
            log,
            cycles_account_manager,
        }
    }

    #[cfg(test)]
    pub fn compile_count(&self) -> u64 {
        if let Some(sandbox_executor) = &self.sandbox_executor {
            sandbox_executor.compile_count_for_testing()
        } else {
            self.wasm_executor.compile_count_for_testing()
        }
    }

    /// Wrapper around the standalone `execute`.
    /// NOTE: this is public to enable integration testing.
    #[doc(hidden)]
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

        let (output, execution_state, system_state_changes) =
            if let Some(sandbox_executor) = self.sandbox_executor.as_ref() {
                sandbox_executor.process(WasmExecutionInput {
                    api_type: api_type.clone(),
                    sandbox_safe_system_state: static_system_state,
                    canister_current_memory_usage,
                    execution_parameters,
                    func_ref,
                    execution_state,
                })
            } else {
                self.wasm_executor.process(WasmExecutionInput {
                    api_type: api_type.clone(),
                    sandbox_safe_system_state: static_system_state,
                    canister_current_memory_usage,
                    execution_parameters,
                    func_ref,
                    execution_state,
                })
            };
        self.metrics.observe(api_type_str, &output);
        system_state_changes.apply_changes(
            &mut system_state,
            network_topology,
            self.own_subnet_id,
            &self.log,
        );
        (output, execution_state, system_state)
    }
}
