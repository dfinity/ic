use crate::QueryExecutionType;
use ic_config::execution_environment::Config;
use ic_cow_state::{error::CowError, CowMemoryManager};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::{WasmExecutionInput, WasmExecutionOutput};
use ic_interfaces::execution_environment::{
    EarlyResult, ExecResult, HypervisorError, HypervisorResult, InstanceStats,
    MessageAcceptanceError, SubnetAvailableMemory,
};
use ic_interfaces::messages::RequestOrIngress;
use ic_logger::{debug, fatal, ReplicaLogger};
use ic_metrics::{buckets::exponential_buckets, MetricsRegistry};
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    page_map::allocated_pages_count, CallContextAction, CallOrigin, CanisterState, ExecutionState,
    SystemState,
};
use ic_sys::PAGE_SIZE;
use ic_system_api::ApiType;
use ic_types::{
    ingress::WasmResult,
    messages::Payload,
    methods::{Callback, FuncRef, SystemMethod, WasmMethod},
    CanisterStatusType, ComputeAllocation, Cycles, NumBytes, NumInstructions, PrincipalId,
    SubnetId, Time,
};
use prometheus::{Histogram, IntGauge};
use runtime::WasmExecutionDispatcher;
use std::{collections::BTreeMap, sync::Arc};

#[doc(hidden)] // pub for usage in tests
pub struct HypervisorMetrics {
    accessed_pages: Histogram,
    dirty_pages: Histogram,
    allocated_pages: IntGauge,
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
        }
    }

    fn update(&self, instance_stats: &InstanceStats) {
        self.accessed_pages
            .observe(instance_stats.accessed_pages as f64);
        self.dirty_pages.observe(instance_stats.dirty_pages as f64);
        self.allocated_pages.set(allocated_pages_count() as i64);
    }
}

#[doc(hidden)]
pub struct Hypervisor {
    config: Config,
    wasm_executor: Arc<WasmExecutionDispatcher>,
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
    /// - If the execution succeeded, then the updated CanisterState otherwise
    /// the old CanisterState.
    ///
    /// - Number of instructions left. This should be <= `instructions_limit`.
    ///
    /// - An enum describing the different actions that should be taken based
    /// the current state of the call context associated with the request that
    /// was executed.
    ///
    /// - The size of delta of heap changes that the canister produced during
    /// execution. If execution failed, then must be 0.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_update(
        &self,
        mut canister: CanisterState,
        mut request: RequestOrIngress,
        instructions_limit: NumInstructions,
        time: Time,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<(CanisterState, NumInstructions, CallContextAction, NumBytes)> {
        debug!(self.log, "execute_update: method {}", request.method_name());

        let received_funds = request.take_funds();
        let incoming_cycles = received_funds.cycles();

        // Validate that the canister is running.
        if CanisterStatusType::Running != canister.status() {
            return EarlyResult::new((
                canister,
                instructions_limit,
                CallContextAction::Fail {
                    error: HypervisorError::CanisterStopped,
                    refund: received_funds.cycles(),
                },
                NumBytes::from(0),
            ));
        }

        // Validate that the canister has an `ExecutionState`.
        if canister.execution_state.is_none() {
            return EarlyResult::new((
                canister,
                instructions_limit,
                CallContextAction::Fail {
                    error: HypervisorError::WasmModuleNotFound,
                    refund: received_funds.cycles(),
                },
                NumBytes::from(0),
            ));
        }

        let wasm_method = WasmMethod::Update(request.method_name().to_string());
        // Validate that the canister exports an update method of the requested name.
        if !canister.exports_update_method(request.method_name().to_string()) {
            return EarlyResult::new((
                canister,
                instructions_limit,
                CallContextAction::Fail {
                    error: HypervisorError::MethodNotFound(wasm_method),
                    refund: received_funds.cycles(),
                },
                NumBytes::from(0),
            ));
        }

        let call_context_id = canister
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(CallOrigin::from(&request), received_funds.cycles());

        let api_type = ApiType::update(
            time,
            request.method_payload().to_vec(),
            incoming_cycles,
            *request.sender(),
            call_context_id,
            self.own_subnet_id,
            self.own_subnet_type,
            routing_table,
            subnet_records,
        );
        let output = execute(
            api_type,
            canister.system_state.clone(),
            instructions_limit,
            self.canister_memory_limit(&canister),
            canister.memory_usage(),
            subnet_available_memory,
            canister.scheduler_state.compute_allocation,
            FuncRef::Method(wasm_method),
            canister.execution_state.take().unwrap(),
            Arc::clone(&self.cycles_account_manager),
            Arc::clone(&self.metrics),
            Arc::clone(&self.wasm_executor),
        );

        output.and_then(move |output| {
            canister.execution_state = Some(output.execution_state);

            let heap_delta = if output.wasm_result.is_ok() {
                canister.system_state = output.system_state;
                NumBytes::from((output.instance_stats.dirty_pages * *PAGE_SIZE) as u64)
            } else {
                NumBytes::from(0)
            };

            let action = canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .on_canister_result(call_context_id, output.wasm_result);

            (canister, output.num_instructions_left, action, heap_delta)
        })
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
        instructions_limit: NumInstructions,
        canister: CanisterState,
        data_certificate: Option<Vec<u8>>,
        time: Time,
    ) -> ExecResult<(
        CanisterState,
        NumInstructions,
        HypervisorResult<Option<WasmResult>>,
    )> {
        let wasm_method = WasmMethod::Query(method.to_string());
        // Validate that the canister is running.
        if CanisterStatusType::Running != canister.status() {
            return EarlyResult::new((
                canister,
                instructions_limit,
                Err(HypervisorError::CanisterStopped),
            ));
        }

        let canister_memory_limit = self.canister_memory_limit(&canister);
        let canister_current_memory_usage = canister.memory_usage();
        let canister_compute_allocation = canister.scheduler_state.compute_allocation;
        let (execution_state, system_state, scheduler_state) = canister.into_parts();

        let mut execution_state = match execution_state {
            None => {
                return EarlyResult::new((
                    CanisterState::from_parts(None, system_state, scheduler_state),
                    instructions_limit,
                    Err(HypervisorError::WasmModuleNotFound),
                ));
            }
            Some(state) => state,
        };

        // Validate that the canister exports a query method of the requested name.
        if !execution_state.exports.has_query_method(method.to_string()) {
            return EarlyResult::new((
                CanisterState::from_parts(Some(execution_state), system_state, scheduler_state),
                instructions_limit,
                Err(HypervisorError::MethodNotFound(wasm_method)),
            ));
        }

        match query_execution_type {
            QueryExecutionType::Replicated => {
                if execution_state.cow_mem_mgr.is_valid() {
                    // Replicated queries are similar to update executions and they operate
                    // against the "current" canister state
                    execution_state.mapped_state =
                        Some(Arc::new(execution_state.cow_mem_mgr.get_map()));
                }

                let api_type =
                    ApiType::replicated_query(time, payload.to_vec(), caller, data_certificate);
                // As we are executing the query in the replicated mode, we do
                // not want to commit updates, i.e. we must return the
                // unmodified version of the canister. Hence, execute on clones
                // of system and execution states so that we have the original
                // versions.
                let output = execute(
                    api_type,
                    system_state.clone(),
                    instructions_limit,
                    canister_memory_limit,
                    canister_current_memory_usage,
                    // Letting the canister grow arbitrarily when executing the
                    // query is fine as we do not persist state modifications.
                    SubnetAvailableMemory::new(self.config.subnet_memory_capacity),
                    canister_compute_allocation,
                    FuncRef::Method(wasm_method),
                    execution_state.clone(),
                    Arc::clone(&self.cycles_account_manager),
                    Arc::clone(&self.metrics),
                    Arc::clone(&self.wasm_executor),
                );
                output.and_then(move |output| {
                    // Updating embedder cache should be the only modification
                    // of the canister state
                    execution_state.embedder_cache = output.execution_state.embedder_cache;
                    let canister = CanisterState::from_parts(
                        Some(execution_state),
                        system_state,
                        scheduler_state,
                    );
                    (canister, output.num_instructions_left, output.wasm_result)
                })
            }
            QueryExecutionType::NonReplicated {
                call_context_id,
                routing_table,
            } => {
                if execution_state.cow_mem_mgr.is_valid() {
                    // Non replicated queries execute against
                    // older snapshotted state.
                    execution_state.mapped_state = match execution_state
                        .cow_mem_mgr
                        .get_map_for_snapshot(execution_state.last_executed_round.get())
                    {
                        Ok(state) => Some(Arc::new(state)),
                        Err(err @ CowError::SlotDbError { .. }) => {
                            fatal!(self.log, "Failure due to {}", err)
                        }
                    };
                }

                let api_type = ApiType::non_replicated_query(
                    time,
                    payload.to_vec(),
                    caller,
                    call_context_id,
                    self.own_subnet_id,
                    routing_table,
                    data_certificate,
                );
                // As we are executing the query in non-replicated mode, we can
                // modify the canister as the caller is not going to be able to
                // commit modifications to the canister anyway.
                let output = execute(
                    api_type,
                    system_state,
                    instructions_limit,
                    canister_memory_limit,
                    canister_current_memory_usage,
                    // Letting the canister grow arbitrarily when executing the
                    // query is fine as we do not persist state modifications.
                    SubnetAvailableMemory::new(self.config.subnet_memory_capacity),
                    canister_compute_allocation,
                    FuncRef::Method(wasm_method),
                    execution_state,
                    Arc::clone(&self.cycles_account_manager),
                    Arc::clone(&self.metrics),
                    Arc::clone(&self.wasm_executor),
                );
                output.and_then(move |output| {
                    let canister = CanisterState::from_parts(
                        Some(output.execution_state),
                        output.system_state,
                        scheduler_state,
                    );
                    (canister, output.num_instructions_left, output.wasm_result)
                })
            }
        }
    }

    /// Execute a callback.
    ///
    /// Callbacks are executed when a canister receives a response to an
    /// outbound request it had made.
    ///
    /// Returns:
    ///
    /// - If the execution succeeded, then the updated CanisterState otherwise
    /// the old CanisterState.
    ///
    /// - Number of instructions left. This should be <= `instructions_limit`.
    ///
    /// - The size of the delta of heap change that the execution produced.
    ///
    /// - A HypervisorResult that on success contains an optional wasm execution
    ///   result and an error if execution failed.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn execute_callback(
        &self,
        mut canister: CanisterState,
        call_origin: &CallOrigin,
        callback: Callback,
        payload: Payload,
        incoming_cycles: Cycles,
        instructions_limit: NumInstructions,
        time: Time,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<(
        CanisterState,
        NumInstructions,
        NumBytes,
        HypervisorResult<Option<WasmResult>>,
    )> {
        // Validate that the canister is not stopped.
        if canister.status() == CanisterStatusType::Stopped {
            return EarlyResult::new((
                canister,
                instructions_limit,
                NumBytes::from(0),
                Err(HypervisorError::CanisterStopped),
            ));
        }

        // Validate that the canister has an `ExecutionState`.
        if canister.execution_state.is_none() {
            return EarlyResult::new((
                canister,
                instructions_limit,
                NumBytes::from(0),
                Err(HypervisorError::WasmModuleNotFound),
            ));
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
            Payload::Data(_) => callback.on_reply.clone(),
            Payload::Reject(_) => callback.on_reject.clone(),
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
                routing_table,
                subnet_records,
            ),
            Payload::Reject(context) => ApiType::reject_callback(
                time,
                context,
                incoming_cycles,
                callback.call_context_id,
                call_responded,
                self.own_subnet_id,
                self.own_subnet_type,
                routing_table,
                subnet_records,
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

        let output = execute(
            api_type,
            canister.system_state.clone(),
            instructions_limit,
            self.canister_memory_limit(&canister),
            canister.memory_usage(),
            subnet_available_memory.clone(),
            canister.scheduler_state.compute_allocation,
            func_ref,
            canister.execution_state.take().unwrap(),
            Arc::clone(&self.cycles_account_manager),
            Arc::clone(&self.metrics),
            Arc::clone(&self.wasm_executor),
        );

        let cycles_account_manager = Arc::clone(&self.cycles_account_manager);
        let metrics = Arc::clone(&self.metrics);
        let wasm_executor = Arc::clone(&self.wasm_executor);
        let canister_memory_limit = self.canister_memory_limit(&canister);
        let canister_current_memory_usage = canister.memory_usage();
        let call_origin = call_origin.clone();

        output.and_then(move |output| {
            canister.execution_state = Some(output.execution_state);
            match output.wasm_result {
                result @ Ok(_) => {
                    // Executing the reply/reject closure succeeded.
                    canister.system_state = output.system_state;
                    let heap_delta =
                        NumBytes::from((output.instance_stats.dirty_pages * *PAGE_SIZE) as u64);
                    (canister, output.num_instructions_left, heap_delta, result)
                }
                Err(callback_err) => {
                    // A trap has occurred when executing the reply/reject closure.
                    // Execute the cleanup if it exists.
                    match callback.on_cleanup {
                        None => {
                            // No cleanup closure present. Return the callback error as-is.
                            (
                                canister,
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
                            execute(
                                ApiType::Cleanup { time },
                                canister.system_state.clone(),
                                output.num_instructions_left,
                                canister_memory_limit,
                                canister_current_memory_usage,
                                subnet_available_memory,
                                canister.scheduler_state.compute_allocation,
                                func_ref,
                                canister.execution_state.take().unwrap(),
                                cycles_account_manager,
                                metrics,
                                wasm_executor,
                            )
                            .and_then(move |cleanup_output| {
                                canister.execution_state = Some(cleanup_output.execution_state);
                                match cleanup_output.wasm_result {
                                    Ok(_) => {
                                        // Executing the cleanup callback has succeeded.
                                        canister.system_state = cleanup_output.system_state;
                                        let heap_delta = NumBytes::from(
                                            (cleanup_output.instance_stats.dirty_pages * *PAGE_SIZE)
                                                as u64,
                                        );

                                        // Note that, even though the callback has succeeded,
                                        // the original callback error is returned.
                                        (
                                            canister,
                                            cleanup_output.num_instructions_left,
                                            heap_delta,
                                            Err(callback_err),
                                        )
                                    }
                                    Err(cleanup_err) => {
                                        // Executing the cleanup call back failed.
                                        (
                                            canister,
                                            cleanup_output.num_instructions_left,
                                            NumBytes::from(0),
                                            Err(HypervisorError::Cleanup {
                                                callback_err: Box::new(callback_err),
                                                cleanup_err: Box::new(cleanup_err),
                                            }),
                                        )
                                    }
                                }
                            })
                            .get_no_pause()
                        }
                    }
                }
            }
        })
    }

    /// Execute the canister start method if it is exposed.
    ///
    /// Returns:
    ///
    /// - If the execution succeeded, then the updated CanisterState otherwise
    /// the old CanisterState.
    ///
    /// - Number of instructions left. This should be <= `instructions_limit`.
    ///
    /// - A HypervisorResult containing the size of the delta of heap change if
    /// execution was successful and the relevant error if execution failed.
    #[allow(clippy::type_complexity)]
    pub fn execute_canister_start(
        &self,
        mut canister: CanisterState,
        instructions_limit: NumInstructions,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<(CanisterState, NumInstructions, HypervisorResult<NumBytes>)> {
        let method = SystemMethod::CanisterStart;

        if canister.execution_state.is_some() && !canister.exports_system_method(method.clone()) {
            return EarlyResult::new((canister, instructions_limit, Ok(NumBytes::from(0))));
        }

        let execution_state = match canister.execution_state.take() {
            None => {
                return EarlyResult::new((
                    canister,
                    instructions_limit,
                    Err(HypervisorError::WasmModuleNotFound),
                ));
            }
            Some(es) => es,
        };

        let output = execute(
            ApiType::start(),
            SystemState::new_for_start(canister.canister_id()),
            instructions_limit,
            self.canister_memory_limit(&canister),
            canister.memory_usage(),
            subnet_available_memory,
            canister.scheduler_state.compute_allocation,
            FuncRef::Method(WasmMethod::System(method)),
            execution_state,
            Arc::clone(&self.cycles_account_manager),
            Arc::clone(&self.metrics),
            Arc::clone(&self.wasm_executor),
        );

        output.and_then(move |output| {
            canister.execution_state = Some(output.execution_state);
            let result = match output.wasm_result {
                Ok(opt_result) => {
                    assert!(opt_result.is_none(), "System methods cannot use msg_reply.");
                    Ok(NumBytes::from(
                        (output.instance_stats.dirty_pages * *PAGE_SIZE) as u64,
                    ))
                }
                Err(err) => Err(err),
            };
            (canister, output.num_instructions_left, result)
        })
    }

    pub fn execute_empty(
        &self,
        mut canister: CanisterState,
    ) -> ExecResult<(CanisterState, HypervisorResult<()>)> {
        let execution_state = match canister.execution_state.take() {
            None => {
                return EarlyResult::new((canister, Err(HypervisorError::WasmModuleNotFound)));
            }
            Some(es) => es,
        };

        let output = execute(
            ApiType::start(),
            SystemState::new_for_start(canister.canister_id()),
            NumInstructions::from(0),
            self.canister_memory_limit(&canister),
            canister.memory_usage(),
            SubnetAvailableMemory::new(NumBytes::from(0)),
            ComputeAllocation::zero(),
            FuncRef::Method(WasmMethod::System(SystemMethod::Empty)),
            execution_state,
            Arc::clone(&self.cycles_account_manager),
            Arc::clone(&self.metrics),
            Arc::clone(&self.wasm_executor),
        );

        output.and_then(move |output| {
            canister.execution_state = Some(output.execution_state);
            let result = match output.wasm_result {
                Ok(opt_result) => {
                    assert!(opt_result.is_none(), "System methods cannot use msg_reply.");
                    Ok(())
                }
                Err(err) => Err(err),
            };
            (canister, result)
        })
    }

    /// Execute a system method.
    ///
    /// System methods are special methods that are called by the IC under
    /// specific circumstances (e.g. canister_init, canister_pre_upgrade, etc.)
    ///
    /// Returns:
    ///
    /// - If the execution succeeded, then the updated CanisterState otherwise
    /// the old CanisterState.
    ///
    /// - Number of instructions left. This should be <= `instructions_limit`.
    ///
    /// - A HypervisorResult containing the size of the delta of heap change if
    /// execution was successful and the relevant error if execution failed.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn execute_system(
        &self,
        mut canister: CanisterState,
        method: SystemMethod,
        caller: PrincipalId,
        payload: &[u8],
        instructions_limit: NumInstructions,
        time: Time,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<(CanisterState, NumInstructions, HypervisorResult<NumBytes>)> {
        // Validate that the canister has an `ExecutionState`.
        if canister.execution_state.is_none() {
            return EarlyResult::new((
                canister,
                instructions_limit,
                Err(HypervisorError::WasmModuleNotFound),
            ));
        }

        if !canister.exports_system_method(method.clone()) {
            // System method isn't exported. Nothing to do.
            return EarlyResult::new((canister, instructions_limit, Ok(NumBytes::from(0))));
        }
        let (api_type, system_state) = match method {
            SystemMethod::CanisterInit | SystemMethod::CanisterPostUpgrade => (
                ApiType::init(time, payload.to_vec(), caller),
                canister.system_state.clone(),
            ),
            SystemMethod::CanisterPreUpgrade => (
                ApiType::pre_upgrade(time, caller),
                canister.system_state.clone(),
            ),
            SystemMethod::CanisterStart => fatal!(self.log, "use execute_canister_start instead"),
            SystemMethod::CanisterInspectMessage => {
                fatal!(self.log, "use execute_inspect_message instead")
            }
            SystemMethod::CanisterHeartbeat => {
                fatal!(self.log, "Use execute_canister_heartbeat instead. execute_system will be broken up per EXE-13");
            }
            SystemMethod::Empty => {
                fatal!(
                    self.log,
                    "Use execute_empty instead. execute_system will be broken up per EXE-13"
                );
            }
        };
        let output = execute(
            api_type,
            system_state,
            instructions_limit,
            self.canister_memory_limit(&canister),
            canister.memory_usage(),
            subnet_available_memory,
            canister.scheduler_state.compute_allocation,
            FuncRef::Method(WasmMethod::System(method)),
            canister.execution_state.take().unwrap(),
            Arc::clone(&self.cycles_account_manager),
            Arc::clone(&self.metrics),
            Arc::clone(&self.wasm_executor),
        );

        output.and_then(move |output| {
            let result = match output.wasm_result {
                Ok(opt_result) => {
                    assert!(opt_result.is_none(), "System methods cannot use msg_reply.");
                    canister.system_state = output.system_state;
                    Ok(NumBytes::from(
                        (output.instance_stats.dirty_pages * *PAGE_SIZE) as u64,
                    ))
                }
                Err(err) => Err(err),
            };
            canister.execution_state = Some(output.execution_state);
            (canister, output.num_instructions_left, result)
        })
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
        instructions_limit: NumInstructions,
        time: Time,
    ) -> ExecResult<Result<(), MessageAcceptanceError>> {
        let canister_memory_limit = self.canister_memory_limit(&canister);
        let canister_current_memory_usage = canister.memory_usage();
        let canister_compute_allocation = canister.scheduler_state.compute_allocation;
        let (mut maybe_execution_state, system_state, _) = canister.into_parts();
        let execution_state = match maybe_execution_state.take() {
            // The canister has no execution state so it does not have a wasm module so it is unable
            // to handle any messages.  Reject the message.
            None => return EarlyResult::new(Err(MessageAcceptanceError::CanisterHasNoWasmModule)),
            Some(execution_state) => execution_state,
        };

        // if a non-empty canister does not expose the inspect message method we accept
        // the message.
        if !execution_state
            .exports
            .has_system_method(SystemMethod::CanisterInspectMessage)
        {
            return EarlyResult::new(Ok(()));
        }

        let system_api = ApiType::inspect_message(sender, method_name, method_payload, time);
        let output = execute(
            system_api,
            system_state,
            instructions_limit,
            canister_memory_limit,
            canister_current_memory_usage,
            SubnetAvailableMemory::new(self.config.subnet_memory_capacity),
            canister_compute_allocation,
            FuncRef::Method(WasmMethod::System(SystemMethod::CanisterInspectMessage)),
            execution_state,
            Arc::clone(&self.cycles_account_manager),
            Arc::clone(&self.metrics),
            Arc::clone(&self.wasm_executor),
        );

        let log = self.log.clone();
        output.and_then(move |output| match output.wasm_result {
            Ok(maybe_wasm_result) => match maybe_wasm_result {
                None => Ok(()),
                Some(_result) => fatal!(
                    log,
                    "SystemApi should guarantee that the canister does not reply"
                ),
            },
            Err(err) => match err {
                HypervisorError::MessageRejected => Err(MessageAcceptanceError::CanisterRejected),
                err => Err(MessageAcceptanceError::CanisterExecutionFailed(err)),
            },
        })
    }

    /// Executes the `canister_heartbeat` system method.
    ///
    /// Returns:
    ///
    /// - If the execution succeeded, then the updated CanisterState otherwise
    /// the old CanisterState.
    ///
    /// - Number of instructions left. This should be <= `instructions_limit`.
    ///
    /// - A HypervisorResult containing the size of the delta of heap change if
    /// execution was successful and the relevant error if execution failed.
    #[allow(clippy::type_complexity)]
    pub fn execute_canister_heartbeat(
        &self,
        mut canister: CanisterState,
        instructions_limit: NumInstructions,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        time: Time,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<(CanisterState, NumInstructions, HypervisorResult<NumBytes>)> {
        if canister.execution_state.is_some()
            && !canister.exports_system_method(SystemMethod::CanisterHeartbeat)
        {
            // System method isn't exported. Nothing to do.
            return EarlyResult::new((canister, instructions_limit, Ok(NumBytes::from(0))));
        }

        let execution_state = match canister.execution_state.take() {
            None => {
                return EarlyResult::new((
                    canister,
                    instructions_limit,
                    Err(HypervisorError::WasmModuleNotFound),
                ));
            }
            Some(execution_state) => execution_state,
        };

        let call_context_id = canister
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(CallOrigin::Heartbeat, Cycles::from(0));

        let api_type = ApiType::heartbeat(
            time,
            call_context_id,
            self.own_subnet_id,
            self.own_subnet_type,
            routing_table,
            subnet_records,
        );

        let output = execute(
            api_type,
            canister.system_state.clone(),
            instructions_limit,
            self.canister_memory_limit(&canister),
            canister.memory_usage(),
            subnet_available_memory,
            canister.scheduler_state.compute_allocation,
            FuncRef::Method(WasmMethod::System(SystemMethod::CanisterHeartbeat)),
            execution_state,
            Arc::clone(&self.cycles_account_manager),
            Arc::clone(&self.metrics),
            Arc::clone(&self.wasm_executor),
        );

        output.and_then(move |output: ic_embedders::WasmExecutionOutput| {
            canister.execution_state = Some(output.execution_state);

            if output.wasm_result.is_ok() {
                canister.system_state = output.system_state;
            }

            let _action = canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .on_canister_result(call_context_id, output.wasm_result.clone());

            let result = match output.wasm_result {
                Ok(opt_result) => {
                    assert!(opt_result.is_none(), "System methods cannot use msg_reply.");
                    Ok(NumBytes::from(
                        (output.instance_stats.dirty_pages * *PAGE_SIZE) as u64,
                    ))
                }
                Err(err) => Err(err),
            };
            (canister, output.num_instructions_left, result)
        })
    }

    pub fn new(
        config: Config,
        num_runtime_threads: usize,
        metrics_registry: &MetricsRegistry,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        log: ReplicaLogger,
        cycles_account_manager: Arc<CyclesAccountManager>,
    ) -> Self {
        let my_config = config.clone();
        let mut dispatcher_config = ic_config::embedders::Config::new();
        dispatcher_config.persistence_type = config.persistence_type;
        dispatcher_config.num_runtime_generic_threads = num_runtime_threads;
        dispatcher_config.num_runtime_query_threads = std::cmp::min(num_runtime_threads, 4);
        let wasm_executor =
            WasmExecutionDispatcher::new(config.embedder_type, dispatcher_config, log.clone());

        Self {
            config: my_config,
            wasm_executor: Arc::new(wasm_executor),
            metrics: Arc::new(HypervisorMetrics::new(metrics_registry)),
            own_subnet_id,
            own_subnet_type,
            log,
            cycles_account_manager,
        }
    }

    /// Returns the maximum amount of memory that the Canister can use.
    fn canister_memory_limit(&self, canister: &CanisterState) -> NumBytes {
        match canister.memory_allocation() {
            Some(memory_allocation) => memory_allocation,
            None => self.config.max_canister_memory_size,
        }
    }
}

/// Executes a Wasm function.
///
/// The function returns an updated execution state as well as an updated
/// system state and WasmResult using the SystemApi.
//
/// If the method is not found or if execution fails, an error is returned
/// via the system API.
///
/// NOTE: this is public to enable integration testing.
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn execute(
    api_type: ApiType,
    system_state: SystemState,
    instructions_limit: NumInstructions,
    canister_memory_limit: NumBytes,
    canister_current_memory_usage: NumBytes,
    subnet_available_memory: SubnetAvailableMemory,
    compute_allocation: ComputeAllocation,
    func_ref: FuncRef,
    execution_state: ExecutionState,
    cycles_account_manager: Arc<CyclesAccountManager>,
    metrics: Arc<HypervisorMetrics>,
    wasm_executor: Arc<WasmExecutionDispatcher>,
) -> ExecResult<WasmExecutionOutput> {
    let result = ExecResult::new(Box::new(wasm_executor.execute(WasmExecutionInput {
        api_type,
        system_state,
        instructions_limit,
        canister_memory_limit,
        canister_current_memory_usage,
        subnet_available_memory,
        compute_allocation,
        func_ref,
        execution_state,
        cycles_account_manager,
    })));

    result.and_then(move |result| {
        metrics.update(&result.instance_stats);
        result
    })
}
