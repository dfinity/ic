use super::query_call_graph::evaluate_query_call_graph;
use crate::{
    NonReplicatedQueryKind, RoundInstructions,
    execution::common::{self, validate_method},
    execution::nonreplicated_query::execute_non_replicated_query,
    execution_environment::{RoundLimits, as_round_instructions},
    hypervisor::Hypervisor,
    metrics::{
        CallTreeMetricsNoOp, MeasurementScope, QUERY_HANDLER_CRITICAL_ERROR, QueryHandlerMetrics,
        SYSTEM_API_CANISTER_CYCLE_BALANCE, SYSTEM_API_CANISTER_CYCLE_BALANCE128,
        SYSTEM_API_DATA_CERTIFICATE_COPY, SYSTEM_API_TIME,
    },
};
use ic_base_types::NumBytes;
use ic_config::flag_status::FlagStatus;
use ic_cycles_account_manager::{CyclesAccountManager, ResourceSaturation};
use ic_embedders::wasmtime_embedder::system_api::{
    ApiType, ExecutionParameters, InstructionLimits,
};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::{
    ExecutionMode, HypervisorError, MessageMemoryUsage, SubnetAvailableMemory,
    SystemApiCallCounters,
};
use ic_interfaces_state_manager::Labeled;
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_logger::{ReplicaLogger, error, info};
use ic_query_stats::QueryStatsCollector;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallContextAction, CallOrigin, CanisterState, NetworkTopology, ReplicatedState,
};
use ic_types::{
    CanisterId, Cycles, NumInstructions, NumMessages, NumSlices, Time,
    batch::{CanisterCyclesCostSchedule, QueryStats},
    ingress::WasmResult,
    messages::{
        CallContextId, CallbackId, NO_DEADLINE, Payload, Query, QuerySource, RejectContext,
        Request, RequestOrResponse, Response,
    },
    methods::{FuncRef, WasmClosure, WasmMethod},
};
use prometheus::IntCounter;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

/// The response of a query. If the query originated from a user, then it
/// contains either `UserResponse` or `UserError`. If the query originated from
/// a canister, then it contains `CanisterResponse`.
pub(super) enum QueryResponse {
    UserResponse(WasmResult),
    UserError(UserError),
    CanisterResponse(Response),
}

/// The result of execution of a query or a response callback.
/// The execution either produces a response or returns a possibly empty set of
/// outgoing calls with the new canister state and the call origin.
#[allow(clippy::large_enum_variant)]
pub(super) enum ExecutionResult {
    Response(QueryResponse),
    Calls(CanisterState, CallOrigin, VecDeque<Arc<Request>>),
    SystemError(UserError),
}

/// Returns either `WasmMethod::CompositeQuery` or `WasmMethod::Query` depending
/// on whether the given method name is exported as a composite query or not.
fn wasm_query_method(
    canister: &CanisterState,
    name: String,
) -> Result<WasmMethod, HypervisorError> {
    // Attempt to validate method name as composite query.
    let method = WasmMethod::CompositeQuery(name.clone());
    match validate_method(&method, canister) {
        Ok(_) => Ok(method),
        Err(_) => {
            // If validating the method as composite query fails, try as
            // regular query instead.
            let method = WasmMethod::Query(name);
            validate_method(&method, canister)?;

            Ok(method)
        }
    }
}

/// Executes a single user query along with its outgoing query calls.
pub(super) struct QueryContext<'a> {
    log: &'a ReplicaLogger,
    hypervisor: &'a Hypervisor,
    own_subnet_type: SubnetType,
    // The state against which all queries in the context will be executed.
    state: Labeled<Arc<ReplicatedState>>,
    network_topology: Arc<NetworkTopology>,
    // Certificate for certified queries + canister ID of the root query of this context
    data_certificate: Option<(Vec<u8>, CanisterId)>,
    max_instructions_per_query: NumInstructions,
    max_query_call_graph_depth: usize,
    instruction_overhead_per_query_call: RoundInstructions,
    round_limits: RoundLimits,
    // The number of concurrent calls / callbacks that is guaranteed to a canister.
    canister_guaranteed_callback_quota: u64,
    composite_queries: FlagStatus,
    // Walltime at which the query has started to execute.
    query_context_time_start: Instant,
    query_context_time_limit: Duration,
    query_critical_error: &'a IntCounter,
    local_query_execution_stats: Option<&'a QueryStatsCollector>,
    /// How many times each tracked System API call was invoked during the query execution.
    system_api_call_counters: SystemApiCallCounters,
    /// A map of canister IDs evaluated and executed at least once in this query context
    /// with their stats. The information is used by the query cache for composite queries.
    evaluated_canister_stats: BTreeMap<CanisterId, QueryStats>,
    /// The number of transient errors.
    transient_errors: usize,
    cycles_account_manager: Arc<CyclesAccountManager>,
}

impl<'a> QueryContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        log: &'a ReplicaLogger,
        hypervisor: &'a Hypervisor,
        own_subnet_type: SubnetType,
        state: Labeled<Arc<ReplicatedState>>,
        data_certificate: Option<Vec<u8>>,
        subnet_available_memory: SubnetAvailableMemory,
        subnet_available_callbacks: i64,
        subnet_memory_reservation: NumBytes,
        canister_guaranteed_callback_quota: u64,
        max_instructions_per_query: NumInstructions,
        max_query_call_graph_depth: usize,
        max_query_call_graph_instructions: NumInstructions,
        max_query_call_walltime: Duration,
        instruction_overhead_per_query_call: NumInstructions,
        composite_queries: FlagStatus,
        canister_id: CanisterId,
        query_critical_error: &'a IntCounter,
        local_query_execution_stats: Option<&'a QueryStatsCollector>,
        cycles_account_manager: Arc<CyclesAccountManager>,
    ) -> Self {
        let network_topology = Arc::new(state.get_ref().metadata.network_topology.clone());
        let round_limits = RoundLimits::new(
            as_round_instructions(max_query_call_graph_instructions),
            subnet_available_memory,
            subnet_available_callbacks,
            // Ignore compute allocation
            0,
            subnet_memory_reservation,
        );
        Self {
            log,
            hypervisor,
            own_subnet_type,
            state,
            network_topology,
            data_certificate: data_certificate
                .map(|data_certificate| (data_certificate, canister_id)),
            max_instructions_per_query,
            max_query_call_graph_depth,
            instruction_overhead_per_query_call: as_round_instructions(
                instruction_overhead_per_query_call,
            ),
            round_limits,
            canister_guaranteed_callback_quota,
            composite_queries,
            query_context_time_start: Instant::now(),
            query_context_time_limit: max_query_call_walltime,
            query_critical_error,
            local_query_execution_stats,
            system_api_call_counters: SystemApiCallCounters::default(),
            // If the `context.run()` returns an error and hence the empty evaluated IDs set,
            // the original canister ID should always be tracked for changes.
            evaluated_canister_stats: BTreeMap::from([(canister_id, QueryStats::default())]),
            transient_errors: 0,
            cycles_account_manager,
        }
    }

    /// Executes the given query sent by an end user.
    ///
    /// - If it produces a response return the response.
    ///
    /// - If it does not produce a response and does not send further queries,
    ///   then return a response indicating that the canister did not reply.
    ///
    /// - If it does not produce a response and produces additional
    ///   inter-canister queries, process them till there is a response or the
    ///   call graph finishes with no reply.
    pub(super) fn run<'b>(
        &mut self,
        query: Query,
        metrics: &'b QueryHandlerMetrics,
        measurement_scope: &MeasurementScope<'b>,
    ) -> Result<WasmResult, UserError> {
        let canister_id = query.receiver;
        let old_canister = self.state.get_ref().get_active_canister(&canister_id)?;
        let call_origin = CallOrigin::Query(query.source().into(), query.method_name.clone());

        let method = match wasm_query_method(old_canister, query.method_name.to_string()) {
            Ok(method) => method,
            Err(err) => return Err(err.into_user_error(&canister_id)),
        };

        let query_kind = match &method {
            WasmMethod::Query(_) => NonReplicatedQueryKind::Pure {
                caller: query.source(),
            },
            WasmMethod::CompositeQuery(_) => NonReplicatedQueryKind::Stateful {
                call_origin: call_origin.clone(),
            },
            WasmMethod::Update(_) | WasmMethod::System(_) => {
                unreachable!("Expected a Wasm query method");
            }
        };

        match query.source {
            QuerySource::System => {
                if let WasmMethod::CompositeQuery(_) = &method {
                    return Err(UserError::new(
                        ErrorCode::CompositeQueryCalledInReplicatedMode,
                        "Composite query cannot be used as transform in canister http outcalls.",
                    ));
                }
            }
            QuerySource::User { .. } => (),
        }

        let instructions_before = self.round_limits.instructions;

        let (mut canister, result) = {
            let measurement_scope =
                MeasurementScope::nested(&metrics.query_initial_call, measurement_scope);
            self.execute_query(
                old_canister.clone(),
                method.clone(),
                &query.method_payload,
                query_kind,
                &measurement_scope,
            )
        };

        let result = match result {
            // If the canister produced a result or if execution failed then it
            // does not matter whether or not it produced any outgoing requests.
            // We can simply return the response we have.
            Err(err) => Err(err),
            Ok(Some(wasm_result)) => Ok(wasm_result),
            Ok(None) => {
                // The query did not produce any response. We need to evaluate
                // the query call graph. Note that if the call graph is empty,
                // then a synthetic reject response will be generated.
                let measurement_scope =
                    MeasurementScope::nested(&metrics.query_spawned_calls, measurement_scope);
                let mut requests = VecDeque::new();
                let result = match self.extract_query_requests(&mut canister, &mut requests) {
                    Err(err) => QueryResponse::UserError(err),
                    Ok(()) => evaluate_query_call_graph(
                        self,
                        canister,
                        call_origin,
                        requests,
                        self.max_query_call_graph_depth,
                        &measurement_scope,
                    ),
                };
                match result {
                    QueryResponse::UserResponse(wasm_result) => Ok(wasm_result),
                    QueryResponse::UserError(err) => Err(err),
                    QueryResponse::CanisterResponse(_) => {
                        unreachable!("A user query cannot produce a canister response.");
                    }
                }
            }
        };

        match query.source {
            QuerySource::System => {
                let instructions_consumed = instructions_before - self.round_limits.instructions;
                if instructions_consumed >= RoundInstructions::from(10_000_000) {
                    info!(
                        self.log,
                        "Canister http transform on canister {} consumed {} instructions.",
                        canister_id,
                        instructions_consumed
                    );
                }
            }
            QuerySource::User { .. } => (),
        }

        result
    }

    // A helper function that extracts the query calls of the given canister and
    // enqueues them onto the given deque.
    fn extract_query_requests(
        &self,
        canister: &mut CanisterState,
        requests: &mut VecDeque<Arc<Request>>,
    ) -> Result<(), UserError> {
        let canister_id = canister.canister_id();

        let outgoing_messages: Vec<_> = canister.output_into_iter().collect();
        let call_context_manager = canister.system_state.call_context_manager().ok_or_else(
            || {
                error!(
                    self.log,
                    "[EXC-BUG] Canister {} does not have a call context manager. This is a bug @{}",
                    canister_id,
                    QUERY_HANDLER_CRITICAL_ERROR,
                );
                self.query_critical_error.inc();
                UserError::new(
                    ErrorCode::QueryCallGraphInternal,
                    "Composite query: canister does not have a call context manager",
                )
            },
        )?;

        // When we deserialize the canister state from the replicated state, it
        // is possible that it already had some messages in its output queues.
        // As we iterate over the messages below, we only want to handle
        // messages that were produced by this module.
        for msg in outgoing_messages {
            match msg {
                RequestOrResponse::Request(msg) => {
                    let call_origin = call_context_manager
                        .callback(msg.sender_reply_callback)
                        .and_then(|x| call_context_manager.call_origin(x.call_context_id));

                    match call_origin {
                        None => {
                            error!(
                                self.log,
                                "[EXC-BUG] Canister {} does not have a call origin for callback. This is a bug @{}",
                                canister_id,
                                QUERY_HANDLER_CRITICAL_ERROR,
                            );
                            self.query_critical_error.inc();
                            return Err(UserError::new(
                                ErrorCode::QueryCallGraphInternal,
                                "Composite query: canister does not have a call origin for callback",
                            ));
                        }
                        Some(CallOrigin::CanisterUpdate(..))
                        | Some(CallOrigin::Ingress(..))
                        | Some(CallOrigin::SystemTask) => {}

                        Some(CallOrigin::Query(..)) | Some(CallOrigin::CanisterQuery(..)) => {
                            // We never serialize messages of such types in the
                            // canister's state so these must have been produced
                            // by this module.
                            requests.push_back(msg);
                        }
                    }
                }

                // Messages of these types are not produced by this
                // module so must have existed on the canister's output
                // queue from before.
                RequestOrResponse::Response(_) => {}
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_query(
        &mut self,
        canister: CanisterState,
        method_name: WasmMethod,
        method_payload: &[u8],
        query_kind: NonReplicatedQueryKind,
        measurement_scope: &MeasurementScope,
    ) -> (CanisterState, Result<Option<WasmResult>, UserError>) {
        if let WasmMethod::CompositeQuery(_) = &method_name
            && self.composite_queries == FlagStatus::Disabled
        {
            return (
                canister,
                Err(UserError::new(
                    ErrorCode::CanisterContractViolation,
                    "Composite queries are not enabled yet",
                )),
            );
        }
        let cost_schedule = self.get_cost_schedule();
        let subnet_size = self
            .network_topology
            .get_subnet_size(&self.cycles_account_manager.get_subnet_id())
            .unwrap_or(SMALL_APP_SUBNET_MAX_SIZE);
        if self.cycles_account_manager.freeze_threshold_cycles(
            canister.system_state.freeze_threshold,
            canister.system_state.memory_allocation,
            canister.memory_usage(),
            canister.message_memory_usage(),
            canister.scheduler_state.compute_allocation,
            subnet_size,
            self.get_cost_schedule(),
            canister.system_state.reserved_balance(),
        ) > canister.system_state.balance()
        {
            let canister_id = canister.canister_id();
            return (
                canister,
                Err(UserError::new(
                    ErrorCode::CanisterOutOfCycles,
                    format!(
                        "Canister {canister_id} is unable to process query calls because it's frozen. Please top up the canister with cycles and try again."
                    ),
                )),
            );
        }

        let instruction_limit = self.max_instructions_per_query.min(NumInstructions::new(
            self.round_limits.instructions.get().max(0) as u64,
        ));
        let instruction_limits = InstructionLimits::new(instruction_limit, instruction_limit);
        let execution_parameters = self.execution_parameters(&canister, instruction_limits);

        let data_certificate = self.get_data_certificate(&canister.canister_id());
        let (mut canister, instructions_left, result, call_context_id, system_api_call_counters) =
            execute_non_replicated_query(
                query_kind,
                method_name,
                method_payload,
                canister,
                data_certificate,
                self.state.get_ref().time(),
                execution_parameters,
                &self.network_topology,
                self.hypervisor,
                &mut self.round_limits,
                self.query_critical_error,
                cost_schedule,
            );
        self.add_system_api_call_counters(system_api_call_counters);
        let instructions_executed = instruction_limit - instructions_left;

        let ingress_payload_size = method_payload.len();
        let egress_payload_size = match &result {
            Ok(result) => match result {
                Some(WasmResult::Reply(vec)) => vec.len(),
                Some(WasmResult::Reject(_)) => 0,
                None => 0,
            },
            Err(_) => 0,
        };

        // Add query statistics to the query aggregator.
        let stats = QueryStats {
            num_calls: 1,
            num_instructions: instructions_executed.get(),
            ingress_payload_size: ingress_payload_size as u64,
            egress_payload_size: egress_payload_size as u64,
        };
        self.add_evaluated_canister_stats(canister.canister_id(), &stats);
        if let Some(query_stats) = self.local_query_execution_stats {
            query_stats.set_epoch_from_height(self.state.height());
            query_stats.register_query_statistics(canister.canister_id(), &stats);
        }

        measurement_scope.add(
            instructions_executed,
            NumSlices::from(1),
            NumMessages::from(1),
        );

        if let Some(call_context_id) = call_context_id {
            let _action = self.finish(
                &mut canister,
                call_context_id,
                None,
                Ok(None),
                instructions_executed,
            );
        }
        (canister, result)
    }

    /// Adds up System API call counters.
    fn add_system_api_call_counters(&mut self, system_api_call_counters: SystemApiCallCounters) {
        self.system_api_call_counters
            .saturating_add(system_api_call_counters);
    }

    /// Adds a canister ID into a set of actually executed canisters.
    fn add_evaluated_canister_stats(&mut self, canister_id: CanisterId, stats: &QueryStats) {
        self.evaluated_canister_stats
            .entry(canister_id)
            .and_modify(|s| s.saturating_accumulate(stats))
            .or_insert(stats.clone());
    }

    /// Accumulates transient errors from result.
    pub fn accumulate_transient_errors_from_result<R>(&mut self, result: Result<R, &UserError>) {
        if result.is_err_and(|err| err.reject_code() == RejectCode::SysTransient) {
            self.transient_errors += 1;
        }
    }

    /// Accumulates transient errors from payload.
    pub fn accumulate_transient_errors_from_payload(&mut self, payload: &Payload) {
        if let Payload::Reject(context) = payload
            && context.code() == RejectCode::SysTransient
        {
            self.transient_errors += 1;
        }
    }

    fn finish(
        &self,
        canister: &mut CanisterState,
        call_context_id: CallContextId,
        callback_id: Option<CallbackId>,
        result: Result<Option<WasmResult>, HypervisorError>,
        instructions_used: NumInstructions,
    ) -> CallContextAction {
        canister
            .system_state
            .on_canister_result(call_context_id, callback_id, result, instructions_used)
            // This `unwrap()` cannot fail because of the non-optional `call_context_id`.
            .unwrap()
            .0
    }

    // Observes query metrics.
    pub(super) fn observe_metrics(&mut self, metrics: &QueryHandlerMetrics) {
        // Observe System API call counters in the corresponding metrics.
        let query_system_api_calls = &metrics.query_system_api_calls;
        query_system_api_calls
            .with_label_values(&[SYSTEM_API_DATA_CERTIFICATE_COPY])
            .inc_by(self.system_api_call_counters.data_certificate_copy as u64);
        query_system_api_calls
            .with_label_values(&[SYSTEM_API_CANISTER_CYCLE_BALANCE])
            .inc_by(self.system_api_call_counters.canister_cycle_balance as u64);
        query_system_api_calls
            .with_label_values(&[SYSTEM_API_CANISTER_CYCLE_BALANCE128])
            .inc_by(self.system_api_call_counters.canister_cycle_balance128 as u64);
        query_system_api_calls
            .with_label_values(&[SYSTEM_API_TIME])
            .inc_by(self.system_api_call_counters.time as u64);

        // Observe the number evaluated canisters in the corresponding metrics.
        metrics
            .evaluated_canisters
            .observe(self.evaluated_canister_stats.len() as f64);

        // Observe transient errors.
        metrics
            .transient_errors
            .inc_by(self.transient_errors as u64);
    }

    fn execute_callback(
        &mut self,
        mut canister: CanisterState,
        response: Response,
        measurement_scope: &MeasurementScope,
    ) -> Result<(CanisterState, CallOrigin, CallContextAction), UserError> {
        let canister_id = canister.canister_id();
        let (callback, callback_id, call_context, call_context_id) =
            match common::get_call_context_and_callback(
                &canister,
                &response,
                self.log,
                self.query_critical_error,
            ) {
                Some(r) => r,
                None => {
                    error!(
                        self.log,
                        "[EXC-BUG] Canister {} does not have call context and callback. This is a bug @{}",
                        canister_id,
                        QUERY_HANDLER_CRITICAL_ERROR,
                    );
                    self.query_critical_error.inc();
                    return Err(UserError::new(
                        ErrorCode::QueryCallGraphInternal,
                        "Composite query: canister does not have call context and callback",
                    ));
                }
            };

        let call_responded = call_context.has_responded();
        let call_origin = call_context.call_origin().clone();
        // Validate that the canister has an `ExecutionState`.
        if canister.execution_state.is_none() {
            let action = self.finish(
                &mut canister,
                call_context_id,
                Some(callback_id),
                Err(HypervisorError::WasmModuleNotFound),
                0.into(),
            );
            return Ok((canister, call_origin, action));
        }

        let closure = match response.response_payload {
            Payload::Data(_) => callback.on_reply.clone(),
            Payload::Reject(_) => callback.on_reject.clone(),
        };
        let func_ref = match call_origin {
            CallOrigin::Ingress(..) | CallOrigin::CanisterUpdate(..) | CallOrigin::SystemTask => {
                unreachable!("Unreachable in the QueryContext.")
            }
            CallOrigin::CanisterQuery(..) | CallOrigin::Query(..) => FuncRef::QueryClosure(closure),
        };

        let time = self.state.get_ref().time();
        // No cycles are refunded in a response to a query call.
        let incoming_cycles = Cycles::zero();

        let instruction_limit = self.max_instructions_per_query.min(NumInstructions::new(
            self.round_limits.instructions.get().max(0) as u64,
        ));
        let instruction_limits = InstructionLimits::new(instruction_limit, instruction_limit);
        let mut execution_parameters = self.execution_parameters(&canister, instruction_limits);
        let api_type = match response.response_payload {
            Payload::Data(payload) => ApiType::composite_reply_callback(
                time,
                call_origin.get_principal(),
                payload.to_vec(),
                incoming_cycles,
                call_context_id,
                call_responded,
                call_context.instructions_executed(),
            ),
            Payload::Reject(context) => ApiType::composite_reject_callback(
                time,
                call_origin.get_principal(),
                context,
                incoming_cycles,
                call_context_id,
                call_responded,
                call_context.instructions_executed(),
            ),
        };

        let cost_schedule = self.get_cost_schedule();

        let (output, output_execution_state, output_system_state) = self.hypervisor.execute(
            api_type,
            time,
            canister.system_state.clone(),
            canister.memory_usage(),
            canister.message_memory_usage(),
            execution_parameters.clone(),
            func_ref,
            canister.execution_state.take().unwrap(),
            &self.network_topology,
            &mut self.round_limits,
            self.query_critical_error,
            &CallTreeMetricsNoOp,
            call_context.time(),
            cost_schedule,
        );

        self.add_system_api_call_counters(output.system_api_call_counters);
        canister.execution_state = Some(output_execution_state);
        execution_parameters
            .instruction_limits
            .update(output.num_instructions_left);

        let (instructions_left, result) = match output.wasm_result {
            result @ Ok(_) => {
                // Executing the reply/reject closure succeeded.
                canister.system_state = output_system_state;
                (output.num_instructions_left, result)
            }
            Err(callback_err) => {
                // A trap has occurred when executing the reply/reject closure.
                // Execute the cleanup if it exists.
                match callback.on_cleanup {
                    None => {
                        // No cleanup closure present. Return the callback error as-is.
                        (output.num_instructions_left, Err(callback_err))
                    }
                    Some(cleanup_closure) => {
                        let canister_current_memory_usage = canister.memory_usage();
                        let canister_current_message_memory_usage = canister.message_memory_usage();
                        self.execute_cleanup(
                            time,
                            &mut canister,
                            cleanup_closure,
                            &call_origin,
                            callback_err,
                            canister_current_memory_usage,
                            canister_current_message_memory_usage,
                            execution_parameters,
                            call_context.instructions_executed(),
                        )
                    }
                }
            }
        };

        let instructions_used = NumInstructions::from(
            instruction_limit
                .get()
                .saturating_sub(instructions_left.get()),
        );
        let action = self.finish(
            &mut canister,
            call_context_id,
            Some(callback_id),
            result,
            instructions_used,
        );

        measurement_scope.add(instructions_used, NumSlices::from(1), NumMessages::from(1));
        Ok((canister, call_origin, action))
    }

    /// Execute cleanup.
    ///
    /// Returns:
    ///     - Number of instructions left.
    ///     - A result containing the wasm result or relevant `HypervisorError`.
    #[allow(clippy::too_many_arguments)]
    fn execute_cleanup(
        &mut self,
        time: Time,
        canister: &mut CanisterState,
        cleanup_closure: WasmClosure,
        call_origin: &CallOrigin,
        callback_err: HypervisorError,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        execution_parameters: ExecutionParameters,
        call_context_instructions_executed: NumInstructions,
    ) -> (NumInstructions, Result<Option<WasmResult>, HypervisorError>) {
        let func_ref = match call_origin {
            CallOrigin::Ingress(..) | CallOrigin::CanisterUpdate(..) | CallOrigin::SystemTask => {
                unreachable!("Unreachable in the QueryContext.")
            }
            CallOrigin::CanisterQuery(..) | CallOrigin::Query(..) => {
                FuncRef::QueryClosure(cleanup_closure)
            }
        };
        let cost_schedule = self.get_cost_schedule();
        let (cleanup_output, output_execution_state, output_system_state) =
            self.hypervisor.execute(
                ApiType::CompositeCleanup {
                    caller: call_origin.get_principal(),
                    time,
                    call_context_instructions_executed,
                },
                time,
                canister.system_state.clone(),
                canister_current_memory_usage,
                canister_current_message_memory_usage,
                execution_parameters,
                func_ref,
                canister.execution_state.take().unwrap(),
                &self.network_topology,
                &mut self.round_limits,
                self.query_critical_error,
                &CallTreeMetricsNoOp,
                time,
                cost_schedule,
            );

        self.add_system_api_call_counters(cleanup_output.system_api_call_counters);
        canister.execution_state = Some(output_execution_state);
        match cleanup_output.wasm_result {
            Ok(_) => {
                // Executing the cleanup callback has succeeded.
                canister.system_state = output_system_state;

                // Note that, even though the callback has succeeded,
                // the original callback error is returned.
                (cleanup_output.num_instructions_left, Err(callback_err))
            }
            Err(cleanup_err) => {
                // Executing the cleanup call back failed.
                (
                    cleanup_output.num_instructions_left,
                    Err(HypervisorError::Cleanup {
                        callback_err: Box::new(callback_err),
                        cleanup_err: Box::new(cleanup_err),
                    }),
                )
            }
        }
    }

    /// Executes a query call in its own query call context.
    /// If the execution does not produce any response, then the function
    /// returns the new query call context (canister and call origin) and a list
    /// of outgoing query calls (requests).
    /// If the execution produces a response, then the function returns it and
    /// discards the call context and outgoing requests.
    pub fn handle_request(
        &mut self,
        request: Arc<Request>,
        measurement_scope: &MeasurementScope,
    ) -> ExecutionResult {
        // A handy function to create a `Response` using parameters from the `Request`
        let to_query_result = |payload: Payload| {
            QueryResponse::CanisterResponse(Response {
                originator: request.sender,
                respondent: request.receiver,
                originator_reply_callback: request.sender_reply_callback,
                response_payload: payload,
                refund: Cycles::zero(),
                deadline: request.deadline,
            })
        };

        let canister_id = request.receiver;
        // Add the canister to the set of evaluated canisters early, i.e. before any errors.
        self.add_evaluated_canister_stats(canister_id, &QueryStats::default());

        let canister = match self.state.get_ref().get_active_canister(&canister_id) {
            Ok(canister) => canister,
            Err(err) => {
                return ExecutionResult::Response(to_query_result(Payload::Reject(
                    RejectContext::from(err),
                )));
            }
        };

        let call_origin = CallOrigin::CanisterQuery(
            request.sender,
            request.sender_reply_callback,
            request.method_name.clone(),
        );

        let method = match wasm_query_method(canister, request.method_name.clone()) {
            Ok(method) => method,
            Err(err) => {
                return ExecutionResult::Response(to_query_result(Payload::Reject(
                    RejectContext::from(err.into_user_error(&canister_id)),
                )));
            }
        };

        let (mut canister, result) = self.execute_query(
            canister.clone(),
            method,
            request.method_payload.as_slice(),
            NonReplicatedQueryKind::Stateful {
                call_origin: call_origin.clone(),
            },
            measurement_scope,
        );

        self.round_limits.instructions -= self.instruction_overhead_per_query_call;

        match result {
            // Execution of the message failed. We do not need to bother with
            // any outstanding requests and we can return a response.
            Err(err) => ExecutionResult::Response(to_query_result(Payload::Reject(
                RejectContext::from(err),
            ))),

            Ok(opt_result) => {
                match opt_result {
                    // The canister produced a response. We do not need to
                    // handle any outgoing requests as we have the response we
                    // needed and we can return it.
                    Some(wasm_result) => {
                        let payload = match wasm_result {
                            WasmResult::Reply(data) => Payload::Data(data),
                            WasmResult::Reject(string) => Payload::Reject(RejectContext::new(
                                RejectCode::CanisterReject,
                                string,
                            )),
                        };
                        ExecutionResult::Response(to_query_result(payload))
                    }
                    None => {
                        let mut requests = VecDeque::default();
                        match self.extract_query_requests(&mut canister, &mut requests) {
                            Ok(()) => ExecutionResult::Calls(canister, call_origin, requests),
                            Err(err) => ExecutionResult::SystemError(err),
                        }
                    }
                }
            }
        }
    }

    /// Extracts the query result from the call context action.
    fn action_to_result(
        &self,
        canister_id: CanisterId,
        action: CallContextAction,
    ) -> Option<Result<WasmResult, UserError>> {
        use CallContextAction::*;
        let (result, refund) = match action {
            Reply { payload, refund } => (Some(Ok(WasmResult::Reply(payload))), refund),
            Reject { payload, refund } => (Some(Ok(WasmResult::Reject(payload))), refund),
            Fail { error, refund } => (Some(Err(error.into_user_error(&canister_id))), refund),
            // The canister did not produce a response and there are no
            // outstanding calls in the call context. Generate a synthetic
            // reject message.
            NoResponse { refund } => (
                Some(Err(UserError::new(
                    ErrorCode::CanisterDidNotReply,
                    format!("Canister {canister_id} did not produce a response"),
                ))),
                refund,
            ),
            // The canister did not produce a response, but there are
            // outstanding calls in the call context that may respond.
            NotYetResponded => (None, Cycles::zero()),
            // This state indicates that the canister produced a response or
            // reject earlier and we continued to keep executing it. This
            // should not happen as once the canister has produced a response,
            // we drop its state and do not process further messages on it.
            AlreadyResponded => {
                error!(
                    self.log,
                    "[EXC-BUG] Canister {} continued execution after responding. This is a bug @{}",
                    canister_id,
                    QUERY_HANDLER_CRITICAL_ERROR,
                );
                self.query_critical_error.inc();
                (
                    Some(Err(UserError::new(
                        ErrorCode::QueryCallGraphInternal,
                        "Composite query: canister continued execution after responding",
                    ))),
                    Cycles::zero(),
                )
            }
        };

        if !refund.is_zero() {
            error!(
                self.log,
                "[EXC-BUG] Canister {} refunded {} in a response to a query call. This is a bug @{}",
                canister_id,
                refund,
                QUERY_HANDLER_CRITICAL_ERROR
            );
            self.query_critical_error.inc();
        }
        result
    }

    /// Executes the response callback corresponding to the given response.
    /// If the execution does not produce any response, then the function returns
    /// a new canister state together with the old and new outgoing requests.
    /// If the execution produces a response, then the function returns it and
    /// discards the canister and outgoing requests.
    pub fn handle_response(
        &mut self,
        canister: CanisterState,
        response: Response,
        mut requests: VecDeque<Arc<Request>>,
        measurement_scope: &MeasurementScope,
    ) -> ExecutionResult {
        let canister_id = response.originator;
        let (mut canister, call_origin, action) =
            match self.execute_callback(canister, response, measurement_scope) {
                Ok(r) => r,
                Err(err) => {
                    return ExecutionResult::SystemError(err);
                }
            };

        match call_origin {
            CallOrigin::CanisterUpdate(..) | CallOrigin::Ingress(..) | CallOrigin::SystemTask => {
                error!(
                    self.log,
                    "[EXC-BUG] Canister {}: unexpected callback with an update origin. This is a bug @{}",
                    canister_id,
                    QUERY_HANDLER_CRITICAL_ERROR,
                );
                self.query_critical_error.inc();
                ExecutionResult::SystemError(UserError::new(
                    ErrorCode::QueryCallGraphInternal,
                    "Composite query: unexpected callback with an update origin",
                ))
            }

            CallOrigin::Query(..) => match self.action_to_result(canister.canister_id(), action) {
                Some(Ok(wasm_result)) => {
                    ExecutionResult::Response(QueryResponse::UserResponse(wasm_result))
                }
                Some(Err(error)) => ExecutionResult::Response(QueryResponse::UserError(error)),
                None => match self.extract_query_requests(&mut canister, &mut requests) {
                    Ok(()) => ExecutionResult::Calls(canister, call_origin, requests),
                    Err(err) => ExecutionResult::SystemError(err),
                },
            },
            CallOrigin::CanisterQuery(originator, callback_id, ref _method_name) => {
                let canister_id = canister.canister_id();
                let to_query_result = |payload| {
                    let response = Response {
                        originator,
                        respondent: canister_id,
                        originator_reply_callback: callback_id,
                        refund: Cycles::zero(),
                        response_payload: payload,
                        // `CallOrigin::CanisterQuery` has no deadline.
                        deadline: NO_DEADLINE,
                    };
                    QueryResponse::CanisterResponse(response)
                };
                match self.action_to_result(canister_id, action) {
                    Some(Ok(wasm_result)) => {
                        let payload = match wasm_result {
                            WasmResult::Reply(payload) => Payload::Data(payload),
                            WasmResult::Reject(reject) => Payload::Reject(RejectContext::new(
                                RejectCode::CanisterReject,
                                reject,
                            )),
                        };
                        ExecutionResult::Response(to_query_result(payload))
                    }
                    Some(Err(error)) => ExecutionResult::Response(to_query_result(
                        Payload::Reject(RejectContext::from(error)),
                    )),
                    None => match self.extract_query_requests(&mut canister, &mut requests) {
                        Ok(()) => ExecutionResult::Calls(canister, call_origin, requests),
                        Err(err) => ExecutionResult::SystemError(err),
                    },
                }
            }
        }
    }

    /// Returns true if the total number of instructions executed by queries and
    /// response callbacks exceeds the limit in `round_limits`.
    pub fn instruction_limit_reached(&self) -> bool {
        self.round_limits.instructions_reached()
    }

    /// Return whether the time limit for this query context has been reached.
    pub fn time_limit_reached(&self) -> bool {
        self.query_context_time_start.elapsed() >= self.query_context_time_limit
    }

    /// Returns a synthetic reject response for the case when a query call
    /// context did not produce any response.
    pub fn empty_response(
        &self,
        canister_id: CanisterId,
        call_origin: CallOrigin,
    ) -> QueryResponse {
        let error = UserError::new(
            ErrorCode::CanisterDidNotReply,
            format!("Canister {canister_id} did not produce a response"),
        );
        match call_origin {
            CallOrigin::Ingress(..) | CallOrigin::CanisterUpdate(..) | CallOrigin::SystemTask => {
                unreachable!("Expected a query call context");
            }
            CallOrigin::Query(..) => QueryResponse::UserError(error),
            CallOrigin::CanisterQuery(originator, callback_id, _method_name) => {
                let response = Response {
                    originator,
                    respondent: canister_id,
                    originator_reply_callback: callback_id,
                    refund: Cycles::zero(),
                    response_payload: Payload::Reject(RejectContext::from(error)),
                    // `CallOrigin::CanisterQuery` has no deadline.
                    deadline: NO_DEADLINE,
                };
                QueryResponse::CanisterResponse(response)
            }
        }
    }

    fn execution_parameters(
        &self,
        canister: &CanisterState,
        instruction_limits: InstructionLimits,
    ) -> ExecutionParameters {
        ExecutionParameters {
            instruction_limits,
            wasm_memory_limit: canister.wasm_memory_limit(),
            memory_allocation: canister.memory_allocation(),
            canister_guaranteed_callback_quota: self.canister_guaranteed_callback_quota,
            compute_allocation: canister.compute_allocation(),
            subnet_type: self.own_subnet_type,
            execution_mode: ExecutionMode::NonReplicated,
            // Effectively disable subnet memory resource reservation for queries.
            subnet_memory_saturation: ResourceSaturation::default(),
        }
    }

    fn get_data_certificate(&self, canister_id: &CanisterId) -> Option<Vec<u8>> {
        self.data_certificate.as_ref().and_then(
            |(data_certificate, data_certificate_canister_id)| {
                if canister_id != data_certificate_canister_id {
                    None
                } else {
                    Some(data_certificate.clone())
                }
            },
        )
    }

    /// Returns how many times each tracked System API call was invoked.
    pub fn system_api_call_counters(&self) -> &SystemApiCallCounters {
        &self.system_api_call_counters
    }

    /// Returns a list of actually executed canisters with their stats.
    pub fn evaluated_canister_stats(&self) -> &BTreeMap<CanisterId, QueryStats> {
        &self.evaluated_canister_stats
    }

    /// Returns a number of transient errors.
    pub fn transient_errors(&self) -> usize {
        self.transient_errors
    }

    pub fn get_cost_schedule(&self) -> CanisterCyclesCostSchedule {
        self.state.get_ref().get_own_cost_schedule()
    }
}
