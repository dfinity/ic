use crate::{
    execution::common::{self, validate_method},
    execution::nonreplicated_query::execute_non_replicated_query,
    execution_environment::{as_round_instructions, RoundLimits},
    hypervisor::Hypervisor,
    metrics::{MeasurementScope, QueryHandlerMetrics, QUERY_HANDLER_CRITICAL_ERROR},
    NonReplicatedQueryKind, RoundInstructions,
};
use ic_base_types::NumBytes;
use ic_config::flag_status::FlagStatus;
use ic_constants::SMALL_APP_SUBNET_MAX_SIZE;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::{
    ExecutionComplexity, ExecutionMode, HypervisorError, SubnetAvailableMemory,
};
use ic_logger::{error, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallContextAction, CallOrigin, CanisterState, NetworkTopology, ReplicatedState,
};
use ic_system_api::{ApiType, ExecutionParameters, InstructionLimits};
use ic_types::{
    ingress::WasmResult,
    messages::{Payload, RejectContext, Request, RequestOrResponse, Response, UserQuery},
    methods::WasmMethod,
    CanisterId, Cycles, NumInstructions, NumMessages, Time,
};
use ic_types::{
    methods::{FuncRef, WasmClosure},
    NumSlices,
};
use prometheus::IntCounter;
use std::{collections::VecDeque, sync::Arc, time::Duration, time::Instant};

use super::query_call_graph::evaluate_query_call_graph;

/// The response of a query. If the query originated from a user, then it
/// contains either `UserResponse` or `UserError`. If the query originated from
/// a canister, then it containts `CanisterResponse`.
pub(super) enum QueryResponse {
    UserResponse(WasmResult),
    UserError(UserError),
    CanisterResponse(Response),
}

/// The result of execution of a query or a response callback.
/// The execution either produces a response or returns a possibly empty set of
/// outgoing calls with the new canister state and the call origin.
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
    state: Arc<ReplicatedState>,
    network_topology: Arc<NetworkTopology>,
    // Certificate for certified queries + canister ID of the root query of this context
    data_certificate: (Vec<u8>, CanisterId),
    max_canister_memory_size: NumBytes,
    max_instructions_per_query: NumInstructions,
    max_query_call_graph_depth: usize,
    instruction_overhead_per_query_call: RoundInstructions,
    round_limits: RoundLimits,
    composite_queries: FlagStatus,
    // Walltime at which the query has started to execute.
    query_context_time_start: Instant,
    query_context_time_limit: Duration,
    query_critical_error: &'a IntCounter,
    subnet_memory_capacity: NumBytes,
}

impl<'a> QueryContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        log: &'a ReplicaLogger,
        hypervisor: &'a Hypervisor,
        own_subnet_type: SubnetType,
        state: Arc<ReplicatedState>,
        data_certificate: Vec<u8>,
        subnet_available_memory: SubnetAvailableMemory,
        subnet_memory_capacity: NumBytes,
        max_canister_memory_size: NumBytes,
        max_instructions_per_query: NumInstructions,
        max_query_call_graph_depth: usize,
        max_query_call_graph_instructions: NumInstructions,
        max_query_call_walltime: Duration,
        instruction_overhead_per_query_call: NumInstructions,
        composite_queries: FlagStatus,
        canister_id: CanisterId,
        query_critical_error: &'a IntCounter,
    ) -> Self {
        let network_topology = Arc::new(state.metadata.network_topology.clone());
        let round_limits = RoundLimits {
            instructions: as_round_instructions(max_query_call_graph_instructions),
            execution_complexity: ExecutionComplexity::with_cpu(max_query_call_graph_instructions),
            subnet_available_memory,
            // Ignore compute allocation
            compute_allocation_used: 0,
        };
        Self {
            log,
            hypervisor,
            own_subnet_type,
            state,
            network_topology,
            data_certificate: (data_certificate, canister_id),
            max_canister_memory_size,
            max_instructions_per_query,
            max_query_call_graph_depth,
            instruction_overhead_per_query_call: as_round_instructions(
                instruction_overhead_per_query_call,
            ),
            round_limits,
            composite_queries,
            query_context_time_start: Instant::now(),
            query_context_time_limit: max_query_call_walltime,
            query_critical_error,
            subnet_memory_capacity,
        }
    }

    /// Executes the given query sent by an end user.
    ///
    /// - If it produces a response return the response.
    ///
    /// - If it does not produce a response and does not send further queries,
    /// then return a response indicating that the canister did not reply.
    ///
    /// - If it does not produce a response and produces additional
    /// inter-canister queries, process them till there is a response or the
    /// call graph finishes with no reply.
    pub(super) fn run<'b>(
        &mut self,
        query: UserQuery,
        metrics: &'b QueryHandlerMetrics,
        cycles_account_manager: Arc<CyclesAccountManager>,
        measurement_scope: &MeasurementScope<'b>,
    ) -> Result<WasmResult, UserError> {
        let canister_id = query.receiver;
        let old_canister = self.state.get_active_canister(&canister_id)?;

        let subnet_size = self
            .network_topology
            .get_subnet_size(&cycles_account_manager.get_subnet_id())
            .unwrap_or(SMALL_APP_SUBNET_MAX_SIZE);
        if cycles_account_manager.freeze_threshold_cycles(
            old_canister.system_state.freeze_threshold,
            old_canister.system_state.memory_allocation,
            old_canister.memory_usage(),
            old_canister.scheduler_state.compute_allocation,
            subnet_size,
            old_canister.system_state.reserved_balance(),
        ) > old_canister.system_state.balance()
        {
            return Err(UserError::new(
                ErrorCode::CanisterOutOfCycles,
                format!("Canister {} is unable to process query calls because it's frozen. Please top up the canister with cycles and try again.", canister_id))
            );
        }

        let call_origin = CallOrigin::Query(query.source);

        let method = match wasm_query_method(old_canister, query.method_name.clone()) {
            Ok(method) => method,
            Err(err) => return Err(err.into_user_error(&canister_id)),
        };

        let query_kind = match &method {
            WasmMethod::Query(_) => NonReplicatedQueryKind::Pure {
                caller: query.source.get(),
            },
            WasmMethod::CompositeQuery(_) => NonReplicatedQueryKind::Stateful {
                call_origin: call_origin.clone(),
            },
            WasmMethod::Update(_) | WasmMethod::System(_) => {
                unreachable!("Expected a Wasm query method");
            }
        };

        let (mut canister, mut result) = {
            let measurement_scope =
                MeasurementScope::nested(&metrics.query_initial_call, measurement_scope);
            self.execute_query(
                old_canister.clone(),
                method.clone(),
                query.method_payload.as_slice(),
                query_kind,
                &measurement_scope,
            )
        };

        // An attempt to call another query will result in `ContractViolation`.
        // If that's the case then retry query execution as `Stateful` if the
        // legacy ICQC is enabled.

        let legacy_icqc_enabled = self.own_subnet_type == SubnetType::System
            || self.own_subnet_type == SubnetType::VerifiedApplication;

        if let WasmMethod::Query(_) = &method {
            if let Err(err) = &result {
                if err.code() == ErrorCode::CanisterContractViolation && legacy_icqc_enabled {
                    let measurement_scope =
                        MeasurementScope::nested(&metrics.query_retry_call, measurement_scope);
                    let old_canister = self.state.get_active_canister(&canister_id)?;
                    let (new_canister, new_result) = self.execute_query(
                        old_canister.clone(),
                        method,
                        query.method_payload.as_slice(),
                        NonReplicatedQueryKind::Stateful {
                            call_origin: call_origin.clone(),
                        },
                        &measurement_scope,
                    );
                    canister = new_canister;
                    result = new_result;
                }
            };
        }

        match result {
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
        }
    }

    // A helper function that extracts the query calls of the given canister and
    // enqueues them onto the given deque.
    fn extract_query_requests(
        &self,
        canister: &mut CanisterState,
        requests: &mut VecDeque<Arc<Request>>,
    ) -> Result<(), UserError> {
        let canister_id = canister.canister_id();

        let outgoing_messages: Vec<_> = canister.output_into_iter().map(|(_, msg)| msg).collect();
        let call_context_manager = canister
            .system_state
            .call_context_manager_mut()
            .ok_or_else(|| {
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
            })?;

        // When we deserialize the canister state from the replicated state, it
        // is possible that it already had some messages in its output queues.
        // As we iterate over the messages below, we only want to handle
        // messages that were produced by this module.
        for msg in outgoing_messages {
            match msg {
                RequestOrResponse::Request(msg) => {
                    let call_origin = call_context_manager
                        .peek_callback(msg.sender_reply_callback)
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

                        Some(CallOrigin::Query(_)) | Some(CallOrigin::CanisterQuery(_, _)) => {
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
        if let WasmMethod::CompositeQuery(_) = &method_name {
            if self.composite_queries == FlagStatus::Disabled {
                return (
                    canister,
                    Err(UserError::new(
                        ErrorCode::CanisterContractViolation,
                        "Composite queries are not enabled yet",
                    )),
                );
            }
        }
        let instruction_limit = self.max_instructions_per_query.min(NumInstructions::new(
            self.round_limits.instructions.get().max(0) as u64,
        ));
        let instruction_limits =
            InstructionLimits::new(FlagStatus::Disabled, instruction_limit, instruction_limit);
        let execution_parameters = self.execution_parameters(&canister, instruction_limits);

        let data_certificate = self.get_data_certificate(&canister.canister_id());
        let (canister, instructions_left, result) = execute_non_replicated_query(
            query_kind,
            method_name,
            method_payload,
            canister,
            data_certificate,
            self.state.time(),
            execution_parameters,
            &self.network_topology,
            self.hypervisor,
            &mut self.round_limits,
        );
        let instructions_executed = instruction_limit - instructions_left;
        measurement_scope.add(
            instructions_executed,
            NumSlices::from(1),
            NumMessages::from(1),
        );
        (canister, result)
    }

    fn execute_callback(
        &mut self,
        mut canister: CanisterState,
        response: Response,
        measurement_scope: &MeasurementScope,
    ) -> Result<(CanisterState, CallOrigin, CallContextAction), UserError> {
        let canister_id = canister.canister_id();
        let (callback, callback_id, call_context, call_context_id) =
            match common::get_call_context_and_callback(&canister, &response, self.log) {
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
            let action = canister
                .system_state
                .call_context_manager_mut()
                // This `unwrap()` cannot fail because we checked for the call
                // context manager in `get_call_context_and_callback()` call.
                .unwrap()
                .on_canister_result(
                    call_context_id,
                    Some(callback_id),
                    Err(HypervisorError::WasmModuleNotFound),
                );
            return Ok((canister, call_origin, action));
        }

        let closure = match response.response_payload {
            Payload::Data(_) => callback.on_reply.clone(),
            Payload::Reject(_) => callback.on_reject.clone(),
        };
        let func_ref = match call_origin {
            CallOrigin::Ingress(_, _)
            | CallOrigin::CanisterUpdate(_, _)
            | CallOrigin::SystemTask => unreachable!("Unreachable in the QueryContext."),
            CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => {
                FuncRef::QueryClosure(closure)
            }
        };

        let time = self.state.time();
        // No cycles are refunded in a response to a query call.
        let incoming_cycles = Cycles::zero();

        let instruction_limit = self.max_instructions_per_query.min(NumInstructions::new(
            self.round_limits.instructions.get().max(0) as u64,
        ));
        let instruction_limits =
            InstructionLimits::new(FlagStatus::Disabled, instruction_limit, instruction_limit);
        let mut execution_parameters = self.execution_parameters(&canister, instruction_limits);
        let api_type = match response.response_payload {
            Payload::Data(payload) => ApiType::reply_callback(
                time,
                call_origin.get_principal(),
                payload.to_vec(),
                incoming_cycles,
                call_context_id,
                call_responded,
                execution_parameters.execution_mode.clone(),
            ),
            Payload::Reject(context) => ApiType::reject_callback(
                time,
                call_origin.get_principal(),
                context,
                incoming_cycles,
                call_context_id,
                call_responded,
                execution_parameters.execution_mode.clone(),
            ),
        };

        let (output, output_execution_state, output_system_state) = self.hypervisor.execute(
            api_type,
            time,
            canister.system_state.clone(),
            canister.memory_usage(),
            execution_parameters.clone(),
            func_ref,
            canister.execution_state.take().unwrap(),
            &self.network_topology,
            &mut self.round_limits,
        );

        let canister_current_memory_usage = canister.memory_usage();
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
                    Some(cleanup_closure) => self.execute_cleanup(
                        time,
                        &mut canister,
                        cleanup_closure,
                        &call_origin,
                        callback_err,
                        canister_current_memory_usage,
                        execution_parameters,
                    ),
                }
            }
        };

        let action = canister
            .system_state
            .call_context_manager_mut()
            // This `unwrap()` cannot fail because we checked for the call
            // context manager in `get_call_context_and_callback()` call.
            .unwrap()
            .on_canister_result(call_context_id, Some(callback_id), result);

        let instructions_executed = instruction_limit - instructions_left;
        measurement_scope.add(
            instructions_executed,
            NumSlices::from(1),
            NumMessages::from(1),
        );
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
        execution_parameters: ExecutionParameters,
    ) -> (NumInstructions, Result<Option<WasmResult>, HypervisorError>) {
        let func_ref = match call_origin {
            CallOrigin::Ingress(_, _)
            | CallOrigin::CanisterUpdate(_, _)
            | CallOrigin::SystemTask => unreachable!("Unreachable in the QueryContext."),
            CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => {
                FuncRef::QueryClosure(cleanup_closure)
            }
        };
        let (cleanup_output, output_execution_state, output_system_state) =
            self.hypervisor.execute(
                ApiType::Cleanup {
                    caller: call_origin.get_principal(),
                    time,
                },
                time,
                canister.system_state.clone(),
                canister_current_memory_usage,
                execution_parameters,
                func_ref,
                canister.execution_state.take().unwrap(),
                &self.network_topology,
                &mut self.round_limits,
            );

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
            })
        };

        let canister_id = request.receiver;

        let canister = match self.state.get_active_canister(&canister_id) {
            Ok(canister) => canister,
            Err(err) => {
                return ExecutionResult::Response(to_query_result(Payload::Reject(
                    RejectContext::from(err),
                )));
            }
        };

        let call_origin = CallOrigin::CanisterQuery(request.sender, request.sender_reply_callback);

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
                    format!("Canister {} did not produce a response", canister_id),
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
            CallOrigin::CanisterUpdate(_, _)
            | CallOrigin::Ingress(_, _)
            | CallOrigin::SystemTask => {
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

            CallOrigin::Query(_) => match self.action_to_result(canister.canister_id(), action) {
                Some(Ok(wasm_result)) => {
                    ExecutionResult::Response(QueryResponse::UserResponse(wasm_result))
                }
                Some(Err(error)) => ExecutionResult::Response(QueryResponse::UserError(error)),
                None => match self.extract_query_requests(&mut canister, &mut requests) {
                    Ok(()) => ExecutionResult::Calls(canister, call_origin, requests),
                    Err(err) => ExecutionResult::SystemError(err),
                },
            },
            CallOrigin::CanisterQuery(originator, callback_id) => {
                let canister_id = canister.canister_id();
                let to_query_result = |payload| {
                    let response = Response {
                        originator,
                        respondent: canister_id,
                        originator_reply_callback: callback_id,
                        refund: Cycles::zero(),
                        response_payload: payload,
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
        self.round_limits.reached()
    }

    /// Return whether the time limit for this query context has been reached.
    pub fn time_limit_reached(&self) -> bool {
        self.query_context_time_start.elapsed() >= self.query_context_time_limit
    }

    /// Returns a synthetic reject reponse for the case when a query call
    /// context did not produce any response.
    pub fn empty_response(
        &self,
        canister_id: CanisterId,
        call_origin: CallOrigin,
    ) -> QueryResponse {
        let error = UserError::new(
            ErrorCode::CanisterDidNotReply,
            format!("Canister {} did not produce a response", canister_id),
        );
        match call_origin {
            CallOrigin::Ingress(_, _)
            | CallOrigin::CanisterUpdate(_, _)
            | CallOrigin::SystemTask => {
                unreachable!("Expected a query call context");
            }
            CallOrigin::Query(_) => QueryResponse::UserError(error),
            CallOrigin::CanisterQuery(originator, callback_id) => {
                let response = Response {
                    originator,
                    respondent: canister_id,
                    originator_reply_callback: callback_id,
                    refund: Cycles::zero(),
                    response_payload: Payload::Reject(RejectContext::from(error)),
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
            canister_memory_limit: canister.memory_limit(self.max_canister_memory_size),
            memory_allocation: canister.memory_allocation(),
            compute_allocation: canister.compute_allocation(),
            subnet_type: self.own_subnet_type,
            execution_mode: ExecutionMode::NonReplicated,
            subnet_memory_capacity: self.subnet_memory_capacity,
            // Effectively disable subnet memory resource reservation for queries.
            subnet_memory_threshold: self.subnet_memory_capacity,
        }
    }

    fn get_data_certificate(&self, canister_id: &CanisterId) -> Option<Vec<u8>> {
        if canister_id != &self.data_certificate.1 {
            None
        } else {
            Some(self.data_certificate.0.clone())
        }
    }
}
