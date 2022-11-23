//! This module implements an MVP version of inter-canister queries. This
//! implementation has the following restrictions:
//!
//! - A canister can only query other canisters on the same subnet.
//!
//! - A canister can only query other canisters when it is doing non-replicated
//! execution, i.e. the originator of the processing is a Query from an end-user
//! and not an Ingress message.
//!
//! - Loops are not allowed. E.g. call graphs like A -> B -> C -> A are not
//! supported.
//!
//! Some interesting factoids about inter-canister query execution to keep in
//! mind:
//!
//! - If a canister produces a response then there is no point in executing any
//! more messages on it or handling any outstanding requests that it sent. This
//! is because additional execution will not change the produced response and as
//! we are not committing modifications to the canister state, any modifications
//! caused by the additional execution are not needed either.
//!
//! - Due to the point above, while a canister has not produced a response and
//! has outstanding requests, we store its modified state in the query context.
//! And as soon as it has produced a response, we drop its state. Once a
//! canister's state has been dropped, it becomes available for being queried
//! again.
//!
//! - We process the outstanding requests in a depth first search manner. This
//! means that if canister A sends canister B two requests (M1 and M2) back to
//! back, we first fully traverse the branch from executing M1; drop the
//! modified state of B after this branch finishes; and then start branch M2 on
//! a clean version of B. If we did breadth first search, then we would have to
//! maintain two distinct versions of B.
//!
//! - For a lack of a better strategy, always prioritise responses over
//! requests.

use crate::{
    execution::common::{self, validate_method},
    execution::nonreplicated_query::execute_non_replicated_query,
    execution_environment::{as_round_instructions, RoundLimits},
    hypervisor::Hypervisor,
    metrics::{MeasurementScope, QueryHandlerMetrics},
    NonReplicatedQueryKind,
};
use ic_base_types::NumBytes;
use ic_config::flag_status::FlagStatus;
use ic_constants::SMALL_APP_SUBNET_MAX_SIZE;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::{ExecutionMode, HypervisorError, SubnetAvailableMemory};
use ic_logger::{debug, error, fatal, warn, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallContextAction, CallOrigin, CanisterState, NetworkTopology, ReplicatedState,
};
use ic_system_api::{ApiType, ExecutionParameters, InstructionLimits};
use ic_types::{
    ingress::WasmResult,
    messages::{
        CallbackId, Payload, RejectContext, Request, RequestOrResponse, Response, UserQuery,
    },
    methods::WasmMethod,
    CanisterId, Cycles, NumInstructions, NumMessages, Time,
};
use ic_types::{
    methods::{FuncRef, WasmClosure},
    NumSlices,
};
use std::{collections::BTreeMap, sync::Arc};

const ENABLE_QUERY_OPTIMIZATION: bool = true;

const LOOP_DETECTED_ERROR_MSG: &str =
    "Loop detected.  MVP inter-canister queries do not support loops.";

const CALL_GRAPH_TOO_DEEP_ERROR_MSG: &str =
    "Call exceeded the limit for maximum number of nested query calls.";

const TOTAL_NUM_INSTRUCTIONS_EXCEEDED: &str =
    "Query call graph exceeded the limit for the total maximum number of instructions.";

/// A simple enum representing the different things that
/// QueryContext::enqueue_requests() can return.
enum EnqueueRequestsResult {
    /// The canister had some valid messages to enqueue and they were
    /// successfully enqueued.
    MessagesEnqueued,
    /// The canister had no messages to enqueue.
    NoMessages,
    /// A loop in the callgraph was detected so no messages were enqueued.
    LoopDetected,
    /// The call graph is too large
    CallGraphTooDeep,
    /// The total number of instructions executed in call context is too large.
    TotalNumInstructionsExceeded,
}

// A handy function to create a `Response` using parameters from the `Request`
fn generate_response(request: Arc<Request>, payload: Payload) -> Response {
    Response {
        originator: request.sender,
        respondent: request.receiver,
        originator_reply_callback: request.sender_reply_callback,
        response_payload: payload,
        refund: Cycles::zero(),
    }
}

/// Map an error occurred when enqueuing a new request to a user error.
///
/// Unless NoMessages or MessagesEnqueued, this is guaranteed to return Some.
fn map_enqueue_error_to_user(enqueue_error: EnqueueRequestsResult) -> Option<UserError> {
    match enqueue_error {
        EnqueueRequestsResult::LoopDetected => Some(UserError::new(
            ErrorCode::QueryCallGraphLoopDetected,
            LOOP_DETECTED_ERROR_MSG.to_string(),
        )),
        EnqueueRequestsResult::CallGraphTooDeep => Some(UserError::new(
            ErrorCode::QueryCallGraphTooDeep,
            CALL_GRAPH_TOO_DEEP_ERROR_MSG.to_string(),
        )),
        EnqueueRequestsResult::TotalNumInstructionsExceeded => Some(UserError::new(
            ErrorCode::QueryCallGraphTotalInstructionLimitExceeded,
            TOTAL_NUM_INSTRUCTIONS_EXCEEDED.to_string(),
        )),
        EnqueueRequestsResult::NoMessages | EnqueueRequestsResult::MessagesEnqueued => None,
    }
}

/// Handles running a single UserQuery to completion by maintaining the call
/// graph of the query execution between canisters.
pub(super) struct QueryContext<'a> {
    log: &'a ReplicaLogger,
    hypervisor: &'a Hypervisor,
    own_subnet_type: SubnetType,
    // The state against which all queries in the context will be executed.
    state: Arc<ReplicatedState>,
    network_topology: Arc<NetworkTopology>,
    data_certificate: Vec<u8>,
    // Contains all canisters that currently have pending calls.
    call_stack: BTreeMap<CanisterId, CanisterState>,
    outstanding_requests: Vec<Arc<Request>>,
    // Response (if available) waiting to be executed. We always process
    // responses first if one is available hence, there will never be more than
    // one outstanding response.
    outstanding_response: Option<Response>,
    max_canister_memory_size: NumBytes,
    max_instructions_per_query: NumInstructions,
    max_query_call_depth: usize,
    remaining_instructions_for_composite_query: NumInstructions,
    // Number of instructions to charge for each query call
    instructions_per_composite_query_call: NumInstructions,
    round_limits: RoundLimits,
    composite_queries: FlagStatus,
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
        max_canister_memory_size: NumBytes,
        max_instructions_per_query: NumInstructions,
        max_query_call_depth: usize,
        initial_instructions_for_composite_query: NumInstructions,
        instructions_per_composite_query_call: NumInstructions,
        composite_queries: FlagStatus,
    ) -> Self {
        let network_topology = Arc::new(state.metadata.network_topology.clone());
        let round_limits = RoundLimits {
            instructions: as_round_instructions(max_instructions_per_query),
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
            data_certificate,
            call_stack: BTreeMap::new(),
            outstanding_requests: Vec::new(),
            outstanding_response: None,
            max_canister_memory_size,
            max_instructions_per_query,
            max_query_call_depth,
            remaining_instructions_for_composite_query: initial_instructions_for_composite_query,
            instructions_per_composite_query_call,
            round_limits,
            composite_queries,
        }
    }

    /// Executes the given Query sent by an end user.
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
        debug!(self.log, "Executing query for {}", canister_id);
        let old_canister = self.state.get_active_canister(&canister_id)?;

        let subnet_size = self
            .network_topology
            .get_subnet_size(&cycles_account_manager.get_subnet_id())
            .unwrap_or(SMALL_APP_SUBNET_MAX_SIZE);
        if cycles_account_manager.freeze_threshold_cycles(
            old_canister.system_state.freeze_threshold,
            old_canister.system_state.memory_allocation,
            old_canister.memory_usage(self.own_subnet_type),
            old_canister.scheduler_state.compute_allocation,
            subnet_size,
        ) > old_canister.system_state.balance()
        {
            return Err(UserError::new(
                ErrorCode::CanisterOutOfCycles,
                format!("Canister {} is unable to process query calls because it's frozen. Please top up the canister with cycles and try again.", canister_id))
            );
        }

        let call_origin = CallOrigin::Query(query.source);
        let (method, query_kind, retry_as_stateful) = {
            let method = WasmMethod::CompositeQuery(query.method_name.clone());
            match validate_method(&method, &old_canister) {
                Ok(_) => {
                    if self.composite_queries == FlagStatus::Disabled {
                        return Err(UserError::new(
                            ErrorCode::CanisterContractViolation,
                            "Composite queries are not enabled yet",
                        ));
                    }
                    let query_kind = NonReplicatedQueryKind::Stateful {
                        call_origin: call_origin.clone(),
                    };
                    (method, query_kind, false)
                }
                Err(_) => {
                    // EXC-500: Contain the usage of inter-canister query calls to the subnets
                    // that currently use it until we decide on the future of this feature and
                    // get a proper spec for it.
                    let cross_canister_query_calls_enabled = self.own_subnet_type
                        == SubnetType::System
                        || self.own_subnet_type == SubnetType::VerifiedApplication;
                    let try_pure_query_first =
                        ENABLE_QUERY_OPTIMIZATION || !cross_canister_query_calls_enabled;

                    let method = WasmMethod::Query(query.method_name.clone());
                    // First try to run the query as `Pure` assuming that it is not going to
                    // call other queries. `Pure` queries are about 2x faster than `Stateful`.
                    let query_kind = if try_pure_query_first {
                        NonReplicatedQueryKind::Pure {
                            caller: query.source.get(),
                        }
                    } else {
                        // TODO(RUN-427): Remove this case after all existing users
                        // transition to composite queries.
                        NonReplicatedQueryKind::Stateful {
                            call_origin: call_origin.clone(),
                        }
                    };
                    let retry_as_stateful =
                        try_pure_query_first && cross_canister_query_calls_enabled;
                    (method, query_kind, retry_as_stateful)
                }
            }
        };

        let (mut canister, mut result) = {
            let measurement_scope =
                MeasurementScope::nested(&metrics.query_initial_call, measurement_scope);
            self.execute_query(
                old_canister,
                method.clone(),
                query.method_payload.as_slice(),
                query_kind,
                &measurement_scope,
            )
        };

        // An attempt to call another query will result in `ContractViolation`.
        // If that's the case then retry query execution as `Stateful`.
        if retry_as_stateful {
            if let Err(err) = &result {
                if err.code() == ErrorCode::CanisterContractViolation {
                    let measurement_scope =
                        MeasurementScope::nested(&metrics.query_retry_call, measurement_scope);
                    let old_canister = self.state.get_active_canister(&canister_id)?;
                    let (new_canister, new_result) = self.execute_query(
                        old_canister,
                        method,
                        query.method_payload.as_slice(),
                        NonReplicatedQueryKind::Stateful { call_origin },
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
                let r = self.enqueue_requests(&mut canister);
                match r {
                    EnqueueRequestsResult::NoMessages => Err(UserError::new(
                        ErrorCode::CanisterDidNotReply,
                        format!(
                            "Canister {} did not reply to the call",
                            canister.canister_id()
                        ),
                    )),
                    EnqueueRequestsResult::MessagesEnqueued => {
                        self.call_stack.insert(canister.canister_id(), canister);
                        self.run_loop(canister_id, metrics, measurement_scope)
                    }
                    _ => Err(map_enqueue_error_to_user(r).unwrap()),
                }
            }
        }
    }

    // Keep processing the call graph till a result is achieved or no more
    // outstanding calls are left.
    fn run_loop<'b>(
        &mut self,
        starting_canister_id: CanisterId,
        metrics: &'b QueryHandlerMetrics,
        measurement_scope: &MeasurementScope<'b>,
    ) -> Result<WasmResult, UserError> {
        let measurement_scope =
            MeasurementScope::nested(&metrics.query_spawned_calls, measurement_scope);
        loop {
            if let Some(response) = self.outstanding_response.take() {
                debug!(self.log, "Executing response for {}", response.originator);
                // Any result returned by `handle_response` is a query context
                // terminating response and can be returned.
                if let Some(result) = self.handle_response(response, &measurement_scope) {
                    return result;
                }
                continue;
            }

            if let Some(request) = self.outstanding_requests.pop() {
                debug!(self.log, "Executing request for {}", request.receiver);
                if let Some(err) = self.handle_request(request, &measurement_scope) {
                    return Err(err);
                }
                continue;
            }

            // There are no outstanding requests and responses. The call
            // graph finished without producing a response.
            debug!(
                self.log,
                "Call graph for {} finished without result", starting_canister_id
            );
            return Err(UserError::new(
                ErrorCode::CanisterDidNotReply,
                format!(
                    "Canister {} did not reply to the call",
                    starting_canister_id
                ),
            ));
        }
    }

    // A helper function that enqueues any outgoing requests that the canister
    // has.
    fn enqueue_requests(&mut self, canister: &mut CanisterState) -> EnqueueRequestsResult {
        let mut sent_messages = false;
        let canister_id = canister.canister_id();

        let outgoing_messages: Vec<_> = canister.output_into_iter().map(|(_, msg)| msg).collect();
        let call_context_manager = canister
            .system_state
            .call_context_manager_mut()
            .unwrap_or_else(|| {
                fatal!(
                    self.log,
                    "Canister {}: Expected to find a CallContextManager",
                    canister_id
                )
            });

        // When we deserialize the canister state from the replicated state, it
        // is possible that it already had some messages in its output queues.
        // As we iterate over the messages below, we only want to handle
        // messages that were produced by this module.
        for msg in outgoing_messages {
            match msg {
                RequestOrResponse::Request(msg) => {
                    // Responses here are only those triggered by the Request that we sent,
                    // so we are sure the unwrap here is safe.
                    let call_origin = call_context_manager
                        .call_origin(
                            call_context_manager
                                .peek_callback(msg.sender_reply_callback)
                                .unwrap()
                                .call_context_id,
                        )
                        .unwrap();
                    match call_origin {
                        // Messages of these types are not produced by this
                        // module so must have existed on the canister's output
                        // queue from before.
                        CallOrigin::CanisterUpdate(_, _)
                        | CallOrigin::SystemTask
                        | CallOrigin::Ingress(_, _) => continue,

                        // We never serialize messages of such types in the
                        // canister's state so these must have been produced by
                        // this module.
                        CallOrigin::Query(_) | CallOrigin::CanisterQuery(_, _) => {}
                    }

                    if msg.receiver == canister_id || self.call_stack.contains_key(&msg.receiver) {
                        // Call graph loop detector. There is already a canister
                        // in the call graph that is waiting for some responses
                        // to come back and this canister is trying to send it
                        // messages. The MVP inter-canister queries
                        // implementation does not support loops.
                        return EnqueueRequestsResult::LoopDetected;
                    }

                    if self.call_stack.len() + 1 > self.max_query_call_depth {
                        return EnqueueRequestsResult::CallGraphTooDeep;
                    }

                    if self.remaining_instructions_for_composite_query
                        < self.instructions_per_composite_query_call
                    {
                        return EnqueueRequestsResult::TotalNumInstructionsExceeded;
                    }

                    self.remaining_instructions_for_composite_query = NumInstructions::from(
                        self.remaining_instructions_for_composite_query
                            .get()
                            .saturating_sub(self.instructions_per_composite_query_call.get()),
                    );

                    sent_messages = true;
                    self.outstanding_requests.push(msg);
                }

                // Messages of these types are not produced by this
                // module so must have existed on the canister's output
                // queue from before.
                RequestOrResponse::Response(_) => {}
            }
        }
        if sent_messages {
            EnqueueRequestsResult::MessagesEnqueued
        } else {
            EnqueueRequestsResult::NoMessages
        }
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
        let instruction_limit = self
            .max_instructions_per_query
            .min(self.remaining_instructions_for_composite_query);
        let instruction_limits =
            InstructionLimits::new(FlagStatus::Disabled, instruction_limit, instruction_limit);
        let execution_parameters = self.execution_parameters(&canister, instruction_limits);

        let (canister, instructions_left, result) = execute_non_replicated_query(
            query_kind,
            method_name,
            method_payload,
            canister,
            Some(self.data_certificate.clone()),
            self.state.time(),
            execution_parameters,
            &self.network_topology,
            self.hypervisor,
            &mut self.round_limits,
        );
        let instructions_executed = instruction_limit - instructions_left;
        self.remaining_instructions_for_composite_query = NumInstructions::from(
            self.remaining_instructions_for_composite_query
                .get()
                .saturating_sub(instructions_executed.get()),
        );
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
    ) -> (CanisterState, CallOrigin, CallContextAction) {
        let canister_id = canister.canister_id();
        let (callback, callback_id, call_context, call_context_id) =
            match common::get_call_context_and_callback(&canister, &response, self.log) {
                Some(r) => r,
                None => {
                    fatal!(
                        self.log,
                        "Canister {}: Expected to find a callback and call context",
                        canister_id
                    )
                }
            };

        let call_responded = call_context.has_responded();
        let call_origin = call_context.call_origin().clone();
        // Validate that the canister has an `ExecutionState`.
        if canister.execution_state.is_none() {
            let action = canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .on_canister_result(
                    call_context_id,
                    Some(callback_id),
                    Err(HypervisorError::WasmModuleNotFound),
                );
            return (canister, call_origin, action);
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

        let instruction_limit = self
            .max_instructions_per_query
            .min(self.remaining_instructions_for_composite_query);
        let instruction_limits =
            InstructionLimits::new(FlagStatus::Disabled, instruction_limit, instruction_limit);
        let mut execution_parameters = self.execution_parameters(&canister, instruction_limits);
        let api_type = match response.response_payload {
            Payload::Data(payload) => ApiType::reply_callback(
                time,
                payload.to_vec(),
                incoming_cycles,
                call_context_id,
                call_responded,
                execution_parameters.execution_mode.clone(),
            ),
            Payload::Reject(context) => ApiType::reject_callback(
                time,
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
            canister.memory_usage(self.own_subnet_type),
            execution_parameters.clone(),
            func_ref,
            canister.execution_state.take().unwrap(),
            &self.network_topology,
            &mut self.round_limits,
        );

        let canister_current_memory_usage = canister.memory_usage(self.own_subnet_type);
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
            .unwrap()
            .on_canister_result(call_context_id, Some(callback_id), result);

        let instructions_executed = instruction_limit - instructions_left;
        self.remaining_instructions_for_composite_query = NumInstructions::from(
            self.remaining_instructions_for_composite_query
                .get()
                .saturating_sub(instructions_executed.get()),
        );

        measurement_scope.add(
            instructions_executed,
            NumSlices::from(1),
            NumMessages::from(1),
        );
        (canister, call_origin, action)
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
                ApiType::Cleanup { time },
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

    // Executes a query sent from one canister to another. If a loop in the call
    // graph is detected, then an error is returned.
    fn handle_request(
        &mut self,
        request: Arc<Request>,
        measurement_scope: &MeasurementScope,
    ) -> Option<UserError> {
        // we are always prioritising responses over requests so when we execute
        // a request, there should not be any outstanding responses.
        if self.outstanding_response.is_some() {
            fatal!(
                self.log,
                "[EXC-BUG] Prioritising responses invariant failed. Handling a request when outstanding responses exist."
            );
        }

        let canister_id = request.receiver;
        // As we do not support loops in the call graph, the canister that we
        // want to execute a request on should not already be loaded.
        if self.call_stack.contains_key(&canister_id) {
            error!(self.log, "[EXC-BUG] The canister that we want to execute a request on should not already be loaded.");
        }

        let canister = match self.state.get_active_canister(&request.receiver) {
            Ok(canister) => canister,
            Err(err) => {
                let payload = Payload::Reject(RejectContext::from(err));
                self.outstanding_response = Some(generate_response(request, payload));
                return None;
            }
        };

        let call_origin = CallOrigin::CanisterQuery(request.sender, request.sender_reply_callback);

        let method = {
            let method = WasmMethod::CompositeQuery(request.method_name.clone());
            match validate_method(&method, &canister) {
                Ok(_) => method,
                Err(_) => WasmMethod::Query(request.method_name.clone()),
            }
        };

        let (mut canister, result) = self.execute_query(
            canister,
            method,
            request.method_payload.as_slice(),
            NonReplicatedQueryKind::Stateful { call_origin },
            measurement_scope,
        );

        match result {
            // Execution of the message failed. We do not need to bother with
            // any outstanding requests and we can return a response.
            Err(err) => {
                let payload = Payload::Reject(RejectContext::from(err));
                let response = generate_response(request, payload);
                self.outstanding_response = Some(response);
                None
            }

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
                        self.outstanding_response = Some(generate_response(request, payload));
                        None
                    }
                    None => {
                        let r = self.enqueue_requests(&mut canister);
                        match r {
                            // The canister did not produce a response and did not
                            // produce any outgoing requests. So produce a "did not
                            // reply" response on its behalf.
                            EnqueueRequestsResult::NoMessages => {
                                let error_msg =
                                    format!("Canister {} did not reply", request.receiver);
                                let payload = Payload::Reject(RejectContext::new(
                                    RejectCode::CanisterError,
                                    error_msg,
                                ));
                                self.outstanding_response =
                                    Some(generate_response(request, payload));
                                None
                            }
                            EnqueueRequestsResult::MessagesEnqueued => {
                                self.call_stack.insert(canister.canister_id(), canister);
                                None
                            }
                            _ => map_enqueue_error_to_user(r),
                        }
                    }
                }
            }
        }
    }

    /// Handles results from executing a response on a canister where the sender
    /// of the request was an end-user. This means that this is the very first
    /// canister in the inter-canister query call graph hence if it produces a
    /// response, it can be returned and the rest of the call graph abandoned.
    fn handle_response_with_query_origin(
        &mut self,
        mut canister: CanisterState,
        action: CallContextAction,
    ) -> Option<Result<WasmResult, UserError>> {
        let canister_id = canister.canister_id();

        use CallContextAction::*;
        match action {
            Reply { payload, refund } => {
                if !refund.is_zero() {
                    warn!(
                        self.log,
                        "[EXC-BUG] No cycles are refunded in a response to a query call."
                    );
                }
                Some(Ok(WasmResult::Reply(payload)))
            }
            Reject { payload, refund } => {
                if !refund.is_zero() {
                    warn!(
                        self.log,
                        "[EXC-BUG] No cycles are refunded in a response to a query call."
                    );
                }
                Some(Ok(WasmResult::Reject(payload)))
            }
            NoResponse { refund } => {
                if !refund.is_zero() {
                    warn!(
                        self.log,
                        "[EXC-BUG] No cycles are refunded in a response to a query call."
                    );
                }
                Some(Err(UserError::new(
                    ErrorCode::CanisterDidNotReply,
                    format!("Canister {} did not produce a response", canister_id),
                )))
            }
            Fail { error, refund } => {
                if !refund.is_zero() {
                    warn!(
                        self.log,
                        "[EXC-BUG] No cycles are refunded in a response to a query call."
                    );
                }
                Some(Err(error.into_user_error(&canister.canister_id())))
            }
            // No response available and there are still outstanding
            // callbacks.  Enqueue any produced requests and continue
            // processing the query context.
            NotYetResponded => {
                let r = self.enqueue_requests(&mut canister);
                match r {
                    EnqueueRequestsResult::NoMessages | EnqueueRequestsResult::MessagesEnqueued => {
                        self.call_stack.insert(canister.canister_id(), canister);
                        None
                    }
                    _ => map_enqueue_error_to_user(r).map(|s| Err(s)),
                }
            }
            // This state indicates that the canister produced a
            // response or reject earlier and we continued to keep
            // executing it.  This should not happen as once the
            // canister has produced a response, we drop its state and
            // do not process further messages on it.
            AlreadyResponded => fatal!(
                self.log,
                "Canister {}: Should not be possible to keep executing after producing a response",
                canister_id
            ),
        }
    }

    // Handles execution results for canister where the sender of the request is
    // a canister. Any produced response must be enqueued for further handling.
    fn handle_response_with_canister_origin(
        &mut self,
        mut canister: CanisterState,
        originator: CanisterId,
        callback_id: CallbackId,
        action: CallContextAction,
    ) -> Option<Result<WasmResult, UserError>> {
        let canister_id = canister.canister_id();
        let logger = self.log;

        // A helper function to produce and enqueue `Response`s from
        // common fields.
        let mut enqueue_response = |payload: Payload| {
            let response = Response {
                originator,
                respondent: canister_id,
                originator_reply_callback: callback_id,
                response_payload: payload,
                refund: Cycles::zero(),
            };
            self.outstanding_response = Some(response);
        };

        use CallContextAction::*;
        match action {
            Reply { payload, refund } => {
                if !refund.is_zero() {
                    warn!(
                        logger,
                        "[EXC-BUG] No cycles are refunded in a response to a query call."
                    );
                }
                enqueue_response(Payload::Data(payload));
                // The canister has produced a response so remove any other
                // requests that it may have produced to minimize unnecessary
                // work.
                self.outstanding_requests
                    .retain(|request| request.sender != canister_id);
                None
            }

            Reject { payload, refund } => {
                if !refund.is_zero() {
                    warn!(
                        logger,
                        "[EXC-BUG] No cycles are refunded in a response to a query call."
                    );
                }
                enqueue_response(Payload::Reject(RejectContext::new(
                    RejectCode::CanisterReject,
                    payload,
                )));
                // The canister has produced a response so remove any other
                // requests that it may have produced to minimize unnecessary
                // work.
                self.outstanding_requests
                    .retain(|request| request.sender != canister_id);
                None
            }

            NoResponse { refund } => {
                if !refund.is_zero() {
                    warn!(
                        logger,
                        "[EXC-BUG] No cycles are refunded in a response to a query call."
                    );
                }
                enqueue_response(Payload::Reject(RejectContext::new(
                    RejectCode::CanisterError,
                    "Canister did not reply".to_string(),
                )));
                None
            }

            Fail { error, refund } => {
                if !refund.is_zero() {
                    warn!(
                        logger,
                        "[EXC-BUG] No cycles are refunded in a response to a query call."
                    );
                }
                let user_error = error.into_user_error(&canister.canister_id());
                enqueue_response(Payload::Reject(RejectContext::from(user_error)));
                None
            }

            // No response available and there are still outstanding
            // callbacks so enqueue any produced requests and continue
            // processing the query context.
            NotYetResponded => {
                let r = self.enqueue_requests(&mut canister);
                match r {
                    EnqueueRequestsResult::NoMessages | EnqueueRequestsResult::MessagesEnqueued => {
                        self.call_stack.insert(canister.canister_id(), canister);
                        None
                    }
                    _ => map_enqueue_error_to_user(r).map(|s| Err(s)),
                }
            }

            // This state indicates that the canister produced a
            // response or reject earlier and we continued to keep
            // executing it.  This should not happen as once the
            // canister has produced a response, we drop its state and
            // do not process further messages on it.
            AlreadyResponded => fatal!(
                self.log,
                "Canister {}: Should not be possible to keep executing after producing a response",
                canister.canister_id()
            ),
        }
    }

    // Executes a query response sent from a canister to another canister.  If
    // executing the response produces another response that terminates the
    // query context, it is returned; otherwise, None is returned.  Any other
    // intermediate requests or response are enqueued by the function.
    fn handle_response(
        &mut self,
        response: Response,
        measurement_scope: &MeasurementScope,
    ) -> Option<Result<WasmResult, UserError>> {
        if self.outstanding_response.is_some() {
            fatal!(
                self.log,
                "[EXC-BUG] Prioritising responses invariant failed. There will never be more than one outstanding response."
            );
        }

        let canister_id = response.originator;
        // As we are executing a response, we must have executed a request on
        // the canister before and must have stored its state so the following
        // should not fail.
        let canister = self.call_stack.remove(&canister_id).unwrap_or_else(|| {
            fatal!(
                self.log,
                "Expected to find canister {} in the cache",
                canister_id
            )
        });

        let (canister, call_origin, action) =
            self.execute_callback(canister, response, measurement_scope);

        match call_origin {
            CallOrigin::Query(_) => self.handle_response_with_query_origin(canister, action),

            CallOrigin::CanisterUpdate(_, _)
            | CallOrigin::Ingress(_, _)
            | CallOrigin::SystemTask => fatal!(
                self.log,
                "Canister {}: query path should not have created a callback with an update origin",
                canister_id
            ),

            CallOrigin::CanisterQuery(originator, callback_id) => {
                self.handle_response_with_canister_origin(canister, originator, callback_id, action)
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
            compute_allocation: canister.scheduler_state.compute_allocation,
            subnet_type: self.own_subnet_type,
            execution_mode: ExecutionMode::NonReplicated,
        }
    }
}
