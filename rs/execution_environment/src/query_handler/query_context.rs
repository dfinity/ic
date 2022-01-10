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

use super::query_allocations::QueryAllocationsUsed;
use crate::{
    hypervisor::Hypervisor,
    metrics::{MeasurementScope, QueryHandlerMetrics},
    QueryExecutionType,
};
use ic_base_types::NumBytes;
use ic_interfaces::execution_environment::{
    ExecutionMode, ExecutionParameters, HypervisorError, HypervisorResult, SubnetAvailableMemory,
};
use ic_logger::{debug, error, fatal, warn, ReplicaLogger};
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CallContextAction, CallOrigin, CanisterState, ReplicatedState};
use ic_system_api::NonReplicatedQueryKind;
use ic_types::{
    ingress::WasmResult,
    messages::{
        CallContextId, CallbackId, Payload, RejectContext, Request, RequestOrResponse, Response,
        UserQuery,
    },
    user_error::{ErrorCode, RejectCode, UserError},
    CanisterId, Cycles, NumInstructions, NumMessages, PrincipalId, QueryAllocation, SubnetId,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

const ENABLE_QUERY_OPTIMIZATION: bool = true;

const LOOP_DETECTED_ERROR_MSG: &str =
    "Loop detected.  MVP inter-canister queries do not support loops.";

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
}

// A handy function to create a `Response` using parameters from the `Request`
fn generate_response(request: Request, payload: Payload) -> Response {
    Response {
        originator: request.sender,
        respondent: request.receiver,
        originator_reply_callback: request.sender_reply_callback,
        response_payload: payload,
        refund: Cycles::zero(),
    }
}

/// Handles running a single UserQuery to completion by maintaining the call
/// graph of the query execution between canisters.
pub(super) struct QueryContext<'a> {
    log: &'a ReplicaLogger,
    hypervisor: &'a Hypervisor,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    // The state against which all queries in the context will be executed.
    state: Arc<ReplicatedState>,
    routing_table: Arc<RoutingTable>,
    data_certificate: Vec<u8>,
    canisters: BTreeMap<CanisterId, CanisterState>,
    outstanding_requests: Vec<Request>,
    // Response (if available) waiting to be executed. We always process
    // responses first if one is available hence, there will never be more than
    // one outstanding response.
    outstanding_response: Option<Response>,
    query_allocations_used: Arc<RwLock<QueryAllocationsUsed>>,
    subnet_available_memory: SubnetAvailableMemory,
    max_canister_memory_size: NumBytes,
    max_instructions_per_message: NumInstructions,
}

impl<'a> QueryContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        log: &'a ReplicaLogger,
        hypervisor: &'a Hypervisor,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        state: Arc<ReplicatedState>,
        data_certificate: Vec<u8>,
        query_allocations_used: Arc<RwLock<QueryAllocationsUsed>>,
        subnet_available_memory: SubnetAvailableMemory,
        max_canister_memory_size: NumBytes,
        max_instructions_per_message: NumInstructions,
    ) -> Self {
        let routing_table = Arc::clone(&state.metadata.network_topology.routing_table);
        Self {
            log,
            hypervisor,
            own_subnet_id,
            own_subnet_type,
            canisters: BTreeMap::new(),
            outstanding_requests: Vec::new(),
            outstanding_response: None,
            state,
            data_certificate,
            query_allocations_used,
            routing_table,
            subnet_available_memory,
            max_canister_memory_size,
            max_instructions_per_message,
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
        measurement_scope: &MeasurementScope<'b>,
    ) -> Result<WasmResult, UserError> {
        let canister_id = query.receiver;
        debug!(self.log, "Executing query for {}", canister_id);
        let old_canister = self.get_canister_from_state(&canister_id)?;
        let call_origin = CallOrigin::Query(query.source);
        // EXC-500: Contain the usage of inter-canister query calls to the subnets
        // that currently use it until we decide on the future of this feature and
        // get a proper spec for it.
        let cross_canister_query_calls_enabled = self.own_subnet_type == SubnetType::System
            || self.own_subnet_type == SubnetType::VerifiedApplication;
        let query_kind = if ENABLE_QUERY_OPTIMIZATION || !cross_canister_query_calls_enabled {
            NonReplicatedQueryKind::Pure
        } else {
            NonReplicatedQueryKind::Stateful
        };

        // First try to run the query as `Pure` assuming that it is not going to
        // call other queries. `Pure` queries are about 2x faster than `Stateful`.
        let (mut canister, mut result) = {
            let measurement_scope =
                MeasurementScope::nested(&metrics.query_initial_call, measurement_scope);
            self.execute_query(
                old_canister,
                call_origin.clone(),
                query.method_name.as_str(),
                query.method_payload.as_slice(),
                query.source.get(),
                query_kind.clone(),
                &measurement_scope,
            )
        };

        // An attempt to call another query will result in `ContractViolation`.
        // If that's the case then retry query execution as `Stateful`.
        if query_kind == NonReplicatedQueryKind::Pure && cross_canister_query_calls_enabled {
            if let Err(HypervisorError::ContractViolation(..)) = result {
                let measurement_scope =
                    MeasurementScope::nested(&metrics.query_retry_call, measurement_scope);
                let old_canister = self.get_canister_from_state(&canister_id)?;
                let (new_canister, new_result) = self.execute_query(
                    old_canister,
                    call_origin,
                    query.method_name.as_str(),
                    query.method_payload.as_slice(),
                    query.source.get(),
                    NonReplicatedQueryKind::Stateful,
                    &measurement_scope,
                );
                canister = new_canister;
                result = new_result;
            };
        }

        match result {
            // If the canister produced a result or if execution failed then it
            // does not matter whether or not it produced any outgoing requests.
            // We can simply return the response we have.
            Err(err) => Err(err.into_user_error(&canister_id)),
            Ok(Some(wasm_result)) => Ok(wasm_result),

            Ok(None) => match self.enqueue_requests(&mut canister) {
                EnqueueRequestsResult::LoopDetected => Err(UserError::new(
                    ErrorCode::InterCanisterQueryLoopDetected,
                    LOOP_DETECTED_ERROR_MSG.to_string(),
                )),

                // The canister did not produce a response and did not enqueue
                // any requests either. As this is the very first canister in
                // the call graph, we can declare that the query execution
                // finished without producing an output.
                EnqueueRequestsResult::NoMessages => Err(UserError::new(
                    ErrorCode::CanisterDidNotReply,
                    format!(
                        "Canister {} did not reply to the call",
                        canister.canister_id()
                    ),
                )),

                EnqueueRequestsResult::MessagesEnqueued => {
                    self.canisters.insert(canister.canister_id(), canister);
                    self.run_loop(canister_id, metrics, measurement_scope)
                }
            },
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

    // A helper function to lookup the CallContextManager and create a new
    // CallContext in it.
    fn new_call_context(
        &self,
        canister: &mut CanisterState,
        call_origin: CallOrigin,
    ) -> CallContextId {
        let canister_id = canister.canister_id();
        // The `unwrap()` here is safe as we ensured that the canister has a call
        // context manager in `get_canister_from_state()`.
        let manager = canister
            .system_state
            .call_context_manager_mut()
            .unwrap_or_else(|| {
                fatal!(
                    self.log,
                    "Canister {}: Expected to find a CallContextManager",
                    canister_id
                )
            });
        manager.new_call_context(call_origin, Cycles::from(0))
    }

    // A helper function that enqueues any outgoing requests that the canister
    // has.
    fn enqueue_requests(&mut self, canister: &mut CanisterState) -> EnqueueRequestsResult {
        let mut sent_messages = false;
        let canister_id = canister.canister_id();

        let outgoing_messages: Vec<_> =
            canister.output_into_iter().map(|(_, _, msg)| msg).collect();
        let call_context_manager = canister
            .system_state
            .call_context_manager_mut()
            .unwrap_or_else(|| {
                fatal!(
                    self.log,
                    "Canister {}: Expected to find a CallContextmanager",
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
                        | CallOrigin::Heartbeat
                        | CallOrigin::Ingress(_, _) => continue,

                        // We never serialize messages of such types in the
                        // canister's state so these must have been produced by
                        // this module.
                        CallOrigin::Query(_) | CallOrigin::CanisterQuery(_, _) => {}
                    }

                    if msg.receiver == canister_id || self.canisters.contains_key(&msg.receiver) {
                        // Call graph loop detector. There is already a canister
                        // in the call graph that is waiting for some responses
                        // to come back and this canister is trying to send it
                        // messages. The MVP inter-canister queries
                        // implementation does not support loops.
                        return EnqueueRequestsResult::LoopDetected;
                    }
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
        mut canister: CanisterState,
        call_origin: CallOrigin,
        method_name: &str,
        method_payload: &[u8],
        source: PrincipalId,
        query_kind: NonReplicatedQueryKind,
        measurement_scope: &MeasurementScope,
    ) -> (CanisterState, HypervisorResult<Option<WasmResult>>) {
        let call_context_id = self.new_call_context(&mut canister, call_origin);
        let instruction_limit = self.max_instructions_per_message.min(
            self.query_allocations_used
                .write()
                .unwrap()
                .allocation_before_execution(&canister)
                .into(),
        );
        let execution_parameters = self.execution_parameters(&canister, instruction_limit);
        let (canister, instructions_left, result) = self.hypervisor.execute_query(
            QueryExecutionType::NonReplicated {
                call_context_id,
                routing_table: Arc::clone(&self.routing_table),
                query_kind,
            },
            method_name,
            method_payload,
            source,
            canister,
            Some(self.data_certificate.clone()),
            self.state.time(),
            execution_parameters,
        );
        let instructions_executed = instruction_limit - instructions_left;
        measurement_scope.add(instructions_executed, NumMessages::from(1));
        self.query_allocations_used
            .write()
            .unwrap()
            .update_allocation_after_execution(
                &canister,
                QueryAllocation::from(instructions_executed),
            );
        (canister, result)
    }

    fn execute_callback(
        &mut self,
        mut canister: CanisterState,
        response: Response,
        measurement_scope: &MeasurementScope,
    ) -> (
        CanisterState,
        CallContextId,
        CallOrigin,
        HypervisorResult<Option<WasmResult>>,
    ) {
        let canister_id = canister.canister_id();
        // As we have executed a request on the canister earlier, it must
        // contain a call context manager hence the following should not fail.
        let call_context_manager = canister
            .system_state
            .call_context_manager_mut()
            .unwrap_or_else(|| {
                fatal!(
                    self.log,
                    "Canister {}: Expected to find a CallContextmanager",
                    canister_id
                )
            });

        // Responses here are only those triggered by the Request that we sent,
        // so we are sure these unwraps are safe.
        let callback = call_context_manager
            .unregister_callback(response.originator_reply_callback)
            .unwrap();
        let call_origin = call_context_manager
            .call_origin(callback.call_context_id)
            .unwrap();
        let call_context_id = callback.call_context_id;

        // We do not support inter canister queries between subnets so
        // we can use nominal values for these fields to satisfy the
        // constraints.
        let mut subnet_records = BTreeMap::new();
        subnet_records.insert(self.own_subnet_id, self.own_subnet_type);
        let subnet_records = Arc::new(subnet_records);

        let instruction_limit = self.max_instructions_per_message.min(
            self.query_allocations_used
                .write()
                .unwrap()
                .allocation_before_execution(&canister)
                .into(),
        );
        let execution_parameters = self.execution_parameters(&canister, instruction_limit);
        let (canister, instructions_left, _heap_delta, execution_result) =
            self.hypervisor.execute_callback(
                canister,
                &call_origin,
                callback,
                response.response_payload,
                // No cycles are refunded in a response to a query call.
                Cycles::from(0),
                self.state.time(),
                Arc::clone(&self.routing_table),
                subnet_records,
                execution_parameters,
            );
        let instructions_executed = instruction_limit - instructions_left;
        measurement_scope.add(instructions_executed, NumMessages::from(1));
        self.query_allocations_used
            .write()
            .unwrap()
            .update_allocation_after_execution(
                &canister,
                QueryAllocation::from(instructions_executed),
            );
        (canister, call_context_id, call_origin, execution_result)
    }

    // Loads a fresh version of the canister from the state and ensures that it
    // has a call context manager i.e. it is not stopped.
    fn get_canister_from_state(
        &self,
        canister_id: &CanisterId,
    ) -> Result<CanisterState, UserError> {
        let canister = self.state.canister_state(canister_id).ok_or_else(|| {
            UserError::new(
                ErrorCode::CanisterNotFound,
                format!("Canister {} not found", canister_id),
            )
        })?;

        if canister.system_state.call_context_manager().is_none() {
            Err(UserError::new(
                ErrorCode::CanisterStopped,
                format!(
                    "Canister {} is stopped and therefore does not have a CallContextManager",
                    canister.canister_id()
                ),
            ))
        } else {
            Ok(canister.clone())
        }
    }

    // Executes a query sent from one canister to another. If a loop in the call
    // graph is detected, then an error is returned.
    fn handle_request(
        &mut self,
        request: Request,
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
        if self.canisters.contains_key(&canister_id) {
            error!(self.log, "[EXC-BUG] The canister that we want to execute a request on should not already be loaded.");
        }

        let canister = match self.get_canister_from_state(&request.receiver) {
            Ok(canister) => canister,
            Err(err) => {
                let payload = Payload::Reject(RejectContext::from(err));
                self.outstanding_response = Some(generate_response(request, payload));
                return None;
            }
        };

        let call_origin = CallOrigin::CanisterQuery(request.sender, request.sender_reply_callback);
        let (mut canister, result) = self.execute_query(
            canister,
            call_origin,
            request.method_name.as_str(),
            request.method_payload.as_slice(),
            request.sender.get(),
            NonReplicatedQueryKind::Stateful,
            measurement_scope,
        );

        match result {
            // Execution of the message failed. We do not need to bother with
            // any outstanding requests and we can return a response.
            Err(err) => {
                let err = err.into_user_error(&request.receiver);
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
                    None => match self.enqueue_requests(&mut canister) {
                        EnqueueRequestsResult::LoopDetected => Some(UserError::new(
                            ErrorCode::InterCanisterQueryLoopDetected,
                            LOOP_DETECTED_ERROR_MSG.to_string(),
                        )),

                        // The canister did not produce a response and did not
                        // produce any outgoing requests. So produce a "did not
                        // reply" response on its behalf.
                        EnqueueRequestsResult::NoMessages => {
                            let error_msg = format!("Canister {} did not reply", request.receiver);
                            let payload = Payload::Reject(RejectContext::new(
                                RejectCode::CanisterReject,
                                error_msg,
                            ));
                            self.outstanding_response = Some(generate_response(request, payload));
                            None
                        }

                        // Canister did not produce a response but did produce
                        // outgoing request(s). Save the canister for when the
                        // response(s) come back in.
                        EnqueueRequestsResult::MessagesEnqueued => {
                            self.canisters.insert(canister.canister_id(), canister);
                            None
                        }
                    },
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
        call_context_id: CallContextId,
        execution_result: Result<Option<WasmResult>, HypervisorError>,
    ) -> Option<Result<WasmResult, UserError>> {
        let canister_id = canister.canister_id();
        // As we have executed a request on the canister earlier, it must
        // contain a call context manager hence the following should not fail.
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

        use CallContextAction::*;
        match call_context_manager.on_canister_result(call_context_id, execution_result) {
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
            NotYetResponded => match self.enqueue_requests(&mut canister) {
                EnqueueRequestsResult::LoopDetected => Some(Err(UserError::new(
                    ErrorCode::InterCanisterQueryLoopDetected,
                    LOOP_DETECTED_ERROR_MSG.to_string(),
                ))),
                EnqueueRequestsResult::NoMessages | EnqueueRequestsResult::MessagesEnqueued => {
                    self.canisters.insert(canister.canister_id(), canister);
                    None
                }
            },
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
        call_context_id: CallContextId,
        execution_result: Result<Option<WasmResult>, HypervisorError>,
    ) -> Option<Result<WasmResult, UserError>> {
        let canister_id = canister.canister_id();
        // As we have executed a request on the canister earlier, it must
        // contain a call context manager hence the following should not fail.
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
        match call_context_manager.on_canister_result(call_context_id, execution_result) {
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
                    RejectCode::CanisterReject,
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
            NotYetResponded => match self.enqueue_requests(&mut canister) {
                EnqueueRequestsResult::LoopDetected => Some(Err(UserError::new(
                    ErrorCode::InterCanisterQueryLoopDetected,
                    LOOP_DETECTED_ERROR_MSG.to_string(),
                ))),
                EnqueueRequestsResult::NoMessages | EnqueueRequestsResult::MessagesEnqueued => {
                    self.canisters.insert(canister.canister_id(), canister);
                    None
                }
            },

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
        let canister = self.canisters.remove(&canister_id).unwrap_or_else(|| {
            fatal!(
                self.log,
                "Expected to find canister {} in the cache",
                canister_id
            )
        });

        let (canister, call_context_id, call_origin, execution_result) =
            self.execute_callback(canister, response, measurement_scope);

        match call_origin {
            CallOrigin::Query(_) => {
                self.handle_response_with_query_origin(canister, call_context_id, execution_result)
            }

            CallOrigin::CanisterUpdate(_, _)
            | CallOrigin::Ingress(_, _)
            | CallOrigin::Heartbeat => fatal!(
                self.log,
                "Canister {}: query path should not have created a callback with an update origin",
                canister_id
            ),

            CallOrigin::CanisterQuery(originator, callback_id) => self
                .handle_response_with_canister_origin(
                    canister,
                    originator,
                    callback_id,
                    call_context_id,
                    execution_result,
                ),
        }
    }

    fn execution_parameters(
        &self,
        canister: &CanisterState,
        instruction_limit: NumInstructions,
    ) -> ExecutionParameters {
        ExecutionParameters {
            instruction_limit,
            canister_memory_limit: canister.memory_limit(self.max_canister_memory_size),
            subnet_available_memory: self.subnet_available_memory.clone(),
            compute_allocation: canister.scheduler_state.compute_allocation,
            subnet_type: self.own_subnet_type,
            execution_mode: ExecutionMode::NonReplicated,
        }
    }
}
