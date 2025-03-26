use std::{collections::VecDeque, sync::Arc};

use ic_error_types::{ErrorCode, UserError};
use ic_replicated_state::{CallOrigin, CanisterState};
use ic_types::messages::Request;

use crate::metrics::MeasurementScope;

use super::query_context::{ExecutionResult, QueryContext, QueryResponse};

/// Represents a node in the query call graph together with the edges that are
/// not visited yet. Specifically, the canister state and the call origin
/// represent the node. The outgoing requests represent the edges.
struct PendingCall(CanisterState, CallOrigin, VecDeque<Arc<Request>>);

/// Performs depth-first search (DFS) traversal of the query call graph of the
/// given query calls (requests) of the given call context. A call context is
/// specified by a canister and a call origin.
///
/// Nodes in the query call graph are call contexts. Edges are outgoing query
/// calls (requests).
///
/// A successful execution of a query produces:
/// - an optional response.
/// - a possibly empty set of outgoing query calls.
///
/// A failed execution of a query produces a synthetic reject response that
/// contains a description of the execution error.
///
/// If a response is produced, then the DFS traversal takes a shortcut and
/// discards the sub-graph of that node. This optimization is valid because
/// evaluation of the sub-graph cannot change the response.
///
/// If there is no response, then the DFS traversal recurses into the outgoing
/// query calls sequentially one by one. On each response from a query call, the
/// response callback of the current call context is executed. Similar to a
/// query execution, the response callback execution may produce an optional
/// response and a possibly empty set of outgoing query calls.
///
/// In order to bound the resource usage, the DFS traversal has two limits:
/// - the limit on the depth of the call graph, which is the maximum number of
///   nested query calls.
/// - the limit on the total number of executed instructions by all queries and
///   response callbacks.
///
/// A note on re-entrancy: currently re-entrant query calls are not allowed.
/// In other words, if a canister is in the call stack, then an attempt to make a
/// new query call to that canister will result in an error. This restriction
/// will be lifted soon.
pub(super) fn evaluate_query_call_graph(
    query_context: &mut QueryContext,
    canister: CanisterState,
    call_origin: CallOrigin,
    requests: VecDeque<Arc<Request>>,
    max_query_call_graph_depth: usize,
    measurement_scope: &MeasurementScope,
) -> QueryResponse {
    // The nodes of the query call graph that are being visited.
    // Invariant: `call_stack[i+1]` corresponds to a query call made by `call_stack[i]`.
    let mut call_stack: Vec<PendingCall> = vec![PendingCall(canister, call_origin, requests)];

    // The result of the most recently visited node (i.e. the last node popped
    // from the call stack).
    let mut callee_result: Option<QueryResponse> = None;

    while let Some(PendingCall(canister, call_origin, mut requests)) = call_stack.pop() {
        // Loop invariant: `callee_result` is a result of a query call made by
        // `(canister, call_origin)`.

        // First check the DFS limits.
        if call_stack.len() >= max_query_call_graph_depth {
            let error = UserError::new(
                ErrorCode::QueryCallGraphTooDeep,
                "Composite query calls exceeded the maximum call depth.",
            );
            return QueryResponse::UserError(error);
        }
        if query_context.instruction_limit_reached() {
            let error = UserError::new(
                ErrorCode::QueryCallGraphTotalInstructionLimitExceeded,
                "Composite query calls exceeded the instruction limit.",
            );
            return QueryResponse::UserError(error);
        }
        if query_context.time_limit_reached() {
            let error = UserError::new(
                ErrorCode::QueryTimeLimitExceeded,
                "Composite query call exceeded the time limit.",
            );
            return QueryResponse::UserError(error);
        }

        // Process the result of the previously visited node.
        match callee_result.take() {
            Some(QueryResponse::UserResponse(_)) | Some(QueryResponse::UserError(_)) => {
                // This case cannot happen due to the loop invariant because we know that
                // the call context `(canister, call_origin)` has called the query that
                // produced `callee_result`, so it must be a canister response.
                unreachable!("Unexpected user response for canister query call.");
            }
            Some(QueryResponse::CanisterResponse(response)) => {
                // This catches both responses from `handle_response()` and `handle_request()`.
                query_context.accumulate_transient_errors_from_payload(&response.response_payload);
                match query_context.handle_response(canister, response, requests, measurement_scope)
                {
                    ExecutionResult::Calls(canister, used_call_origin, requests) => {
                        debug_assert_eq!(call_origin, used_call_origin);
                        call_stack.push(PendingCall(canister, call_origin, requests));
                    }
                    ExecutionResult::Response(result) => {
                        callee_result = Some(result);
                    }
                    ExecutionResult::SystemError(err) => {
                        return QueryResponse::UserError(err);
                    }
                }
            }
            // There is no response, so we need to execute the next outgoing
            // request and visit its sub-graph.
            None => match requests.pop_front() {
                Some(request) => {
                    // Push the current node (caller) onto the stack before
                    // executing the request (callee). This is needed to
                    // properly handle the response of the callee.
                    call_stack.push(PendingCall(canister, call_origin, requests));

                    match query_context.handle_request(request, measurement_scope) {
                        ExecutionResult::Calls(canister, call_origin, requests) => {
                            call_stack.push(PendingCall(canister, call_origin, requests));
                        }
                        ExecutionResult::Response(result) => {
                            callee_result = Some(result);
                        }
                        ExecutionResult::SystemError(err) => {
                            return QueryResponse::UserError(err);
                        }
                    }
                }
                None => {
                    // Produce a synthetic reject response because we have
                    // processed all outgoing requests of the current node
                    // without a response.
                    callee_result =
                        Some(query_context.empty_response(canister.canister_id(), call_origin));
                }
            },
        }
    }

    // Each iteration of the loop above either pushes an entry onto the call
    // stack or sets the callee result. At this point the call stack is empty,
    // so the callee result must have been set and `unwrap` is safe here.
    callee_result.unwrap()
}
