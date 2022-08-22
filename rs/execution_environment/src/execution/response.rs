// This module defines how response callbacks are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#_callback_invocation.

use crate::execution_environment::{
    ExecuteMessageResult, ExecutionResponse, PausedExecution, RoundContext, RoundLimits,
};
use ic_embedders::wasm_executor::{PausedWasmExecution, WasmExecutionResult};
use ic_interfaces::messages::CanisterInputMessage;
use ic_replicated_state::{CallOrigin, CanisterState};
use ic_types::ingress::WasmResult;
use ic_types::messages::{CallContextId, CallbackId, Payload, Response};
use ic_types::{NumBytes, NumInstructions, Time};

use crate::execution::common;
use crate::execution::common::{
    action_to_response, apply_canister_state_changes, update_round_limits,
};
use ic_interfaces::execution_environment::HypervisorError;
use ic_logger::error;
use ic_sys::PAGE_SIZE;
use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::methods::{Callback, FuncRef, WasmClosure};
use ic_types::Cycles;
use prometheus::IntCounter;
use std::sync::Arc;

/// The algorithm for executing the response callback works with two canisters:
/// - `clean_canister`: the canister state from the current replicated state
///    without any changes by the ongoing execution.
/// - `executing_canister`: the canister state that contains changes done by
///    the ongoing execution. This state is re-created in each entry point of
///    the algorithm by applying the state changes to `clean_canister`.
///
/// Summary of the algorithm:
/// 1. The main entry point is `execute_response()` that takes `clean_canister`
///    as input. The function looks up the callback/call context and computes
///    the refund cycles. It remembers the refund cycles as the initial state
///    changes because they need to be applied to `clean_canister` in each entry
///    point: `execute_response()`, `PausedResponseExecution::resume()`
///    and `PausedCleanupExecution::resume()`.
///
/// 2. The next step is to execute the response callback, which may become
///    paused if it exceeds the slice limit. In that case the function
///    returns the unchanged `clean_canister` along with the paused execution.
///
/// 3. If the response callback execution fails, then the algorithm runs the
///    cleanup callback if it exists. That execution may also become paused
///    if it exceeds the slice limit. In that case the function returns the
///    unchanged `clean_canister` along with the paused execution.
///
/// 4. The final step is to unregister the callback and the call context if
///    needed and to refund the remaining execution cycles.
///
/// ```text
/// [begin]
///   │
///   ▼
/// [look up callback/call context and prepare initial state changes]
///   │
///   │
///   │                   exceeded slice
///   ▼                  instruction limit
/// [execute response] ───────────────────────► PausedResponseExecution
///   │                                          │    │         ▲
///   │                                          │    └─────────┘
///   │            finished execution            │    exceeded slice
///   │◄─────────────────────────────────────────┘   instruction limit
///   │
///   │
///   │                                        exceeded slice
///   ▼      on error                        instruction limit
/// [error?]───────────►[execute cleanup()]───────────────────► PausedCleanupExecution
///   │                                                          │    │        ▲
///   │                                                          │    └────────┘
///   │             finished execution                           │   exceeded slice
///   │◄─────────────────────────────────────────────────────────┘  instruction limit
///   │
/// [unregister callback, refund execution cycles]
///   │
///   ▼
/// [end]
///```

/// The initial state changes that need to be applied to the clean canister
/// state before executing any Wasm code.
#[derive(Clone, Debug)]
struct InitialStateChanges {
    refund_for_sent_cycles: Cycles,
    refund_for_response_transmission: Cycles,
}

impl InitialStateChanges {
    fn new(
        response: &Response,
        callback: &Callback,
        error_counter: &IntCounter,
        round: &RoundContext,
    ) -> Self {
        // Canister A sends a request to canister B with some cycles.
        // Canister B can accept a subset of the cycles in the request.
        // The unaccepted cycles are returned to A in the response.
        //
        // Therefore, the number of cycles in the response should always
        // be <= to the cycles in the request. If this is not the case,
        // then that indicates (potential malicious) faults.
        let refund_for_sent_cycles = if response.refund > callback.cycles_sent {
            error!(
            round.log,
            "[EXC-BUG] Canister got a response with too many cycles.  originator {} respondent {} max cycles expected {} got {}.",
            response.originator,
            response.respondent,
            callback.cycles_sent,
            response.refund,
        );
            callback.cycles_sent
        } else {
            response.refund
        };

        // The canister that sends a request must also pay the fee for
        // the transmission of the response. As we do not know how big
        // the response might be, we reserve cycles for the largest
        // possible response when the request is being sent. Now that we
        // have received the response, we can refund the cycles based on
        // the actual size of the response.
        let refund_for_response_transmission = round
            .cycles_account_manager
            .refund_for_response_transmission(round.log, error_counter, response);
        Self {
            refund_for_sent_cycles,
            refund_for_response_transmission,
        }
    }

    // Clones the given canister and applies the initial state changes that are done
    // before executing any Wasm code.
    fn apply(&self, clean_canister: &CanisterState, round: &RoundContext) -> CanisterState {
        let mut executing_canister = clean_canister.clone();
        round.cycles_account_manager.add_cycles(
            executing_canister.system_state.balance_mut(),
            self.refund_for_sent_cycles,
        );
        // The `refund_cycles()` is similar to `add_cycles()` but it
        // additionally fixes up the cycles-burned metric.
        round.cycles_account_manager.refund_cycles(
            &mut executing_canister.system_state,
            self.refund_for_response_transmission,
        );
        executing_canister
    }
}

/// Context variables that remain the same throughput the entire deterministic
/// time slicing execution of a response.
#[derive(Clone, Debug)]
struct OriginalContext {
    callback: Callback,
    call_context_id: CallContextId,
    callback_id: CallbackId,
    call_origin: CallOrigin,
    time: Time,
    message_instruction_limit: NumInstructions,
    message: Arc<Response>,
    initial_state_changes: InitialStateChanges,
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of a response.
#[derive(Debug)]
struct PausedResponseExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    execution_parameters: ExecutionParameters,
    original: OriginalContext,
}

impl PausedExecution for PausedResponseExecution {
    /// Resumes the response callback execution taking the current clean
    /// canister state as input. There are two outcomes:
    /// - execution is paused again: in this case the function returns the
    ///   unchanged clean canister state along with the paused execution.
    /// - execution finishes: in this case the function applies the initial
    ///   state changes and the state changes from the Wasm execution to the
    ///   clean canister state and proceeds to executing the cleanup callback
    ///   if needed. Note that if execution of the cleanup callback gets paused
    ///   then it will return the clean canister state.
    fn resume(
        self: Box<Self>,
        clean_canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> ExecuteMessageResult {
        // The height of the `clean_canister` state increases with every call of
        // `resume()`. We re-create `executing_canister` based on `clean_state`
        // so that the Wasm state changes are applied to the up-to-date state.
        let executing_canister = self
            .original
            .initial_state_changes
            .apply(&clean_canister, &round);
        let execution_state = executing_canister.execution_state.as_ref().unwrap();
        let result = self.paused_wasm_execution.resume(execution_state);
        process_response_result(
            result,
            clean_canister,
            executing_canister,
            self.execution_parameters,
            self.original,
            round,
            round_limits,
        )
    }

    fn abort(self: Box<Self>) -> CanisterInputMessage {
        self.paused_wasm_execution.abort();
        CanisterInputMessage::Response(self.original.message)
    }
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of a cleanup callback.
#[derive(Debug)]
struct PausedCleanupExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    callback_err: HypervisorError,
    original: OriginalContext,
}

impl PausedExecution for PausedCleanupExecution {
    /// Resumes the cleanup callback execution taking the current clean
    /// canister state as input. There are two outcomes:
    /// - execution is paused again: in this case the function returns the
    ///   unchanged clean canister state along with the paused execution.
    /// - execution finishes: in this case the function applies the initial
    ///   state changes and the state changes from the Wasm execution to the
    ///   clean canister state.
    fn resume(
        self: Box<Self>,
        clean_canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> ExecuteMessageResult {
        // The height of the `clean_canister` state increases with every call of
        // `resume()`. We re-create `executing_canister` based on `clean_state`
        // so that the Wasm state changes are applied to the up-to-date state.
        //
        // Note that we don't apply changes from the response callback execution
        // because the cleanup callback runs only if the response callback fails.
        let executing_canister = self
            .original
            .initial_state_changes
            .apply(&clean_canister, &round);
        let execution_state = executing_canister.execution_state.as_ref().unwrap();
        let result = self.paused_wasm_execution.resume(execution_state);
        process_cleanup_result(
            result,
            clean_canister,
            executing_canister,
            self.callback_err,
            self.original,
            round,
            round_limits,
        )
    }

    fn abort(self: Box<Self>) -> CanisterInputMessage {
        self.paused_wasm_execution.abort();
        CanisterInputMessage::Response(self.original.message)
    }
}

/// Executes the response callback.
///
/// If execution finishes, then the function returns the new canister state.
/// If execution is paused, then the function returns the clean canister state
/// without any changes.
#[allow(clippy::too_many_arguments)]
pub fn execute_response(
    clean_canister: CanisterState,
    response: Arc<Response>,
    time: Time,
    execution_parameters: ExecutionParameters,
    error_counter: &IntCounter,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> ExecuteMessageResult {
    let (callback, callback_id, call_context, call_context_id) =
        match common::get_call_context_and_callback(&clean_canister, &response, round.log) {
            Some(r) => r,
            None => {
                // This case is unreachable because the call context and
                // callback should always exist.
                return ExecuteMessageResult::Finished {
                    canister: clean_canister,
                    heap_delta: NumBytes::from(0),
                    response: ExecutionResponse::Empty,
                };
            }
        };

    let initial_state_changes =
        InitialStateChanges::new(&response, &callback, error_counter, &round);

    let executing_canister = initial_state_changes.apply(&clean_canister, &round);

    let original = OriginalContext {
        callback,
        call_context_id,
        callback_id,
        call_origin: call_context.call_origin().clone(),
        time,
        message_instruction_limit: execution_parameters.instruction_limits.message(),
        message: Arc::clone(&response),
        initial_state_changes,
    };

    // If the call context was deleted (e.g. in uninstall), then do not execute anything.
    if call_context.is_deleted() {
        if !call_context.has_responded() {
            // This case is unreachable because `is_deleted() => has_responded()`
            // is a critical invariant and should hold.
            error!(
                round.log,
                "[EXC-BUG] Canister {} has a deleted context that has not responded",
                executing_canister.system_state.canister_id,
            );
            return ExecuteMessageResult::Finished {
                canister: executing_canister,
                heap_delta: NumBytes::from(0),
                response: ExecutionResponse::Empty,
            };
        }
        // Since the call context has responded, passing `Ok(None)` will produce
        // an empty response and take care of all other bookkeeping.
        let result: Result<Option<WasmResult>, HypervisorError> = Ok(None);
        return early_finish(executing_canister, result, original, round);
    }

    // Validate that the canister has an `ExecutionState`.
    if executing_canister.execution_state.is_none() {
        error!(
                round.log,
                "[EXC-BUG] Canister {} is attempting to execute a response, but the execution state does not exist.",
                executing_canister.system_state.canister_id,
            );
        let result = Err(HypervisorError::WasmModuleNotFound);
        return early_finish(executing_canister, result, original, round);
    }

    let closure = match response.response_payload {
        Payload::Data(_) => original.callback.on_reply.clone(),
        Payload::Reject(_) => original.callback.on_reject.clone(),
    };

    let func_ref = match original.call_origin {
        CallOrigin::Ingress(_, _) | CallOrigin::CanisterUpdate(_, _) | CallOrigin::Heartbeat => {
            FuncRef::UpdateClosure(closure)
        }
        CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => FuncRef::QueryClosure(closure),
    };

    let api_type = match &response.response_payload {
        Payload::Data(payload) => ApiType::reply_callback(
            time,
            payload.to_vec(),
            original.initial_state_changes.refund_for_sent_cycles,
            call_context_id,
            call_context.has_responded(),
            execution_parameters.execution_mode.clone(),
        ),
        Payload::Reject(context) => ApiType::reject_callback(
            time,
            context.clone(),
            original.initial_state_changes.refund_for_sent_cycles,
            call_context_id,
            call_context.has_responded(),
            execution_parameters.execution_mode.clone(),
        ),
    };

    let result = round.hypervisor.execute_dts(
        api_type,
        executing_canister.execution_state.as_ref().unwrap(),
        &executing_canister.system_state,
        executing_canister.memory_usage(round.hypervisor.subnet_type()),
        execution_parameters.clone(),
        func_ref,
        round_limits,
        round.network_topology,
    );

    process_response_result(
        result,
        clean_canister,
        executing_canister,
        execution_parameters,
        original,
        round,
        round_limits,
    )
}

// Helper function for finishing the response execution before calling any Wasm.
fn early_finish(
    mut executing_canister: CanisterState,
    result: Result<Option<WasmResult>, HypervisorError>,
    original: OriginalContext,
    round: RoundContext,
) -> ExecuteMessageResult {
    let action = executing_canister
        .system_state
        .call_context_manager_mut()
        .unwrap()
        .on_canister_result(original.call_context_id, Some(original.callback_id), result);
    let response = action_to_response(
        &executing_canister,
        action,
        original.call_origin,
        original.time,
        round.log,
    );
    round.cycles_account_manager.refund_execution_cycles(
        &mut executing_canister.system_state,
        original.message_instruction_limit,
        original.message_instruction_limit,
    );
    ExecuteMessageResult::Finished {
        canister: executing_canister,
        response,
        heap_delta: NumBytes::from(0),
    }
}

// Helper function to execute response cleanup.
//
// Returns `ExecuteMessageResult`.
#[allow(clippy::too_many_arguments)]
fn execute_response_cleanup(
    clean_canister: CanisterState,
    executing_canister: CanisterState,
    cleanup_closure: WasmClosure,
    callback_err: HypervisorError,
    instructions_left: NumInstructions,
    mut execution_parameters: ExecutionParameters,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> ExecuteMessageResult {
    execution_parameters
        .instruction_limits
        .update(instructions_left);
    let func_ref = match original.call_origin {
        CallOrigin::Ingress(_, _) | CallOrigin::CanisterUpdate(_, _) | CallOrigin::Heartbeat => {
            FuncRef::UpdateClosure(cleanup_closure)
        }
        CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => {
            FuncRef::QueryClosure(cleanup_closure)
        }
    };
    let own_subnet_type = round.hypervisor.subnet_type();
    let result = round.hypervisor.execute_dts(
        ApiType::Cleanup {
            time: original.time,
        },
        executing_canister.execution_state.as_ref().unwrap(),
        &executing_canister.system_state,
        executing_canister.memory_usage(own_subnet_type),
        execution_parameters,
        func_ref,
        round_limits,
        round.network_topology,
    );
    process_cleanup_result(
        result,
        clean_canister,
        executing_canister,
        callback_err,
        original,
        round,
        round_limits,
    )
}

// Helper function to process the execution result of a response.
//
// Returns `ExecuteMessageResult`.
fn process_response_result(
    result: WasmExecutionResult,
    clean_canister: CanisterState,
    mut executing_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> ExecuteMessageResult {
    match result {
        WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
            update_round_limits(round_limits, &slice);
            let paused_execution = Box::new(PausedResponseExecution {
                paused_wasm_execution,
                execution_parameters,
                original,
            });
            ExecuteMessageResult::Paused {
                canister: clean_canister,
                paused_execution,
            }
        }
        WasmExecutionResult::Finished(slice, mut response_output, canister_state_changes) => {
            update_round_limits(round_limits, &slice);
            apply_canister_state_changes(
                canister_state_changes,
                executing_canister.execution_state.as_mut().unwrap(),
                &mut executing_canister.system_state,
                &mut response_output,
                round_limits,
                round.time,
                round.network_topology,
                round.hypervisor.subnet_id(),
                round.log,
            );
            // Executing the reply/reject closure succeeded.
            let (num_instructions_left, heap_delta, result) = match response_output.wasm_result {
                Ok(_) => {
                    let heap_delta = NumBytes::from(
                        (response_output.instance_stats.dirty_pages * PAGE_SIZE) as u64,
                    );
                    (
                        response_output.num_instructions_left,
                        heap_delta,
                        response_output.wasm_result.clone(),
                    )
                }
                Err(callback_err) => {
                    // A trap has occurred when executing the reply/reject closure.
                    // Execute the cleanup if it exists.
                    match original.callback.on_cleanup.clone() {
                        Some(cleanup_closure) => {
                            return execute_response_cleanup(
                                clean_canister,
                                executing_canister,
                                cleanup_closure,
                                callback_err,
                                response_output.num_instructions_left,
                                execution_parameters,
                                original,
                                round,
                                round_limits,
                            );
                        }
                        None => {
                            // No cleanup closure present. Return the callback error as-is.
                            (
                                response_output.num_instructions_left,
                                NumBytes::from(0),
                                Err(callback_err),
                            )
                        }
                    }
                }
            };
            let action = executing_canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .on_canister_result(original.call_context_id, Some(original.callback_id), result);
            let response = action_to_response(
                &executing_canister,
                action,
                original.call_origin,
                original.time,
                round.log,
            );

            // Refund the canister with any cycles left after message execution.
            round.cycles_account_manager.refund_execution_cycles(
                &mut executing_canister.system_state,
                num_instructions_left,
                original.message_instruction_limit,
            );
            ExecuteMessageResult::Finished {
                canister: executing_canister,
                response,
                heap_delta,
            }
        }
    }
}

// Helper function to process the execution result of a cleanup callback.
fn process_cleanup_result(
    result: WasmExecutionResult,
    clean_canister: CanisterState,
    mut executing_canister: CanisterState,
    callback_err: HypervisorError,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> ExecuteMessageResult {
    match result {
        WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
            update_round_limits(round_limits, &slice);
            let paused_execution = Box::new(PausedCleanupExecution {
                paused_wasm_execution,
                callback_err,
                original,
            });
            ExecuteMessageResult::Paused {
                canister: clean_canister,
                paused_execution,
            }
        }
        WasmExecutionResult::Finished(slice, mut cleanup_output, canister_state_changes) => {
            update_round_limits(round_limits, &slice);
            apply_canister_state_changes(
                canister_state_changes,
                executing_canister.execution_state.as_mut().unwrap(),
                &mut executing_canister.system_state,
                &mut cleanup_output,
                round_limits,
                round.time,
                round.network_topology,
                round.hypervisor.subnet_id(),
                round.log,
            );

            let (num_instructions_left, heap_delta, result) = match cleanup_output.wasm_result {
                Ok(_) => {
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
            };
            let action = executing_canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .on_canister_result(original.call_context_id, Some(original.callback_id), result);
            let response = action_to_response(
                &executing_canister,
                action,
                original.call_origin,
                original.time,
                round.log,
            );

            // Refund the canister with any cycles left after message execution.
            round.cycles_account_manager.refund_execution_cycles(
                &mut executing_canister.system_state,
                num_instructions_left,
                original.message_instruction_limit,
            );
            ExecuteMessageResult::Finished {
                canister: executing_canister,
                response,
                heap_delta,
            }
        }
    }
}
