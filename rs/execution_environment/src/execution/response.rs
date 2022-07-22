// This module defines how response callbacks are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#_callback_invocation.

use crate::execution_environment::{
    ExecuteMessageResult, ExecutionResponse, PausedExecution, RoundContext, RoundLimits,
};
use ic_embedders::wasm_executor::{PausedWasmExecution, WasmExecutionResult};
use ic_interfaces::messages::CanisterInputMessage;
use ic_replicated_state::{CallOrigin, CanisterState};
use ic_types::messages::{CallContextId, Payload, Response};
use ic_types::{NumBytes, NumInstructions, Time};

use crate::execution::common;
use crate::execution::common::action_to_response;
use ic_interfaces::execution_environment::HypervisorError;
use ic_logger::error;
use ic_sys::PAGE_SIZE;
use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::methods::{Callback, FuncRef, WasmClosure};
use prometheus::IntCounter;
use std::sync::Arc;

use super::common::update_round_limits;

/// Context variables that remain the same throughput the entire deterministic
/// time slicing execution of a response.
#[derive(Clone, Debug)]
struct OriginalContext {
    callback: Callback,
    call_context_id: CallContextId,
    call_origin: CallOrigin,
    time: Time,
    message_instruction_limit: NumInstructions,
    message: Arc<Response>,
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
    fn resume(
        self: Box<Self>,
        mut canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> ExecuteMessageResult {
        let execution_state = canister.execution_state.take().unwrap();
        let (execution_state, result) = self.paused_wasm_execution.resume(execution_state);
        canister.execution_state = Some(execution_state);
        process_response_result(
            result,
            canister,
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
    fn resume(
        self: Box<Self>,
        mut canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> ExecuteMessageResult {
        let execution_state = canister.execution_state.take().unwrap();
        let (execution_state, result) = self.paused_wasm_execution.resume(execution_state);
        canister.execution_state = Some(execution_state);
        process_cleanup_result(
            result,
            canister,
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

/// Executes an inter-canister response.
///
/// Before executing the response, the following steps are done :
///     - verifies if the call context was marked as deleted, which ends the execution.
///     - refunds cycles sent with the response and any cycles reserved for the transmission
///          of the response, based on the actual size of the response.
///     - validates that canister has execution state.
///
/// Returns `ExecuteMessageResult` result which contains:
///
/// - The updated `CanisterState`.
///
/// - Number of instructions left.
///
/// - The size of the heap delta change that the execution produced.
///
/// - A ExecResult that contains the response of the executed message.
#[allow(clippy::too_many_arguments)]
pub fn execute_response(
    mut canister: CanisterState,
    response: Arc<Response>,
    time: Time,
    execution_parameters: ExecutionParameters,
    error_counter: &IntCounter,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> ExecuteMessageResult {
    let message_instruction_limit = execution_parameters.instruction_limits.message();
    let failure = |mut canister: CanisterState, response| {
        // Refund the canister with any cycles left after message execution.
        round.cycles_account_manager.refund_execution_cycles(
            &mut canister.system_state,
            message_instruction_limit,
            message_instruction_limit,
        );
        ExecuteMessageResult::Finished {
            canister,
            response,
            heap_delta: NumBytes::from(0),
        }
    };

    let (callback, call_context) =
        match common::get_call_context_and_callback(&mut canister, &response, round.log) {
            Some((callback, call_context)) => (callback, call_context),
            None => {
                return ExecuteMessageResult::Finished {
                    canister,
                    heap_delta: NumBytes::from(0),
                    response: ExecutionResponse::Empty,
                };
            }
        };

    let call_context_id = callback.call_context_id;
    let call_origin = call_context.call_origin().clone();
    let is_call_context_deleted = call_context.is_deleted();

    // Canister A sends a request to canister B with some cycles.
    // Canister B can accept a subset of the cycles in the request.
    // The unaccepted cycles are returned to A in the response.
    //
    // Therefore, the number of cycles in the response should always
    // be <= to the cycles in the request. If this is not the case,
    // then that indicates (potential malicious) faults.
    let refunded_cycles = if response.refund > callback.cycles_sent {
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

    round
        .cycles_account_manager
        .add_cycles(canister.system_state.balance_mut(), refunded_cycles);

    // The canister that sends a request must also pay the fee for
    // the transmission of the response. As we do not know how big
    // the response might be, we reserve cycles for the largest
    // possible response when the request is being sent. Now that we
    // have received the response, we can refund the cycles based on
    // the actual size of the response.
    round.cycles_account_manager.response_cycles_refund(
        round.log,
        error_counter,
        &mut canister.system_state,
        &response,
    );

    // If the call context was deleted (e.g. in uninstall), then do not execute anything.
    if is_call_context_deleted {
        return failure(canister, ExecutionResponse::Empty);
    }

    // Validate that the canister has an `ExecutionState`.
    if canister.execution_state.is_none() {
        error!(
                round.log,
                "[EXC-BUG] Canister {} is attempting to execute a response, but the execution state does not exist.",
                canister.system_state.canister_id,
            );

        let action = canister
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .on_canister_result(
                callback.call_context_id,
                Err(HypervisorError::WasmModuleNotFound),
            );
        let response = action_to_response(&canister, action, call_origin, time, round.log);
        return failure(canister, response);
    }

    let closure = match response.response_payload {
        Payload::Data(_) => callback.on_reply.clone(),
        Payload::Reject(_) => callback.on_reject.clone(),
    };

    let func_ref = match call_origin {
        CallOrigin::Ingress(_, _) | CallOrigin::CanisterUpdate(_, _) | CallOrigin::Heartbeat => {
            FuncRef::UpdateClosure(closure)
        }
        CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => FuncRef::QueryClosure(closure),
    };

    let api_type = match &response.response_payload {
        Payload::Data(payload) => ApiType::reply_callback(
            time,
            payload.to_vec(),
            refunded_cycles,
            call_context_id,
            call_context.has_responded(),
        ),
        Payload::Reject(context) => ApiType::reject_callback(
            time,
            context.clone(),
            refunded_cycles,
            call_context_id,
            call_context.has_responded(),
        ),
    };

    let (output_execution_state, result) = round.hypervisor.execute_dts(
        api_type,
        &canister.system_state,
        canister.memory_usage(round.hypervisor.subnet_type()),
        execution_parameters.clone(),
        func_ref,
        canister.execution_state.take().unwrap(),
        round_limits,
        round.network_topology,
    );

    canister.execution_state = Some(output_execution_state);

    let original = OriginalContext {
        callback,
        call_context_id,
        call_origin,
        time,
        message_instruction_limit,
        message: response,
    };

    process_response_result(
        result,
        canister,
        execution_parameters,
        original,
        round,
        round_limits,
    )
}

// Helper function to execute response cleanup.
//
// Returns `ExecuteMessageResult`.
#[allow(clippy::too_many_arguments)]
fn execute_response_cleanup(
    mut canister: CanisterState,
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
    let (output_execution_state, result) = round.hypervisor.execute_dts(
        ApiType::Cleanup {
            time: original.time,
        },
        &canister.system_state,
        canister.memory_usage(own_subnet_type),
        execution_parameters,
        func_ref,
        canister.execution_state.take().unwrap(),
        round_limits,
        round.network_topology,
    );
    canister.execution_state = Some(output_execution_state);
    process_cleanup_result(
        result,
        canister,
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
    mut canister: CanisterState,
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
                canister,
                paused_execution,
            }
        }
        WasmExecutionResult::Finished(slice, response_output, system_state_changes) => {
            update_round_limits(round_limits, &slice);
            let (num_instructions_left, heap_delta, result) = match response_output.wasm_result {
                Ok(_) => {
                    // TODO(RUN-265): Replace `unwrap` with a proper execution error
                    // here because subnet available memory may have changed since
                    // the start of execution.
                    round_limits
                        .subnet_available_memory
                        .try_decrement(
                            response_output.allocated_bytes,
                            response_output.allocated_message_bytes,
                        )
                        .unwrap();
                    // Executing the reply/reject closure succeeded.
                    system_state_changes.apply_changes(
                        round.time,
                        &mut canister.system_state,
                        round.network_topology,
                        round.hypervisor.subnet_id(),
                        round.log,
                    );
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
                                canister,
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
            let action = canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .on_canister_result(original.call_context_id, result);
            let response = action_to_response(
                &canister,
                action,
                original.call_origin,
                original.time,
                round.log,
            );

            // Refund the canister with any cycles left after message execution.
            round.cycles_account_manager.refund_execution_cycles(
                &mut canister.system_state,
                num_instructions_left,
                original.message_instruction_limit,
            );
            ExecuteMessageResult::Finished {
                canister,
                response,
                heap_delta,
            }
        }
    }
}

// Helper function to process the execution result of a cleanup callback.
fn process_cleanup_result(
    result: WasmExecutionResult,
    mut canister: CanisterState,
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
                canister,
                paused_execution,
            }
        }
        WasmExecutionResult::Finished(slice, cleanup_output, system_state_changes) => {
            update_round_limits(round_limits, &slice);
            let (num_instructions_left, heap_delta, result) = match cleanup_output.wasm_result {
                Ok(_) => {
                    // TODO(RUN-265): Replace `unwrap` with a proper execution error
                    // here because subnet available memory may have changed since
                    // the start of execution.
                    round_limits
                        .subnet_available_memory
                        .try_decrement(
                            cleanup_output.allocated_bytes,
                            cleanup_output.allocated_message_bytes,
                        )
                        .unwrap();
                    // Executing the cleanup callback has succeeded.
                    system_state_changes.apply_changes(
                        round.time,
                        &mut canister.system_state,
                        round.network_topology,
                        round.hypervisor.subnet_id(),
                        round.log,
                    );
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
            let action = canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .on_canister_result(original.call_context_id, result);
            let response = action_to_response(
                &canister,
                action,
                original.call_origin,
                original.time,
                round.log,
            );

            // Refund the canister with any cycles left after message execution.
            round.cycles_account_manager.refund_execution_cycles(
                &mut canister.system_state,
                num_instructions_left,
                original.message_instruction_limit,
            );
            ExecuteMessageResult::Finished {
                canister,
                response,
                heap_delta,
            }
        }
    }
}
