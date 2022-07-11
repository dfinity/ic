// This module defines how response callbacks are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#_callback_invocation.

use crate::execution_environment::{
    ExecuteMessageResult, ExecutionResponse, PausedExecution, RoundContext, RoundLimits,
};
use ic_embedders::wasm_executor::{PausedWasmExecution, WasmExecutionResult};
use ic_interfaces::messages::CanisterInputMessage;
use ic_replicated_state::{CallOrigin, CanisterState};
use ic_types::messages::{CallContextId, Payload, Response};
use ic_types::{ComputeAllocation, NumBytes, NumInstructions, Time};

use crate::execution::common;
use crate::execution::common::action_to_response;
use ic_interfaces::execution_environment::{ExecutionMode, ExecutionParameters, HypervisorError};
use ic_logger::error;
use ic_sys::PAGE_SIZE;
use ic_system_api::ApiType;
use ic_types::methods::{Callback, FuncRef, WasmClosure};
use prometheus::IntCounter;
use std::sync::Arc;

/// Context variables that remain the same throughput the entire deterministic
/// time slicing execution of a response.
#[derive(Clone, Debug)]
struct OriginalContext {
    callback: Callback,
    call_context_id: CallContextId,
    call_origin: CallOrigin,
    canister_memory_limit: NumBytes,
    compute_allocation: ComputeAllocation,
    time: Time,
    total_instruction_limit: NumInstructions,
    message: Arc<Response>,
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of a response.
#[derive(Debug)]
struct PausedResponseExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
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
        let (execution_state, result) = self
            .paused_wasm_execution
            .resume(execution_state, round.subnet_available_memory.clone());
        canister.execution_state = Some(execution_state);
        process_response_result(result, canister, self.original, round, round_limits)
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
        let (execution_state, result) = self
            .paused_wasm_execution
            .resume(execution_state, round.subnet_available_memory.clone());
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
    let failure = |mut canister: CanisterState, response, instruction_limit| {
        // Refund the canister with any cycles left after message execution.
        round.cycles_account_manager.refund_execution_cycles(
            &mut canister.system_state,
            instruction_limit,
            instruction_limit,
        );
        // TODO(RUN-59): We need to distinguish between instructions left from
        // the total limit and instructions left from the slice limit.
        ExecuteMessageResult {
            canister,
            num_instructions_left: instruction_limit,
            response,
            heap_delta: NumBytes::from(0),
        }
    };

    let total_instruction_limit = execution_parameters.total_instruction_limit;

    let (callback, call_context) =
        match common::get_call_context_and_callback(&mut canister, &response, round.log) {
            Some((callback, call_context)) => (callback, call_context),
            None => {
                return ExecuteMessageResult {
                    canister,
                    num_instructions_left: execution_parameters.slice_instruction_limit,
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
        return failure(canister, ExecutionResponse::Empty, total_instruction_limit);
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

        return failure(canister, response, total_instruction_limit);
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
        canister.system_state.clone(),
        canister.memory_usage(round.hypervisor.subnet_type()),
        execution_parameters.clone(),
        round.subnet_available_memory.clone(),
        func_ref,
        canister.execution_state.take().unwrap(),
        round_limits,
    );

    canister.execution_state = Some(output_execution_state);

    let original = OriginalContext {
        callback,
        call_context_id,
        call_origin,
        canister_memory_limit: execution_parameters.canister_memory_limit,
        compute_allocation: execution_parameters.compute_allocation,
        time,
        total_instruction_limit,
        message: response,
    };

    process_response_result(result, canister, original, round, round_limits)
}

// Helper function to execute response cleanup.
//
// Returns `ExecuteMessageResult`.
fn execute_response_cleanup(
    mut canister: CanisterState,
    cleanup_closure: WasmClosure,
    callback_err: HypervisorError,
    instructions_left: NumInstructions,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> ExecuteMessageResult {
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
        canister.system_state.clone(),
        canister.memory_usage(own_subnet_type),
        ExecutionParameters {
            total_instruction_limit: instructions_left,
            slice_instruction_limit: instructions_left,
            canister_memory_limit: original.canister_memory_limit,
            compute_allocation: original.compute_allocation,
            subnet_type: round.hypervisor.subnet_type(),
            execution_mode: ExecutionMode::Replicated,
        },
        round.subnet_available_memory.clone(),
        func_ref,
        canister.execution_state.take().unwrap(),
        round_limits,
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
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> ExecuteMessageResult {
    match result {
        WasmExecutionResult::Paused(paused_wasm_execution) => {
            let paused_execution = Box::new(PausedResponseExecution {
                paused_wasm_execution,
                original,
            });
            ExecuteMessageResult {
                canister,
                num_instructions_left: NumInstructions::from(0),
                response: ExecutionResponse::Paused(paused_execution),
                heap_delta: NumBytes::from(0),
            }
        }
        WasmExecutionResult::Finished(response_output, system_state_changes) => {
            let (num_instructions_left, heap_delta, result) = match response_output.wasm_result {
                Ok(_) => {
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
                original.total_instruction_limit,
            );
            ExecuteMessageResult {
                canister,
                num_instructions_left,
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
    _round_limits: &mut RoundLimits,
) -> ExecuteMessageResult {
    match result {
        WasmExecutionResult::Paused(paused_wasm_execution) => {
            let paused_execution = Box::new(PausedCleanupExecution {
                paused_wasm_execution,
                callback_err,
                original,
            });
            ExecuteMessageResult {
                canister,
                num_instructions_left: NumInstructions::from(0),
                response: ExecutionResponse::Paused(paused_execution),
                heap_delta: NumBytes::from(0),
            }
        }
        WasmExecutionResult::Finished(cleanup_output, system_state_changes) => {
            let (num_instructions_left, heap_delta, result) = match cleanup_output.wasm_result {
                Ok(_) => {
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
                original.total_instruction_limit,
            );
            ExecuteMessageResult {
                canister,
                num_instructions_left,
                response,
                heap_delta,
            }
        }
    }
}
