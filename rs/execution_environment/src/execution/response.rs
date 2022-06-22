// This module defines how response callbacks are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#_callback_invocation.

use crate::execution_environment::{ExecuteMessageResult, ExecutionResponse, PausedExecution};
use crate::Hypervisor;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::wasm_executor::{PausedWasmExecution, WasmExecutionResult};
use ic_replicated_state::{CallContext, CallOrigin, CanisterState, NetworkTopology};
use ic_types::messages::{CallContextId, Payload, Response};
use ic_types::{NumBytes, NumInstructions, Time};

use crate::execution::common::action_to_response;
use ic_ic00_types::CanisterStatusType;
use ic_interfaces::execution_environment::{
    ExecutionParameters, HypervisorError, SubnetAvailableMemory, WasmExecutionOutput,
};
use ic_logger::{error, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_sys::PAGE_SIZE;
use ic_system_api::sandbox_safe_system_state::SystemStateChanges;
use ic_system_api::ApiType;
use ic_types::methods::{Callback, FuncRef, WasmClosure};
use ic_types::SubnetId;
use prometheus::IntCounter;
use std::sync::Arc;

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of a response.
#[derive(Debug)]
struct PausedResponseExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    time: Time,
    callback: Callback,
    call_context_id: CallContextId,
    call_origin: CallOrigin,
    execution_parameters: ExecutionParameters,
    canister_current_memory_usage: NumBytes,
}

impl PausedExecution for PausedResponseExecution {
    fn resume(
        self: Box<Self>,
        mut canister: CanisterState,
        subnet_available_memory: SubnetAvailableMemory,
        network_topology: &NetworkTopology,
        hypervisor: &Hypervisor,
        cycles_account_manager: &CyclesAccountManager,
        logger: &ReplicaLogger,
    ) -> ExecuteMessageResult {
        let execution_state = canister.execution_state.take().unwrap();
        let (execution_state, wasm_execution_result) = self
            .paused_wasm_execution
            .resume(execution_state, subnet_available_memory);
        canister.execution_state = Some(execution_state);

        match wasm_execution_result {
            WasmExecutionResult::Finished(response_output, system_state_changes) => {
                process_response_result(
                    self.time,
                    canister,
                    response_output,
                    system_state_changes,
                    self.callback,
                    self.call_origin,
                    self.call_context_id,
                    hypervisor,
                    network_topology,
                    self.canister_current_memory_usage,
                    self.execution_parameters,
                    cycles_account_manager,
                    logger,
                )
            }
            WasmExecutionResult::Paused(paused_wasm_execution) => {
                let paused_execution = Box::new(PausedResponseExecution {
                    paused_wasm_execution,
                    ..*self
                });
                ExecuteMessageResult {
                    canister,
                    num_instructions_left: NumInstructions::from(0),
                    response: ExecutionResponse::Paused(paused_execution),
                    heap_delta: NumBytes::from(0),
                }
            }
        }
    }

    fn abort(self: Box<Self>) {
        todo!()
    }
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of a cleanup callback.
#[derive(Debug)]
struct PausedCleanupExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    time: Time,
    own_subnet_id: SubnetId,
    call_context_id: CallContextId,
    call_origin: CallOrigin,
    callback_err: HypervisorError,
    slice_instruction_limit: NumInstructions,
}

impl PausedExecution for PausedCleanupExecution {
    fn resume(
        self: Box<Self>,
        mut canister: CanisterState,
        subnet_available_memory: SubnetAvailableMemory,
        network_topology: &NetworkTopology,
        _hypervisor: &Hypervisor,
        cycles_account_manager: &CyclesAccountManager,
        logger: &ReplicaLogger,
    ) -> ExecuteMessageResult {
        let execution_state = canister.execution_state.take().unwrap();
        let (execution_state, result) = self
            .paused_wasm_execution
            .resume(execution_state, subnet_available_memory);
        canister.execution_state = Some(execution_state);

        match result {
            WasmExecutionResult::Finished(cleanup_output, system_state_changes) => {
                process_cleanup_result(
                    self.time,
                    canister,
                    cleanup_output,
                    system_state_changes,
                    self.own_subnet_id,
                    self.call_origin,
                    self.call_context_id,
                    self.callback_err,
                    network_topology,
                    self.slice_instruction_limit,
                    cycles_account_manager,
                    logger,
                )
            }
            WasmExecutionResult::Paused(paused_wasm_execution) => {
                let paused_execution = Box::new(PausedCleanupExecution {
                    paused_wasm_execution,
                    ..*self
                });
                ExecuteMessageResult {
                    canister,
                    num_instructions_left: NumInstructions::from(0),
                    response: ExecutionResponse::Paused(paused_execution),
                    heap_delta: NumBytes::from(0),
                }
            }
        }
    }

    fn abort(self: Box<Self>) {
        unimplemented!();
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
pub fn execute_response(
    mut canister: CanisterState,
    response: Arc<Response>,
    time: Time,
    own_subnet_type: SubnetType,
    network_topology: Arc<NetworkTopology>,
    execution_parameters: ExecutionParameters,
    logger: &ReplicaLogger,
    error_counter: &IntCounter,
    hypervisor: &Hypervisor,
    cycles_account_manager: &CyclesAccountManager,
) -> ExecuteMessageResult {
    let (callback, call_context) =
        match get_call_context_and_callback(&mut canister, &response, logger) {
            Some(call_context) => call_context,
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
            logger,
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

    cycles_account_manager.add_cycles(canister.system_state.balance_mut(), refunded_cycles);

    // The canister that sends a request must also pay the fee for
    // the transmission of the response. As we do not know how big
    // the response might be, we reserve cycles for the largest
    // possible response when the request is being sent. Now that we
    // have received the response, we can refund the cycles based on
    // the actual size of the response.
    cycles_account_manager.response_cycles_refund(
        logger,
        error_counter,
        &mut canister.system_state,
        &response,
    );

    // If the call context was deleted (e.g. in uninstall), then do not execute anything.
    if is_call_context_deleted {
        // Refund the canister with any cycles left after message execution.
        cycles_account_manager.refund_execution_cycles(
            &mut canister.system_state,
            execution_parameters.slice_instruction_limit,
            execution_parameters.slice_instruction_limit,
        );
        ExecuteMessageResult {
            canister,
            num_instructions_left: execution_parameters.slice_instruction_limit,
            response: ExecutionResponse::Empty,
            heap_delta: NumBytes::from(0),
        }
    } else {
        // Validate that the canister has an `ExecutionState`.
        if canister.execution_state.is_none() {
            error!(
                logger,
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
            let response = action_to_response(&canister, action, call_origin, time, logger);

            // Refund the canister with any cycles left after message execution.
            cycles_account_manager.refund_execution_cycles(
                &mut canister.system_state,
                execution_parameters.slice_instruction_limit,
                execution_parameters.slice_instruction_limit,
            );
            return ExecuteMessageResult {
                canister,
                num_instructions_left: execution_parameters.slice_instruction_limit,
                response,
                heap_delta: NumBytes::from(0),
            };
        }

        let closure = match response.response_payload {
            Payload::Data(_) => callback.on_reply.clone(),
            Payload::Reject(_) => callback.on_reject.clone(),
        };

        let func_ref = match call_origin {
            CallOrigin::Ingress(_, _)
            | CallOrigin::CanisterUpdate(_, _)
            | CallOrigin::Heartbeat => FuncRef::UpdateClosure(closure),
            CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => {
                FuncRef::QueryClosure(closure)
            }
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

        let (output_execution_state, result) = hypervisor.execute_dts(
            api_type,
            canister.system_state.clone(),
            canister.memory_usage(own_subnet_type),
            execution_parameters.clone(),
            func_ref,
            canister.execution_state.take().unwrap(),
        );
        let canister_current_memory_usage = canister.memory_usage(own_subnet_type);
        canister.execution_state = Some(output_execution_state);

        match result {
            WasmExecutionResult::Finished(response_output, system_state_changes) => {
                process_response_result(
                    time,
                    canister,
                    response_output,
                    system_state_changes,
                    callback,
                    call_origin,
                    call_context_id,
                    hypervisor,
                    &network_topology,
                    canister_current_memory_usage,
                    execution_parameters,
                    cycles_account_manager,
                    logger,
                )
            }
            WasmExecutionResult::Paused(paused_wasm_execution) => {
                let paused_execution = Box::new(PausedResponseExecution {
                    paused_wasm_execution,
                    time,
                    callback,
                    call_context_id,
                    call_origin,
                    execution_parameters,
                    canister_current_memory_usage,
                });
                ExecuteMessageResult {
                    canister,
                    num_instructions_left: NumInstructions::from(0),
                    response: ExecutionResponse::Paused(paused_execution),
                    heap_delta: NumBytes::from(0),
                }
            }
        }
    }
}

// Helper function to execute response cleanup.
//
// Returns `ExecuteMessageResult`.
fn execute_response_cleanup(
    time: Time,
    mut canister: CanisterState,
    cleanup_closure: WasmClosure,
    call_origin: CallOrigin,
    call_context_id: CallContextId,
    callback_err: HypervisorError,
    hypervisor: &Hypervisor,
    network_topology: &NetworkTopology,
    canister_current_memory_usage: NumBytes,
    execution_parameters: ExecutionParameters,
    cycles_account_manager: &CyclesAccountManager,
    logger: &ReplicaLogger,
) -> ExecuteMessageResult {
    let func_ref = match call_origin {
        CallOrigin::Ingress(_, _) | CallOrigin::CanisterUpdate(_, _) | CallOrigin::Heartbeat => {
            FuncRef::UpdateClosure(cleanup_closure)
        }
        CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => {
            FuncRef::QueryClosure(cleanup_closure)
        }
    };

    let (output_execution_state, result) = hypervisor.execute_dts(
        ApiType::Cleanup { time },
        canister.system_state.clone(),
        canister_current_memory_usage,
        execution_parameters.clone(),
        func_ref,
        canister.execution_state.take().unwrap(),
    );
    canister.execution_state = Some(output_execution_state);

    match result {
        WasmExecutionResult::Finished(cleanup_output, system_state_changes) => {
            process_cleanup_result(
                time,
                canister,
                cleanup_output,
                system_state_changes,
                hypervisor.subnet_id(),
                call_origin,
                call_context_id,
                callback_err,
                network_topology,
                execution_parameters.slice_instruction_limit,
                cycles_account_manager,
                logger,
            )
        }
        WasmExecutionResult::Paused(paused_wasm_execution) => {
            let paused_execution = Box::new(PausedCleanupExecution {
                paused_wasm_execution,
                time,
                own_subnet_id: hypervisor.subnet_id(),
                call_context_id,
                call_origin,
                callback_err,
                slice_instruction_limit: execution_parameters.slice_instruction_limit,
            });
            ExecuteMessageResult {
                canister,
                num_instructions_left: NumInstructions::from(0),
                response: ExecutionResponse::Paused(paused_execution),
                heap_delta: NumBytes::from(0),
            }
        }
    }
}

// Helper function to process the execution result of a response.
//
// Returns `ExecuteMessageResult`.
fn process_response_result(
    time: Time,
    mut canister: CanisterState,
    response_output: WasmExecutionOutput,
    system_state_changes: SystemStateChanges,
    callback: Callback,
    call_origin: CallOrigin,
    call_context_id: CallContextId,
    hypervisor: &Hypervisor,
    network_topology: &NetworkTopology,
    canister_current_memory_usage: NumBytes,
    execution_parameters: ExecutionParameters,
    cycles_account_manager: &CyclesAccountManager,
    logger: &ReplicaLogger,
) -> ExecuteMessageResult {
    let (num_instructions_left, heap_delta, result) = match response_output.wasm_result {
        Ok(_) => {
            // Executing the reply/reject closure succeeded.
            system_state_changes.apply_changes(
                &mut canister.system_state,
                network_topology,
                hypervisor.subnet_id(),
                logger,
            );
            let heap_delta =
                NumBytes::from((response_output.instance_stats.dirty_pages * PAGE_SIZE) as u64);
            (
                response_output.num_instructions_left,
                heap_delta,
                response_output.wasm_result.clone(),
            )
        }
        Err(callback_err) => {
            // A trap has occurred when executing the reply/reject closure.
            // Execute the cleanup if it exists.
            match callback.on_cleanup {
                Some(cleanup_closure) => {
                    return execute_response_cleanup(
                        time,
                        canister,
                        cleanup_closure,
                        call_origin,
                        call_context_id,
                        callback_err,
                        hypervisor,
                        network_topology,
                        canister_current_memory_usage,
                        ExecutionParameters {
                            total_instruction_limit: response_output.num_instructions_left,
                            slice_instruction_limit: response_output.num_instructions_left,
                            ..execution_parameters
                        },
                        cycles_account_manager,
                        logger,
                    );
                }
                None => {
                    // No cleanup closure present. Return the callback error as-is.
                    (
                        execution_parameters.slice_instruction_limit,
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
        .on_canister_result(call_context_id, result);
    let response = action_to_response(&canister, action, call_origin, time, logger);

    // Refund the canister with any cycles left after message execution.
    cycles_account_manager.refund_execution_cycles(
        &mut canister.system_state,
        num_instructions_left,
        execution_parameters.slice_instruction_limit,
    );
    ExecuteMessageResult {
        canister,
        num_instructions_left,
        response,
        heap_delta,
    }
}

// Helper function to process the execution result of a cleanup callback.
fn process_cleanup_result(
    time: Time,
    mut canister: CanisterState,
    cleanup_output: WasmExecutionOutput,
    system_state_changes: SystemStateChanges,
    own_subnet_id: SubnetId,
    call_origin: CallOrigin,
    call_context_id: CallContextId,
    callback_err: HypervisorError,
    network_topology: &NetworkTopology,
    slice_instruction_limit: NumInstructions,
    cycles_account_manager: &CyclesAccountManager,
    logger: &ReplicaLogger,
) -> ExecuteMessageResult {
    let (num_instructions_left, heap_delta, result) = match cleanup_output.wasm_result {
        Ok(_) => {
            // Executing the cleanup callback has succeeded.
            system_state_changes.apply_changes(
                &mut canister.system_state,
                network_topology,
                own_subnet_id,
                logger,
            );
            let heap_delta =
                NumBytes::from((cleanup_output.instance_stats.dirty_pages * PAGE_SIZE) as u64);

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
        .on_canister_result(call_context_id, result);
    let response = action_to_response(&canister, action, call_origin, time, logger);

    // Refund the canister with any cycles left after message execution.
    cycles_account_manager.refund_execution_cycles(
        &mut canister.system_state,
        num_instructions_left,
        slice_instruction_limit,
    );
    ExecuteMessageResult {
        canister,
        num_instructions_left,
        response,
        heap_delta,
    }
}

// Helper function that extracts the corresponding callback and call context
// from the `CallContextManager`.
//
// Calling this function will unregister the callback identified based on the callback id.
// When the call context is marked as deleted, and there are no more outstanding
// callbacks, it will also unregister the call context.
fn get_call_context_and_callback(
    canister: &mut CanisterState,
    response: &Response,
    logger: &ReplicaLogger,
) -> Option<(Callback, CallContext)> {
    let call_context_manager = match canister.status() {
        CanisterStatusType::Stopped => {
            // A canister by definition can only be stopped when no open call contexts.
            // Hence, if we receive a response for a stopped canister then that is
            // a either a bug in the code or potentially a faulty (or
            // malicious) subnet generating spurious messages.
            error!(
                logger,
                "[EXC-BUG] Stopped canister got a response.  originator {} respondent {}.",
                response.originator,
                response.respondent,
            );
            return None;
        }
        CanisterStatusType::Running | CanisterStatusType::Stopping => {
            // We are sure there's a call context manager since the canister isn't stopped.
            canister.system_state.call_context_manager_mut().unwrap()
        }
    };

    let callback = match call_context_manager
        .unregister_callback(response.originator_reply_callback)
    {
        Some(callback) => callback,
        None => {
            // Received an unknown callback ID. Nothing to do.
            error!(
                logger,
                "[EXC-BUG] Canister got a response with unknown callback ID {}.  originator {} respondent {}.",
                response.originator_reply_callback,
                response.originator,
                response.respondent,
            );
            return None;
        }
    };

    let call_context_id = callback.call_context_id;
    let call_context = match call_context_manager.call_context(call_context_id) {
        Some(call_context) => call_context.clone(),
        None => {
            // Unknown call context. Nothing to do.
            error!(
                logger,
                "[EXC-BUG] Canister got a response for unknown request.  originator {} respondent {} callback id {}.",
                response.originator,
                response.respondent,
                response.originator_reply_callback,
            );
            return None;
        }
    };

    // The call context is completely removed if there are no outstanding callbacks.
    let num_outstanding_calls = call_context_manager.outstanding_calls(call_context_id);
    if call_context.is_deleted() && num_outstanding_calls == 0 {
        call_context_manager.unregister_call_context(call_context_id);
    }

    Some((callback, call_context))
}
