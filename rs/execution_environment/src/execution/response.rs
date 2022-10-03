// This module defines how response callbacks are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#_callback_invocation.

use std::sync::Arc;

use prometheus::IntCounter;

use ic_embedders::wasm_executor::{
    wasm_execution_error, CanisterStateChanges, PausedWasmExecution, WasmExecutionResult,
};
use ic_interfaces::execution_environment::{HypervisorError, WasmExecutionOutput};
use ic_interfaces::messages::CanisterInputMessage;
use ic_logger::error;
use ic_replicated_state::{CallContext, CallOrigin, CanisterState};
use ic_sys::PAGE_SIZE;
use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::ingress::WasmResult;
use ic_types::messages::{CallContextId, CallbackId, Payload, Response};
use ic_types::methods::{Callback, FuncRef, WasmClosure};
use ic_types::Cycles;
use ic_types::{NumBytes, NumInstructions, Time};
use ic_wasm_types::WasmEngineError::FailedToApplySystemChanges;

use crate::execution::common::{
    self, action_to_response, apply_canister_state_changes, update_round_limits,
};
use crate::execution_environment::{
    ExecuteMessageResult, ExecutionResponse, PausedExecution, RoundContext, RoundLimits,
};

#[cfg(test)]
mod tests;

/// The algorithm for executing the response callback works with two canisters:
/// - `clean_canister`: the canister state from the current replicated state
///    without any changes by the ongoing execution.
/// - `helper.canister()`: the canister state that contains changes done by
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

/// Contains fields of `ResponseHelper` that are necessary for resuming the
/// response execution.
#[derive(Debug)]
struct PausedResponseHelper {
    refund_for_sent_cycles: Cycles,
    refund_for_response_transmission: Cycles,
    initial_cycles_balance: Cycles,
}

/// A helper that implements and keeps track of response execution steps.
/// It is used to safely pause and resume a response execution.
struct ResponseHelper {
    canister: CanisterState,
    refund_for_sent_cycles: Cycles,
    refund_for_response_transmission: Cycles,
    initial_cycles_balance: Cycles,
}

impl ResponseHelper {
    /// Construct a new helper by cloning the clean canister state and
    /// precomputing the cycles to refund.
    fn new(
        clean_canister: &CanisterState,
        response: &Response,
        error_counter: &IntCounter,
        original: &OriginalContext,
        round: &RoundContext,
    ) -> Self {
        // Canister A sends a request to canister B with some cycles.
        // Canister B can accept some of the cycles in the request.
        // The unaccepted cycles are returned to A in the response.
        //
        // Therefore, the cycles in the response must not exceed the cycles in
        // the request. Otherwise, there might be potentially malicious faults.
        let refund_for_sent_cycles = if response.refund > original.callback.cycles_sent {
            error!(
            round.log,
            "[EXC-BUG] Canister got a response with too many cycles.  originator {} respondent {} max cycles expected {} got {}.",
            response.originator,
            response.respondent,
            original.callback.cycles_sent,
            response.refund,
        );
            original.callback.cycles_sent
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
            .refund_for_response_transmission(
                round.log,
                error_counter,
                response,
                original.subnet_size,
            );

        let canister = clean_canister.clone();
        let initial_cycles_balance = canister.system_state.balance();
        Self {
            canister,
            refund_for_sent_cycles,
            refund_for_response_transmission,
            initial_cycles_balance,
        }
    }

    /// Refunds the canister for the cycles that were not accepted by the callee
    /// and for the cycles reserved for response transmission.
    ///
    /// These are the only state changes to the initial canister state before
    /// executing Wasm code.
    fn apply_initial_refunds(&mut self, round: &RoundContext) {
        round.cycles_account_manager.add_cycles(
            self.canister.system_state.balance_mut(),
            self.refund_for_sent_cycles,
        );
        // The `refund_cycles()` is similar to `add_cycles()` but it
        // additionally fixes up the cycles-burned metric.
        round.cycles_account_manager.refund_cycles(
            &mut self.canister.system_state,
            self.refund_for_response_transmission,
        );
    }

    /// Checks that the canister has not been uninstalled:
    /// - the call context is not deleted
    /// - the execute state exists.
    ///
    /// DTS relies on the invariant that once this validation succeeds, it will
    /// also continue to succeed later on for the same canister while DTS
    /// execution is in progress.
    fn validate(
        self,
        call_context: &CallContext,
        original: &OriginalContext,
        round: &RoundContext,
    ) -> Result<ResponseHelper, ExecuteMessageResult> {
        // If the call context was deleted (e.g. in uninstall), then do not execute anything.
        if call_context.is_deleted() {
            if !call_context.has_responded() {
                // This case is unreachable because `is_deleted() => has_responded()`
                // is a critical invariant and should hold.
                error!(
                    round.log,
                    "[EXC-BUG] Canister {} has a deleted context that has not responded",
                    self.canister.system_state.canister_id,
                );
                return Err(ExecuteMessageResult::Finished {
                    canister: self.canister,
                    heap_delta: NumBytes::from(0),
                    instructions_used: NumInstructions::from(0),
                    response: ExecutionResponse::Empty,
                });
            }
            // Since the call context has responded, passing `Ok(None)` will produce
            // an empty response and take care of all other bookkeeping.
            let result: Result<Option<WasmResult>, HypervisorError> = Ok(None);
            return Err(self.early_finish(result, original, round));
        }

        // Validate that the canister has an `ExecutionState`.
        if self.canister.execution_state.is_none() {
            error!(
                round.log,
                "[EXC-BUG] Canister {} is attempting to execute a response, but the execution state does not exist.",
                self.canister.system_state.canister_id,
            );
            let result = Err(HypervisorError::WasmModuleNotFound);
            return Err(self.early_finish(result, original, round));
        }
        Ok(self)
    }

    /// Returns a struct with all the necessary information to replay the
    /// initial steps in subsequent rounds.
    fn pause(self) -> PausedResponseHelper {
        PausedResponseHelper {
            refund_for_sent_cycles: self.refund_for_sent_cycles,
            refund_for_response_transmission: self.refund_for_response_transmission,
            initial_cycles_balance: self.initial_cycles_balance,
        }
    }

    /// Replays validation and the initial steps on the given clean canister and
    /// returns the helper to continue the DTS execution.
    ///
    /// It panics if the clean canister doesn't have the expected callback,
    /// call context, and execution state because it is not possible to invoke
    /// the cleanup callback in such cases.
    ///
    /// It returns an error if the cycles balance of the clean canister differs
    /// from the cycles balances at the start of the DTS execution.
    fn resume(
        paused: PausedResponseHelper,
        clean_canister: &CanisterState,
        original: &OriginalContext,
        round: &RoundContext,
    ) -> Result<ResponseHelper, (ResponseHelper, HypervisorError)> {
        // We expect the function call to succeed because the call context and
        // the callback have been checked in `execute_response()`.
        // Note that we cannot return an error here because the cleanup callback
        // cannot be invoked without a valid call context and a callback.
        let (_, _, call_context, _) =
            common::get_call_context_and_callback(clean_canister, &original.message, round.log)
                .expect("Failed to resume DTS response: get call context and callback");

        let mut helper = Self {
            canister: clean_canister.clone(),
            refund_for_sent_cycles: paused.refund_for_sent_cycles,
            refund_for_response_transmission: paused.refund_for_response_transmission,
            initial_cycles_balance: clean_canister.system_state.balance(),
        };
        helper.apply_initial_refunds(round);

        // This validation succeeded in `execute_response()` and we expect it to
        // succeed here too.
        // Note that we cannot return an error here because the cleanup callback
        // cannot be invoked without a valid call context and a callback.
        helper = helper
            .validate(&call_context, original, round)
            .expect("Failed to resume DTS response: validation");

        // The cycles balance of the clean canister must not change during the
        // DTS execution.
        if helper.initial_cycles_balance != paused.initial_cycles_balance {
            let msg = "Mismatch in cycles balance when resuming a response call".to_string();
            let err = HypervisorError::WasmEngineError(FailedToApplySystemChanges(msg));
            return Err((helper, err));
        }
        Ok(helper)
    }

    /// Processes the output and the state changes of Wasm execution of the
    /// response callback.
    fn handle_wasm_execution_of_response_callback(
        mut self,
        mut output: WasmExecutionOutput,
        canister_state_changes: Option<CanisterStateChanges>,
        original: &OriginalContext,
        round: &RoundContext,
        round_limits: &mut RoundLimits,
    ) -> Result<ExecuteMessageResult, (Self, HypervisorError, NumInstructions)> {
        apply_canister_state_changes(
            canister_state_changes,
            self.canister.execution_state.as_mut().unwrap(),
            &mut self.canister.system_state,
            &mut output,
            round_limits,
            round.time,
            round.network_topology,
            round.hypervisor.subnet_id(),
            round.log,
        );
        match output.wasm_result {
            Ok(_) => Ok(self.finish(
                output.wasm_result,
                output.num_instructions_left,
                NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64),
                original,
                round,
            )),
            Err(err) => Err((self, err, output.num_instructions_left)),
        }
    }

    /// Processes the output and the state changes of Wasm execution of the
    /// cleanup callback.
    fn handle_wasm_execution_of_cleanup_callback(
        mut self,
        mut output: WasmExecutionOutput,
        canister_state_changes: Option<CanisterStateChanges>,
        callback_err: HypervisorError,
        original: &OriginalContext,
        round: &RoundContext,
        round_limits: &mut RoundLimits,
    ) -> ExecuteMessageResult {
        apply_canister_state_changes(
            canister_state_changes,
            self.canister.execution_state.as_mut().unwrap(),
            &mut self.canister.system_state,
            &mut output,
            round_limits,
            round.time,
            round.network_topology,
            round.hypervisor.subnet_id(),
            round.log,
        );

        match output.wasm_result {
            Ok(_) => {
                // Note that, even though the callback has succeeded,
                // the original callback error is returned.
                self.finish(
                    Err(callback_err),
                    output.num_instructions_left,
                    NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64),
                    original,
                    round,
                )
            }
            Err(cleanup_err) => {
                let result = Err(HypervisorError::Cleanup {
                    callback_err: Box::new(callback_err),
                    cleanup_err: Box::new(cleanup_err),
                });
                self.finish(
                    result,
                    output.num_instructions_left,
                    NumBytes::from(0),
                    original,
                    round,
                )
            }
        }
    }

    /// Completes execution of the response and cleanup callbacks:
    /// - Unregisters the callback.
    /// - Unregisters the call context if there are no outstanding calls.
    /// - Refunds the remaining execution cycles.
    fn finish(
        mut self,
        result: Result<Option<WasmResult>, HypervisorError>,
        instructions_left: NumInstructions,
        heap_delta: NumBytes,
        original: &OriginalContext,
        round: &RoundContext,
    ) -> ExecuteMessageResult {
        let action = self
            .canister
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .on_canister_result(original.call_context_id, Some(original.callback_id), result);
        let response = action_to_response(
            &self.canister,
            action,
            original.call_origin.clone(),
            round.time,
            round.log,
        );
        // Refund the canister with any cycles left after message execution.
        round.cycles_account_manager.refund_execution_cycles(
            &mut self.canister.system_state,
            instructions_left,
            original.message_instruction_limit,
            original.subnet_size,
        );
        let instructions_used = NumInstructions::from(
            original
                .message_instruction_limit
                .get()
                .saturating_sub(instructions_left.get()),
        );
        ExecuteMessageResult::Finished {
            canister: self.canister,
            response,
            instructions_used,
            heap_delta,
        }
    }

    /// Completes execution of the respose and cleanup callbacks without
    /// consuming any instructions and without producing any heap delta.
    fn early_finish(
        self,
        result: Result<Option<WasmResult>, HypervisorError>,
        original: &OriginalContext,
        round: &RoundContext,
    ) -> ExecuteMessageResult {
        self.finish(
            result,
            original.message_instruction_limit,
            NumBytes::from(0),
            original,
            round,
        )
    }

    fn canister(&self) -> &CanisterState {
        &self.canister
    }

    fn refund_for_sent_cycles(&self) -> Cycles {
        self.refund_for_sent_cycles
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
    subnet_size: usize,
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of a response.
#[derive(Debug)]
struct PausedResponseExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    helper: PausedResponseHelper,
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
        _subnet_size: usize,
    ) -> ExecuteMessageResult {
        // The height of the `clean_canister` state increases with every call of
        // `resume()`. We re-create the helper based on `clean_state` so that
        // the Wasm state changes are applied to the up-to-date state.
        let (helper, result) =
            match ResponseHelper::resume(self.helper, &clean_canister, &self.original, &round) {
                Ok(helper) => {
                    let execution_state = helper.canister().execution_state.as_ref().unwrap();
                    let result = self.paused_wasm_execution.resume(execution_state);
                    (helper, result)
                }
                Err((helper, err)) => {
                    self.paused_wasm_execution.abort();
                    let result = wasm_execution_error(
                        err,
                        self.execution_parameters.instruction_limits.message(),
                    );
                    (helper, result)
                }
            };
        process_response_result(
            result,
            clean_canister,
            helper,
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
    helper: PausedResponseHelper,
    execution_parameters: ExecutionParameters,
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
        _subnet_size: usize,
    ) -> ExecuteMessageResult {
        // The height of the `clean_canister` state increases with every call of
        // `resume()`. We re-create the helper based on `clean_state` so that
        // the Wasm state changes are applied to the up-to-date state.
        //
        // Note that we don't apply changes from the response callback execution
        // because the cleanup callback runs only if the response callback fails.
        let (helper, result) =
            match ResponseHelper::resume(self.helper, &clean_canister, &self.original, &round) {
                Ok(helper) => {
                    let execution_state = helper.canister().execution_state.as_ref().unwrap();
                    let result = self.paused_wasm_execution.resume(execution_state);
                    (helper, result)
                }
                Err((helper, err)) => {
                    self.paused_wasm_execution.abort();
                    let result = wasm_execution_error(
                        err,
                        self.execution_parameters.instruction_limits.message(),
                    );
                    (helper, result)
                }
            };
        process_cleanup_result(
            result,
            clean_canister,
            helper,
            self.execution_parameters,
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
    subnet_size: usize,
) -> ExecuteMessageResult {
    let (callback, callback_id, call_context, call_context_id) =
        match common::get_call_context_and_callback(&clean_canister, &response, round.log) {
            Some(r) => r,
            None => {
                // This case is unreachable because the call context and
                // callback should always exist.
                return ExecuteMessageResult::Finished {
                    canister: clean_canister,
                    instructions_used: NumInstructions::from(0),
                    heap_delta: NumBytes::from(0),
                    response: ExecutionResponse::Empty,
                };
            }
        };

    let original = OriginalContext {
        callback,
        call_context_id,
        callback_id,
        call_origin: call_context.call_origin().clone(),
        time,
        message_instruction_limit: execution_parameters.instruction_limits.message(),
        message: Arc::clone(&response),
        subnet_size,
    };

    let mut helper =
        ResponseHelper::new(&clean_canister, &response, error_counter, &original, &round);
    helper.apply_initial_refunds(&round);
    let helper = match helper.validate(&call_context, &original, &round) {
        Ok(helper) => helper,
        Err(result) => {
            return result;
        }
    };

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
            helper.refund_for_sent_cycles(),
            call_context_id,
            call_context.has_responded(),
            execution_parameters.execution_mode.clone(),
        ),
        Payload::Reject(context) => ApiType::reject_callback(
            time,
            context.clone(),
            helper.refund_for_sent_cycles(),
            call_context_id,
            call_context.has_responded(),
            execution_parameters.execution_mode.clone(),
        ),
    };

    let result = round.hypervisor.execute_dts(
        api_type,
        helper.canister().execution_state.as_ref().unwrap(),
        &helper.canister().system_state,
        helper
            .canister()
            .memory_usage(round.hypervisor.subnet_type()),
        execution_parameters.clone(),
        func_ref,
        round_limits,
        round.network_topology,
    );

    process_response_result(
        result,
        clean_canister,
        helper,
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
    clean_canister: CanisterState,
    helper: ResponseHelper,
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
        helper.canister().execution_state.as_ref().unwrap(),
        &helper.canister().system_state,
        helper.canister().memory_usage(own_subnet_type),
        execution_parameters.clone(),
        func_ref,
        round_limits,
        round.network_topology,
    );
    process_cleanup_result(
        result,
        clean_canister,
        helper,
        execution_parameters,
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
    helper: ResponseHelper,
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
                helper: helper.pause(),
                execution_parameters,
                original,
            });
            ExecuteMessageResult::Paused {
                canister: clean_canister,
                paused_execution,
            }
        }
        WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
            update_round_limits(round_limits, &slice);
            match helper.handle_wasm_execution_of_response_callback(
                output,
                canister_state_changes,
                &original,
                &round,
                round_limits,
            ) {
                Ok(result) => result,
                Err((helper, err, instructions_left)) => {
                    // A trap has occurred when executing the reply/reject closure.
                    // Execute the cleanup if it exists.
                    match original.callback.on_cleanup.clone() {
                        Some(cleanup_closure) => execute_response_cleanup(
                            clean_canister,
                            helper,
                            cleanup_closure,
                            err,
                            instructions_left,
                            execution_parameters,
                            original,
                            round,
                            round_limits,
                        ),
                        None => {
                            // No cleanup closure present. Return the callback error as-is.
                            helper.finish(
                                Err(err),
                                instructions_left,
                                NumBytes::from(0),
                                &original,
                                &round,
                            )
                        }
                    }
                }
            }
        }
    }
}

// Helper function to process the execution result of a cleanup callback.
fn process_cleanup_result(
    result: WasmExecutionResult,
    clean_canister: CanisterState,
    helper: ResponseHelper,
    execution_parameters: ExecutionParameters,
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
                helper: helper.pause(),
                execution_parameters,
                callback_err,
                original,
            });
            ExecuteMessageResult::Paused {
                canister: clean_canister,
                paused_execution,
            }
        }
        WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
            update_round_limits(round_limits, &slice);
            helper.handle_wasm_execution_of_cleanup_callback(
                output,
                canister_state_changes,
                callback_err,
                &original,
                &round,
                round_limits,
            )
        }
    }
}
