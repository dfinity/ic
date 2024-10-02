// This module defines how response callbacks are executed.
// See https://internetcomputer.org/docs/interface-spec/index.html#callback-invocation

use std::sync::Arc;

use ic_base_types::CanisterId;
use ic_limits::LOG_CANISTER_OPERATION_CYCLES_THRESHOLD;
use ic_replicated_state::canister_state::system_state::CyclesUseCase;

use ic_embedders::wasm_executor::{
    wasm_execution_error, CanisterStateChanges, PausedWasmExecution, WasmExecutionResult,
};
use ic_interfaces::execution_environment::{
    CanisterOutOfCyclesError, HypervisorError, WasmExecutionOutput,
};
use ic_logger::{error, info, ReplicaLogger};
use ic_replicated_state::{CallContext, CallOrigin, CanisterState};
use ic_sys::PAGE_SIZE;
use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::ingress::WasmResult;
use ic_types::messages::{
    CallContextId, CallbackId, CanisterMessage, CanisterMessageOrTask, Payload, RequestMetadata,
    Response,
};
use ic_types::methods::{Callback, FuncRef, WasmClosure};
use ic_types::Cycles;
use ic_types::{NumBytes, NumInstructions, Time};
use ic_wasm_types::WasmEngineError::FailedToApplySystemChanges;

use crate::execution::common::{
    self, action_to_response, apply_canister_state_changes, update_round_limits,
};
use crate::execution_environment::{
    log_dirty_pages, ExecuteMessageResult, ExecutionResponse, PausedExecution, RoundContext,
    RoundLimits,
};
use crate::metrics::CallTreeMetrics;
use ic_config::flag_status::FlagStatus;

#[cfg(test)]
mod tests;

/// A percentage of the total message limit reserved for executing the cleanup
/// callback.
const RESERVED_CLEANUP_INSTRUCTIONS_IN_PERCENT: u64 = 5;

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
    response_sender: CanisterId,
}

/// A helper that implements and keeps track of response execution steps.
/// It is used to safely pause and resume a response execution.
struct ResponseHelper {
    canister: CanisterState,
    refund_for_sent_cycles: Cycles,
    refund_for_response_transmission: Cycles,
    initial_cycles_balance: Cycles,
    response_sender: CanisterId,
    applied_subnet_memory_reservation: NumBytes,
}

impl ResponseHelper {
    /// Construct a new helper by cloning the clean canister state and
    /// precomputing the cycles to refund.
    fn new(
        clean_canister: &CanisterState,
        response: &Response,
        original: &OriginalContext,
        round: &RoundContext,
        round_limits: &mut RoundLimits,
    ) -> Self {
        // Canister A sends a request to canister B with some cycles.
        // Canister B can accept some of the cycles in the request.
        // The unaccepted cycles are returned to A in the response.
        //
        // Therefore, the cycles in the response must not exceed the cycles in
        // the request. Otherwise, there might be potentially malicious faults.
        debug_assert!(response.refund <= original.callback.cycles_sent);
        let refund_for_sent_cycles = if response.refund > original.callback.cycles_sent {
            round.counters.response_cycles_refund_error.inc();
            error!(
                round.log,
                "[EXC-BUG] Canister got a response with too many cycles. \
                 Originator {} respondent {} max cycles expected {} got {}.",
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
                round.counters.response_cycles_refund_error,
                response,
                original.callback.prepayment_for_response_transmission,
                original.subnet_size,
            );

        let canister = clean_canister.clone();
        let initial_cycles_balance = canister.system_state.balance();
        let response_sender = response.respondent;
        let mut helper = Self {
            canister,
            refund_for_sent_cycles,
            refund_for_response_transmission,
            initial_cycles_balance,
            response_sender,
            applied_subnet_memory_reservation: NumBytes::new(0),
        };
        helper.apply_subnet_memory_reservation(original, round_limits);
        helper
    }

    /// Refunds the canister for the cycles that were not accepted by the callee
    /// and for the cycles reserved for response transmission.
    ///
    /// These are the only state changes to the initial canister state before
    /// executing Wasm code.
    fn apply_initial_refunds(&mut self) {
        self.canister
            .system_state
            .add_cycles(self.refund_for_sent_cycles, CyclesUseCase::NonConsumed);

        self.canister.system_state.add_cycles(
            self.refund_for_response_transmission,
            CyclesUseCase::RequestAndResponseTransmission,
        );
    }

    /// Checks that the canister has not been uninstalled:
    /// - the call context is not deleted
    /// - the execute state exists.
    ///
    /// DTS relies on the invariant that once this validation succeeds, it will
    /// also continue to succeed later on for the same canister while DTS
    /// execution is in progress.
    //
    // The concern about large `Err` variants is about propagation of large
    // errors through the `?` operator, see https://rust-lang.github.io/rust-clippy/master/index.html#/result_large_err.
    // In this case, the result is local to this module, so we allow the warning
    // as keeping the `Result` is more readable than using a custom enum.
    #[allow(clippy::result_large_err)]
    fn validate(
        self,
        call_context: &CallContext,
        original: &OriginalContext,
        round: &RoundContext,
        round_limits: &mut RoundLimits,
    ) -> Result<ResponseHelper, ExecuteMessageResult> {
        // If the call context was deleted (e.g. in uninstall), then do not execute anything.
        if call_context.is_deleted() {
            debug_assert!(call_context.has_responded());
            if !call_context.has_responded() {
                // This case is unreachable because `is_deleted() => has_responded()`
                // is a critical invariant and should hold.
                round.counters.invalid_canister_state_error.inc();
                error!(
                    round.log,
                    "[EXC-BUG] Canister {} has a deleted context that has not responded",
                    self.canister.system_state.canister_id,
                );
                // Since this branch doesn't call `early_finish()`, it needs to manually
                // revert the subnet memory reservation.
                self.revert_subnet_memory_reservation(original, round_limits);
                return Err(ExecuteMessageResult::Finished {
                    canister: self.canister,
                    heap_delta: NumBytes::from(0),
                    instructions_used: NumInstructions::from(0),
                    response: ExecutionResponse::Empty,
                    call_duration: Some(round.time.saturating_duration_since(call_context.time())),
                });
            }
            // Since the call context has responded, passing `Ok(None)` will produce
            // an empty response and take care of all other bookkeeping.
            let result: Result<Option<WasmResult>, HypervisorError> = Ok(None);
            return Err(self.early_finish(result, original, round, round_limits));
        }

        // Validate that the canister has an `ExecutionState`.
        debug_assert!(self.canister.execution_state.is_some());
        if self.canister.execution_state.is_none() {
            round.counters.invalid_canister_state_error.inc();
            error!(
                round.log,
                "[EXC-BUG] Canister {} is attempting to execute a response, but the execution state does not exist.",
                self.canister.system_state.canister_id,
            );
            let result = Err(HypervisorError::WasmModuleNotFound);
            return Err(self.early_finish(result, original, round, round_limits));
        }
        Ok(self)
    }

    /// Returns a struct with all the necessary information to replay the
    /// initial steps in subsequent rounds.
    fn pause(
        &self,
        original: &OriginalContext,
        round_limits: &mut RoundLimits,
    ) -> PausedResponseHelper {
        self.revert_subnet_memory_reservation(original, round_limits);
        PausedResponseHelper {
            refund_for_sent_cycles: self.refund_for_sent_cycles,
            refund_for_response_transmission: self.refund_for_response_transmission,
            initial_cycles_balance: self.initial_cycles_balance,
            response_sender: self.response_sender,
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
        round_limits: &mut RoundLimits,
    ) -> Result<ResponseHelper, (ResponseHelper, HypervisorError)> {
        // We expect the function call to succeed because the call context and
        // the callback have been checked in `execute_response()`.
        // Note that we cannot return an error here because the cleanup callback
        // cannot be invoked without a valid call context and a callback.
        let (_, _, call_context, _) = common::get_call_context_and_callback(
            clean_canister,
            &original.message,
            round.log,
            round.counters.unexpected_response_error,
        )
        .expect("Failed to resume DTS response: get call context and callback");

        let mut helper = Self {
            canister: clean_canister.clone(),
            refund_for_sent_cycles: paused.refund_for_sent_cycles,
            refund_for_response_transmission: paused.refund_for_response_transmission,
            initial_cycles_balance: clean_canister.system_state.balance(),
            response_sender: paused.response_sender,
            applied_subnet_memory_reservation: NumBytes::new(0),
        };

        helper.apply_subnet_memory_reservation(original, round_limits);

        helper.apply_initial_refunds();

        // This validation succeeded in `execute_response()` and we expect it to
        // succeed here too.
        // Note that we cannot return an error here because the cleanup callback
        // cannot be invoked without a valid call context and a callback.
        helper = helper
            .validate(&call_context, original, round, round_limits)
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
        reserved_cleanup_instructions: NumInstructions,
        call_tree_metrics: &dyn CallTreeMetrics,
    ) -> Result<ExecuteMessageResult, (Self, HypervisorError, NumInstructions)> {
        self.canister
            .system_state
            .canister_log
            .append(&mut output.canister_log);
        self.canister
            .system_state
            .apply_ingress_induction_cycles_debit(
                self.canister.canister_id(),
                round.log,
                round.counters.charging_from_balance_error,
            );

        // Check that the cycles balance does not go below zero after applying
        // the Wasm execution state changes.
        if let Some(state_changes) = &canister_state_changes {
            let old_balance = self.canister.system_state.balance();
            let requested = state_changes.system_state_changes.removed_cycles();
            // Note that we ignore the freezing threshold as required by the spec.
            if old_balance < requested {
                let reveal_top_up = self
                    .canister
                    .controllers()
                    .contains(&original.call_origin.get_principal());
                let err = CanisterOutOfCyclesError {
                    canister_id: self.canister.canister_id(),
                    available: old_balance,
                    requested,
                    threshold: original.freezing_threshold,
                    reveal_top_up,
                };
                info!(
                    round.log,
                    "[DTS] Failed response callback execution of canister {} due to concurrent cycle change: {:?}.",
                    self.canister.canister_id(),
                    err,
                );
                // Return total instructions: wasm executor leftovers + cleanup reservation.
                return Err((
                    self,
                    HypervisorError::InsufficientCyclesBalance(err),
                    output.num_instructions_left + reserved_cleanup_instructions,
                ));
            }
        }

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
            round.counters.state_changes_error,
            call_tree_metrics,
            original.call_context_creation_time,
        );

        // Return total instructions: wasm executor leftovers + cleanup reservation.
        let instructions_available = output.num_instructions_left + reserved_cleanup_instructions;
        match output.wasm_result {
            Ok(_) => Ok(self.finish(
                output.wasm_result,
                instructions_available,
                NumBytes::from((output.instance_stats.dirty_pages() * PAGE_SIZE) as u64),
                original,
                round,
                round_limits,
            )),
            Err(err) => Err((self, err, instructions_available)),
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
        call_tree_metrics: &dyn CallTreeMetrics,
    ) -> ExecuteMessageResult {
        self.canister
            .system_state
            .canister_log
            .append(&mut output.canister_log);
        self.canister
            .system_state
            .apply_ingress_induction_cycles_debit(
                self.canister.canister_id(),
                round.log,
                round.counters.charging_from_balance_error,
            );

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
            round.counters.state_changes_error,
            call_tree_metrics,
            original.call_context_creation_time,
        );

        match output.wasm_result {
            Ok(_) => {
                // Note that, even though the callback has succeeded,
                // the original callback error is returned.
                self.finish(
                    Err(callback_err),
                    output.num_instructions_left,
                    NumBytes::from((output.instance_stats.dirty_pages() * PAGE_SIZE) as u64),
                    original,
                    round,
                    round_limits,
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
                    round_limits,
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
        round_limits: &mut RoundLimits,
    ) -> ExecuteMessageResult {
        self.revert_subnet_memory_reservation(original, round_limits);

        let instructions_used = NumInstructions::from(
            original
                .message_instruction_limit
                .get()
                .saturating_sub(instructions_left.get()),
        );
        let (action, call_context) = self
            .canister
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .on_canister_result(
                original.call_context_id,
                Some(original.callback_id),
                result,
                instructions_used,
            );
        let response = action_to_response(
            &self.canister,
            action,
            original.call_origin.clone(),
            round.time,
            round.log,
            round.counters.ingress_with_cycles_error,
        );

        round.cycles_account_manager.refund_unused_execution_cycles(
            &mut self.canister.system_state,
            instructions_left,
            original.message_instruction_limit,
            original.callback.prepayment_for_response_execution,
            round.counters.execution_refund_error,
            original.subnet_size,
            round.log,
        );

        if self.refund_for_sent_cycles.get() > LOG_CANISTER_OPERATION_CYCLES_THRESHOLD {
            info!(
                round.log,
                "Canister {} received unaccepted {} cycles as refund from canister {}.",
                self.canister.system_state.canister_id,
                self.refund_for_sent_cycles,
                self.response_sender,
            );
        }

        if original.log_dirty_pages == FlagStatus::Enabled {
            log_dirty_pages(
                round.log,
                &original.canister_id,
                format!("reponse_to_{}", original.message.originator).as_str(),
                heap_delta.get() as usize / PAGE_SIZE,
                instructions_used,
            );
        }

        ExecuteMessageResult::Finished {
            canister: self.canister,
            response,
            instructions_used,
            heap_delta,
            call_duration: call_context
                .map(|call_context| round.time.saturating_duration_since(call_context.time())),
        }
    }

    /// Completes execution of the response and cleanup callbacks without
    /// consuming any instructions and without producing any heap delta.
    fn early_finish(
        self,
        result: Result<Option<WasmResult>, HypervisorError>,
        original: &OriginalContext,
        round: &RoundContext,
        round_limits: &mut RoundLimits,
    ) -> ExecuteMessageResult {
        self.finish(
            result,
            original.message_instruction_limit,
            NumBytes::from(0),
            original,
            round,
            round_limits,
        )
    }

    fn canister(&self) -> &CanisterState {
        &self.canister
    }

    fn refund_for_sent_cycles(&self) -> Cycles {
        self.refund_for_sent_cycles
    }

    fn apply_subnet_memory_reservation(
        &mut self,
        original: &OriginalContext,
        round_limits: &mut RoundLimits,
    ) {
        let reservation = original.subnet_memory_reservation;
        round_limits.subnet_available_memory.apply_reservation(
            reservation,
            NumBytes::new(0),
            NumBytes::new(0),
        );
        debug_assert_eq!(self.applied_subnet_memory_reservation, NumBytes::new(0));
        self.applied_subnet_memory_reservation = reservation;
    }

    fn revert_subnet_memory_reservation(
        &self,
        original: &OriginalContext,
        round_limits: &mut RoundLimits,
    ) {
        debug_assert_eq!(
            self.applied_subnet_memory_reservation,
            original.subnet_memory_reservation
        );
        round_limits.subnet_available_memory.revert_reservation(
            self.applied_subnet_memory_reservation,
            NumBytes::new(0),
            NumBytes::new(0),
        );
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
    call_context_creation_time: Time,
    request_metadata: RequestMetadata,
    message_instruction_limit: NumInstructions,
    message: Arc<Response>,
    subnet_size: usize,
    freezing_threshold: Cycles,
    canister_id: CanisterId,
    subnet_memory_reservation: NumBytes,
    instructions_executed: NumInstructions,
    log_dirty_pages: FlagStatus,
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of a response.
#[derive(Debug)]
struct PausedResponseExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    helper: PausedResponseHelper,
    execution_parameters: ExecutionParameters,
    reserved_cleanup_instructions: NumInstructions,
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
        call_tree_metrics: &dyn CallTreeMetrics,
    ) -> ExecuteMessageResult {
        info!(
            round.log,
            "[DTS] Resuming paused response callback {:?} of canister {}.",
            self.original.callback_id,
            clean_canister.canister_id(),
        );
        // The height of the `clean_canister` state increases with every call of
        // `resume()`. We re-create the helper based on `clean_canister` so that
        // the Wasm state changes are applied to the up-to-date state.
        let (helper, result) = match ResponseHelper::resume(
            self.helper,
            &clean_canister,
            &self.original,
            &round,
            round_limits,
        ) {
            Ok(helper) => {
                let execution_state = helper.canister().execution_state.as_ref().unwrap();
                let result = self.paused_wasm_execution.resume(execution_state);
                (helper, result)
            }
            Err((helper, err)) => {
                info!(
                    round.log,
                    "[DTS] Failed to resume paused response callback {:?} of canister {}: {:?}.",
                    self.original.callback_id,
                    clean_canister.canister_id(),
                    err,
                );
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
            self.reserved_cleanup_instructions,
            self.original,
            round,
            round_limits,
            call_tree_metrics,
        )
    }

    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (CanisterMessageOrTask, Cycles) {
        info!(
            log,
            "[DTS] Aborting paused response callback {:?} of canister {}.",
            self.original.callback_id,
            self.original.canister_id,
        );
        self.paused_wasm_execution.abort();
        let message = CanisterMessage::Response(self.original.message);
        // No cycles were prepaid for execution during this DTS execution.
        (CanisterMessageOrTask::Message(message), Cycles::zero())
    }

    fn input(&self) -> CanisterMessageOrTask {
        CanisterMessageOrTask::Message(CanisterMessage::Response(self.original.message.clone()))
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
        call_tree_metrics: &dyn CallTreeMetrics,
    ) -> ExecuteMessageResult {
        info!(
            round.log,
            "[DTS] Resuming paused cleanup callback {:?} of canister {}.",
            self.original.callback_id,
            clean_canister.canister_id(),
        );
        // The height of the `clean_canister` state increases with every call of
        // `resume()`. We re-create the helper based on `clean_state` so that
        // the Wasm state changes are applied to the up-to-date state.
        //
        // Note that we don't apply changes from the response callback execution
        // because the cleanup callback runs only if the response callback fails.
        let (helper, result) = match ResponseHelper::resume(
            self.helper,
            &clean_canister,
            &self.original,
            &round,
            round_limits,
        ) {
            Ok(helper) => {
                let execution_state = helper.canister().execution_state.as_ref().unwrap();
                let result = self.paused_wasm_execution.resume(execution_state);
                (helper, result)
            }
            Err((helper, err)) => {
                info!(
                    round.log,
                    "[DTS] Failed to resume paused cleanup callback {:?} of canister {}: {:?}.",
                    self.original.callback_id,
                    clean_canister.canister_id(),
                    err,
                );
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
            call_tree_metrics,
        )
    }

    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (CanisterMessageOrTask, Cycles) {
        info!(
            log,
            "[DTS] Aborting paused cleanup callback {:?} of canister {}.",
            self.original.callback_id,
            self.original.canister_id,
        );
        self.paused_wasm_execution.abort();
        let message = CanisterMessage::Response(self.original.message);
        // No cycles were prepaid for execution during this DTS execution.
        (CanisterMessageOrTask::Message(message), Cycles::zero())
    }

    fn input(&self) -> CanisterMessageOrTask {
        CanisterMessageOrTask::Message(CanisterMessage::Response(self.original.message.clone()))
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
    round: RoundContext,
    round_limits: &mut RoundLimits,
    subnet_size: usize,
    subnet_memory_reservation: NumBytes,
    call_tree_metrics: &dyn CallTreeMetrics,
    log_dirty_pages: FlagStatus,
) -> ExecuteMessageResult {
    let (callback, callback_id, call_context, call_context_id) =
        match common::get_call_context_and_callback(
            &clean_canister,
            &response,
            round.log,
            round.counters.unexpected_response_error,
        ) {
            Some(r) => r,
            None => {
                // This case is unreachable because the call context and
                // callback should always exist.
                return ExecuteMessageResult::Finished {
                    canister: clean_canister,
                    instructions_used: NumInstructions::from(0),
                    heap_delta: NumBytes::from(0),
                    response: ExecutionResponse::Empty,
                    call_duration: None,
                };
            }
        };

    let freezing_threshold = round.cycles_account_manager.freeze_threshold_cycles(
        clean_canister.system_state.freeze_threshold,
        clean_canister.system_state.memory_allocation,
        clean_canister.memory_usage(),
        clean_canister.message_memory_usage(),
        clean_canister.compute_allocation(),
        subnet_size,
        clean_canister.system_state.reserved_balance(),
    );

    let original = OriginalContext {
        callback,
        call_context_id,
        callback_id,
        call_origin: call_context.call_origin().clone(),
        time,
        call_context_creation_time: call_context.time(),
        request_metadata: call_context.metadata().clone(),
        message_instruction_limit: execution_parameters.instruction_limits.message(),
        message: Arc::clone(&response),
        subnet_size,
        freezing_threshold,
        canister_id: clean_canister.canister_id(),
        subnet_memory_reservation,
        instructions_executed: call_context.instructions_executed(),
        log_dirty_pages,
    };

    let mut helper =
        ResponseHelper::new(&clean_canister, &response, &original, &round, round_limits);
    helper.apply_initial_refunds();
    let helper = match helper.validate(&call_context, &original, &round, round_limits) {
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
        CallOrigin::Ingress(_, _)
        | CallOrigin::CanisterUpdate(_, _, _)
        | CallOrigin::SystemTask => FuncRef::UpdateClosure(closure),
        CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => FuncRef::QueryClosure(closure),
    };

    let api_type = match &response.response_payload {
        Payload::Data(payload) => ApiType::reply_callback(
            time,
            original.call_origin.get_principal(),
            payload.to_vec(),
            helper.refund_for_sent_cycles(),
            call_context_id,
            call_context.has_responded(),
            execution_parameters.execution_mode.clone(),
            call_context.instructions_executed(),
        ),
        Payload::Reject(context) => ApiType::reject_callback(
            time,
            original.call_origin.get_principal(),
            context.clone(),
            helper.refund_for_sent_cycles(),
            call_context_id,
            call_context.has_responded(),
            execution_parameters.execution_mode.clone(),
            call_context.instructions_executed(),
        ),
    };

    let (execution_parameters, reserved_cleanup_instructions) =
        reserve_cleanup_instructions(execution_parameters);

    let result = round.hypervisor.execute_dts(
        api_type,
        helper.canister().execution_state.as_ref().unwrap(),
        &helper.canister().system_state,
        helper.canister().memory_usage(),
        helper.canister().message_memory_usage(),
        execution_parameters.clone(),
        func_ref,
        original.request_metadata.clone(),
        round_limits,
        round.network_topology,
    );

    process_response_result(
        result,
        clean_canister,
        helper,
        execution_parameters,
        reserved_cleanup_instructions,
        original,
        round,
        round_limits,
        call_tree_metrics,
    )
}

// Reserves a percentage of message instructions limit for a cleanup callback execution.
fn reserve_cleanup_instructions(
    mut execution_parameters: ExecutionParameters,
) -> (ExecutionParameters, NumInstructions) {
    let instruction_limits = &mut execution_parameters.instruction_limits;
    let initial_message_limit = instruction_limits.message();
    let reserved_cleanup_instructions =
        (initial_message_limit * RESERVED_CLEANUP_INSTRUCTIONS_IN_PERCENT) / 100;
    instruction_limits.reduce_by(reserved_cleanup_instructions);
    (execution_parameters, reserved_cleanup_instructions)
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
    call_tree_metrics: &dyn CallTreeMetrics,
) -> ExecuteMessageResult {
    execution_parameters
        .instruction_limits
        .update(instructions_left);
    let func_ref = match original.call_origin {
        CallOrigin::Ingress(_, _)
        | CallOrigin::CanisterUpdate(_, _, _)
        | CallOrigin::SystemTask => FuncRef::UpdateClosure(cleanup_closure),
        CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => {
            FuncRef::QueryClosure(cleanup_closure)
        }
    };
    let result = round.hypervisor.execute_dts(
        ApiType::Cleanup {
            caller: original.call_origin.get_principal(),
            time: original.time,
            execution_mode: execution_parameters.execution_mode.clone(),
            call_context_instructions_executed: original.instructions_executed,
        },
        helper.canister().execution_state.as_ref().unwrap(),
        &helper.canister().system_state,
        helper.canister().memory_usage(),
        helper.canister().message_memory_usage(),
        execution_parameters.clone(),
        func_ref,
        original.request_metadata.clone(),
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
        call_tree_metrics,
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
    reserved_cleanup_instructions: NumInstructions,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
    call_tree_metrics: &dyn CallTreeMetrics,
) -> ExecuteMessageResult {
    match result {
        WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
            info!(
                round.log,
                "[DTS] Pausing response callback {:?} of canister {} after {} instructions.",
                original.callback_id,
                clean_canister.canister_id(),
                slice.executed_instructions,
            );
            update_round_limits(round_limits, &slice);
            let paused_execution = Box::new(PausedResponseExecution {
                paused_wasm_execution,
                helper: helper.pause(&original, round_limits),
                execution_parameters,
                reserved_cleanup_instructions,
                original,
            });
            ExecuteMessageResult::Paused {
                canister: clean_canister,
                paused_execution,
                // Pausing a resumed execution doesn't change the ingress
                // status.
                ingress_status: None,
            }
        }
        WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
            let instructions_used =
                original.message_instruction_limit - output.num_instructions_left;
            if instructions_used >= execution_parameters.instruction_limits.slice() {
                info!(
                    round.log,
                    "[DTS] Finished response callback {:} of canister {} after {} / {} instructions.",
                    original.callback_id,
                    clean_canister.canister_id(),
                    slice.executed_instructions.display(),
                    instructions_used.display(),
                );
            }
            update_round_limits(round_limits, &slice);
            match helper.handle_wasm_execution_of_response_callback(
                output,
                canister_state_changes,
                &original,
                &round,
                round_limits,
                reserved_cleanup_instructions,
                call_tree_metrics,
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
                            call_tree_metrics,
                        ),
                        None => {
                            // No cleanup closure present. Return the callback error as-is.
                            helper.finish(
                                Err(err),
                                instructions_left,
                                NumBytes::from(0),
                                &original,
                                &round,
                                round_limits,
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
    call_tree_metrics: &dyn CallTreeMetrics,
) -> ExecuteMessageResult {
    match result {
        WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
            info!(
                round.log,
                "[DTS] Pausing cleanup callback {:?} of canister {} after {} instructions.",
                original.callback_id,
                clean_canister.canister_id(),
                slice.executed_instructions,
            );
            update_round_limits(round_limits, &slice);
            let paused_execution = Box::new(PausedCleanupExecution {
                paused_wasm_execution,
                helper: helper.pause(&original, round_limits),
                execution_parameters,
                callback_err,
                original,
            });
            ExecuteMessageResult::Paused {
                canister: clean_canister,
                paused_execution,
                // Pausing a resumed execution doesn't change the ingress
                // status.
                ingress_status: None,
            }
        }
        WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
            let instructions_used =
                original.message_instruction_limit - output.num_instructions_left;
            if instructions_used >= execution_parameters.instruction_limits.slice() {
                info!(
                    round.log,
                    "[DTS] Finished cleanup callback {:?} of canister {} after {} / {} instructions.",
                    original.callback_id,
                    clean_canister.canister_id(),
                    slice.executed_instructions.display(),
                    instructions_used.display(),
                );
            }
            update_round_limits(round_limits, &slice);
            helper.handle_wasm_execution_of_cleanup_callback(
                output,
                canister_state_changes,
                callback_err,
                &original,
                &round,
                round_limits,
                call_tree_metrics,
            )
        }
    }
}
