// This module defines how replicated queries are executed.
// See https://internetcomputer.org/docs/interface-spec/index.html#rule-message-execution
//
// A replicated query is a call to a `canister_query` function in update
// context.

use crate::execution::common::{
    finish_call_with_error, ingress_status_with_processing_state, into_message_or_task,
    update_round_limits, validate_message, wasm_result_to_query_response,
};
use crate::execution_environment::{
    ExecuteMessageResult, PausedExecution, RoundContext, RoundLimits,
};
use crate::metrics::CallTreeMetrics;
use ic_base_types::CanisterId;
use ic_embedders::wasm_executor::{CanisterStateChanges, PausedWasmExecution, WasmExecutionResult};
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::{
    CanisterOutOfCyclesError, HypervisorError, WasmExecutionOutput,
};
use ic_logger::{info, ReplicaLogger};
use ic_replicated_state::{CallContextAction, CallOrigin, CanisterState};
use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::methods::{FuncRef, WasmMethod};
use ic_types::{
    messages::{
        CallContextId, CanisterCall, CanisterCallOrTask, CanisterMessageOrTask, RequestMetadata,
    },
    Cycles, NumBytes, NumInstructions, Time,
};
use ic_utils_thread::deallocator_thread::DeallocationSender;
use ic_wasm_types::WasmEngineError::FailedToApplySystemChanges;

// Execute an inter-canister request or an ingress message as a replicated query.
#[allow(clippy::too_many_arguments)]
pub fn execute_replicated_query(
    clean_canister: CanisterState,
    req: CanisterCall,
    method: WasmMethod,
    prepaid_execution_cycles: Option<Cycles>,
    execution_parameters: ExecutionParameters,
    time: Time,
    round: RoundContext,
    round_limits: &mut RoundLimits,
    subnet_size: usize,
    deallocation_sender: &DeallocationSender,
) -> ExecuteMessageResult {
    let (clean_canister, prepaid_execution_cycles, resuming_aborted) =
        match prepaid_execution_cycles {
            Some(prepaid_execution_cycles) => (clean_canister, prepaid_execution_cycles, true),
            None => {
                let mut canister = clean_canister;
                let memory_usage = canister.memory_usage();
                let message_memory_usage = canister.message_memory_usage();
                let reveal_top_up = canister.controllers().contains(req.sender());

                let is_wasm64_execution = canister
                    .execution_state
                    .as_ref()
                    .is_some_and(|es| es.is_wasm64);

                let prepaid_execution_cycles =
                    match round.cycles_account_manager.prepay_execution_cycles(
                        &mut canister.system_state,
                        memory_usage,
                        message_memory_usage,
                        execution_parameters.compute_allocation,
                        execution_parameters.instruction_limits.message(),
                        subnet_size,
                        reveal_top_up,
                        is_wasm64_execution.into(),
                    ) {
                        Ok(cycles) => cycles,
                        Err(err) => {
                            return finish_call_with_error(
                                UserError::new(ErrorCode::CanisterOutOfCycles, err),
                                canister,
                                CanisterCallOrTask::Call(req),
                                NumInstructions::from(0),
                                round.time,
                                execution_parameters.subnet_type,
                                round.log,
                            );
                        }
                    };
                (canister, prepaid_execution_cycles, false)
            }
        };

    let call_origin = CallOrigin::from(&req);

    let freezing_threshold = round.cycles_account_manager.freeze_threshold_cycles(
        clean_canister.system_state.freeze_threshold,
        clean_canister.system_state.memory_allocation,
        clean_canister.memory_usage(),
        clean_canister.message_memory_usage(),
        clean_canister.compute_allocation(),
        subnet_size,
        clean_canister.system_state.reserved_balance(),
    );

    let request_metadata = match &req {
        CanisterCall::Request(request) => request.metadata.for_downstream_call(),
        CanisterCall::Ingress(_) => RequestMetadata::for_new_call_tree(time),
    };

    let original = OriginalContext {
        call_origin,
        call: req,
        prepaid_execution_cycles,
        method,
        execution_parameters,
        subnet_size,
        time,
        request_metadata,
        freezing_threshold,
        canister_id: clean_canister.canister_id(),
    };

    let helper = match ReplicatedQueryHelper::new(&clean_canister, &original, deallocation_sender) {
        Ok(helper) => helper,
        Err(err) => {
            return finish_err(
                clean_canister,
                original.execution_parameters.instruction_limits.message(),
                err,
                original,
                round,
            )
        }
    };

    let api_type = ApiType::replicated_query(
        time,
        original.call.method_payload().to_vec(),
        *original.call.sender(),
        helper.call_context_id(),
    );

    let result = round.hypervisor.execute_dts(
        api_type,
        helper.canister().execution_state.as_ref().unwrap(),
        &helper.canister().system_state,
        helper.canister().memory_usage(),
        helper.canister().message_memory_usage(),
        original.execution_parameters.clone(),
        FuncRef::Method(original.method.clone()),
        original.request_metadata.clone(),
        round_limits,
        round.network_topology,
    );

    match result {
        WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
            info!(
                round.log,
                "[DTS] Pausing {:?} execution of canister {} after {} instructions.",
                original.method,
                clean_canister.canister_id(),
                slice.executed_instructions,
            );
            update_round_limits(round_limits, &slice);

            let ingress_status = match (resuming_aborted, &original.call) {
                (true, _) => {
                    // Resuming an aborted execution doesn't change the ingress
                    // status.
                    None
                }
                (false, call) => ingress_status_with_processing_state(call, original.time),
            };
            let paused_execution = Box::new(PausedReplicatedQueryExecution {
                paused_wasm_execution,
                paused_helper: helper.pause(),
                original,
            });
            ExecuteMessageResult::Paused {
                canister: clean_canister,
                paused_execution,
                ingress_status,
            }
        }
        WasmExecutionResult::Finished(slice, output, state_changes) => {
            update_round_limits(round_limits, &slice);
            helper.finish(output, clean_canister, state_changes, original, round)
        }
    }
}

/// Finishes a replicated query execution early due to an error. The only state
/// change that is applied to the clean canister state is refunding the prepaid
/// execution cycles.
fn finish_err(
    clean_canister: CanisterState,
    instructions_left: NumInstructions,
    err: UserError,
    original: OriginalContext,
    round: RoundContext,
) -> ExecuteMessageResult {
    let mut canister = clean_canister;

    canister.system_state.apply_ingress_induction_cycles_debit(
        canister.canister_id(),
        round.log,
        round.counters.charging_from_balance_error,
    );

    let is_wasm64_execution = canister
        .execution_state
        .as_ref()
        .is_some_and(|es| es.is_wasm64);

    let instruction_limit = original.execution_parameters.instruction_limits.message();
    round.cycles_account_manager.refund_unused_execution_cycles(
        &mut canister.system_state,
        instructions_left,
        instruction_limit,
        original.prepaid_execution_cycles,
        round.counters.execution_refund_error,
        original.subnet_size,
        is_wasm64_execution.into(),
        round.log,
    );
    let instructions_used = instruction_limit - instructions_left;
    finish_call_with_error(
        err,
        canister,
        CanisterCallOrTask::Call(original.call),
        instructions_used,
        round.time,
        original.execution_parameters.subnet_type,
        round.log,
    )
}

/// Context variables that remain the same throughout the entire deterministic
/// time slicing execution of an replicated query execution.
#[derive(Debug)]
struct OriginalContext {
    call_origin: CallOrigin,
    call: CanisterCall,
    prepaid_execution_cycles: Cycles,
    method: WasmMethod,
    execution_parameters: ExecutionParameters,
    subnet_size: usize,
    time: Time,
    request_metadata: RequestMetadata,
    freezing_threshold: Cycles,
    canister_id: CanisterId,
}

/// Contains fields of `UpdateHelper` that are necessary for resuming an update
/// call execution.
#[derive(Debug)]
struct PausedReplicatedQueryHelper {
    call_context_id: CallContextId,
    initial_cycles_balance: Cycles,
}

/// A helper that implements and keeps track of replicated query steps.
/// It is used to safely pause and resume an replicated query execution.
struct ReplicatedQueryHelper {
    canister: CanisterState,
    call_context_id: CallContextId,
    initial_cycles_balance: Cycles,
    deallocation_sender: DeallocationSender,
}

impl ReplicatedQueryHelper {
    /// Applies the initial state changes and performs the initial validation.
    fn new(
        clean_canister: &CanisterState,
        original: &OriginalContext,
        deallocation_sender: &DeallocationSender,
    ) -> Result<Self, UserError> {
        let mut canister = clean_canister.clone();

        if let WasmMethod::CompositeQuery(_) = &original.method {
            let user_error = UserError::new(
                ErrorCode::CompositeQueryCalledInReplicatedMode,
                "Composite query cannot be called in replicated mode",
            );
            return Err(user_error);
        }

        validate_message(&canister, &original.method)?;

        let call_context_id = canister
            .system_state
            .new_call_context(
                original.call_origin.clone(),
                original.call.cycles(),
                original.time,
                original.request_metadata.clone(),
            )
            .unwrap();

        let initial_cycles_balance = canister.system_state.balance();

        Ok(Self {
            canister,
            call_context_id,
            initial_cycles_balance,
            deallocation_sender: deallocation_sender.clone(),
        })
    }

    /// Returns a struct with all the necessary information to replay the
    /// performed replicated query steps in subsequent rounds.
    fn pause(self) -> PausedReplicatedQueryHelper {
        self.deallocation_sender.send(Box::new(self.canister));
        PausedReplicatedQueryHelper {
            call_context_id: self.call_context_id,
            initial_cycles_balance: self.initial_cycles_balance,
        }
    }

    /// Replays the previous replicated query steps on the given clean canister.
    /// Returns an error if any step fails. Otherwise, it returns an instance of
    /// the helper that can be used to continue the update call execution.
    fn resume(
        clean_canister: &CanisterState,
        original: &OriginalContext,
        paused: PausedReplicatedQueryHelper,
        deallocation_sender: &DeallocationSender,
    ) -> Result<Self, UserError> {
        let helper = Self::new(clean_canister, original, deallocation_sender)?;
        if helper.initial_cycles_balance != paused.initial_cycles_balance {
            let msg = "Mismatch in cycles balance when resuming a replicated query".to_string();
            let err = HypervisorError::WasmEngineError(FailedToApplySystemChanges(msg));
            return Err(err.into_user_error(&clean_canister.canister_id()));
        }
        if helper.call_context_id != paused.call_context_id {
            let msg = "Mismatch in call context id when resuming a replicated query".to_string();
            let err = HypervisorError::WasmEngineError(FailedToApplySystemChanges(msg));
            return Err(err.into_user_error(&clean_canister.canister_id()));
        }
        Ok(helper)
    }

    /// Finishes a replicated query execution that could have run multiple rounds
    /// due to deterministic time slicing.
    fn finish(
        mut self,
        mut output: WasmExecutionOutput,
        clean_canister: CanisterState,
        canister_state_changes: CanisterStateChanges,
        mut original: OriginalContext,
        round: RoundContext,
    ) -> ExecuteMessageResult {
        self.canister.append_log(&mut output.canister_log);
        self.canister
            .system_state
            .apply_ingress_induction_cycles_debit(
                self.canister.canister_id(),
                round.log,
                round.counters.charging_from_balance_error,
            );

        // Check that the cycles balance does not go below the freezing
        // threshold after applying the Wasm execution state changes.
        let old_balance = self.canister.system_state.balance();
        let requested = canister_state_changes.system_state_changes.removed_cycles();
        let reveal_top_up = self
            .canister
            .controllers()
            .contains(&original.call_origin.get_principal());
        if old_balance < requested + original.freezing_threshold {
            let err = CanisterOutOfCyclesError {
                canister_id: self.canister.canister_id(),
                available: old_balance,
                requested,
                threshold: original.freezing_threshold,
                reveal_top_up,
            };
            let err = UserError::new(ErrorCode::CanisterOutOfCycles, err);
            info!(
                round.log,
                "[DTS] Failed {:?} execution of canister {} due to concurrent cycle change: {:?}.",
                original.method,
                clean_canister.canister_id(),
                err,
            );
            // Perf counter: no need to update the call context, as it won't be saved.
            return finish_err(
                clean_canister,
                output.num_instructions_left,
                err,
                original,
                round,
            );
        }

        if let Err(err) = canister_state_changes.system_state_changes.apply_changes(
            round.time,
            &mut self.canister.system_state,
            round.network_topology,
            round.hypervisor.subnet_id(),
            round.log,
        ) {
            return finish_err(
                clean_canister,
                output.num_instructions_left,
                err.into_user_error(&original.canister_id),
                original,
                round,
            );
        }
        self.canister.system_state.canister_version += 1;
        self.deallocation_sender.send(Box::new(clean_canister));

        let is_wasm64_execution = self
            .canister
            .execution_state
            .as_ref()
            .is_some_and(|es| es.is_wasm64);
        round.cycles_account_manager.refund_unused_execution_cycles(
            &mut self.canister.system_state,
            output.num_instructions_left,
            original.execution_parameters.instruction_limits.message(),
            original.prepaid_execution_cycles,
            round.counters.execution_refund_error,
            original.subnet_size,
            is_wasm64_execution.into(),
            round.log,
        );

        let instructions_used = NumInstructions::from(
            original
                .execution_parameters
                .instruction_limits
                .message()
                .get()
                .saturating_sub(output.num_instructions_left.get()),
        );
        let (action, call_context) = self
            .canister
            .system_state
            .on_canister_result(
                self.call_context_id,
                None,
                output.wasm_result.clone(),
                instructions_used,
            )
            .unwrap();

        let result = output.wasm_result;
        let result = result.map_err(|err| err.into_user_error(&self.canister.canister_id()));
        let refund = match action {
            CallContextAction::Reply { refund, .. }
            | CallContextAction::Reject { refund, .. }
            | CallContextAction::NoResponse { refund, .. }
            | CallContextAction::Fail { refund, .. } => refund,
            CallContextAction::NotYetResponded | CallContextAction::AlreadyResponded => {
                original.call.take_cycles()
            }
        };
        let response = wasm_result_to_query_response(
            result,
            &self.canister,
            round.time,
            original.call_origin,
            round.log,
            refund,
        );

        ExecuteMessageResult::Finished {
            canister: self.canister,
            response,
            instructions_used,
            heap_delta: NumBytes::from(0),
            call_duration: call_context
                .map(|call_context| round.time.saturating_duration_since(call_context.time())),
        }
    }

    fn canister(&self) -> &CanisterState {
        &self.canister
    }

    fn call_context_id(&self) -> CallContextId {
        self.call_context_id
    }
}

#[derive(Debug)]
struct PausedReplicatedQueryExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    paused_helper: PausedReplicatedQueryHelper,
    original: OriginalContext,
}

impl PausedExecution for PausedReplicatedQueryExecution {
    fn resume(
        self: Box<Self>,
        clean_canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
        _subnet_size: usize,
        _call_tree_metrics: &dyn CallTreeMetrics,
        deallocation_sender: &DeallocationSender,
    ) -> ExecuteMessageResult {
        info!(
            round.log,
            "[DTS] Resuming {:?} execution of canister {}.",
            self.original.method,
            clean_canister.canister_id(),
        );
        let helper = match ReplicatedQueryHelper::resume(
            &clean_canister,
            &self.original,
            self.paused_helper,
            deallocation_sender,
        ) {
            Ok(helper) => helper,
            Err(err) => {
                info!(
                    round.log,
                    "[DTS] Failed to resume {:?} execution of canister {}: {:?}.",
                    self.original.method,
                    clean_canister.canister_id(),
                    err,
                );
                self.paused_wasm_execution.abort();
                return finish_err(
                    clean_canister,
                    self.original
                        .execution_parameters
                        .instruction_limits
                        .message(),
                    err,
                    self.original,
                    round,
                );
            }
        };

        let execution_state = helper.canister().execution_state.as_ref().unwrap();
        let result = self.paused_wasm_execution.resume(execution_state);
        match result {
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                info!(
                    round.log,
                    "[DTS] Pausing {:?} execution of canister {} after {} instructions.",
                    self.original.method,
                    clean_canister.canister_id(),
                    slice.executed_instructions,
                );
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedReplicatedQueryExecution {
                    paused_wasm_execution,
                    paused_helper: helper.pause(),
                    original: self.original,
                });
                ExecuteMessageResult::Paused {
                    canister: clean_canister,
                    paused_execution,
                    // Pausing a resumed execution doesn't change the ingress
                    // status.
                    ingress_status: None,
                }
            }
            WasmExecutionResult::Finished(slice, output, state_changes) => {
                let instructions_consumed = self
                    .original
                    .execution_parameters
                    .instruction_limits
                    .message()
                    - output.num_instructions_left;
                info!(
                    round.log,
                    "[DTS] Finished {:?} execution of canister {} after {} / {} instructions.",
                    self.original.method,
                    clean_canister.canister_id(),
                    slice.executed_instructions.display(),
                    instructions_consumed.display(),
                );
                update_round_limits(round_limits, &slice);
                helper.finish(output, clean_canister, state_changes, self.original, round)
            }
        }
    }

    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (CanisterMessageOrTask, Cycles) {
        info!(
            log,
            "[DTS] Aborting {:?} execution of canister {}",
            self.original.method,
            self.original.canister_id,
        );
        self.paused_wasm_execution.abort();
        let message_or_task = into_message_or_task(CanisterCallOrTask::Call(self.original.call));
        (message_or_task, self.original.prepaid_execution_cycles)
    }

    fn input(&self) -> CanisterMessageOrTask {
        into_message_or_task(CanisterCallOrTask::Call(self.original.call.clone()))
    }
}
