// This module defines how update messages are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#rule-message-execution

use crate::execution::common::{
    action_to_response, apply_canister_state_changes, finish_call_with_error, update_round_limits,
    validate_message,
};
use crate::execution_environment::{
    ExecuteMessageResult, PausedExecution, RoundContext, RoundLimits,
};
use ic_embedders::wasm_executor::{CanisterStateChanges, PausedWasmExecution, WasmExecutionResult};
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::{HypervisorError, WasmExecutionOutput};
use ic_interfaces::messages::CanisterInputMessage;
use ic_interfaces::messages::RequestOrIngress;
use ic_replicated_state::{CallOrigin, CanisterState};
use ic_types::messages::CallContextId;
use ic_types::{Cycles, NumBytes, NumInstructions, Time};
use ic_wasm_types::WasmEngineError::FailedToApplySystemChanges;

use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::methods::{FuncRef, WasmMethod};

#[cfg(test)]
mod tests;

// Execute an inter-canister request or an ingress update message.
#[allow(clippy::too_many_arguments)]
pub fn execute_update(
    clean_canister: CanisterState,
    message: RequestOrIngress,
    execution_parameters: ExecutionParameters,
    time: Time,
    round: RoundContext,
    round_limits: &mut RoundLimits,
    subnet_size: usize,
) -> ExecuteMessageResult {
    let original = OriginalContext {
        call_origin: CallOrigin::from(&message),
        method: WasmMethod::Update(message.method_name().to_string()),
        message,
        execution_parameters,
        subnet_size,
        time,
    };

    let helper = match UpdateHelper::new(&clean_canister, &original, &round) {
        Ok(helper) => helper,
        Err(err) => return finish_err(clean_canister, err, original, round),
    };

    let api_type = ApiType::update(
        time,
        original.message.method_payload().to_vec(),
        original.message.cycles(),
        *original.message.sender(),
        helper.call_context_id(),
    );

    let memory_usage = helper
        .canister()
        .memory_usage(original.execution_parameters.subnet_type);
    let result = round.hypervisor.execute_dts(
        api_type,
        helper.canister().execution_state.as_ref().unwrap(),
        &helper.canister().system_state,
        memory_usage,
        original.execution_parameters.clone(),
        FuncRef::Method(original.method.clone()),
        round_limits,
        round.network_topology,
    );
    match result {
        WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
            update_round_limits(round_limits, &slice);
            let paused_execution = Box::new(PausedCallExecution {
                paused_wasm_execution,
                paused_helper: helper.pause(),
                original,
            });
            ExecuteMessageResult::Paused {
                canister: clean_canister,
                paused_execution,
            }
        }
        WasmExecutionResult::Finished(slice, output, state_changes) => {
            update_round_limits(round_limits, &slice);
            helper.finish(output, state_changes, original, round, round_limits)
        }
    }
}

/// Finishes an update call execution early due to an error. The only state
/// changes that are applied to the clean canister state are charging for and
/// accounting the executed instructions.
fn finish_err(
    clean_canister: CanisterState,
    err: UserError,
    original: OriginalContext,
    round: RoundContext,
) -> ExecuteMessageResult {
    let mut canister = clean_canister;

    // Note that at this point we know exactly how many instructions were
    // executed and could withdraw the fee for that directly, but we do that in
    // two steps (reserve and refund) to be consistent with the success path.
    let memory_usage = canister.memory_usage(original.execution_parameters.subnet_type);
    let instruction_limit = original.execution_parameters.instruction_limits.message();
    if let Err(err) = round.cycles_account_manager.withdraw_execution_cycles(
        &mut canister.system_state,
        memory_usage,
        original.execution_parameters.compute_allocation,
        instruction_limit,
        original.subnet_size,
    ) {
        let err = UserError::new(ErrorCode::CanisterOutOfCycles, err);
        return finish_call_with_error(err, canister, original.message, round.time);
    }

    round.cycles_account_manager.refund_execution_cycles(
        &mut canister.system_state,
        instruction_limit,
        instruction_limit,
        original.subnet_size,
    );

    finish_call_with_error(err, canister, original.message, round.time)
}

/// Context variables that remain the same throughout the entire deterministic
/// time slicing execution of an update call execution.
#[derive(Debug)]
struct OriginalContext {
    call_origin: CallOrigin,
    message: RequestOrIngress,
    method: WasmMethod,
    execution_parameters: ExecutionParameters,
    subnet_size: usize,
    time: Time,
}

/// Contains fields of `UpdateHelper` that are necessary for resuming an update
/// call execution.
#[derive(Debug)]
struct PausedUpdateHelper {
    call_context_id: CallContextId,
    cycles_balance_after_withdrawal: Cycles,
}

/// A helper that implements and keeps track of update call steps.
/// It is used to safely pause and resume an update call execution.
struct UpdateHelper {
    canister: CanisterState,
    call_context_id: CallContextId,
    cycles_balance_after_withdrawal: Cycles,
}

impl UpdateHelper {
    /// Applies the initial state changes and performs the initial validation.
    fn new(
        clean_canister: &CanisterState,
        original: &OriginalContext,
        round: &RoundContext,
    ) -> Result<Self, UserError> {
        let mut canister = clean_canister.clone();

        // Withdraw execution cycles.
        let memory_usage = canister.memory_usage(original.execution_parameters.subnet_type);
        round
            .cycles_account_manager
            .withdraw_execution_cycles(
                &mut canister.system_state,
                memory_usage,
                original.execution_parameters.compute_allocation,
                original.execution_parameters.instruction_limits.message(),
                original.subnet_size,
            )
            .map_err(|err| UserError::new(ErrorCode::CanisterOutOfCycles, err))?;

        validate_message(
            &canister,
            &original.message,
            &original.method,
            original.time,
            round.log,
        )?;

        let call_context_id = canister
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                original.call_origin.clone(),
                original.message.cycles(),
                original.time,
            );

        let cycles_balance_after_withdrawal = canister.system_state.balance();

        Ok(Self {
            canister,
            call_context_id,
            cycles_balance_after_withdrawal,
        })
    }

    /// Returns a struct with all the necessary information to replay the
    /// performed update call steps in subsequent rounds.
    fn pause(self) -> PausedUpdateHelper {
        PausedUpdateHelper {
            call_context_id: self.call_context_id,
            cycles_balance_after_withdrawal: self.cycles_balance_after_withdrawal,
        }
    }

    /// Replays the previous update call steps on the given clean canister.
    /// Returns an error if any step fails. Otherwise, it returns an instance of
    /// the helper that can be used to continue the update call execution.
    fn resume(
        clean_canister: &CanisterState,
        original: &OriginalContext,
        round: &RoundContext,
        paused: PausedUpdateHelper,
    ) -> Result<Self, UserError> {
        let helper = Self::new(clean_canister, original, round)?;
        if helper.cycles_balance_after_withdrawal != paused.cycles_balance_after_withdrawal {
            let msg = "Mismatch in cycles balance when resuming an update call".to_string();
            let err = HypervisorError::WasmEngineError(FailedToApplySystemChanges(msg));
            return Err(err.into_user_error(&clean_canister.canister_id()));
        }
        if helper.call_context_id != paused.call_context_id {
            let msg = "Mismatch in call context id when resuming an update call".to_string();
            let err = HypervisorError::WasmEngineError(FailedToApplySystemChanges(msg));
            return Err(err.into_user_error(&clean_canister.canister_id()));
        }
        Ok(helper)
    }

    /// Finishes an update call execution that could have run multiple rounds
    /// due to determnistic time slicing.
    fn finish(
        mut self,
        mut output: WasmExecutionOutput,
        canister_state_changes: Option<CanisterStateChanges>,
        original: OriginalContext,
        round: RoundContext,
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
        let heap_delta = if output.wasm_result.is_ok() {
            NumBytes::from((output.instance_stats.dirty_pages * ic_sys::PAGE_SIZE) as u64)
        } else {
            NumBytes::from(0)
        };

        let action = self
            .canister
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .on_canister_result(self.call_context_id, None, output.wasm_result);

        let response = action_to_response(
            &self.canister,
            action,
            original.call_origin,
            round.time,
            round.log,
        );
        round.cycles_account_manager.refund_execution_cycles(
            &mut self.canister.system_state,
            output.num_instructions_left,
            original.execution_parameters.instruction_limits.message(),
            original.subnet_size,
        );
        let instructions_used = NumInstructions::from(
            original
                .execution_parameters
                .instruction_limits
                .message()
                .get()
                .saturating_sub(output.num_instructions_left.get()),
        );
        ExecuteMessageResult::Finished {
            canister: self.canister,
            response,
            instructions_used,
            heap_delta,
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
struct PausedCallExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    paused_helper: PausedUpdateHelper,
    original: OriginalContext,
}

impl PausedExecution for PausedCallExecution {
    fn resume(
        self: Box<Self>,
        clean_canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
        _subnet_size: usize,
    ) -> ExecuteMessageResult {
        let helper =
            match UpdateHelper::resume(&clean_canister, &self.original, &round, self.paused_helper)
            {
                Ok(helper) => helper,
                Err(err) => {
                    self.paused_wasm_execution.abort();
                    return finish_err(clean_canister, err, self.original, round);
                }
            };

        let execution_state = helper.canister().execution_state.as_ref().unwrap();
        let result = self.paused_wasm_execution.resume(execution_state);
        match result {
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedCallExecution {
                    paused_wasm_execution,
                    paused_helper: helper.pause(),
                    original: self.original,
                });
                ExecuteMessageResult::Paused {
                    canister: clean_canister,
                    paused_execution,
                }
            }
            WasmExecutionResult::Finished(slice, output, state_changes) => {
                update_round_limits(round_limits, &slice);
                helper.finish(output, state_changes, self.original, round, round_limits)
            }
        }
    }

    fn abort(self: Box<Self>) -> CanisterInputMessage {
        self.paused_wasm_execution.abort();
        match self.original.message {
            RequestOrIngress::Request(r) => CanisterInputMessage::Request(r),
            RequestOrIngress::Ingress(i) => CanisterInputMessage::Ingress(i),
        }
    }
}
