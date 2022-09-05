// This module defines how update messages are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#rule-message-execution

use crate::execution::common::{
    action_to_response, apply_canister_state_changes, finish_call_with_error, update_round_limits,
    validate_message,
};
use crate::execution_environment::{
    ExecuteMessageResult, PausedExecution, RoundContext, RoundLimits,
};
use ic_embedders::wasm_executor::{PausedWasmExecution, WasmExecutionResult};
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::messages::CanisterInputMessage;
use ic_interfaces::messages::RequestOrIngress;
use ic_replicated_state::{CallOrigin, CanisterState};
use ic_types::messages::CallContextId;
use ic_types::{NumBytes, NumInstructions, Time};

use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::methods::{FuncRef, WasmMethod};

// Execute an inter-canister request or an ingress message.
#[allow(clippy::too_many_arguments)]
pub fn execute_update(
    mut canister: CanisterState,
    mut req: RequestOrIngress,
    execution_parameters: ExecutionParameters,
    time: Time,
    round: RoundContext,
    round_limits: &mut RoundLimits,
    subnet_size: usize,
) -> ExecuteMessageResult {
    // Withdraw execution cycles.
    let subnet_type = round.hypervisor.subnet_type();
    let memory_usage = canister.memory_usage(subnet_type);
    let compute_allocation = canister.scheduler_state.compute_allocation;
    if let Err(err) = round.cycles_account_manager.withdraw_execution_cycles(
        &mut canister.system_state,
        memory_usage,
        compute_allocation,
        execution_parameters.instruction_limits.message(),
        subnet_size,
    ) {
        let user_error = UserError::new(ErrorCode::CanisterOutOfCycles, err);
        return finish_call_with_error(user_error, canister, req, time);
    }

    let method = WasmMethod::Update(req.method_name().to_string());
    if let Err(user_error) = validate_message(&canister, &req, &method, time, round.log) {
        round.cycles_account_manager.refund_execution_cycles(
            &mut canister.system_state,
            execution_parameters.instruction_limits.message(),
            execution_parameters.instruction_limits.message(),
            subnet_size,
        );
        return finish_call_with_error(user_error, canister, req, time);
    }

    let call_origin = CallOrigin::from(&req);
    let memory_usage = canister.memory_usage(round.hypervisor.subnet_type());
    let incoming_cycles = req.take_cycles();

    let call_context_id = canister
        .system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(call_origin.clone(), incoming_cycles, time);

    let api_type = ApiType::update(
        time,
        req.method_payload().to_vec(),
        incoming_cycles,
        *req.sender(),
        call_context_id,
    );

    let result = round.hypervisor.execute_dts(
        api_type,
        canister.execution_state.as_ref().unwrap(),
        &canister.system_state,
        memory_usage,
        execution_parameters.clone(),
        FuncRef::Method(method),
        round_limits,
        round.network_topology,
    );
    let original = OriginalContext {
        call_context_id,
        call_origin,
        time,
        message_instruction_limit: execution_parameters.instruction_limits.message(),
        message: req,
    };
    process_update_result(canister, result, original, round, round_limits, subnet_size)
}

fn process_update_result(
    mut canister: CanisterState,
    result: WasmExecutionResult,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
    subnet_size: usize,
) -> ExecuteMessageResult {
    match result {
        WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
            update_round_limits(round_limits, &slice);
            let paused_execution = Box::new(PausedCallExecution {
                paused_wasm_execution,
                original,
            });
            ExecuteMessageResult::Paused {
                canister,
                paused_execution,
            }
        }
        WasmExecutionResult::Finished(slice, mut output, canister_state_changes) => {
            update_round_limits(round_limits, &slice);
            apply_canister_state_changes(
                canister_state_changes,
                canister.execution_state.as_mut().unwrap(),
                &mut canister.system_state,
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

            let action = canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .on_canister_result(original.call_context_id, None, output.wasm_result);

            let response = action_to_response(
                &canister,
                action,
                original.call_origin,
                original.time,
                round.log,
            );
            round.cycles_account_manager.refund_execution_cycles(
                &mut canister.system_state,
                output.num_instructions_left,
                original.message_instruction_limit,
                subnet_size,
            );
            ExecuteMessageResult::Finished {
                canister,
                response,
                heap_delta,
            }
        }
    }
}

/// Context variables that remain the same throughput the entire deterministic
/// time slicing execution of a call.
#[derive(Debug)]
struct OriginalContext {
    call_context_id: CallContextId,
    call_origin: CallOrigin,
    time: Time,
    message_instruction_limit: NumInstructions,
    message: RequestOrIngress,
}

#[derive(Debug)]
struct PausedCallExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    original: OriginalContext,
}

impl PausedExecution for PausedCallExecution {
    fn resume(
        self: Box<Self>,
        canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
    ) -> ExecuteMessageResult {
        let execution_state = canister.execution_state.as_ref().unwrap();
        let result = self.paused_wasm_execution.resume(execution_state);
        process_update_result(
            canister,
            result,
            self.original,
            round,
            round_limits,
            subnet_size,
        )
    }

    fn abort(self: Box<Self>) -> CanisterInputMessage {
        self.paused_wasm_execution.abort();
        match self.original.message {
            RequestOrIngress::Request(r) => CanisterInputMessage::Request(r),
            RequestOrIngress::Ingress(i) => CanisterInputMessage::Ingress(i),
        }
    }
}
