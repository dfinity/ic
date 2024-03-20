// This module defines how replicated queries are executed.
// See https://internetcomputer.org/docs/interface-spec/index.html#rule-message-execution
//
// A replicated query is a call to a `canister_query` function in update
// context.

use std::time::Duration;

use crate::execution::common::{
    finish_call_with_error, validate_message, wasm_result_to_query_response,
};
use crate::execution_environment::{ExecuteMessageResult, RoundContext, RoundLimits};
use crate::metrics::CallTreeMetricsNoOp;
use ic_error_types::{ErrorCode, UserError};
use ic_replicated_state::{CallOrigin, CanisterState};
use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::methods::{FuncRef, WasmMethod};
use ic_types::{
    messages::{CanisterCall, CanisterCallOrTask},
    NumBytes, NumInstructions, Time,
};
use prometheus::IntCounter;

// Execute an inter-canister request or an ingress message as a replicated query.
#[allow(clippy::too_many_arguments)]
pub fn execute_replicated_query(
    mut canister: CanisterState,
    mut req: CanisterCall,
    method: WasmMethod,
    execution_parameters: ExecutionParameters,
    time: Time,
    round: RoundContext,
    round_limits: &mut RoundLimits,
    subnet_size: usize,
    state_changes_error: &IntCounter,
) -> ExecuteMessageResult {
    // A replicated query runs without DTS.
    let instruction_limits = &execution_parameters.instruction_limits;
    assert_eq!(instruction_limits.message(), instruction_limits.slice());
    let instruction_limit = instruction_limits.message();
    // Withdraw execution cycles.
    let memory_usage = canister.memory_usage();
    let message_memory_usage = canister.message_memory_usage();
    let compute_allocation = canister.scheduler_state.compute_allocation;

    let reveal_top_up = canister.controllers().contains(req.sender());
    let prepaid_execution_cycles = match round.cycles_account_manager.prepay_execution_cycles(
        &mut canister.system_state,
        memory_usage,
        message_memory_usage,
        compute_allocation,
        instruction_limit,
        subnet_size,
        reveal_top_up,
    ) {
        Ok(cycles) => cycles,
        Err(err) => {
            return finish_call_with_error(
                UserError::new(ErrorCode::CanisterOutOfCycles, err),
                canister,
                CanisterCallOrTask::Call(req),
                NumInstructions::from(0),
                time,
                execution_parameters.subnet_type,
                round.log,
            );
        }
    };

    if let WasmMethod::CompositeQuery(_) = &method {
        round.cycles_account_manager.refund_unused_execution_cycles(
            &mut canister.system_state,
            instruction_limit,
            instruction_limit,
            prepaid_execution_cycles,
            round.counters.execution_refund_error,
            subnet_size,
            round.log,
        );
        let user_error = UserError::new(
            ErrorCode::CompositeQueryCalledInReplicatedMode,
            "Composite query cannot be called in replicated mode",
        );
        return finish_call_with_error(
            user_error,
            canister,
            CanisterCallOrTask::Call(req),
            NumInstructions::from(0),
            time,
            execution_parameters.subnet_type,
            round.log,
        );
    }

    if let Err(user_error) = validate_message(&canister, &method) {
        round.cycles_account_manager.refund_unused_execution_cycles(
            &mut canister.system_state,
            instruction_limit,
            instruction_limit,
            prepaid_execution_cycles,
            round.counters.execution_refund_error,
            subnet_size,
            round.log,
        );
        return finish_call_with_error(
            user_error,
            canister,
            CanisterCallOrTask::Call(req),
            NumInstructions::from(0),
            time,
            execution_parameters.subnet_type,
            round.log,
        );
    }

    let call_origin = CallOrigin::from(&req);

    let memory_usage = canister.memory_usage();
    let message_memory_usage = canister.message_memory_usage();

    let api_type =
        ApiType::replicated_query(time, req.method_payload().to_vec(), *req.sender(), None);

    // As we are executing the query in the replicated mode, we do
    // not want to commit updates, i.e. we must return the
    // unmodified version of the canister. Hence, execute on clones
    // of system and execution states so that we have the original
    // versions.
    let (mut output, _output_execution_state, _output_system_state) = round.hypervisor.execute(
        api_type,
        time,
        canister.system_state.clone(),
        memory_usage,
        message_memory_usage,
        execution_parameters,
        FuncRef::Method(method),
        canister.execution_state.clone().unwrap(),
        round.network_topology,
        round_limits,
        state_changes_error,
        &CallTreeMetricsNoOp,
        time,
    );

    canister.append_log(&mut output.canister_log);
    let result = output.wasm_result;
    let log = round.log;
    let result = result.map_err(|err| err.into_user_error(&canister.canister_id()));
    let response =
        wasm_result_to_query_response(result, &canister, time, call_origin, log, req.take_cycles());

    round.cycles_account_manager.refund_unused_execution_cycles(
        &mut canister.system_state,
        output.num_instructions_left,
        instruction_limit,
        prepaid_execution_cycles,
        round.counters.execution_refund_error,
        subnet_size,
        round.log,
    );

    let instructions_used = NumInstructions::from(
        instruction_limit
            .get()
            .saturating_sub(output.num_instructions_left.get()),
    );

    ExecuteMessageResult::Finished {
        canister,
        response,
        instructions_used,
        heap_delta: NumBytes::from(0),
        call_duration: Some(Duration::from_secs(0)),
    }
}
