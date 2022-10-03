// This module defines how replicated queries are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#rule-message-execution
//
// A replicated query is a call to a `canister_query` function in update
// context.

use crate::execution::common::{
    finish_call_with_error, validate_message, wasm_result_to_query_response,
};
use crate::execution_environment::{ExecuteMessageResult, RoundContext, RoundLimits};
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::{execution_environment::HypervisorError, messages::RequestOrIngress};
use ic_logger::{info, ReplicaLogger};
use ic_replicated_state::{CallOrigin, CanisterState};
use ic_types::{CanisterId, NumBytes, NumInstructions, Time};

use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::methods::{FuncRef, WasmMethod};

// Execute an inter-canister request or an ingress message as a replicated query.
#[allow(clippy::too_many_arguments)]
pub fn execute_replicated_query(
    mut canister: CanisterState,
    req: RequestOrIngress,
    execution_parameters: ExecutionParameters,
    time: Time,
    round: RoundContext,
    round_limits: &mut RoundLimits,
    subnet_size: usize,
) -> ExecuteMessageResult {
    let instruction_limit = execution_parameters.instruction_limits.message();
    // Withdraw execution cycles.
    let subnet_type = round.hypervisor.subnet_type();
    let memory_usage = canister.memory_usage(subnet_type);
    let compute_allocation = canister.scheduler_state.compute_allocation;
    if let Err(err) = round.cycles_account_manager.withdraw_execution_cycles(
        &mut canister.system_state,
        memory_usage,
        compute_allocation,
        instruction_limit,
        subnet_size,
    ) {
        let user_error = UserError::new(ErrorCode::CanisterOutOfCycles, err);
        return finish_call_with_error(user_error, canister, req, time);
    }

    let method = WasmMethod::Query(req.method_name().to_string());

    if let Err(user_error) = validate_message(&canister, &req, &method, time, round.log) {
        round.cycles_account_manager.refund_execution_cycles(
            &mut canister.system_state,
            instruction_limit,
            instruction_limit,
            subnet_size,
        );
        return finish_call_with_error(user_error, canister, req, time);
    }

    let call_origin = CallOrigin::from(&req);

    let memory_usage = canister.memory_usage(round.hypervisor.subnet_type());

    let api_type =
        ApiType::replicated_query(time, req.method_payload().to_vec(), *req.sender(), None);

    // As we are executing the query in the replicated mode, we do
    // not want to commit updates, i.e. we must return the
    // unmodified version of the canister. Hence, execute on clones
    // of system and execution states so that we have the original
    // versions.
    let (output, _output_execution_state, _output_system_state) = round.hypervisor.execute(
        api_type,
        time,
        canister.system_state.clone(),
        memory_usage,
        execution_parameters,
        FuncRef::Method(method),
        canister.execution_state.clone().unwrap(),
        round.network_topology,
        round_limits,
    );

    let result = output.wasm_result;
    let log = round.log;
    let result =
        result.map_err(|err| log_and_transform_to_user_error(log, err, &canister.canister_id()));
    let response = wasm_result_to_query_response(result, &canister, time, call_origin, log);

    round.cycles_account_manager.refund_execution_cycles(
        &mut canister.system_state,
        output.num_instructions_left,
        instruction_limit,
        subnet_size,
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
    }
}

fn log_and_transform_to_user_error(
    log: &ReplicaLogger,
    hypervisor_err: HypervisorError,
    canister_id: &CanisterId,
) -> UserError {
    let user_error = hypervisor_err.into_user_error(canister_id);
    info!(
        log,
        "Executing message on {} failed with {:?}", canister_id, user_error
    );
    user_error
}
