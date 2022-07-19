// This module defines how update messages and replicated queries are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#rule-message-execution
//
// A replicated query is a call to a `canister_query` function in update
// context.

use crate::execution::common::{
    action_to_response, validate_canister, validate_method, wasm_result_to_query_response,
};
use crate::execution_environment::{
    ExecuteMessageResult, ExecutionResponse, PausedExecution, RoundContext, RoundLimits,
};
use ic_config::flag_status::FlagStatus;
use ic_embedders::wasm_executor::{PausedWasmExecution, WasmExecutionResult};
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::messages::CanisterInputMessage;
use ic_interfaces::{execution_environment::HypervisorError, messages::RequestOrIngress};
use ic_logger::{error, info, ReplicaLogger};
use ic_replicated_state::{CallOrigin, CanisterState};
use ic_types::messages::CallContextId;
use ic_types::{
    ingress::{IngressState, IngressStatus},
    messages::{Payload, Response},
    CanisterId, NumBytes, NumInstructions, Time,
};

use ic_system_api::{ApiType, ExecutionParameters, InstructionLimits};
use ic_types::methods::{FuncRef, WasmMethod};

use super::common::update_round_limits;

fn early_error_to_result(
    user_error: UserError,
    canister: CanisterState,
    req: RequestOrIngress,
    time: Time,
) -> ExecuteMessageResult {
    let result = match req {
        RequestOrIngress::Request(request) => {
            let response = Response {
                originator: request.sender,
                respondent: canister.canister_id(),
                originator_reply_callback: request.sender_reply_callback,
                refund: request.payment,
                response_payload: Payload::from(Err(user_error)),
            };
            ExecutionResponse::Request(response)
        }
        RequestOrIngress::Ingress(ingress) => {
            let status = IngressStatus::Known {
                receiver: canister.canister_id().get(),
                user_id: ingress.source,
                time,
                state: IngressState::Failed(user_error),
            };
            ExecutionResponse::Ingress((ingress.message_id.clone(), status))
        }
    };
    ExecuteMessageResult {
        canister,
        response: result,
        heap_delta: NumBytes::from(0),
    }
}

fn validate_message(
    canister: &CanisterState,
    req: &RequestOrIngress,
    time: Time,
    log: &ReplicaLogger,
) -> Result<(), UserError> {
    validate_canister(canister)?;

    if let RequestOrIngress::Ingress(ingress) = req {
        if ingress.expiry_time < time {
            error!(log, "[EXC-BUG] Executing expired ingress message.");
            return Err(UserError::new(
                ErrorCode::IngressMessageTimeout,
                "Ingress message timed out waiting to start executing.",
            ));
        }
    }

    let query = WasmMethod::Query(req.method_name().to_string());
    if validate_method(&query, canister).is_err() {
        let update = WasmMethod::Update(req.method_name().to_string());
        validate_method(&update, canister)
            .map_err(|err| err.into_user_error(&canister.canister_id()))?;
    }

    Ok(())
}

// Execute an inter-canister request or an ingress message.
#[allow(clippy::too_many_arguments)]
pub fn execute_call(
    mut canister: CanisterState,
    req: RequestOrIngress,
    mut execution_parameters: ExecutionParameters,
    time: Time,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> ExecuteMessageResult {
    let is_query_call = canister.exports_query_method(req.method_name().to_string());
    if is_query_call {
        // A query call is expected to finish quickly, so DTS is not supported for it.
        let slice_instruction_limit = execution_parameters.instruction_limits.slice();
        execution_parameters.instruction_limits = InstructionLimits::new(
            FlagStatus::Disabled,
            slice_instruction_limit,
            slice_instruction_limit,
        )
    };
    // Withdraw execution cycles.
    let subnet_type = round.hypervisor.subnet_type();
    let memory_usage = canister.memory_usage(subnet_type);
    let compute_allocation = canister.scheduler_state.compute_allocation;
    if let Err(err) = round.cycles_account_manager.withdraw_execution_cycles(
        &mut canister.system_state,
        memory_usage,
        compute_allocation,
        execution_parameters.instruction_limits.message(),
    ) {
        let user_error = UserError::new(ErrorCode::CanisterOutOfCycles, err);
        return early_error_to_result(user_error, canister, req, time);
    }

    if let Err(user_error) = validate_message(&canister, &req, time, round.log) {
        round.cycles_account_manager.refund_execution_cycles(
            &mut canister.system_state,
            execution_parameters.instruction_limits.message(),
            execution_parameters.instruction_limits.message(),
        );
        return early_error_to_result(user_error, canister, req, time);
    }

    if is_query_call {
        execute_query_method(
            canister,
            req,
            time,
            execution_parameters,
            round,
            round_limits,
        )
    } else {
        execute_update_method(
            canister,
            req,
            time,
            execution_parameters,
            round,
            round_limits,
        )
    }
}

// Execute an update method from an inter-canister request
// or from an ingress message.
#[allow(clippy::too_many_arguments)]
fn execute_update_method(
    mut canister: CanisterState,
    mut req: RequestOrIngress,
    time: Time,
    execution_parameters: ExecutionParameters,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> ExecuteMessageResult {
    let call_origin = CallOrigin::from(&req);
    let method = WasmMethod::Update(req.method_name().to_string());
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

    let (output_execution_state, result) = round.hypervisor.execute_dts(
        api_type,
        canister.system_state.clone(),
        memory_usage,
        execution_parameters.clone(),
        FuncRef::Method(method),
        canister.execution_state.take().unwrap(),
        round_limits,
        round.network_topology,
    );
    canister.execution_state = Some(output_execution_state);
    let original = OriginalContext {
        call_context_id,
        call_origin,
        time,
        message_instruction_limit: execution_parameters.instruction_limits.message(),
        message: req,
    };
    process_update_result(canister, result, original, round, round_limits)
}

fn process_update_result(
    mut canister: CanisterState,
    result: WasmExecutionResult,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> ExecuteMessageResult {
    match result {
        WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
            update_round_limits(round_limits, &slice);
            let paused_execution = Box::new(PausedCallExecution {
                paused_wasm_execution,
                original,
            });
            ExecuteMessageResult {
                canister,
                response: ExecutionResponse::Paused(paused_execution),
                heap_delta: NumBytes::from(0),
            }
        }
        WasmExecutionResult::Finished(slice, output, system_state_changes) => {
            update_round_limits(round_limits, &slice);
            let heap_delta = if output.wasm_result.is_ok() {
                // TODO(RUN-265): Replace `unwrap` with a proper execution error
                // here because subnet available memory may have changed since
                // the start of execution.
                round_limits
                    .subnet_available_memory
                    .try_decrement(output.allocated_bytes, output.allocated_message_bytes)
                    .unwrap();
                system_state_changes.apply_changes(
                    round.time,
                    &mut canister.system_state,
                    round.network_topology,
                    round.hypervisor.subnet_id(),
                    round.log,
                );
                NumBytes::from((output.instance_stats.dirty_pages * ic_sys::PAGE_SIZE) as u64)
            } else {
                NumBytes::from(0)
            };

            let action = canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .on_canister_result(original.call_context_id, output.wasm_result);

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
            );
            ExecuteMessageResult {
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
        mut canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> ExecuteMessageResult {
        let execution_state = canister.execution_state.take().unwrap();
        let (execution_state, result) = self.paused_wasm_execution.resume(execution_state);
        canister.execution_state = Some(execution_state);
        process_update_result(canister, result, self.original, round, round_limits)
    }

    fn abort(self: Box<Self>) -> CanisterInputMessage {
        self.paused_wasm_execution.abort();
        match self.original.message {
            RequestOrIngress::Request(r) => CanisterInputMessage::Request(r),
            RequestOrIngress::Ingress(i) => CanisterInputMessage::Ingress(i),
        }
    }
}

// Execute a query method from an inter-canister request
// or from an ingress message.
#[allow(clippy::too_many_arguments)]
fn execute_query_method(
    mut canister: CanisterState,
    req: RequestOrIngress,
    time: Time,
    execution_parameters: ExecutionParameters,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> ExecuteMessageResult {
    let call_origin = CallOrigin::from(&req);

    let method = WasmMethod::Query(req.method_name().to_string());
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
        execution_parameters.clone(),
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
        execution_parameters.instruction_limits.message(),
    );

    ExecuteMessageResult {
        canister,
        response,
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
