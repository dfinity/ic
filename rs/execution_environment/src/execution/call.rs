// This module defines how update messages and replicated queries are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#rule-message-execution
//
// A replicated query is a call to a `canister_query` function in update
// context.

use crate::execution::common::{
    action_to_response, validate_canister, validate_method, wasm_result_to_query_response,
};
use crate::execution_environment::{
    ExecuteMessageResult, ExecutionResponse, PausedExecution, RoundContext,
};
use crate::hypervisor::Hypervisor;
use ic_config::execution_environment::Config as ExecutionConfig;
use ic_embedders::wasm_executor::{PausedWasmExecution, WasmExecutionResult};
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::messages::CanisterInputMessage;
use ic_interfaces::{
    execution_environment::{
        AvailableMemory, ExecutionMode, ExecutionParameters, HypervisorError, SubnetAvailableMemory,
    },
    messages::RequestOrIngress,
};
use ic_logger::{error, info, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CallOrigin, CanisterState, NetworkTopology};
use ic_types::messages::CallContextId;
use ic_types::{
    ingress::{IngressState, IngressStatus},
    messages::{Payload, Response},
    CanisterId, NumBytes, NumInstructions, Time,
};

use ic_cycles_account_manager::CyclesAccountManager;
use ic_system_api::ApiType;
use ic_types::methods::{FuncRef, WasmMethod};
use std::{convert::Into, sync::Arc};

fn early_error_to_result(
    user_error: UserError,
    canister: CanisterState,
    req: RequestOrIngress,
    cycles: NumInstructions,
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
        num_instructions_left: cycles,
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
    instruction_limit: NumInstructions,
    time: Time,
    network_topology: Arc<NetworkTopology>,
    subnet_available_memory: SubnetAvailableMemory,
    config: &ExecutionConfig,
    subnet_type: SubnetType,
    hypervisor: &Hypervisor,
    cycles_account_manager: &CyclesAccountManager,
    log: &ReplicaLogger,
) -> ExecuteMessageResult {
    let memory_usage = canister.memory_usage(subnet_type);
    let compute_allocation = canister.scheduler_state.compute_allocation;
    if let Err(err) = cycles_account_manager.withdraw_execution_cycles(
        &mut canister.system_state,
        memory_usage,
        compute_allocation,
        instruction_limit,
    ) {
        let user_error = UserError::new(ErrorCode::CanisterOutOfCycles, err);
        return early_error_to_result(user_error, canister, req, instruction_limit, time);
    }

    let mut execution_parameters = ExecutionParameters {
        total_instruction_limit: instruction_limit,
        slice_instruction_limit: instruction_limit,
        canister_memory_limit: canister.memory_limit(config.max_canister_memory_size),
        compute_allocation: canister.scheduler_state.compute_allocation,
        subnet_type,
        execution_mode: ExecutionMode::Replicated,
    };

    if let Err(user_error) = validate_message(&canister, &req, time, log) {
        let mut result = early_error_to_result(user_error, canister, req, instruction_limit, time);
        cycles_account_manager.refund_execution_cycles(
            &mut result.canister.system_state,
            result.num_instructions_left,
            instruction_limit,
        );
        result
    } else if canister.exports_query_method(req.method_name().to_string()) {
        // Letting the canister grow arbitrarily when executing the
        // query is fine as we do not persist state modifications.
        let subnet_available_memory = subnet_memory_capacity(config);
        // DTS is not supported in query calls.
        execution_parameters.total_instruction_limit = execution_parameters.slice_instruction_limit;
        execute_query_method(
            canister,
            req,
            time,
            &network_topology,
            execution_parameters,
            subnet_available_memory,
            hypervisor,
            cycles_account_manager,
            log,
        )
    } else {
        execute_update_method(
            canister,
            req,
            time,
            network_topology,
            execution_parameters,
            subnet_available_memory,
            hypervisor,
            cycles_account_manager,
            log,
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
    network_topology: Arc<NetworkTopology>,
    execution_parameters: ExecutionParameters,
    subnet_available_memory: SubnetAvailableMemory,
    hypervisor: &Hypervisor,
    cycles_account_manager: &CyclesAccountManager,
    log: &ReplicaLogger,
) -> ExecuteMessageResult {
    let call_origin = CallOrigin::from(&req);
    let method = WasmMethod::Update(req.method_name().to_string());
    let memory_usage = canister.memory_usage(hypervisor.subnet_type());
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

    let (output_execution_state, result) = hypervisor.execute_dts(
        api_type,
        canister.system_state.clone(),
        memory_usage,
        execution_parameters.clone(),
        subnet_available_memory.clone(),
        FuncRef::Method(method),
        canister.execution_state.take().unwrap(),
    );
    canister.execution_state = Some(output_execution_state);
    let original = OriginalContext {
        call_context_id,
        call_origin,
        time,
        total_instruction_limit: execution_parameters.total_instruction_limit,
        message: req,
    };
    let round = RoundContext {
        subnet_available_memory,
        network_topology: &*network_topology,
        hypervisor,
        cycles_account_manager,
        log,
    };
    process_update_result(canister, result, original, round)
}

fn process_update_result(
    mut canister: CanisterState,
    result: WasmExecutionResult,
    original: OriginalContext,
    round: RoundContext,
) -> ExecuteMessageResult {
    match result {
        WasmExecutionResult::Paused(paused_wasm_execution) => {
            let paused_execution = Box::new(PausedCallExecution {
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
        WasmExecutionResult::Finished(output, system_state_changes) => {
            let heap_delta = if output.wasm_result.is_ok() {
                system_state_changes.apply_changes(
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
                original.total_instruction_limit,
            );
            ExecuteMessageResult {
                canister,
                num_instructions_left: output.num_instructions_left,
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
    total_instruction_limit: NumInstructions,
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
    ) -> ExecuteMessageResult {
        let execution_state = canister.execution_state.take().unwrap();
        let (execution_state, result) = self
            .paused_wasm_execution
            .resume(execution_state, round.subnet_available_memory.clone());
        canister.execution_state = Some(execution_state);
        process_update_result(canister, result, self.original, round)
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
    network_topology: &NetworkTopology,
    execution_parameters: ExecutionParameters,
    subnet_available_memory: SubnetAvailableMemory,
    hypervisor: &Hypervisor,
    cycles_account_manager: &CyclesAccountManager,
    log: &ReplicaLogger,
) -> ExecuteMessageResult {
    let call_origin = CallOrigin::from(&req);

    let method = WasmMethod::Query(req.method_name().to_string());
    let memory_usage = canister.memory_usage(hypervisor.subnet_type());

    let api_type =
        ApiType::replicated_query(time, req.method_payload().to_vec(), *req.sender(), None);

    // As we are executing the query in the replicated mode, we do
    // not want to commit updates, i.e. we must return the
    // unmodified version of the canister. Hence, execute on clones
    // of system and execution states so that we have the original
    // versions.
    let (output, _output_execution_state, _output_system_state) = hypervisor.execute(
        api_type,
        canister.system_state.clone(),
        memory_usage,
        execution_parameters.clone(),
        subnet_available_memory,
        FuncRef::Method(method),
        canister.execution_state.clone().unwrap(),
        network_topology,
    );

    let result = output.wasm_result;
    let result =
        result.map_err(|err| log_and_transform_to_user_error(log, err, &canister.canister_id()));
    let response = wasm_result_to_query_response(result, &canister, time, call_origin, log);

    cycles_account_manager.refund_execution_cycles(
        &mut canister.system_state,
        output.num_instructions_left,
        execution_parameters.slice_instruction_limit,
    );

    ExecuteMessageResult {
        canister,
        num_instructions_left: output.num_instructions_left,
        response,
        heap_delta: NumBytes::from(0),
    }
}

/// Returns the subnet's configured memory capacity (ignoring current usage).
pub(crate) fn subnet_memory_capacity(config: &ExecutionConfig) -> SubnetAvailableMemory {
    AvailableMemory::new(
        config.subnet_memory_capacity.get() as i64,
        config.subnet_message_memory_capacity.get() as i64,
    )
    .into()
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
