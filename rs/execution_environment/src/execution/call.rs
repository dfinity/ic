// This module defines how update messages and replicated queries are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#rule-message-execution
//
// A replicated query is a call to a `canister_query` function in update
// context.

use crate::execution::common::{
    action_to_result, validate_canister, validate_method, wasm_result_to_query_exec_result,
};
use crate::hypervisor::Hypervisor;
use ic_config::execution_environment::Config as ExecutionConfig;
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::{
    execution_environment::{
        AvailableMemory, ExecResult, ExecuteMessageResult, ExecutionMode, ExecutionParameters,
        HypervisorError, SubnetAvailableMemory,
    },
    messages::RequestOrIngress,
};
use ic_logger::{error, info, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CallOrigin, CanisterState, NetworkTopology};
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
) -> ExecuteMessageResult<CanisterState> {
    let result = match req {
        RequestOrIngress::Request(request) => {
            let response = Response {
                originator: request.sender,
                respondent: canister.canister_id(),
                originator_reply_callback: request.sender_reply_callback,
                refund: request.payment,
                response_payload: Payload::from(Err(user_error)),
            };
            ExecResult::ResponseResult(response)
        }
        RequestOrIngress::Ingress(ingress) => {
            let status = IngressStatus::Known {
                receiver: canister.canister_id().get(),
                user_id: ingress.source,
                time,
                state: IngressState::Failed(user_error),
            };
            ExecResult::IngressResult((ingress.message_id, status))
        }
    };
    ExecuteMessageResult {
        canister,
        num_instructions_left: cycles,
        result,
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
    cycles: NumInstructions,
    time: Time,
    network_topology: Arc<NetworkTopology>,
    subnet_available_memory: SubnetAvailableMemory,
    config: &ExecutionConfig,
    subnet_type: SubnetType,
    hypervisor: &Hypervisor,
    cycles_account_manager: &CyclesAccountManager,
    log: &ReplicaLogger,
) -> ExecuteMessageResult<CanisterState> {
    let memory_usage = canister.memory_usage(subnet_type);
    let compute_allocation = canister.scheduler_state.compute_allocation;
    if let Err(err) = cycles_account_manager.withdraw_execution_cycles(
        &mut canister.system_state,
        memory_usage,
        compute_allocation,
        cycles,
    ) {
        let user_error = UserError::new(ErrorCode::CanisterOutOfCycles, err);
        return early_error_to_result(user_error, canister, req, cycles, time);
    }

    let mut execution_parameters = ExecutionParameters {
        total_instruction_limit: cycles,
        slice_instruction_limit: cycles,
        canister_memory_limit: canister.memory_limit(config.max_canister_memory_size),
        subnet_available_memory,
        compute_allocation: canister.scheduler_state.compute_allocation,
        subnet_type,
        execution_mode: ExecutionMode::Replicated,
    };

    let mut result = if let Err(user_error) = validate_message(&canister, &req, time, log) {
        early_error_to_result(user_error, canister, req, cycles, time)
    } else if canister.exports_query_method(req.method_name().to_string()) {
        // Letting the canister grow arbitrarily when executing the
        // query is fine as we do not persist state modifications.
        execution_parameters.subnet_available_memory = subnet_memory_capacity(config);

        execute_query_method(
            canister,
            req,
            time,
            &network_topology,
            execution_parameters,
            hypervisor,
            log,
        )
    } else {
        execute_update_method(
            canister,
            req,
            time,
            network_topology,
            execution_parameters,
            hypervisor,
            log,
        )
    };

    cycles_account_manager.refund_execution_cycles(
        &mut result.canister.system_state,
        result.num_instructions_left,
        cycles,
    );

    result
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
    hypervisor: &Hypervisor,
    log: &ReplicaLogger,
) -> ExecuteMessageResult<CanisterState> {
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

    let (output, output_execution_state, output_system_state) = hypervisor.execute(
        api_type,
        canister.system_state.clone(),
        memory_usage,
        execution_parameters,
        FuncRef::Method(method),
        canister.execution_state.take().unwrap(),
        &network_topology,
    );

    canister.execution_state = Some(output_execution_state);
    let heap_delta = if output.wasm_result.is_ok() {
        canister.system_state = output_system_state;
        NumBytes::from((output.instance_stats.dirty_pages * ic_sys::PAGE_SIZE) as u64)
    } else {
        // In contrast to other methods, update methods ignore the
        // Wasm execution error and return 0 as the heap delta.
        NumBytes::from(0)
    };

    let action = canister
        .system_state
        .call_context_manager_mut()
        .unwrap()
        .on_canister_result(call_context_id, output.wasm_result);

    let result = action_to_result(&canister, action, call_origin, time, log);

    ExecuteMessageResult {
        canister,
        num_instructions_left: output.num_instructions_left,
        result,
        heap_delta,
    }
}

// Execute a query method from an inter-canister request
// or from an ingress message.
fn execute_query_method(
    canister: CanisterState,
    req: RequestOrIngress,
    time: Time,
    network_topology: &NetworkTopology,
    execution_parameters: ExecutionParameters,
    hypervisor: &Hypervisor,
    log: &ReplicaLogger,
) -> ExecuteMessageResult<CanisterState> {
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
        execution_parameters,
        FuncRef::Method(method),
        canister.execution_state.clone().unwrap(),
        network_topology,
    );

    let result = output.wasm_result;
    let result =
        result.map_err(|err| log_and_transform_to_user_error(log, err, &canister.canister_id()));
    let result = wasm_result_to_query_exec_result(result, &canister, time, call_origin, log);

    ExecuteMessageResult {
        canister,
        num_instructions_left: output.num_instructions_left,
        result,
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
