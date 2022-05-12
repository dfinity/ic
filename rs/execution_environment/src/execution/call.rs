// This module defines how update messages and replicated queries are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#rule-message-execution
//
// A replicated query is a call to a `canister_query` function in update
// context.
//
// TODO(RUN-60): Move update/replicated-query execution functions here.

use crate::execution::common::action_to_result;
use crate::{hypervisor::Hypervisor, QueryExecutionType};
use ic_config::execution_environment::Config as ExecutionConfig;
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::CanisterStatusType;
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
    ingress::IngressStatus,
    messages::{Ingress, Payload, Request, Response},
    CanisterId, Cycles, NumBytes, NumInstructions, Time,
};

use std::{convert::Into, sync::Arc};

fn validate_canister(canister: &CanisterState) -> Result<(), UserError> {
    if CanisterStatusType::Running != canister.status() {
        let canister_id = canister.canister_id();
        let err_code = match canister.status() {
            CanisterStatusType::Running => unreachable!(),
            CanisterStatusType::Stopping => ErrorCode::CanisterStopping,
            CanisterStatusType::Stopped => ErrorCode::CanisterStopped,
        };
        let err_msg = format!("Canister {} is not running", canister_id);
        return Err(UserError::new(err_code, err_msg));
    }
    Ok(())
}

// Execute an inter-canister request.
#[allow(clippy::too_many_arguments)]
pub fn execute_request_call(
    canister: CanisterState,
    req: Request,
    cycles: NumInstructions,
    time: Time,
    network_topology: Arc<NetworkTopology>,
    subnet_available_memory: SubnetAvailableMemory,
    config: &ExecutionConfig,
    subnet_type: SubnetType,
    hypervisor: &Hypervisor,
    log: &ReplicaLogger,
) -> ExecuteMessageResult<CanisterState> {
    if let Err(user_error) = validate_canister(&canister) {
        let response = Response {
            originator: req.sender,
            respondent: canister.canister_id(),
            originator_reply_callback: req.sender_reply_callback,
            refund: req.payment,
            response_payload: Payload::from(Err(user_error)),
        };
        return ExecuteMessageResult {
            canister,
            num_instructions_left: cycles,
            result: ExecResult::ResponseResult(response),
            heap_delta: NumBytes::from(0),
        };
    }

    let mut execution_parameters = execution_parameters(
        config,
        &canister,
        cycles,
        subnet_available_memory,
        ExecutionMode::Replicated,
        subnet_type,
    );

    if canister.exports_query_method(req.method_name.clone()) {
        // Letting the canister grow arbitrarily when executing the
        // query is fine as we do not persist state modifications.
        execution_parameters.subnet_available_memory = subnet_memory_capacity(config);

        execute_query_method_for_request(canister, req, time, execution_parameters, hypervisor, log)
    } else {
        execute_update_method(
            canister,
            RequestOrIngress::Request(req),
            time,
            network_topology,
            execution_parameters,
            hypervisor,
            log,
        )
    }
}

// Execute an update method from an inter-canister request
// or from an ingress message.
#[allow(clippy::too_many_arguments)]
fn execute_update_method(
    canister: CanisterState,
    req: RequestOrIngress,
    time: Time,
    network_topology: Arc<NetworkTopology>,
    execution_parameters: ExecutionParameters,
    hypervisor: &Hypervisor,
    log: &ReplicaLogger,
) -> ExecuteMessageResult<CanisterState> {
    let call_origin = CallOrigin::from(&req);

    let (canister, cycles, action, heap_delta) =
        hypervisor.execute_update(canister, req, time, network_topology, execution_parameters);

    let result = action_to_result(&canister, action, call_origin, time, log);

    ExecuteMessageResult {
        canister,
        num_instructions_left: cycles,
        result,
        heap_delta,
    }
}

// Execute a query method from an inter-canister request.
fn execute_query_method_for_request(
    canister: CanisterState,
    req: Request,
    time: Time,
    execution_parameters: ExecutionParameters,
    hypervisor: &Hypervisor,
    log: &ReplicaLogger,
) -> ExecuteMessageResult<CanisterState> {
    let (canister, cycles, result) = hypervisor.execute_query(
        QueryExecutionType::Replicated,
        req.method_name.as_str(),
        req.method_payload.as_slice(),
        *req.sender.get_ref(),
        canister,
        None,
        time,
        execution_parameters,
    );

    let result =
        result.map_err(|err| log_and_transform_to_user_error(log, err, &canister.canister_id()));

    let response = Response {
        originator: req.sender,
        respondent: canister.canister_id(),
        originator_reply_callback: req.sender_reply_callback,
        refund: Cycles::zero(),
        response_payload: Payload::from(result),
    };
    ExecuteMessageResult {
        canister,
        num_instructions_left: cycles,
        result: ExecResult::ResponseResult(response),
        heap_delta: NumBytes::from(0),
    }
}

// Execute an ingress message.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_ingress_call(
    canister: CanisterState,
    ingress: Ingress,
    num_instructions: NumInstructions,
    time: Time,
    network_topology: Arc<NetworkTopology>,
    subnet_available_memory: SubnetAvailableMemory,
    config: &ExecutionConfig,
    subnet_type: SubnetType,
    hypervisor: &Hypervisor,
    log: &ReplicaLogger,
) -> ExecuteMessageResult<CanisterState> {
    let canister_id = canister.canister_id();
    if let Err(error) = validate_canister(&canister) {
        let status = IngressStatus::Failed {
            receiver: canister_id.get(),
            user_id: ingress.source,
            error,
            time,
        };

        return ExecuteMessageResult {
            canister,
            num_instructions_left: num_instructions,
            result: ExecResult::IngressResult((ingress.message_id, status)),
            heap_delta: NumBytes::from(0),
        };
    }

    // Scheduler must ensure that this function is never called for expired
    // messages.
    if ingress.expiry_time < time {
        error!(log, "[EXC-BUG] Executing expired ingress message.");
        let status = IngressStatus::Failed {
            receiver: canister_id.get(),
            user_id: ingress.source,
            error: UserError::new(
                ErrorCode::IngressMessageTimeout,
                "Ingress message timed out waiting to start executing.",
            ),
            time,
        };
        return ExecuteMessageResult {
            canister,
            num_instructions_left: num_instructions,
            result: ExecResult::IngressResult((ingress.message_id, status)),
            heap_delta: NumBytes::from(0),
        };
    }

    let mut execution_parameters = execution_parameters(
        config,
        &canister,
        num_instructions,
        subnet_available_memory,
        ExecutionMode::Replicated,
        subnet_type,
    );

    if canister.exports_query_method(ingress.method_name.clone()) {
        // Letting the canister grow arbitrarily when executing the
        // query is fine as we do not persist state modifications.
        execution_parameters.subnet_available_memory = subnet_memory_capacity(config);

        execute_query_method_for_ingress(
            canister,
            ingress,
            time,
            execution_parameters,
            hypervisor,
            log,
        )
    } else {
        execute_update_method(
            canister,
            RequestOrIngress::Ingress(ingress),
            time,
            network_topology,
            execution_parameters,
            hypervisor,
            log,
        )
    }
}

// Execute a query call from an ingress message.
fn execute_query_method_for_ingress(
    canister: CanisterState,
    ingress: Ingress,
    time: Time,
    execution_parameters: ExecutionParameters,
    hypervisor: &Hypervisor,
    log: &ReplicaLogger,
) -> ExecuteMessageResult<CanisterState> {
    let (canister, cycles, result) = hypervisor.execute_query(
        QueryExecutionType::Replicated,
        ingress.method_name.as_str(),
        ingress.method_payload.as_slice(),
        *ingress.source.get_ref(),
        canister,
        None,
        time,
        execution_parameters,
    );

    let result =
        result.map_err(|err| log_and_transform_to_user_error(log, err, &canister.canister_id()));
    let ingress_status = match result {
        Ok(wasm_result) => match wasm_result {
            None => IngressStatus::Failed {
                receiver: canister.canister_id().get(),
                user_id: ingress.source,
                error: UserError::new(
                    ErrorCode::CanisterDidNotReply,
                    format!(
                        "Canister {} did not reply to the call",
                        canister.canister_id(),
                    ),
                ),
                time,
            },
            Some(wasm_result) => IngressStatus::Completed {
                receiver: canister.canister_id().get(),
                user_id: ingress.source,
                result: wasm_result,
                time,
            },
        },
        Err(user_error) => IngressStatus::Failed {
            receiver: canister.canister_id().get(),
            user_id: ingress.source,
            error: user_error,
            time,
        },
    };
    ExecuteMessageResult {
        canister,
        num_instructions_left: cycles,
        result: ExecResult::IngressResult((ingress.message_id, ingress_status)),
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

fn execution_parameters(
    config: &ExecutionConfig,
    canister: &CanisterState,
    instruction_limit: NumInstructions,
    subnet_available_memory: SubnetAvailableMemory,
    execution_mode: ExecutionMode,
    subnet_type: SubnetType,
) -> ExecutionParameters {
    ExecutionParameters {
        total_instruction_limit: instruction_limit,
        slice_instruction_limit: instruction_limit,
        canister_memory_limit: canister.memory_limit(config.max_canister_memory_size),
        subnet_available_memory,
        compute_allocation: canister.scheduler_state.compute_allocation,
        subnet_type,
        execution_mode,
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
