// This module defines how `canister_heartbeat` messages are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#_heartbeat.
use crate::{CanisterHeartbeatError, Hypervisor};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_ic00_types::CanisterStatusType;
use ic_interfaces::execution_environment::{ExecutionParameters, HypervisorError};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallOrigin, CanisterState, ExecutionState, NetworkTopology, SchedulerState, SystemState,
};
use ic_system_api::ApiType;
use ic_types::methods::{FuncRef, SystemMethod, WasmMethod};
use ic_types::{Cycles, NumBytes, NumInstructions, SubnetId, Time};
use std::sync::Arc;

/// Holds the result of heartbeat execution.
pub struct HeartbeatResult {
    /// The canister state resulted from the heartbeat execution.
    pub canister_state: CanisterState,
    /// Instructions left at the end of the heartbeat execution.
    pub instructions_left: NumInstructions,
    /// The size of the heap delta change, if execution is successful
    /// or the relevant error in case of failure.
    pub heap_delta_result: Result<NumBytes, CanisterHeartbeatError>,
}

impl HeartbeatResult {
    pub fn new(
        canister_state: CanisterState,
        instructions_left: NumInstructions,
        heap_delta_result: Result<NumBytes, CanisterHeartbeatError>,
    ) -> Self {
        Self {
            canister_state,
            instructions_left,
            heap_delta_result,
        }
    }
}

// Validates a canister before executing the heartbeat.
//
// Returns the canister split in parts if successful,
// otherwise `HeartbeatResult` which contains the error.
fn validate_canister(
    canister: CanisterState,
    instructions_left: NumInstructions,
    method: WasmMethod,
) -> Result<(ExecutionState, SystemState, SchedulerState), HeartbeatResult> {
    // Check that the status of the canister is Running.
    if canister.status() != CanisterStatusType::Running {
        let status = canister.status();
        return Err(HeartbeatResult::new(
            canister,
            instructions_left,
            Err(CanisterHeartbeatError::CanisterNotRunning { status }),
        ));
    }

    let (execution_state, old_system_state, scheduler_state) = canister.into_parts();

    // Validate that the Wasm module is present.
    let execution_state = match execution_state {
        Some(es) => es,
        None => {
            return Err(HeartbeatResult::new(
                CanisterState::from_parts(None, old_system_state, scheduler_state),
                instructions_left,
                Err(CanisterHeartbeatError::CanisterExecutionFailed(
                    HypervisorError::WasmModuleNotFound,
                )),
            ))
        }
    };

    if !execution_state.exports_method(&method) {
        return Err(HeartbeatResult::new(
            CanisterState::from_parts(Some(execution_state), old_system_state, scheduler_state),
            instructions_left,
            // If the Wasm module does not export the method, then this execution
            // succeeds as a no-op.
            Ok(NumBytes::from(0)),
        ));
    }

    Ok((execution_state, old_system_state, scheduler_state))
}

/// Executes a heartbeat of a given canister.
///
/// Before executing the heartbeat, the canister is validated to meet the following
/// conditions:
///     - The status of the canister is Running.
///     Otherwise, `CanisterHeartbeatError::CanisterNotRunning` error is returned.
///     - Wasm module is present.
///     Otherwise, `CanisterHeartbeatError::CanisterExecutionFailed` error is returned.
///     - Wasm module exports the heartbeat method.
///    
/// When the heartbeat method is not exported, the execution succeeds as a no-op operation.
/// No changes are applied to the canister state if the canister cannot be validated.
///
/// Returns:
///
/// - The updated `CanisterState` if the execution succeeded, otherwise
/// the old `CanisterState`.
///
/// - Number of instructions left. This should be <= `instructions_limit`.
///
/// - A result containing the size of the heap delta change if
/// execution was successful or the relevant `CanisterHeartbeatError` error if execution fails.
#[allow(dead_code)]
pub fn execute_heartbeat(
    canister: CanisterState,
    network_topology: Arc<NetworkTopology>,
    execution_parameters: ExecutionParameters,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    time: Time,
    hypervisor: &Hypervisor,
    cycles_account_manager: &CyclesAccountManager,
) -> HeartbeatResult {
    let method = WasmMethod::System(SystemMethod::CanisterHeartbeat);
    let memory_usage = canister.memory_usage(own_subnet_type);
    let compute_allocation = canister.scheduler_state.compute_allocation;
    let instructions_limit = execution_parameters.slice_instruction_limit;

    // Validate and extract execution state.
    let (execution_state, mut system_state, scheduler_state) =
        match validate_canister(canister, instructions_limit, method.clone()) {
            Ok((execution_state, system_state, scheduler_state)) => {
                (execution_state, system_state, scheduler_state)
            }
            Err(err) => return err,
        };

    // Charge for heartbeat execution.
    if let Err(err) = cycles_account_manager.withdraw_execution_cycles(
        &mut system_state,
        memory_usage,
        compute_allocation,
        instructions_limit,
    ) {
        return HeartbeatResult::new(
            CanisterState::from_parts(Some(execution_state), system_state, scheduler_state),
            instructions_limit,
            Err(CanisterHeartbeatError::OutOfCycles(err)),
        );
    }

    // Execute canister heartbeat.
    let call_context_id = system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(CallOrigin::Heartbeat, Cycles::new(0), time);
    let api_type = ApiType::heartbeat(
        time,
        call_context_id,
        own_subnet_id,
        own_subnet_type,
        network_topology,
    );
    let (output, output_execution_state, output_system_state) = hypervisor.execute(
        api_type,
        system_state.clone(),
        memory_usage,
        execution_parameters,
        FuncRef::Method(method),
        execution_state,
    );

    // Post execution processing.
    let wasm_result = output.wasm_result.clone();
    let (mut canister, num_instructions_left, heap_delta) = hypervisor.system_execution_result(
        output,
        output_execution_state,
        system_state,
        scheduler_state,
        output_system_state,
    );
    let _action = canister
        .system_state
        .call_context_manager_mut()
        .unwrap()
        .on_canister_result(call_context_id, wasm_result);

    let heap_delta = match heap_delta {
        Ok(heap_delta) => Ok(heap_delta),
        Err(err) => Err(CanisterHeartbeatError::CanisterExecutionFailed(err)),
    };

    // Refund the canister with any cycles left after message execution.
    cycles_account_manager.refund_execution_cycles(
        &mut canister.system_state,
        num_instructions_left,
        instructions_limit,
    );

    HeartbeatResult::new(canister, num_instructions_left, heap_delta)
}
