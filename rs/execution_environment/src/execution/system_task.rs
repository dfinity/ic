use crate::execution_environment::RoundLimits;
// This module defines how `canister_heartbeat` messages are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#_heartbeat.
use crate::Hypervisor;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_ic00_types::CanisterStatusType;
use ic_interfaces::execution_environment::{CanisterOutOfCyclesError, HypervisorError};
use ic_logger::ReplicaLogger;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::NextExecution;
use ic_replicated_state::{
    CallOrigin, CanisterState, ExecutionState, NetworkTopology, SchedulerState, SystemState,
};
use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::methods::{FuncRef, SystemMethod, WasmMethod};
use ic_types::{Cycles, NumBytes, NumInstructions, Time};
use prometheus::IntCounter;
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// Holds the result of a system task execution.
pub struct SystemTaskResult {
    /// The canister state resulted from the system task execution.
    pub canister_state: CanisterState,
    /// The number of instructions used by the system task execution.
    pub instructions_used: NumInstructions,
    /// The size of the heap delta change, if execution is successful
    /// or the relevant error in case of failure.
    pub heap_delta_result: Result<NumBytes, CanisterSystemTaskError>,
}

impl SystemTaskResult {
    pub fn new(
        canister_state: CanisterState,
        instructions_used: NumInstructions,
        heap_delta_result: Result<NumBytes, CanisterSystemTaskError>,
    ) -> Self {
        Self {
            canister_state,
            instructions_used,
            heap_delta_result,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        CanisterState,
        NumInstructions,
        Result<NumBytes, CanisterSystemTaskError>,
    ) {
        (
            self.canister_state,
            self.instructions_used,
            self.heap_delta_result,
        )
    }
}

// Validates a canister before executing a heartbeat or a timer.
//
// Returns the canister split in parts if successful,
// otherwise `SystemTaskResult` which contains the error.
fn validate_canister(
    canister: CanisterState,
    method: WasmMethod,
) -> Result<(ExecutionState, SystemState, SchedulerState), SystemTaskResult> {
    // Check that the status of the canister is Running.
    if canister.status() != CanisterStatusType::Running {
        let status = canister.status();
        return Err(SystemTaskResult::new(
            canister,
            NumInstructions::from(0),
            Err(CanisterSystemTaskError::CanisterNotRunning { status }),
        ));
    }

    let (execution_state, old_system_state, scheduler_state) = canister.into_parts();

    // Validate that the Wasm module is present.
    let execution_state = match execution_state {
        Some(es) => es,
        None => {
            return Err(SystemTaskResult::new(
                CanisterState::from_parts(None, old_system_state, scheduler_state),
                NumInstructions::from(0),
                Err(CanisterSystemTaskError::CanisterExecutionFailed(
                    HypervisorError::WasmModuleNotFound,
                )),
            ))
        }
    };

    if !execution_state.exports_method(&method) {
        return Err(SystemTaskResult::new(
            CanisterState::from_parts(Some(execution_state), old_system_state, scheduler_state),
            NumInstructions::from(0),
            // If the Wasm module does not export the method, then this execution
            // succeeds as a no-op.
            Ok(NumBytes::from(0)),
        ));
    }

    Ok((execution_state, old_system_state, scheduler_state))
}

/// Executes a system task method of a given canister.
///
/// Before executing, the canister is validated to meet the following conditions:
///     - The status of the canister is Running.
///       Otherwise, `CanisterSystemTaskError::CanisterNotRunning` error is returned.
///     - Wasm module is present.
///       Otherwise, `CanisterSystemTaskError::CanisterExecutionFailed` error is returned.
///     - Wasm module exports `canister_heartbeat` or `canister_global_timer`
///       system method.
///    
/// When the system method is not exported, the execution succeeds as a no-op operation.
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
/// execution was successful or the relevant `CanisterSystemTaskError` error if execution fails.
#[allow(clippy::too_many_arguments)]
pub fn execute_system_task(
    canister: CanisterState,
    system_task: SystemMethod,
    network_topology: Arc<NetworkTopology>,
    execution_parameters: ExecutionParameters,
    own_subnet_type: SubnetType,
    time: Time,
    hypervisor: &Hypervisor,
    cycles_account_manager: &CyclesAccountManager,
    round_limits: &mut RoundLimits,
    error_counter: &IntCounter,
    subnet_size: usize,
    log: &ReplicaLogger,
) -> SystemTaskResult {
    match canister.next_execution() {
        NextExecution::None | NextExecution::StartNew => {}
        NextExecution::ContinueLong | NextExecution::ContinueInstallCode => {
            // We should never try to execute a system task if
            // there is a pending long execution.
            panic!(
                "System task {:?} execution with another pending DTS execution: {:?}",
                system_task,
                canister.next_execution()
            );
        }
    }
    // Only `canister_heartbeat` and `canister_global_timer` are allowed.
    assert!(
        system_task == SystemMethod::CanisterHeartbeat
            || system_task == SystemMethod::CanisterGlobalTimer
    );
    // System task methods run without DTS.
    let instruction_limits = &execution_parameters.instruction_limits;
    assert_eq!(instruction_limits.message(), instruction_limits.slice());
    let method = WasmMethod::System(system_task.clone());
    let memory_usage = canister.memory_usage(own_subnet_type);
    let compute_allocation = canister.scheduler_state.compute_allocation;
    let message_instruction_limit = instruction_limits.message();

    // Validate and extract execution state.
    let (execution_state, mut system_state, scheduler_state) =
        match validate_canister(canister, method.clone()) {
            Ok((execution_state, system_state, scheduler_state)) => {
                (execution_state, system_state, scheduler_state)
            }
            Err(err) => return err,
        };

    // Charge for system method execution.
    let prepaid_execution_cycles = match cycles_account_manager.prepay_execution_cycles(
        &mut system_state,
        memory_usage,
        compute_allocation,
        message_instruction_limit,
        subnet_size,
    ) {
        Ok(cycles) => cycles,
        Err(err) => {
            return SystemTaskResult::new(
                CanisterState::from_parts(Some(execution_state), system_state, scheduler_state),
                NumInstructions::from(0),
                Err(CanisterSystemTaskError::OutOfCycles(err)),
            )
        }
    };

    // Execute canister system method.
    let call_context_id = system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(CallOrigin::SystemTask, Cycles::new(0), time);
    let api_type = ApiType::system_task(system_task, time, call_context_id);
    let (output, output_execution_state, output_system_state) = hypervisor.execute(
        api_type,
        time,
        system_state.clone(),
        memory_usage,
        execution_parameters,
        FuncRef::Method(method),
        execution_state,
        &network_topology,
        round_limits,
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
        .on_canister_result(call_context_id, None, wasm_result);

    let heap_delta = match heap_delta {
        Ok(heap_delta) => Ok(heap_delta),
        Err(err) => Err(CanisterSystemTaskError::CanisterExecutionFailed(err)),
    };

    // Refund the canister with any cycles left after message execution.
    cycles_account_manager.refund_unused_execution_cycles(
        &mut canister.system_state,
        num_instructions_left,
        message_instruction_limit,
        prepaid_execution_cycles,
        error_counter,
        subnet_size,
        log,
    );

    let instructions_used = NumInstructions::from(
        message_instruction_limit
            .get()
            .saturating_sub(num_instructions_left.get()),
    );

    SystemTaskResult::new(canister, instructions_used, heap_delta)
}

/// Errors when executing `canister_heartbeat` or `canister_global_timer`
/// system tasks.
#[derive(Debug, Eq, PartialEq)]
pub enum CanisterSystemTaskError {
    /// The canister isn't running.
    CanisterNotRunning {
        status: CanisterStatusType,
    },

    OutOfCycles(CanisterOutOfCyclesError),

    /// Execution failed while executing the `canister_heartbeat`.
    CanisterExecutionFailed(HypervisorError),
}

impl std::fmt::Display for CanisterSystemTaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanisterSystemTaskError::CanisterNotRunning { status } => write!(
                f,
                "Canister in status {} instead of {}",
                status,
                CanisterStatusType::Running
            ),
            CanisterSystemTaskError::OutOfCycles(err) => write!(f, "{}", err),
            CanisterSystemTaskError::CanisterExecutionFailed(err) => write!(f, "{}", err),
        }
    }
}

impl CanisterSystemTaskError {
    /// Does this error come from a problem in the execution environment?
    /// Other errors could be caused by bad canister code.
    pub fn is_system_error(&self) -> bool {
        match self {
            CanisterSystemTaskError::CanisterExecutionFailed(hypervisor_err) => {
                hypervisor_err.is_system_error()
            }
            CanisterSystemTaskError::CanisterNotRunning { status: _ }
            | CanisterSystemTaskError::OutOfCycles(_) => false,
        }
    }
}
