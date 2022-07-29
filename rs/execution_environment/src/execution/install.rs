// This module defines how the `install_code` IC method in mode
// `install`/`reinstall` is executed.
// See https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-install_code
use crate::canister_manager::{canister_layout, CanisterManagerError, InstallCodeContext};
use crate::execution::common::{apply_canister_state_changes, update_round_limits};
use crate::execution::install_code::{InstallCodeRoutineResult, PausedInstallCodeRoutine};
use crate::execution_environment::{CompilationCostHandling, RoundContext, RoundLimits};
use ic_base_types::{NumBytes, PrincipalId};
use ic_embedders::wasm_executor::{CanisterStateChanges, PausedWasmExecution, WasmExecutionResult};
use ic_interfaces::execution_environment::WasmExecutionOutput;
use ic_logger::{fatal, info};
use ic_replicated_state::{CanisterState, SystemState};
use ic_sys::PAGE_SIZE;
use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::methods::{FuncRef, SystemMethod, WasmMethod};
use ic_types::{MemoryAllocation, NumInstructions, Time};
use std::path::PathBuf;

/// Installs a new code in canister. The algorithm consists of three stages:
/// - Stage 1: create a new execution state based on the new Wasm code.
/// - Stage 2: invoke the `start()` method (if present).
/// - Stage 3: invoke the `canister_init()` method (if present).
///
/// With deterministic time slicing stages 2 and 3 may require multiple rounds
/// to complete. In order to support that, the algorithm is implemented as a
/// state machine:
/// ```text
/// [begin]
///   │
///   ▼
/// [create new execution state]
///   │
///   │
///   │                   exceeded slice
///   ▼                  instruction limit
/// [execute start()] ───────────────────────► PausedStartExecutionDuringInstall
///   │                                          │    │         ▲
///   │                                          │    └─────────┘
///   │            finished execution            │    exceeded slice
///   │◄─────────────────────────────────────────┘   instruction limit
///   │
///   │
///   │                        exceeded slice
///   ▼                       instruction limit
/// [execute canister_init()]───────────────────► PausedInitExecution
///   │                                              │    │        ▲
///   │                                              │    └────────┘
///   │             finished execution               │   exceeded slice
///   │◄─────────────────────────────────────────────┘  instruction limit
///   │
///   │
///   ▼
/// [end]
///```
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_install(
    context: InstallCodeContext,
    old_canister: &CanisterState,
    time: Time,
    canister_layout_path: PathBuf,
    mut execution_parameters: ExecutionParameters,
    round: RoundContext,
    round_limits: &mut RoundLimits,
    compilation_cost_handling: CompilationCostHandling,
) -> InstallCodeRoutineResult {
    // Stage 1: create a new execution state based on the new Wasm binary.

    let canister_id = context.canister_id;
    let layout = canister_layout(&canister_layout_path, &canister_id);

    let (instructions_from_compilation, result) = round.hypervisor.create_execution_state(
        context.wasm_module,
        layout.raw_path(),
        canister_id,
        round_limits,
        compilation_cost_handling,
    );
    execution_parameters
        .instruction_limits
        .reduce_by(instructions_from_compilation);

    let execution_state = match result {
        Ok(result) => result,
        Err(err) => {
            return InstallCodeRoutineResult::Finished {
                instructions_left: execution_parameters.instruction_limits.message(),
                result: Err((canister_id, err).into()),
            };
        }
    };

    let system_state = old_canister.system_state.clone();
    let scheduler_state = old_canister.scheduler_state.clone();
    let mut new_canister = CanisterState::new(system_state, Some(execution_state), scheduler_state);

    // Update allocations.  This must happen after we have created the new
    // execution state so that we fairly account for the memory requirements
    // of the new wasm module.
    if let Some(compute_allocation) = context.compute_allocation {
        new_canister.scheduler_state.compute_allocation = compute_allocation;
        execution_parameters.compute_allocation = compute_allocation;
    }

    // While the memory allocation can still be included in the context, we need to
    // try to take it from there. Otherwise, we should use the current memory
    // allocation of the canister.
    let desired_memory_allocation = match context.memory_allocation {
        Some(allocation) => allocation,
        None => new_canister.system_state.memory_allocation,
    };
    let subnet_type = round.hypervisor.subnet_type();
    if let MemoryAllocation::Reserved(bytes) = desired_memory_allocation {
        if bytes < new_canister.memory_usage(subnet_type) {
            return InstallCodeRoutineResult::Finished {
                instructions_left: execution_parameters.instruction_limits.message(),
                result: Err(CanisterManagerError::NotEnoughMemoryAllocationGiven {
                    canister_id,
                    memory_allocation_given: desired_memory_allocation,
                    memory_usage_needed: new_canister.memory_usage(subnet_type),
                }),
            };
        }
        execution_parameters.canister_memory_limit = bytes;
    }
    new_canister.system_state.memory_allocation = desired_memory_allocation;

    let total_heap_delta = NumBytes::from(0);

    // Stage 2: invoke the `start()` method of the Wasm module (if present).

    let method = WasmMethod::System(SystemMethod::CanisterStart);
    let memory_usage = new_canister.memory_usage(round.hypervisor.subnet_type());
    let canister_id = new_canister.canister_id();

    // The execution state is present because we just put it there.
    let execution_state = new_canister.execution_state.as_ref().unwrap();

    // If the Wasm module does not export the method, then this execution
    // succeeds as a no-op.
    if !execution_state.exports_method(&method) {
        let instructions_left = execution_parameters.instruction_limits.message();
        info!(
            round.log,
            "Executing (start) on canister {} consumed {} instructions.  {} instructions are left.",
            canister_id,
            execution_parameters.instruction_limits.message() - instructions_left,
            instructions_left
        );
        install_stage_2b_continue_install_after_start(
            context.sender,
            context.arg,
            new_canister,
            execution_parameters,
            instructions_left,
            total_heap_delta,
            time,
            round,
            round_limits,
        )
    } else {
        let wasm_execution_result = round.hypervisor.execute_dts(
            ApiType::start(),
            execution_state,
            &SystemState::new_for_start(canister_id),
            memory_usage,
            execution_parameters.clone(),
            FuncRef::Method(method),
            round_limits,
            round.network_topology,
        );

        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
                update_round_limits(round_limits, &slice);
                install_stage_2a_process_start_result(
                    canister_state_changes,
                    output,
                    context.sender,
                    context.arg,
                    new_canister,
                    execution_parameters,
                    total_heap_delta,
                    time,
                    round,
                    round_limits,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedStartExecutionDuringInstall {
                    paused_wasm_execution,
                    new_canister,
                    execution_parameters,
                    total_heap_delta,
                    context_sender: context.sender,
                    context_arg: context.arg,
                    time,
                });
                InstallCodeRoutineResult::Paused { paused_execution }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn install_stage_2a_process_start_result(
    canister_state_changes: Option<CanisterStateChanges>,
    mut output: WasmExecutionOutput,
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    mut new_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    mut total_heap_delta: NumBytes,
    time: Time,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> InstallCodeRoutineResult {
    apply_canister_state_changes(
        canister_state_changes,
        new_canister.execution_state.as_mut().unwrap(),
        &mut new_canister.system_state,
        &mut output,
        round_limits,
        time,
        round.network_topology,
        round.hypervisor.subnet_id(),
        round.log,
    );
    let canister_id = new_canister.canister_id();
    let instructions_left = output.num_instructions_left;
    match output.wasm_result {
        Ok(opt_result) => {
            if opt_result.is_some() {
                fatal!(round.log, "[EXC-BUG] System methods cannot use msg_reply.");
            }
            total_heap_delta +=
                NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64);
        }
        Err(err) => {
            return InstallCodeRoutineResult::Finished {
                instructions_left,
                result: Err((canister_id, err).into()),
            }
        }
    };

    install_stage_2b_continue_install_after_start(
        context_sender,
        context_arg,
        new_canister,
        execution_parameters,
        instructions_left,
        total_heap_delta,
        time,
        round,
        round_limits,
    )
}

#[allow(clippy::too_many_arguments)]
fn install_stage_2b_continue_install_after_start(
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    new_canister: CanisterState,
    mut execution_parameters: ExecutionParameters,
    instructions_left: NumInstructions,
    total_heap_delta: NumBytes,
    time: Time,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> InstallCodeRoutineResult {
    let canister_id = new_canister.canister_id();
    info!(
        round.log,
        "Executing (start) on canister {} consumed {} instructions.  {} instructions are left.",
        canister_id,
        execution_parameters.instruction_limits.message() - instructions_left,
        instructions_left
    );
    execution_parameters
        .instruction_limits
        .update(instructions_left);

    // Stage 3: invoke the `canister_init()` method of the Wasm module (if present).

    let method = WasmMethod::System(SystemMethod::CanisterInit);

    // If the Wasm module does not export the method, then this execution
    // succeeds as a no-op.
    if !new_canister
        .execution_state
        .as_ref()
        .unwrap()
        .exports_method(&method)
    {
        info!(
            round.log,
            "Executing (canister_init) on canister {} consumed {} instructions.  {} instructions are left.",
            canister_id,
            execution_parameters.instruction_limits.message() - instructions_left,
            instructions_left
        );
        return InstallCodeRoutineResult::Finished {
            instructions_left,
            result: Ok((new_canister, total_heap_delta)),
        };
    }

    let memory_usage = new_canister.memory_usage(round.hypervisor.subnet_type());
    let wasm_execution_result = round.hypervisor.execute_dts(
        ApiType::init(time, context_arg, context_sender),
        new_canister.execution_state.as_ref().unwrap(),
        &new_canister.system_state,
        memory_usage,
        execution_parameters.clone(),
        FuncRef::Method(method),
        round_limits,
        round.network_topology,
    );
    match wasm_execution_result {
        WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
            update_round_limits(round_limits, &slice);
            install_stage_3_process_init_result(
                canister_state_changes,
                new_canister,
                output,
                execution_parameters,
                total_heap_delta,
                round,
                round_limits,
            )
        }
        WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
            update_round_limits(round_limits, &slice);
            let paused_execution = Box::new(PausedInitExecution {
                new_canister,
                paused_wasm_execution,
                execution_parameters,
                total_heap_delta,
            });
            InstallCodeRoutineResult::Paused { paused_execution }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn install_stage_3_process_init_result(
    canister_state_changes: Option<CanisterStateChanges>,
    mut new_canister: CanisterState,
    mut output: WasmExecutionOutput,
    execution_parameters: ExecutionParameters,
    mut total_heap_delta: NumBytes,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> InstallCodeRoutineResult {
    let canister_id = new_canister.canister_id();
    info!(
        round.log,
        "Executing (canister_init) on canister {} consumed {} instructions.  {} instructions are left.",
        canister_id,
        execution_parameters.instruction_limits.message() - output.num_instructions_left,
        output.num_instructions_left
    );

    apply_canister_state_changes(
        canister_state_changes,
        new_canister.execution_state.as_mut().unwrap(),
        &mut new_canister.system_state,
        &mut output,
        round_limits,
        round.time,
        round.network_topology,
        round.hypervisor.subnet_id(),
        round.log,
    );
    match output.wasm_result {
        Ok(opt_result) => {
            if opt_result.is_some() {
                fatal!(round.log, "[EXC-BUG] System methods cannot use msg_reply.");
            }

            total_heap_delta +=
                NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64);

            InstallCodeRoutineResult::Finished {
                instructions_left: output.num_instructions_left,
                result: Ok((new_canister, total_heap_delta)),
            }
        }
        Err(err) => InstallCodeRoutineResult::Finished {
            instructions_left: output.num_instructions_left,
            result: Err((canister_id, err).into()),
        },
    }
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of canister install.
#[derive(Debug)]
struct PausedInitExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    new_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    total_heap_delta: NumBytes,
}

impl PausedInstallCodeRoutine for PausedInitExecution {
    fn resume(
        self: Box<Self>,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> InstallCodeRoutineResult {
        let execution_state = self.new_canister.execution_state.as_ref().unwrap();
        let wasm_execution_result = self.paused_wasm_execution.resume(execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
                update_round_limits(round_limits, &slice);
                install_stage_3_process_init_result(
                    canister_state_changes,
                    self.new_canister,
                    output,
                    self.execution_parameters,
                    self.total_heap_delta,
                    round,
                    round_limits,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedInitExecution {
                    paused_wasm_execution,
                    ..*self
                });
                InstallCodeRoutineResult::Paused { paused_execution }
            }
        }
    }

    fn abort(self: Box<Self>) {
        self.paused_wasm_execution.abort();
    }
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of canister install.
#[derive(Debug)]
struct PausedStartExecutionDuringInstall {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    new_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    total_heap_delta: NumBytes,
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    time: Time,
}

impl PausedInstallCodeRoutine for PausedStartExecutionDuringInstall {
    fn resume(
        self: Box<Self>,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> InstallCodeRoutineResult {
        let execution_state = self.new_canister.execution_state.as_ref().unwrap();
        let wasm_execution_result = self.paused_wasm_execution.resume(execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
                update_round_limits(round_limits, &slice);
                install_stage_2a_process_start_result(
                    canister_state_changes,
                    output,
                    self.context_sender,
                    self.context_arg,
                    self.new_canister,
                    self.execution_parameters,
                    self.total_heap_delta,
                    self.time,
                    round,
                    round_limits,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedStartExecutionDuringInstall {
                    paused_wasm_execution,
                    ..*self
                });
                InstallCodeRoutineResult::Paused { paused_execution }
            }
        }
    }

    fn abort(self: Box<Self>) {
        self.paused_wasm_execution.abort();
    }
}
