// This module defines how the `install_code` IC method in mode
// `upgrade` is executed.
// See https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-install_code
// and https://internetcomputer.org/docs/current/references/ic-interface-spec/#system-api-upgrades
use crate::canister_manager::{canister_layout, CanisterManagerError, InstallCodeContext};
use crate::execution::common::update_round_limits;
use crate::execution::install_code::{InstallCodeRoutineResult, PausedInstallCodeRoutine};
use crate::execution_environment::{CompilationCostHandling, RoundContext, RoundLimits};
use ic_base_types::{NumBytes, PrincipalId};
use ic_embedders::wasm_executor::{PausedWasmExecution, WasmExecutionResult};
use ic_interfaces::execution_environment::{HypervisorError, WasmExecutionOutput};
use ic_logger::{fatal, info};
use ic_replicated_state::{CanisterState, Memory, SystemState};
use ic_sys::PAGE_SIZE;
use ic_system_api::sandbox_safe_system_state::SystemStateChanges;
use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::methods::{FuncRef, SystemMethod, WasmMethod};
use ic_types::{MemoryAllocation, NumInstructions, Time};
use std::path::PathBuf;

/// Performs a canister upgrade. The algorithm consists of four stages:
/// - Stage 1: invoke `canister_pre_upgrade()` (if present) using the old code.
/// - Stage 2: create a new execution state based on the new Wasm code.
/// - Stage 3: invoke the `start()` method (if present).
/// - Stage 4: invoke the `canister_post_upgrade()` method (if present).
///
/// With deterministic time slicing stages 2, 3, and 4 may require multiple
/// rounds to complete. In order to support that, the algorithm is implemented
/// as a state machine:
/// ```text
/// [begin]
///   │                                   exceeded slice
///   ▼                                 instruction limit
/// [execute canister_pre_upgrade()] ─────────────────────────► PausedPreUpgradeExecution
///   │                                                           │    │          ▲
///   │                                                           │    └──────────┘
///   │            finished execution                             │    exceeded slice
///   │◄──────────────────────────────────────────────────────────┘   instruction limit
///   │
///   │
///   │
///   ▼
/// [create new execution state]
///   │
///   │
///   │                         exceeded slice
///   ▼                       instruction limit
/// [execute start()]─────────────────────────────────► PausedStartExecutionDuringUpgrade
///   │                                                   │       │         ▲
///   │                                                   │       └─────────┘
///   │             finished execution                    │      exceeded slice
///   │◄──────────────────────────────────────────────────┘     instruction limit
///   │
///   │
///   │                                    exceeded slice
///   ▼                                  instruction limit
/// [execute canister_post_upgrade()] ───────────────────────► PausedPostUpgradeExecution
///   │                                                          │    │          ▲
///   │                                                          │    └──────────┘
///   │            finished execution                            │    exceeded slice
///   │◄─────────────────────────────────────────────────────────┘   instruction limit
///   │
///   │
///   ▼
/// [end]
///```
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_upgrade(
    context: InstallCodeContext,
    old_canister: &CanisterState,
    time: Time,
    canister_layout_path: PathBuf,
    execution_parameters: ExecutionParameters,
    round: RoundContext,
    round_limits: &mut RoundLimits,
    compilation_cost_handling: CompilationCostHandling,
) -> InstallCodeRoutineResult {
    let canister_id = context.canister_id;
    let mut new_canister = old_canister.clone();
    let total_heap_delta = NumBytes::from(0);

    // Stage 1: invoke `canister_pre_upgrade()` (if present) using the old code.

    let method = WasmMethod::System(SystemMethod::CanisterPreUpgrade);
    let memory_usage = new_canister.memory_usage(round.hypervisor.subnet_type());

    // Validate that the Wasm module is present.
    let execution_state = match new_canister.execution_state.take() {
        None => {
            return InstallCodeRoutineResult::Finished {
                instructions_left: execution_parameters.instruction_limits.message(),
                result: Err((canister_id, HypervisorError::WasmModuleNotFound).into()),
            }
        }
        Some(es) => es,
    };

    // If the Wasm module does not export the method, then this execution
    // succeeds as a no-op.
    if !execution_state.exports_method(&method) {
        new_canister.execution_state = Some(execution_state);
        let instructions_left = execution_parameters.instruction_limits.message();
        upgrade_stage_2_and_3a_create_execution_state_and_call_start(
            context,
            new_canister,
            canister_layout_path,
            execution_parameters,
            instructions_left,
            total_heap_delta,
            time,
            round,
            round_limits,
            compilation_cost_handling,
        )
    } else {
        let (output_execution_state, wasm_execution_result) = round.hypervisor.execute_dts(
            ApiType::pre_upgrade(time, context.sender),
            &new_canister.system_state,
            memory_usage,
            execution_parameters.clone(),
            FuncRef::Method(method),
            execution_state,
            round_limits,
            round.network_topology,
        );
        new_canister.execution_state = Some(output_execution_state);

        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, system_state_changes) => {
                update_round_limits(round_limits, &slice);
                upgrade_stage_1_process_pre_upgrade_result(
                    output,
                    system_state_changes,
                    context,
                    new_canister,
                    canister_layout_path,
                    execution_parameters,
                    total_heap_delta,
                    time,
                    round,
                    round_limits,
                    compilation_cost_handling,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedPreUpgradeExecution {
                    paused_wasm_execution,
                    new_canister,
                    execution_parameters,
                    total_heap_delta,
                    context,
                    canister_layout_path,
                    time,
                    compilation_cost_handling,
                });
                InstallCodeRoutineResult::Paused { paused_execution }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn upgrade_stage_1_process_pre_upgrade_result(
    output: WasmExecutionOutput,
    system_state_changes: SystemStateChanges,
    context: InstallCodeContext,
    mut new_canister: CanisterState,
    canister_layout_path: PathBuf,
    execution_parameters: ExecutionParameters,
    mut total_heap_delta: NumBytes,
    time: Time,
    round: RoundContext,
    round_limits: &mut RoundLimits,
    compilation_cost_handling: CompilationCostHandling,
) -> InstallCodeRoutineResult {
    let canister_id = new_canister.canister_id();
    let instructions_left = output.num_instructions_left;
    match output.wasm_result {
        Ok(opt_result) => {
            if opt_result.is_some() {
                fatal!(round.log, "[EXC-BUG] System methods cannot use msg_reply.");
            }
            // TODO(RUN-265): Replace `unwrap` with a proper execution error
            // here because subnet available memory may have changed since
            // the start of execution.
            round_limits
                .subnet_available_memory
                .try_decrement(output.allocated_bytes, output.allocated_message_bytes)
                .unwrap();
            system_state_changes.apply_changes(
                time,
                &mut new_canister.system_state,
                round.network_topology,
                round.hypervisor.subnet_id(),
                round.log,
            );
            let bytes = NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64);
            total_heap_delta += bytes;
            upgrade_stage_2_and_3a_create_execution_state_and_call_start(
                context,
                new_canister,
                canister_layout_path,
                execution_parameters,
                instructions_left,
                total_heap_delta,
                time,
                round,
                round_limits,
                compilation_cost_handling,
            )
        }
        Err(err) => InstallCodeRoutineResult::Finished {
            instructions_left,
            result: Err((canister_id, err).into()),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn upgrade_stage_2_and_3a_create_execution_state_and_call_start(
    context: InstallCodeContext,
    mut new_canister: CanisterState,
    canister_layout_path: PathBuf,
    mut execution_parameters: ExecutionParameters,
    instructions_left: NumInstructions,
    total_heap_delta: NumBytes,
    time: Time,
    round: RoundContext,
    round_limits: &mut RoundLimits,
    compilation_cost_handling: CompilationCostHandling,
) -> InstallCodeRoutineResult {
    let canister_id = new_canister.canister_id();

    info!(
        round.log,
        "Executing (canister_pre_upgrade) on canister {} consumed {} instructions.  {} instructions are left.",
        canister_id,
        execution_parameters.instruction_limits.message() - instructions_left,
        instructions_left
    );
    execution_parameters
        .instruction_limits
        .update(instructions_left);

    // Stage 2: create a new execution state based on the new Wasm code.
    // Replace the execution state of the canister with a new execution state, but
    // persist the stable memory (if it exists).
    let layout = canister_layout(&canister_layout_path, &canister_id);
    let (instructions_from_compilation, execution_state) =
        match round.hypervisor.create_execution_state(
            context.wasm_module,
            layout.raw_path(),
            canister_id,
            round_limits,
            compilation_cost_handling,
        ) {
            Err(err) => {
                return InstallCodeRoutineResult::Finished {
                    instructions_left,
                    result: Err((canister_id, err).into()),
                };
            }
            Ok((instructions_from_compilation, mut execution_state)) => {
                let stable_memory = match new_canister.execution_state {
                    Some(es) => es.stable_memory,
                    None => Memory::default(),
                };
                execution_state.stable_memory = stable_memory;
                (instructions_from_compilation, execution_state)
            }
        };
    new_canister.execution_state = Some(execution_state);

    execution_parameters
        .instruction_limits
        .reduce_by(match compilation_cost_handling {
            CompilationCostHandling::Ignore => NumInstructions::from(0),
            CompilationCostHandling::Charge => instructions_from_compilation,
        });
    let instructions_left = execution_parameters.instruction_limits.message();

    // Update allocations.  This must happen after we have created the new
    // execution state so that we fairly account for the memory requirements
    // of the new wasm module.
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
                instructions_left,
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

    // Stage 3: invoke the `start()` method (if present).

    let method = WasmMethod::System(SystemMethod::CanisterStart);
    let memory_usage = new_canister.memory_usage(subnet_type);
    let canister_id = new_canister.canister_id();

    // The execution state is present because we just put it there.
    let execution_state = new_canister.execution_state.take().unwrap();

    // If the Wasm module does not export the method, then this execution
    // succeeds as a no-op.
    if !execution_state.exports_method(&method) {
        new_canister.execution_state = Some(execution_state);
        upgrade_stage_4a_call_post_upgrade(
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
        let (output_execution_state, wasm_execution_result) = round.hypervisor.execute_dts(
            ApiType::start(),
            &SystemState::new_for_start(canister_id),
            memory_usage,
            execution_parameters.clone(),
            FuncRef::Method(method),
            execution_state,
            round_limits,
            round.network_topology,
        );
        new_canister.execution_state = Some(output_execution_state);

        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, _system_state_changes) => {
                update_round_limits(round_limits, &slice);
                upgrade_stage_3b_process_start_result(
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
                let paused_execution = Box::new(PausedStartExecutionDuringUpgrade {
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
fn upgrade_stage_3b_process_start_result(
    output: WasmExecutionOutput,
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    new_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    mut total_heap_delta: NumBytes,
    time: Time,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> InstallCodeRoutineResult {
    let canister_id = new_canister.canister_id();
    let instructions_left = output.num_instructions_left;

    match output.wasm_result {
        Ok(opt_result) => {
            if opt_result.is_some() {
                fatal!(round.log, "[EXC-BUG] System methods cannot use msg_reply.");
            }
            // TODO(RUN-265): Replace `unwrap` with a proper execution error
            // here because subnet available memory may have changed since
            // the start of execution.
            round_limits
                .subnet_available_memory
                .try_decrement(output.allocated_bytes, output.allocated_message_bytes)
                .unwrap();
            total_heap_delta +=
                NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64);
            upgrade_stage_4a_call_post_upgrade(
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
        Err(err) => InstallCodeRoutineResult::Finished {
            instructions_left,
            result: Err((canister_id, err).into()),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn upgrade_stage_4a_call_post_upgrade(
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    mut new_canister: CanisterState,
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

    // Stage 4: invoke the `canister_post_upgrade()` method (if present).

    let method = WasmMethod::System(SystemMethod::CanisterPostUpgrade);
    let memory_usage = new_canister.memory_usage(round.hypervisor.subnet_type());

    // The execution state is guaranteed to be present because this function is
    // called after creating a new execution state.
    let execution_state = new_canister.execution_state.unwrap();

    // If the Wasm module does not export the method, then this execution
    // succeeds as a no-op.
    if !execution_state.exports_method(&method) {
        new_canister.execution_state = Some(execution_state);
        upgrade_stage_4c_finish_upgrade(
            new_canister,
            execution_parameters,
            instructions_left,
            total_heap_delta,
            round,
        )
    } else {
        let (output_execution_state, wasm_execution_result) = round.hypervisor.execute_dts(
            ApiType::init(time, context_arg, context_sender),
            &new_canister.system_state,
            memory_usage,
            execution_parameters.clone(),
            FuncRef::Method(method),
            execution_state,
            round_limits,
            round.network_topology,
        );
        new_canister.execution_state = Some(output_execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, system_state_changes) => {
                update_round_limits(round_limits, &slice);
                upgrade_stage_4b_process_post_upgrade_result(
                    output,
                    system_state_changes,
                    new_canister,
                    execution_parameters,
                    total_heap_delta,
                    round,
                    round_limits,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedPostUpgradeExecution {
                    paused_wasm_execution,
                    new_canister,
                    execution_parameters,
                    total_heap_delta,
                });
                InstallCodeRoutineResult::Paused { paused_execution }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn upgrade_stage_4b_process_post_upgrade_result(
    output: WasmExecutionOutput,
    system_state_changes: SystemStateChanges,
    mut new_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    mut total_heap_delta: NumBytes,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> InstallCodeRoutineResult {
    let canister_id = new_canister.canister_id();
    let instructions_left = output.num_instructions_left;
    match output.wasm_result {
        Ok(opt_result) => {
            if opt_result.is_some() {
                fatal!(round.log, "[EXC-BUG] System methods cannot use msg_reply.");
            }
            // TODO(RUN-265): Replace `unwrap` with a proper execution error
            // here because subnet available memory may have changed since
            // the start of execution.
            round_limits
                .subnet_available_memory
                .try_decrement(output.allocated_bytes, output.allocated_message_bytes)
                .unwrap();
            system_state_changes.apply_changes(
                round.time,
                &mut new_canister.system_state,
                round.network_topology,
                round.hypervisor.subnet_id(),
                round.log,
            );
            let bytes = NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64);
            total_heap_delta += bytes;
            upgrade_stage_4c_finish_upgrade(
                new_canister,
                execution_parameters,
                instructions_left,
                total_heap_delta,
                round,
            )
        }
        Err(err) => InstallCodeRoutineResult::Finished {
            instructions_left,
            result: Err((canister_id, err).into()),
        },
    }
}

fn upgrade_stage_4c_finish_upgrade(
    new_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    instructions_left: NumInstructions,
    total_heap_delta: NumBytes,
    round: RoundContext,
) -> InstallCodeRoutineResult {
    let canister_id = new_canister.canister_id();

    info!(
        round.log,
        "Executing (canister_post_upgrade) on canister {} consumed {} instructions.  {} instructions are left.",
        canister_id,
        execution_parameters.instruction_limits.message() - instructions_left,
        instructions_left
    );

    InstallCodeRoutineResult::Finished {
        instructions_left,
        result: Ok((new_canister, total_heap_delta)),
    }
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of canister upgrade.
/// Pre upgrade is the first stage of the upgrade procedure.
#[derive(Debug)]
struct PausedPreUpgradeExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    new_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    total_heap_delta: NumBytes,
    context: InstallCodeContext,
    canister_layout_path: PathBuf,
    time: Time,
    compilation_cost_handling: CompilationCostHandling,
}

impl PausedInstallCodeRoutine for PausedPreUpgradeExecution {
    fn resume(
        self: Box<Self>,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> InstallCodeRoutineResult {
        let mut new_canister = self.new_canister;
        let execution_state = new_canister.execution_state.take().unwrap();
        let (execution_state, wasm_execution_result) =
            self.paused_wasm_execution.resume(execution_state);
        new_canister.execution_state = Some(execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, system_state_changes) => {
                update_round_limits(round_limits, &slice);
                upgrade_stage_1_process_pre_upgrade_result(
                    output,
                    system_state_changes,
                    self.context,
                    new_canister,
                    self.canister_layout_path,
                    self.execution_parameters,
                    self.total_heap_delta,
                    self.time,
                    round,
                    round_limits,
                    self.compilation_cost_handling,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedPreUpgradeExecution {
                    new_canister,
                    paused_wasm_execution,
                    ..*self
                });
                InstallCodeRoutineResult::Paused { paused_execution }
            }
        }
    }

    fn abort(self: Box<Self>) {
        todo!()
    }
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of canister upgrade.
/// Start is the second stage of the upgrade procedure.
#[derive(Debug)]
struct PausedStartExecutionDuringUpgrade {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    new_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    total_heap_delta: NumBytes,
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    time: Time,
}

impl PausedInstallCodeRoutine for PausedStartExecutionDuringUpgrade {
    fn resume(
        self: Box<Self>,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> InstallCodeRoutineResult {
        let mut new_canister = self.new_canister;
        let execution_state = new_canister.execution_state.take().unwrap();
        let (execution_state, wasm_execution_result) =
            self.paused_wasm_execution.resume(execution_state);
        new_canister.execution_state = Some(execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, _system_state_changes) => {
                update_round_limits(round_limits, &slice);
                upgrade_stage_3b_process_start_result(
                    output,
                    self.context_sender,
                    self.context_arg,
                    new_canister,
                    self.execution_parameters,
                    self.total_heap_delta,
                    self.time,
                    round,
                    round_limits,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedStartExecutionDuringUpgrade {
                    new_canister,
                    paused_wasm_execution,
                    ..*self
                });
                InstallCodeRoutineResult::Paused { paused_execution }
            }
        }
    }

    fn abort(self: Box<Self>) {
        todo!()
    }
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of canister upgrade.
/// Post upgrade is the third stage of the upgrade procedure.
#[derive(Debug)]
struct PausedPostUpgradeExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    new_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    total_heap_delta: NumBytes,
}

impl PausedInstallCodeRoutine for PausedPostUpgradeExecution {
    fn resume(
        self: Box<Self>,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> InstallCodeRoutineResult {
        let mut new_canister = self.new_canister;
        let execution_state = new_canister.execution_state.take().unwrap();
        let (execution_state, wasm_execution_result) =
            self.paused_wasm_execution.resume(execution_state);
        new_canister.execution_state = Some(execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, system_state_changes) => {
                update_round_limits(round_limits, &slice);
                upgrade_stage_4b_process_post_upgrade_result(
                    output,
                    system_state_changes,
                    new_canister,
                    self.execution_parameters,
                    self.total_heap_delta,
                    round,
                    round_limits,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedPostUpgradeExecution {
                    new_canister,
                    paused_wasm_execution,
                    ..*self
                });
                InstallCodeRoutineResult::Paused { paused_execution }
            }
        }
    }

    fn abort(self: Box<Self>) {
        todo!()
    }
}
