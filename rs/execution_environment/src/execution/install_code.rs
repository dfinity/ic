// This module defines types and functions common between canister installation
// and upgrades.

use std::path::{Path, PathBuf};

use ic_base_types::{CanisterId, NumBytes, PrincipalId};
use ic_config::flag_status::FlagStatus;
use ic_embedders::wasm_executor::CanisterStateChanges;
use ic_ic00_types::CanisterInstallMode;
use ic_interfaces::{
    execution_environment::{
        HypervisorError, HypervisorResult, SubnetAvailableMemory, SubnetAvailableMemoryError,
        WasmExecutionOutput,
    },
    messages::RequestOrIngress,
};
use ic_logger::{error, fatal, info, warn};
use ic_replicated_state::{CanisterState, ExecutionState};
use ic_state_layout::{CanisterLayout, CheckpointLayout, ReadOnly};
use ic_sys::PAGE_SIZE;
use ic_system_api::ExecutionParameters;
use ic_types::{
    funds::Cycles, CanisterTimer, ComputeAllocation, Height, MemoryAllocation, NumInstructions,
    Time,
};

use crate::{
    canister_manager::{
        CanisterManagerError, CanisterMgrConfig, DtsInstallCodeResult, InstallCodeResult,
    },
    execution_environment::RoundContext,
    CompilationCostHandling, RoundLimits,
};

#[cfg(test)]
mod tests;

/// Indicates whether to keep the old stable memory or replace it with the new
/// (empty) stable memory.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum StableMemoryHandling {
    Keep,
    Replace,
}

/// The main steps of `install_code` execution that may fail with an error or
/// change the canister state.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum InstallCodeStep {
    ValidateInput,
    ReplaceExecutionStateAndAllocations {
        instructions_from_compilation: NumInstructions,
        maybe_execution_state: HypervisorResult<ExecutionState>,
        stable_memory_handling: StableMemoryHandling,
    },
    HandleWasmExecution {
        canister_state_changes: Option<CanisterStateChanges>,
        output: WasmExecutionOutput,
    },
}

/// Contains fields of `InstallCodeHelper` that are necessary for resuming
/// `install_code` execution.
#[derive(Debug)]
pub(crate) struct PausedInstallCodeHelper {
    steps: Vec<InstallCodeStep>,
    instructions_left: NumInstructions,
}

/// A helper that implements and keeps track of `install_code` steps.
/// It is used to safely pause and resume `install_code` execution.
pub(crate) struct InstallCodeHelper {
    // The current canister state.
    canister: CanisterState,
    // All steps that were performed on the current canister state.
    steps: Vec<InstallCodeStep>,
    // The original instruction limit.
    message_instruction_limit: NumInstructions,
    // The current execution parameters that change after steps.
    execution_parameters: ExecutionParameters,
    // Bytes allocated and deallocated by the steps.
    allocated_bytes: NumBytes,
    allocated_message_bytes: NumBytes,
    deallocated_bytes: NumBytes,
    // The total heap delta of all steps.
    total_heap_delta: NumBytes,
}

impl InstallCodeHelper {
    pub fn new(clean_canister: &CanisterState, original: &OriginalContext) -> Self {
        Self {
            steps: vec![],
            canister: clean_canister.clone(),
            message_instruction_limit: original.execution_parameters.instruction_limits.message(),
            execution_parameters: original.execution_parameters.clone(),
            allocated_bytes: NumBytes::from(0),
            allocated_message_bytes: NumBytes::from(0),
            deallocated_bytes: NumBytes::from(0),
            total_heap_delta: NumBytes::from(0),
        }
    }

    pub fn canister(&self) -> &CanisterState {
        &self.canister
    }

    pub fn deactivate_global_timer(&mut self) {
        self.canister.system_state.global_timer = CanisterTimer::Inactive;
    }

    pub fn execution_parameters(&self) -> &ExecutionParameters {
        &self.execution_parameters
    }

    pub fn instructions_left(&self) -> NumInstructions {
        self.execution_parameters.instruction_limits.message()
    }

    pub fn instructions_consumed(&self) -> NumInstructions {
        self.message_instruction_limit - self.instructions_left()
    }

    pub fn canister_memory_usage(&self) -> NumBytes {
        self.canister
            .memory_usage(self.execution_parameters.subnet_type)
    }

    /// Returns a struct with all the necessary information to replay the
    /// performed `install_code` steps in subsequent rounds.
    pub fn pause(self) -> PausedInstallCodeHelper {
        PausedInstallCodeHelper {
            instructions_left: self.instructions_left(),
            steps: self.steps,
        }
    }

    /// Replays the previous `install_code` steps on the given clean canister.
    /// Returns an error if any step fails. Otherwise, it returns an instance of
    /// the helper that can be used to continue the `install_code` execution.
    pub fn resume(
        clean_canister: &CanisterState,
        paused: PausedInstallCodeHelper,
        original: &OriginalContext,
        round: &RoundContext,
        round_limits: &RoundLimits,
    ) -> Result<Self, (CanisterManagerError, NumInstructions)> {
        let mut helper = Self::new(clean_canister, original);
        let paused_instructions_left = paused.instructions_left;
        for state_change in paused.steps.into_iter() {
            helper
                .replay_step(state_change, original, round, round_limits)
                .map_err(|err| (err, paused_instructions_left))?;
        }
        assert_eq!(paused_instructions_left, helper.instructions_left());
        Ok(helper)
    }

    /// Finishes an `install_code` execution that could have run multiple rounds
    /// due to deterministic time slicing. It updates the subnet available memory
    /// and compute allocation in the given `round_limits`, which may cause the
    /// execution to fail with errors.
    pub fn finish(
        mut self,
        clean_canister: CanisterState,
        original: OriginalContext,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> DtsInstallCodeResult {
        let message_instruction_limit = original.execution_parameters.instruction_limits.message();
        let instructions_left = self.instructions_left();

        // The balance should not change because `install_code` cannot accept or
        // send cycles. The execution cycles have already been accounted for in
        // the clean canister state.
        assert_eq!(
            clean_canister.system_state.balance(),
            self.canister.system_state.balance()
        );

        self.canister
            .system_state
            .apply_cycles_debit(self.canister.canister_id(), round.log);

        let mut subnet_available_memory = round_limits.subnet_available_memory;
        subnet_available_memory.increment(self.deallocated_bytes, NumBytes::from(0));
        if let Err(err) = subnet_available_memory
            .try_decrement(self.allocated_bytes, self.allocated_message_bytes)
        {
            match err {
                SubnetAvailableMemoryError::InsufficientMemory {
                    requested_total,
                    message_requested: _,
                    available_total,
                    available_messages: _,
                } => {
                    return finish_err(
                        clean_canister,
                        self.instructions_left(),
                        original,
                        round,
                        CanisterManagerError::SubnetMemoryCapacityOverSubscribed {
                            requested: requested_total,
                            available: NumBytes::new(available_total.max(0) as u64),
                        },
                    );
                }
            }
        }

        let old_compute_allocation = clean_canister.compute_allocation();
        let new_compute_allocation = self.canister.compute_allocation();
        if new_compute_allocation.as_percent() > old_compute_allocation.as_percent() {
            let others = round_limits
                .compute_allocation_used
                .saturating_sub(old_compute_allocation.as_percent());
            let available = original.config.compute_capacity.saturating_sub(others + 1);
            if new_compute_allocation.as_percent() > available {
                return finish_err(
                    clean_canister,
                    self.instructions_left(),
                    original,
                    round,
                    CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                        requested: new_compute_allocation,
                        available: available.max(old_compute_allocation.as_percent()),
                    },
                );
            }
            round_limits.compute_allocation_used = others + new_compute_allocation.as_percent();
        } else {
            let others = round_limits
                .compute_allocation_used
                .saturating_sub(old_compute_allocation.as_percent());
            round_limits.compute_allocation_used = others + new_compute_allocation.as_percent();
        }

        // After this point `install_code` is guaranteed to succeed.
        // Commit all the remaining state and round limit changes.

        round_limits.subnet_available_memory = subnet_available_memory;

        round.cycles_account_manager.refund_unused_execution_cycles(
            &mut self.canister.system_state,
            instructions_left,
            message_instruction_limit,
            original.prepaid_execution_cycles,
            round.execution_refund_error_counter,
            original.subnet_size,
            round.log,
        );

        if original.config.rate_limiting_of_instructions == FlagStatus::Enabled {
            self.canister.scheduler_state.install_code_debit += self.instructions_consumed();
        }

        let instructions_used = NumInstructions::from(
            message_instruction_limit
                .get()
                .saturating_sub(instructions_left.get()),
        );

        let old_wasm_hash = get_wasm_hash(&clean_canister);
        let new_wasm_hash = get_wasm_hash(&self.canister);
        DtsInstallCodeResult::Finished {
            canister: self.canister,
            message: original.message,
            instructions_used,
            result: Ok(InstallCodeResult {
                heap_delta: self.total_heap_delta,
                old_wasm_hash,
                new_wasm_hash,
            }),
        }
    }

    /// Validates the input context of `install_code`.
    pub fn validate_input(
        &mut self,
        original: &OriginalContext,
        round_limits: &RoundLimits,
    ) -> Result<(), CanisterManagerError> {
        self.steps.push(InstallCodeStep::ValidateInput);

        let config = &original.config;
        let id = self.canister.system_state.canister_id;

        validate_compute_allocation(
            round_limits.compute_allocation_used,
            &self.canister,
            original.requested_compute_allocation,
            &original.config,
        )?;

        validate_memory_allocation(
            &round_limits.subnet_available_memory,
            &self.canister,
            original.requested_memory_allocation,
            config,
        )?;

        validate_controller(&self.canister, &original.sender)?;

        match original.mode {
            CanisterInstallMode::Install => {
                if self.canister.execution_state.is_some() {
                    return Err(CanisterManagerError::CanisterNonEmpty(id));
                }
            }
            CanisterInstallMode::Reinstall | CanisterInstallMode::Upgrade => {}
        }

        if self.canister.scheduler_state.install_code_debit.get() > 0
            && config.rate_limiting_of_instructions == FlagStatus::Enabled
        {
            return Err(CanisterManagerError::InstallCodeRateLimited(id));
        }

        Ok(())
    }

    /// Replaces the execution state of the current canister with the freshly
    /// created execution state. The stable memory is conditionally replaced
    /// based on the given `stable_memory_handling`.
    ///
    /// It also updates the compute and memory allocations with the requested
    /// values in `original` context.
    pub fn replace_execution_state_and_allocations(
        &mut self,
        instructions_from_compilation: NumInstructions,
        maybe_execution_state: HypervisorResult<ExecutionState>,
        stable_memory_handling: StableMemoryHandling,
        original: &OriginalContext,
    ) -> Result<(), CanisterManagerError> {
        self.steps
            .push(InstallCodeStep::ReplaceExecutionStateAndAllocations {
                instructions_from_compilation,
                maybe_execution_state: maybe_execution_state.clone(),
                stable_memory_handling,
            });

        self.execution_parameters
            .instruction_limits
            .reduce_by(instructions_from_compilation);

        let subnet_type = self.execution_parameters.subnet_type;
        let old_memory_usage = self.canister.memory_usage(subnet_type);
        let old_memory_allocation = self.canister.system_state.memory_allocation;
        let old_compute_allocation = self.canister.scheduler_state.compute_allocation;

        // Replace the execution state and maybe the stable memory.
        let mut execution_state =
            maybe_execution_state.map_err(|err| (self.canister.canister_id(), err))?;
        execution_state.stable_memory =
            match (stable_memory_handling, self.canister.execution_state.take()) {
                (StableMemoryHandling::Keep, Some(old)) => old.stable_memory,
                (StableMemoryHandling::Keep, None) | (StableMemoryHandling::Replace, _) => {
                    execution_state.stable_memory
                }
            };
        self.canister.execution_state = Some(execution_state);

        // Update the compute allocation.
        let new_compute_allocation = original
            .requested_compute_allocation
            .unwrap_or(old_compute_allocation);
        self.canister.scheduler_state.compute_allocation = new_compute_allocation;
        self.execution_parameters.compute_allocation = new_compute_allocation;

        // Update the memory allocation.
        let new_memory_allocation = original
            .requested_memory_allocation
            .unwrap_or(old_memory_allocation);
        self.canister.system_state.memory_allocation = new_memory_allocation;

        // It is impossible to transition from `MemoryAllocation::Reserved` to
        // `MemoryAllocation::BestEffort` because `None` in `InstallCodeArgs` is
        // interpreted as keeping the old memory allocation.
        // This means that we can use the existing canister memory limit as the
        // best effort memory limit.
        debug_assert!(
            old_memory_allocation == new_memory_allocation
                || new_memory_allocation != MemoryAllocation::BestEffort
        );
        let best_effort_limit = self.execution_parameters.canister_memory_limit;
        self.execution_parameters.canister_memory_limit =
            self.canister.memory_limit(best_effort_limit);

        let new_memory_usage = self.canister.memory_usage(subnet_type);
        if new_memory_usage > self.execution_parameters.canister_memory_limit {
            return Err(CanisterManagerError::NotEnoughMemoryAllocationGiven {
                canister_id: self.canister.canister_id(),
                memory_allocation_given: new_memory_allocation,
                memory_usage_needed: new_memory_usage,
            });
        }
        self.update_allocated_bytes(
            old_memory_usage,
            old_memory_allocation,
            new_memory_usage,
            new_memory_allocation,
        );
        Ok(())
    }

    // A helper method to keep track of allocated and deallocated memory bytes.
    fn update_allocated_bytes(
        &mut self,
        old_memory_usage: NumBytes,
        old_memory_allocation: MemoryAllocation,
        new_memory_usage: NumBytes,
        new_memory_allocation: MemoryAllocation,
    ) {
        let old_bytes = old_memory_allocation.bytes().max(old_memory_usage);
        let new_bytes = new_memory_allocation.bytes().max(new_memory_usage);
        if old_bytes <= new_bytes {
            self.allocated_bytes += new_bytes - old_bytes;
        } else {
            self.deallocated_bytes += old_bytes - new_bytes;
        }
    }

    /// Checks the result of Wasm execution and applies the state changes.
    pub fn handle_wasm_execution(
        &mut self,
        canister_state_changes: Option<CanisterStateChanges>,
        output: WasmExecutionOutput,
        original: &OriginalContext,
        round: &RoundContext,
    ) -> Result<(), CanisterManagerError> {
        self.steps.push(InstallCodeStep::HandleWasmExecution {
            canister_state_changes: canister_state_changes.clone(),
            output: output.clone(),
        });

        self.execution_parameters
            .instruction_limits
            .update(output.num_instructions_left);

        match output.wasm_result {
            Ok(None) => {}
            Ok(Some(_response)) => {
                fatal!(round.log, "[EXC-BUG] System methods cannot use msg_reply.");
            }
            Err(err) => {
                if let HypervisorError::SliceOverrun {
                    instructions,
                    limit,
                } = &err
                {
                    info!(
                        round.log,
                        "Canister {} overrun a slice in install_code: {} / {}",
                        self.canister.canister_id(),
                        instructions,
                        limit
                    );
                }
                return Err((self.canister().canister_id(), err).into());
            }
        };

        if let Some(CanisterStateChanges {
            globals,
            wasm_memory,
            stable_memory,
            system_state_changes,
        }) = canister_state_changes
        {
            if let Err(err) = system_state_changes.apply_changes(
                original.time,
                &mut self.canister.system_state,
                round.network_topology,
                round.hypervisor.subnet_id(),
                round.log,
            ) {
                match &err {
                    HypervisorError::WasmEngineError(err) => {
                        // TODO(RUN-299): Increment a critical error counter here.
                        error!(
                            round.log,
                            "[EXC-BUG]: Failed to apply state changes due to a bug: {}", err
                        )
                    }
                    HypervisorError::OutOfMemory => {
                        warn!(
                            round.log,
                            "Failed to apply state changes due to DTS: {}", err
                        )
                    }
                    _ => {
                        // TODO(RUN-299): Increment a critical error counter here.
                        error!(
                            round.log,
                            "[EXC-BUG]: Failed to apply state changes due to an unexpected error: {}", err
                        )
                    }
                }
                return Err((self.canister.canister_id(), err).into());
            }
            let execution_state = self.canister.execution_state.as_mut().unwrap();
            execution_state.wasm_memory = wasm_memory;
            execution_state.stable_memory = stable_memory;
            execution_state.exported_globals = globals;
            match self.canister.system_state.memory_allocation {
                MemoryAllocation::Reserved(_) => {}
                MemoryAllocation::BestEffort => {
                    self.allocated_bytes += output.allocated_bytes;
                    self.allocated_message_bytes += output.allocated_message_bytes;
                }
            }
            self.total_heap_delta +=
                NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64);
        }
        Ok(())
    }

    // A helper method to replay the given step.
    fn replay_step(
        &mut self,
        step: InstallCodeStep,
        original: &OriginalContext,
        round: &RoundContext,
        round_limits: &RoundLimits,
    ) -> Result<(), CanisterManagerError> {
        match step {
            InstallCodeStep::ValidateInput => self.validate_input(original, round_limits),
            InstallCodeStep::ReplaceExecutionStateAndAllocations {
                instructions_from_compilation,
                maybe_execution_state,
                stable_memory_handling,
            } => self.replace_execution_state_and_allocations(
                instructions_from_compilation,
                maybe_execution_state,
                stable_memory_handling,
                original,
            ),
            InstallCodeStep::HandleWasmExecution {
                canister_state_changes,
                output,
            } => self.handle_wasm_execution(canister_state_changes, output, original, round),
        }
    }
}

/// Context variables that remain the same throughput the entire deterministic
/// time slicing execution of `install_code`.
#[derive(Debug)]
pub(crate) struct OriginalContext {
    pub execution_parameters: ExecutionParameters,
    pub mode: CanisterInstallMode,
    pub canister_layout_path: PathBuf,
    pub config: CanisterMgrConfig,
    pub message: RequestOrIngress,
    pub prepaid_execution_cycles: Cycles,
    pub time: Time,
    pub compilation_cost_handling: CompilationCostHandling,
    pub subnet_size: usize,
    pub requested_compute_allocation: Option<ComputeAllocation>,
    pub requested_memory_allocation: Option<MemoryAllocation>,
    pub sender: PrincipalId,
    pub canister_id: CanisterId,
}

pub(crate) fn validate_controller(
    canister: &CanisterState,
    controller: &PrincipalId,
) -> Result<(), CanisterManagerError> {
    if !canister.controllers().contains(controller) {
        return Err(CanisterManagerError::CanisterInvalidController {
            canister_id: canister.canister_id(),
            controllers_expected: canister.system_state.controllers.clone(),
            controller_provided: *controller,
        });
    }
    Ok(())
}

pub(crate) fn validate_compute_allocation(
    total_subnet_compute_allocation_used: u64,
    canister: &CanisterState,
    new_compute_allocation: Option<ComputeAllocation>,
    config: &CanisterMgrConfig,
) -> Result<(), CanisterManagerError> {
    if let Some(new_compute_allocation) = new_compute_allocation {
        let old_compute_allocation = canister.compute_allocation();
        if new_compute_allocation.as_percent() > old_compute_allocation.as_percent() {
            let others = total_subnet_compute_allocation_used
                .saturating_sub(old_compute_allocation.as_percent());
            let available = config.compute_capacity.saturating_sub(others + 1);
            if new_compute_allocation.as_percent() > available {
                return Err(CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                    requested: new_compute_allocation,
                    available: available.max(old_compute_allocation.as_percent()),
                });
            }
        }
    }
    Ok(())
}

// Ensures that the subnet has enough memory capacity left to install the
// canister.
pub(crate) fn validate_memory_allocation(
    available_memory: &SubnetAvailableMemory,
    canister: &CanisterState,
    memory_allocation: Option<MemoryAllocation>,
    config: &CanisterMgrConfig,
) -> Result<(), CanisterManagerError> {
    if let Some(memory_allocation) = memory_allocation {
        if let MemoryAllocation::Reserved(requested_allocation) = memory_allocation {
            if requested_allocation < canister.memory_usage(config.own_subnet_type) {
                return Err(CanisterManagerError::NotEnoughMemoryAllocationGiven {
                    canister_id: canister.canister_id(),
                    memory_allocation_given: memory_allocation,
                    memory_usage_needed: canister.memory_usage(config.own_subnet_type),
                });
            }
        }
        let canister_current_allocation = match canister.memory_allocation() {
            MemoryAllocation::Reserved(bytes) => bytes,
            MemoryAllocation::BestEffort => canister.memory_usage(config.own_subnet_type),
        };
        if memory_allocation.bytes().get() as i128
            > available_memory.get_total_memory() as i128
                + canister_current_allocation.get() as i128
        {
            return Err(CanisterManagerError::SubnetMemoryCapacityOverSubscribed {
                requested: memory_allocation.bytes(),
                available: NumBytes::from((available_memory.get_total_memory()).max(0) as u64),
            });
        }
    }
    Ok(())
}

pub(crate) fn get_wasm_hash(canister: &CanisterState) -> Option<[u8; 32]> {
    canister
        .execution_state
        .as_ref()
        .map(|execution_state| execution_state.wasm_binary.binary.module_hash())
}

#[doc(hidden)] // pub for usage in tests
pub(crate) fn canister_layout(
    state_path: &Path,
    canister_id: &CanisterId,
) -> CanisterLayout<ReadOnly> {
    // We use ReadOnly, as CheckpointLayouts with write permissions have side effects
    // of creating directories
    CheckpointLayout::<ReadOnly>::new(state_path.into(), Height::from(0))
        .and_then(|layout| layout.canister(canister_id))
        .expect("failed to obtain canister layout")
}

/// Finishes an `install_code` execution early due to an error. The only state
/// change that is applied to the clean canister state is refunding the prepaid
/// execution cycles.
pub(crate) fn finish_err(
    clean_canister: CanisterState,
    instructions_left: NumInstructions,
    original: OriginalContext,
    round: RoundContext,
    err: CanisterManagerError,
) -> DtsInstallCodeResult {
    let mut new_canister = clean_canister;

    new_canister
        .system_state
        .apply_cycles_debit(new_canister.canister_id(), round.log);

    let message_instruction_limit = original.execution_parameters.instruction_limits.message();
    round.cycles_account_manager.refund_unused_execution_cycles(
        &mut new_canister.system_state,
        instructions_left,
        message_instruction_limit,
        original.prepaid_execution_cycles,
        round.execution_refund_error_counter,
        original.subnet_size,
        round.log,
    );

    let instructions_used = NumInstructions::from(
        message_instruction_limit
            .get()
            .saturating_sub(instructions_left.get()),
    );

    if original.config.rate_limiting_of_instructions == FlagStatus::Enabled {
        new_canister.scheduler_state.install_code_debit += instructions_used;
    }

    DtsInstallCodeResult::Finished {
        canister: new_canister,
        message: original.message,
        instructions_used,
        result: Err(err),
    }
}
