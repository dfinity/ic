// This module defines types and functions common between canister installation
// and upgrades.

use std::path::{Path, PathBuf};

use crate::execution::common::log_dirty_pages;
use ic_base_types::{CanisterId, NumBytes, PrincipalId};
use ic_config::flag_status::FlagStatus;
use ic_embedders::{
    wasm_executor::{CanisterStateChanges, ExecutionStateChanges},
    wasmtime_embedder::system_api::ExecutionParameters,
};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, MessageMemoryUsage, SubnetAvailableExecutionMemoryChange,
    SubnetAvailableMemoryError, WasmExecutionOutput,
};
use ic_logger::{error, fatal, info, warn};
use ic_management_canister_types_private::{
    CanisterChangeDetails, CanisterChangeOrigin, CanisterInstallModeV2,
};
use ic_replicated_state::canister_state::system_state::ReservationError;
use ic_replicated_state::metadata_state::subnet_call_context_manager::InstallCodeCallId;
use ic_replicated_state::{CanisterState, ExecutionState, num_bytes_try_from};
use ic_state_layout::{CanisterLayout, CheckpointLayout, ReadOnly};
use ic_sys::PAGE_SIZE;
use ic_types::{
    CanisterLog, CanisterTimer, Height, MemoryAllocation, NumInstructions, Time, funds::Cycles,
    messages::CanisterCall,
};
use ic_wasm_types::WasmHash;

use crate::{
    CompilationCostHandling, RoundLimits,
    canister_manager::types::{
        CanisterManagerError, CanisterMgrConfig, DtsInstallCodeResult, InstallCodeResult,
    },
    execution_environment::RoundContext,
};
use ic_replicated_state::canister_state::execution_state::WasmExecutionMode;

#[cfg(test)]
mod tests;

/// Indicates whether the memory is kept or replaced with new (initial) memory.
/// Applicable to both the stable memory and the main memory of a canister.
#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum MemoryHandling {
    /// Retain the memory.
    Keep,
    /// Reset the memory.
    Replace,
}

/// Specifies the handling of the canister's memories.
/// * On install and re-install:
///   - Replace both the stable memory and the main memory.
/// * On upgrade:
///   - For canisters with enhanced orthogonal persistence (Motoko):
///     Retain both the main memory and the stable memory.
///   - For all other canisters:
///     Retain only the stable memory and erase the main memory.
#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) struct CanisterMemoryHandling {
    pub stable_memory_handling: MemoryHandling,
    pub main_memory_handling: MemoryHandling,
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
        memory_handling: CanisterMemoryHandling,
    },
    ClearCertifiedData,
    ClearLog,
    DeactivateGlobalTimer,
    BumpCanisterVersion,
    AddCanisterChange {
        timestamp_nanos: Time,
        origin: CanisterChangeOrigin,
        mode: CanisterInstallModeV2,
        module_hash: WasmHash,
    },
    HandleWasmExecution {
        canister_state_changes: CanisterStateChanges,
        output: WasmExecutionOutput,
    },
    ChargeForLargeWasmAssembly {
        instructions: NumInstructions,
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
    allocated_guaranteed_response_message_bytes: NumBytes,
    allocated_wasm_custom_sections_bytes: NumBytes,
    deallocated_bytes: NumBytes,
    deallocated_wasm_custom_sections_bytes: NumBytes,
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
            allocated_bytes: NumBytes::new(0),
            allocated_guaranteed_response_message_bytes: NumBytes::new(0),
            allocated_wasm_custom_sections_bytes: NumBytes::new(0),
            deallocated_bytes: NumBytes::new(0),
            deallocated_wasm_custom_sections_bytes: NumBytes::new(0),
            total_heap_delta: NumBytes::new(0),
        }
    }

    pub fn canister(&self) -> &CanisterState {
        &self.canister
    }

    pub fn clear_certified_data(&mut self) {
        self.steps.push(InstallCodeStep::ClearCertifiedData);
        self.canister.system_state.certified_data = Vec::new();
    }

    pub fn clear_log_obsolete(&mut self) {
        self.steps.push(InstallCodeStep::ClearLog);
        self.canister.clear_log_obsolete();
    }

    pub fn deactivate_global_timer(&mut self) {
        self.steps.push(InstallCodeStep::DeactivateGlobalTimer);
        self.canister.system_state.global_timer = CanisterTimer::Inactive;
    }

    pub fn bump_canister_version(&mut self) {
        self.steps.push(InstallCodeStep::BumpCanisterVersion);
        self.canister.system_state.canister_version += 1;
    }

    pub fn add_canister_change(
        &mut self,
        timestamp_nanos: Time,
        origin: CanisterChangeOrigin,
        mode: CanisterInstallModeV2,
        module_hash: WasmHash,
    ) {
        self.steps.push(InstallCodeStep::AddCanisterChange {
            timestamp_nanos,
            origin: origin.clone(),
            mode,
            module_hash: module_hash.clone(),
        });
        let details = CanisterChangeDetails::code_deployment(mode.into(), module_hash.to_slice());
        let available_execution_memory_change =
            self.canister
                .add_canister_change(timestamp_nanos, origin, details);
        match available_execution_memory_change {
            SubnetAvailableExecutionMemoryChange::Allocated(allocated_bytes) => {
                self.allocated_bytes += allocated_bytes;
            }
            SubnetAvailableExecutionMemoryChange::Deallocated(deallocated_bytes) => {
                self.deallocated_bytes += deallocated_bytes;
            }
        }
    }

    pub fn charge_for_large_wasm_assembly(&mut self, instructions: NumInstructions) {
        self.steps
            .push(InstallCodeStep::ChargeForLargeWasmAssembly { instructions });
        self.reduce_instructions_by(instructions);
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
        self.canister.memory_usage()
    }

    pub fn canister_message_memory_usage(&self) -> MessageMemoryUsage {
        self.canister.message_memory_usage()
    }

    pub fn reduce_instructions_by(&mut self, instructions: NumInstructions) {
        self.execution_parameters
            .instruction_limits
            .reduce_by(instructions);
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
    #[allow(clippy::result_large_err)]
    pub fn resume(
        clean_canister: &CanisterState,
        paused: PausedInstallCodeHelper,
        original: &OriginalContext,
        round: &RoundContext,
    ) -> Result<Self, (CanisterManagerError, NumInstructions, CanisterLog)> {
        let mut helper = Self::new(clean_canister, original);
        let paused_instructions_left = paused.instructions_left;
        for state_change in paused.steps.into_iter() {
            helper
                .replay_step(state_change, original, round)
                .map_err(|err| (err, paused_instructions_left, helper.take_canister_log()))?;
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

        let instructions_used = NumInstructions::from(
            message_instruction_limit
                .get()
                .saturating_sub(instructions_left.get()),
        );

        round.cycles_account_manager.refund_unused_execution_cycles(
            &mut self.canister.system_state,
            instructions_left,
            message_instruction_limit,
            original.prepaid_execution_cycles,
            round.counters.execution_refund_error,
            original.subnet_size,
            round.cost_schedule,
            original.wasm_execution_mode,
            round.log,
        );

        self.canister
            .system_state
            .apply_ingress_induction_cycles_debit(
                self.canister.canister_id(),
                round.log,
                round.counters.charging_from_balance_error,
            );

        let wasm_memory_usage = self
            .canister
            .execution_state
            .as_ref()
            .map_or(NumBytes::new(0), |es| {
                num_bytes_try_from(es.wasm_memory.size).unwrap()
            });

        if let Some(wasm_memory_limit) = self.canister.system_state.wasm_memory_limit {
            // A Wasm memory limit of 0 means unlimited.
            if wasm_memory_limit.get() != 0 && wasm_memory_usage > wasm_memory_limit {
                let err = HypervisorError::WasmMemoryLimitExceeded {
                    bytes: wasm_memory_usage,
                    limit: wasm_memory_limit,
                };
                return finish_err(
                    clean_canister,
                    self.instructions_left(),
                    original,
                    round,
                    CanisterManagerError::Hypervisor(self.canister.canister_id(), err),
                    self.take_canister_log(),
                );
            }
        }

        if self.allocated_bytes > self.deallocated_bytes {
            let bytes = self.allocated_bytes - self.deallocated_bytes;

            let reservation_cycles = round.cycles_account_manager.storage_reservation_cycles(
                bytes,
                &original.execution_parameters.subnet_memory_saturation,
                original.subnet_size,
                round.cost_schedule,
            );

            match self
                .canister
                .system_state
                .reserve_cycles(reservation_cycles)
            {
                Ok(()) => {}
                Err(err) => {
                    let err = match err {
                        ReservationError::InsufficientCycles {
                            requested,
                            available,
                        } => CanisterManagerError::InsufficientCyclesInMemoryGrow {
                            bytes,
                            available,
                            required: requested,
                        },
                        ReservationError::ReservedLimitExceed { requested, limit } => {
                            CanisterManagerError::ReservedCyclesLimitExceededInMemoryGrow {
                                bytes,
                                requested,
                                limit,
                            }
                        }
                    };
                    return finish_err(
                        clean_canister,
                        self.instructions_left(),
                        original,
                        round,
                        err,
                        self.take_canister_log(),
                    );
                }
            }

            let threshold = round.cycles_account_manager.freeze_threshold_cycles(
                self.canister.system_state.freeze_threshold,
                self.canister.memory_allocation(),
                self.canister.memory_usage(),
                self.canister.message_memory_usage(),
                self.canister.compute_allocation(),
                original.subnet_size,
                round.cost_schedule,
                self.canister.system_state.reserved_balance(),
            );
            if self.canister.system_state.balance() < threshold {
                let err = CanisterManagerError::InsufficientCyclesInMemoryGrow {
                    bytes,
                    available: self.canister.system_state.balance(),
                    required: threshold,
                };
                return finish_err(
                    clean_canister,
                    self.instructions_left(),
                    original,
                    round,
                    err,
                    self.take_canister_log(),
                );
            }
        }

        let mut subnet_available_memory = round_limits.subnet_available_memory;
        subnet_available_memory.increment(
            self.deallocated_bytes,
            NumBytes::new(0),
            self.deallocated_wasm_custom_sections_bytes,
        );
        if let Err(err) = subnet_available_memory.try_decrement(
            self.allocated_bytes,
            self.allocated_guaranteed_response_message_bytes,
            self.allocated_wasm_custom_sections_bytes,
        ) {
            match err {
                SubnetAvailableMemoryError::InsufficientMemory {
                    execution_requested,
                    guaranteed_response_message_requested: _,
                    wasm_custom_sections_requested,
                    available_execution,
                    available_guaranteed_response_messages: _,
                    available_wasm_custom_sections,
                } => {
                    let err = if wasm_custom_sections_requested.get() as i128
                        > available_wasm_custom_sections as i128
                    {
                        CanisterManagerError::SubnetWasmCustomSectionCapacityOverSubscribed {
                            requested: wasm_custom_sections_requested,
                            available: NumBytes::new(available_wasm_custom_sections.max(0) as u64),
                        }
                    } else {
                        CanisterManagerError::SubnetMemoryCapacityOverSubscribed {
                            requested: execution_requested,
                            available: NumBytes::new(available_execution.max(0) as u64),
                        }
                    };
                    return finish_err(
                        clean_canister,
                        self.instructions_left(),
                        original,
                        round,
                        err,
                        self.take_canister_log(),
                    );
                }
            }
        }

        // After this point `install_code` is guaranteed to succeed.
        // Commit all the remaining state and round limit changes.

        round_limits.subnet_available_memory = subnet_available_memory;

        if original.config.rate_limiting_of_instructions == FlagStatus::Enabled {
            self.canister.scheduler_state.install_code_debit += self.instructions_consumed();
        }

        let old_wasm_hash = get_wasm_hash(&clean_canister);
        let new_wasm_hash = get_wasm_hash(&self.canister);

        if original.log_dirty_pages == FlagStatus::Enabled {
            log_dirty_pages(
                round.log,
                &original.canister_id,
                original.message.method_name(),
                self.total_heap_delta.get() as usize / PAGE_SIZE,
                instructions_used,
            );
        }

        DtsInstallCodeResult::Finished {
            canister: self.canister,
            message: original.message,
            call_id: original.call_id,
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
    ) -> Result<(), CanisterManagerError> {
        self.steps.push(InstallCodeStep::ValidateInput);

        let config = &original.config;
        let id = self.canister.system_state.canister_id;

        validate_controller(&self.canister, &original.sender)?;

        match original.mode {
            CanisterInstallModeV2::Install => {
                if self.canister.execution_state.is_some() {
                    return Err(CanisterManagerError::CanisterNonEmpty(id));
                }
            }
            CanisterInstallModeV2::Reinstall | CanisterInstallModeV2::Upgrade(..) => {}
        }

        if self.canister.scheduler_state.install_code_debit.get() > 0
            && config.rate_limiting_of_instructions == FlagStatus::Enabled
        {
            return Err(CanisterManagerError::InstallCodeRateLimited(id));
        }

        Ok(())
    }

    /// Replaces the execution state of the current canister with the freshly
    /// created execution state. The stable memory and the main memory are
    /// conditionally replaced based on the given `memory_handling`.
    ///
    /// It also updates the compute and memory allocations with the requested
    /// values in `original` context.
    pub fn replace_execution_state_and_allocations(
        &mut self,
        instructions_from_compilation: NumInstructions,
        maybe_execution_state: HypervisorResult<ExecutionState>,
        memory_handling: CanisterMemoryHandling,
    ) -> Result<(), CanisterManagerError> {
        self.steps
            .push(InstallCodeStep::ReplaceExecutionStateAndAllocations {
                instructions_from_compilation,
                maybe_execution_state: maybe_execution_state.clone(),
                memory_handling,
            });

        self.reduce_instructions_by(instructions_from_compilation);

        let old_memory_usage = self.canister.memory_usage();
        let memory_allocation = self.canister.system_state.memory_allocation;
        let old_wasm_custom_sections_memory_used = self
            .canister
            .execution_state
            .as_ref()
            .map_or(NumBytes::new(0), |es| es.metadata.memory_usage());

        // Replace the execution state and maybe the stable memory.
        let mut execution_state =
            maybe_execution_state.map_err(|err| (self.canister.canister_id(), err))?;

        let new_wasm_custom_sections_memory_used = execution_state.metadata.memory_usage();

        if let Some(old) = self.canister.execution_state.take() {
            match memory_handling.stable_memory_handling {
                MemoryHandling::Keep => execution_state.stable_memory = old.stable_memory,
                MemoryHandling::Replace => {}
            }
            match memory_handling.main_memory_handling {
                MemoryHandling::Keep => execution_state.wasm_memory = old.wasm_memory,
                MemoryHandling::Replace => {}
            }
        };

        self.canister.execution_state = Some(execution_state);

        let new_memory_usage = self.canister.memory_usage();
        self.update_allocated_bytes(
            old_memory_usage,
            old_wasm_custom_sections_memory_used,
            new_memory_usage,
            new_wasm_custom_sections_memory_used,
            memory_allocation,
        );
        Ok(())
    }

    // A helper method to keep track of allocated and deallocated memory bytes.
    fn update_allocated_bytes(
        &mut self,
        old_memory_usage: NumBytes,
        old_wasm_custom_sections_memory_used: NumBytes,
        new_memory_usage: NumBytes,
        new_wasm_custom_sections_memory_used: NumBytes,
        memory_allocation: MemoryAllocation,
    ) {
        let old_bytes = memory_allocation.allocated_bytes(old_memory_usage);
        let new_bytes = memory_allocation.allocated_bytes(new_memory_usage);
        if old_bytes <= new_bytes {
            self.allocated_bytes += new_bytes - old_bytes;
        } else {
            self.deallocated_bytes += old_bytes - new_bytes;
        }
        if new_wasm_custom_sections_memory_used >= old_wasm_custom_sections_memory_used {
            self.allocated_wasm_custom_sections_bytes +=
                new_wasm_custom_sections_memory_used - old_wasm_custom_sections_memory_used;
        } else {
            self.deallocated_wasm_custom_sections_bytes +=
                old_wasm_custom_sections_memory_used - new_wasm_custom_sections_memory_used;
        }
    }

    /// Takes the canister log.
    pub(crate) fn take_canister_log(&mut self) -> CanisterLog {
        self.canister.system_state.canister_log.take()
    }

    /// Checks the result of Wasm execution and applies the state changes.
    ///
    /// Returns the amount of instructions consumed along with the result of
    /// applying the state changes.
    pub fn handle_wasm_execution(
        &mut self,
        canister_state_changes: CanisterStateChanges,
        output: WasmExecutionOutput,
        original: &OriginalContext,
        round: &RoundContext,
    ) -> (NumInstructions, Result<(), CanisterManagerError>) {
        self.steps.push(InstallCodeStep::HandleWasmExecution {
            canister_state_changes: canister_state_changes.clone(),
            output: output.clone(),
        });

        let instructions_consumed = NumInstructions::from(
            self.execution_parameters
                .instruction_limits
                .message()
                .get()
                .saturating_sub(output.num_instructions_left.get()),
        );

        self.execution_parameters
            .instruction_limits
            .update(output.num_instructions_left);

        debug_assert!(
            output
                .wasm_result
                .clone()
                .map_or(true, |result| result.is_none())
        );

        let CanisterStateChanges {
            execution_state_changes,
            system_state_modifications,
        } = canister_state_changes;

        // Apply system state changes always.
        // The result will be checked later after we've checked the wasm execution result so that we
        // don't miss logging in case there was an error from Wasm execution.
        let result_of_applying_system_state_modifications = system_state_modifications
            .apply_changes(
                original.time,
                &mut self.canister.system_state,
                round.network_topology,
                round.hypervisor.subnet_id(),
                false, // Install cannot happen in composite_query.
                round.log,
            );

        match output.wasm_result {
            Ok(None) => {}
            Ok(Some(_response)) => {
                debug_assert!(false);
                round.counters.invalid_system_call_error.inc();
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
                return (
                    instructions_consumed,
                    Err((self.canister.canister_id(), err).into()),
                );
            }
        };

        if let Err(err) = result_of_applying_system_state_modifications {
            debug_assert_eq!(err, HypervisorError::OutOfMemory);
            match &err {
                HypervisorError::WasmEngineError(err) => {
                    round.counters.state_changes_error.inc();
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
                    round.counters.state_changes_error.inc();
                    error!(
                        round.log,
                        "[EXC-BUG]: Failed to apply state changes due to an unexpected error: {}",
                        err
                    )
                }
            }
            return (
                instructions_consumed,
                Err((self.canister.canister_id(), err).into()),
            );
        }

        if let Some(ExecutionStateChanges {
            globals,
            wasm_memory,
            stable_memory,
        }) = execution_state_changes
        {
            let execution_state = self.canister.execution_state.as_mut().unwrap();
            execution_state.wasm_memory = wasm_memory;
            execution_state.stable_memory = stable_memory;
            execution_state.exported_globals = globals;
            self.allocated_bytes += output.allocated_bytes;
            debug_assert_eq!(
                output.allocated_guaranteed_response_message_bytes,
                NumBytes::new(0)
            ); // no messages can be created during `install_code`
            self.allocated_guaranteed_response_message_bytes +=
                output.allocated_guaranteed_response_message_bytes;
            self.total_heap_delta +=
                NumBytes::new((output.instance_stats.dirty_pages() * PAGE_SIZE) as u64);
        }
        (instructions_consumed, Ok(()))
    }

    // A helper method to replay the given step.
    fn replay_step(
        &mut self,
        step: InstallCodeStep,
        original: &OriginalContext,
        round: &RoundContext,
    ) -> Result<(), CanisterManagerError> {
        match step {
            InstallCodeStep::ValidateInput => self.validate_input(original),
            InstallCodeStep::ReplaceExecutionStateAndAllocations {
                instructions_from_compilation,
                maybe_execution_state,
                memory_handling,
            } => self.replace_execution_state_and_allocations(
                instructions_from_compilation,
                maybe_execution_state,
                memory_handling,
            ),
            InstallCodeStep::ClearCertifiedData => {
                self.clear_certified_data();
                Ok(())
            }
            InstallCodeStep::ClearLog => {
                self.clear_log_obsolete();
                Ok(())
            }
            InstallCodeStep::DeactivateGlobalTimer => {
                self.deactivate_global_timer();
                Ok(())
            }
            InstallCodeStep::BumpCanisterVersion => {
                self.bump_canister_version();
                Ok(())
            }
            InstallCodeStep::AddCanisterChange {
                timestamp_nanos,
                origin,
                mode,
                module_hash,
            } => {
                self.add_canister_change(timestamp_nanos, origin, mode, module_hash);
                Ok(())
            }
            InstallCodeStep::HandleWasmExecution {
                canister_state_changes,
                output,
            } => {
                let (_, result) =
                    self.handle_wasm_execution(canister_state_changes, output, original, round);
                result
            }
            InstallCodeStep::ChargeForLargeWasmAssembly { instructions } => {
                self.charge_for_large_wasm_assembly(instructions);
                Ok(())
            }
        }
    }
}

/// Context variables that remain the same throughput the entire deterministic
/// time slicing execution of `install_code`.
#[derive(Debug)]
pub(crate) struct OriginalContext {
    pub execution_parameters: ExecutionParameters,
    pub mode: CanisterInstallModeV2,
    pub canister_layout_path: PathBuf,
    pub config: CanisterMgrConfig,
    pub message: CanisterCall,
    pub call_id: InstallCodeCallId,
    pub prepaid_execution_cycles: Cycles,
    pub time: Time,
    pub compilation_cost_handling: CompilationCostHandling,
    pub subnet_size: usize,
    pub sender: PrincipalId,
    pub canister_id: CanisterId,
    pub log_dirty_pages: FlagStatus,
    pub wasm_execution_mode: WasmExecutionMode,
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
    CheckpointLayout::<ReadOnly>::new_untracked(state_path.into(), Height::from(0))
        .and_then(|layout| layout.canister(canister_id))
        .expect("failed to obtain canister layout")
}

/// Finishes an `install_code` execution early due to an error.
///
/// The only state changes applied to the clean canister state:
///  - saving the new canister log
///  - refunding the prepaid execution cycles
pub(crate) fn finish_err(
    clean_canister: CanisterState,
    instructions_left: NumInstructions,
    original: OriginalContext,
    round: RoundContext,
    err: CanisterManagerError,
    new_canister_log: CanisterLog,
) -> DtsInstallCodeResult {
    let mut new_canister = clean_canister;

    new_canister.set_log(new_canister_log);
    new_canister
        .system_state
        .apply_ingress_induction_cycles_debit(
            new_canister.canister_id(),
            round.log,
            round.counters.charging_from_balance_error,
        );

    let message_instruction_limit = original.execution_parameters.instruction_limits.message();

    round.cycles_account_manager.refund_unused_execution_cycles(
        &mut new_canister.system_state,
        instructions_left,
        message_instruction_limit,
        original.prepaid_execution_cycles,
        round.counters.execution_refund_error,
        original.subnet_size,
        round.cost_schedule,
        original.wasm_execution_mode,
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
        call_id: original.call_id,
        instructions_used,
        result: Err(err),
    }
}
