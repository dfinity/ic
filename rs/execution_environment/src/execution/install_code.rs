// This module defines types and functions common between canister installation
// and upgrades.

use std::path::{Path, PathBuf};

use ic_base_types::{CanisterId, NumBytes, PrincipalId};
use ic_config::flag_status::FlagStatus;
use ic_ic00_types::CanisterInstallMode;
use ic_interfaces::{
    execution_environment::{HypervisorError, SubnetAvailableMemory},
    messages::RequestOrIngress,
};
use ic_logger::{error, fatal, ReplicaLogger};
use ic_replicated_state::CanisterState;
use ic_state_layout::{CanisterLayout, CheckpointLayout, RwPolicy};
use ic_types::{ComputeAllocation, Height, MemoryAllocation, NumInstructions};

use crate::{
    canister_manager::{
        CanisterManagerError, CanisterMgrConfig, DtsInstallCodeResult, InstallCodeResult,
    },
    execution_environment::RoundContext,
    RoundLimits,
};

/// The result of canister installation or upgrade routines.
/// If the routine has finished successfuly, then the canister state is the new
/// canister state with all changes. If the routine has failed, then there is no
/// new canister state and the caller should use the old state after refunding
/// the remaining instructions.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum InstallCodeRoutineResult {
    Finished {
        instructions_left: NumInstructions,
        result: Result<(CanisterState, NumBytes), CanisterManagerError>,
    },
    Paused {
        paused_execution: Box<dyn PausedInstallCodeRoutine>,
    },
}

/// Represents a paused execution of install code routine,
/// that can be resumed or aborted.
pub(crate) trait PausedInstallCodeRoutine: std::fmt::Debug + Send {
    /// Resumes a paused install code execution.
    fn resume(
        self: Box<Self>,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> InstallCodeRoutineResult;

    // Aborts the paused execution.
    fn abort(self: Box<Self>);
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
    compute_allocation: Option<ComputeAllocation>,
    config: &CanisterMgrConfig,
) -> Result<(), CanisterManagerError> {
    if let Some(compute_allocation) = compute_allocation {
        let canister_current_allocation = canister.scheduler_state.compute_allocation.as_percent();
        // Check only the case when compute allocation increases. Other
        // cases always succeed.
        if compute_allocation.as_percent() > canister_current_allocation {
            // current_compute_allocation of this canister will be subtracted from the
            // total_compute_allocation() of the subnet if the canister's compute_allocation
            // is changed to the requested_compute_allocation
            if compute_allocation.as_percent() + total_subnet_compute_allocation_used
                - canister_current_allocation
                >= config.compute_capacity
            {
                let capped_usage = std::cmp::min(
                    config.compute_capacity,
                    total_subnet_compute_allocation_used + 1,
                );
                return Err(CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                    requested: compute_allocation,
                    available: config.compute_capacity + canister_current_allocation - capped_usage,
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
                available: NumBytes::from(
                    (available_memory.get_total_memory() - canister_current_allocation.get() as i64)
                        .max(0) as u64,
                ),
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
) -> CanisterLayout<RwPolicy> {
    CheckpointLayout::<RwPolicy>::new(state_path.into(), Height::from(0))
        .and_then(|layout| layout.canister(canister_id))
        .expect("failed to obtain canister layout")
}

pub(crate) fn truncate_canister_heap(
    log: &ReplicaLogger,
    state_path: &Path,
    canister_id: CanisterId,
) {
    let layout = canister_layout(state_path, &canister_id);
    let heap_file = layout.vmemory_0();
    if let Err(err) = nix::unistd::truncate(&heap_file, 0) {
        // It's OK if the file doesn't exist, everything else is a fatal error.
        if err != nix::errno::Errno::ENOENT {
            fatal!(
                log,
                "failed to truncate heap of canister {} stored at {}: {}",
                canister_id,
                heap_file.display(),
                err
            )
        }
    }
}

pub(crate) fn truncate_canister_stable_memory(
    log: &ReplicaLogger,
    state_path: &Path,
    canister_id: CanisterId,
) {
    let layout = canister_layout(state_path, &canister_id);
    let stable_memory_file = layout.stable_memory_blob();
    if let Err(err) = nix::unistd::truncate(&stable_memory_file, 0) {
        // It's OK if the file doesn't exist, everything else is a fatal error.
        if err != nix::errno::Errno::ENOENT {
            fatal!(
                log,
                "failed to truncate stable memory of canister {} stored at {}: {}",
                canister_id,
                stable_memory_file.display(),
                err
            )
        }
    }
}

// Finalizes execution of the `install_code` message that could have run
// multiple rounds due to determnistic time slicing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_install_code(
    mut old_canister: CanisterState,
    message: RequestOrIngress,
    instruction_limit: NumInstructions,
    instructions_left: NumInstructions,
    result: Result<(CanisterState, NumBytes), CanisterManagerError>,
    mode: CanisterInstallMode,
    canister_layout_path: PathBuf,
    config: &CanisterMgrConfig,
    round: RoundContext,
    subnet_size: usize,
) -> DtsInstallCodeResult {
    let canister_id = old_canister.canister_id();
    let instructions_consumed = instruction_limit - instructions_left;
    match result {
        Ok((mut new_canister, heap_delta)) => {
            if mode == CanisterInstallMode::Upgrade
                && old_canister.system_state.queues().input_queues_stats()
                    != new_canister.system_state.queues().input_queues_stats()
            {
                error!(
                    round.log,
                    "Input queues changed after upgrade. Before: {:?}. After: {:?}",
                    old_canister.system_state.queues().input_queues_stats(),
                    new_canister.system_state.queues().input_queues_stats()
                );
                let err = CanisterManagerError::Hypervisor(
                    old_canister.canister_id(),
                    HypervisorError::ContractViolation(
                        "Input queues changed after upgrade".to_string(),
                    ),
                );
                return DtsInstallCodeResult::Finished {
                    canister: old_canister,
                    message,
                    result: Err(err),
                };
            }

            // Refund the left over execution cycles to the new canister and
            // replace the old canister with the new one.
            let old_wasm_hash = get_wasm_hash(&old_canister);
            let new_wasm_hash = get_wasm_hash(&new_canister);
            round.cycles_account_manager.refund_execution_cycles(
                &mut new_canister.system_state,
                instructions_left,
                instruction_limit,
                subnet_size,
            );
            if config.rate_limiting_of_instructions == FlagStatus::Enabled {
                new_canister.scheduler_state.install_code_debit += instructions_consumed;
            }

            // We managed to create a new canister and will be dropping the
            // older one. So we get rid of the previous heap to make sure it
            // doesn't interfere with the new deltas and replace the old
            // canister with the new one.
            truncate_canister_heap(round.log, canister_layout_path.as_path(), canister_id);
            if mode != CanisterInstallMode::Upgrade {
                truncate_canister_stable_memory(
                    round.log,
                    canister_layout_path.as_path(),
                    canister_id,
                );
            }

            // TODO(RUN-221): Copy parts of `old_canister_state` that could have changed
            // externally into the new canister state in `result`.
            DtsInstallCodeResult::Finished {
                canister: new_canister,
                message,
                result: Ok(InstallCodeResult {
                    heap_delta,
                    old_wasm_hash,
                    new_wasm_hash,
                }),
            }
        }
        Err(err) => {
            // the install / upgrade failed. Refund the left over cycles to
            // the old canister and leave it in the state.
            if config.rate_limiting_of_instructions == FlagStatus::Enabled {
                old_canister.scheduler_state.install_code_debit += instructions_consumed;
            }
            round.cycles_account_manager.refund_execution_cycles(
                &mut old_canister.system_state,
                instructions_left,
                instruction_limit,
                subnet_size,
            );
            DtsInstallCodeResult::Finished {
                canister: old_canister,
                message,
                result: Err(err),
            }
        }
    }
}
