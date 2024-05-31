//! This module defines how the `install_code` IC method in mode
//! `upgrade` is executed.
//! See https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-install_code
//! and https://internetcomputer.org/docs/current/references/ic-interface-spec/#system-api-upgrades

use crate::as_round_instructions;
use crate::canister_manager::{
    CanisterManagerError, DtsInstallCodeResult, InstallCodeContext, PausedInstallCodeExecution,
};
use crate::execution::common::{ingress_status_with_processing_state, update_round_limits};
use crate::execution::install_code::{
    canister_layout, finish_err, CanisterMemoryHandling, InstallCodeHelper, OriginalContext,
    PausedInstallCodeHelper,
};
use crate::execution_environment::{RoundContext, RoundLimits};
use ic_base_types::PrincipalId;
use ic_embedders::wasm_executor::{CanisterStateChanges, PausedWasmExecution, WasmExecutionResult};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, WasmExecutionOutput,
};
use ic_logger::{info, warn, ReplicaLogger};
use ic_management_canister_types::{
    CanisterInstallModeV2, CanisterUpgradeOptions, WasmMemoryPersistence,
};
use ic_replicated_state::{
    metadata_state::subnet_call_context_manager::InstallCodeCallId, CanisterState, ExecutionState,
};
use ic_system_api::ApiType;
use ic_types::methods::{FuncRef, SystemMethod, WasmMethod};
use ic_types::{
    funds::Cycles,
    messages::{CanisterCall, RequestMetadata},
};

use super::install_code::MemoryHandling;

#[cfg(test)]
mod tests;

pub const ENHANCED_ORTHOGONAL_PERSISTENCE_SECTION: &str = "enhanced-orthogonal-persistence";

/// Performs a canister upgrade. The algorithm consists of six stages:
/// - Stage 0: validate input.
/// - Stage 1: invoke `canister_pre_upgrade()` (if present) using the old code.
/// - Stage 2: create a new execution state based on the new Wasm code, deactivate global timer, and bump canister version.
/// - Stage 3: invoke the `start()` method (if present).
/// - Stage 4: invoke the `canister_post_upgrade()` method (if present).
/// - Stage 5: finalize execution and refund execution cycles.
///
/// With deterministic time slicing stages 2, 3, and 4 may require multiple
/// rounds to complete. In order to support that, the algorithm is implemented
/// as a state machine:
/// ```text
/// [begin]
///   │
///   ▼
/// [validate input]
///   │
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
/// [create new execution state, deactivate global timer, and bump canister version]
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
/// [finalize execution and refund execution cycles]
///   │
///   │
///   ▼
/// [end]
///```
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_upgrade(
    context: InstallCodeContext,
    clean_canister: CanisterState,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> DtsInstallCodeResult {
    let mut helper = InstallCodeHelper::new(&clean_canister, &original);

    // Stage 0: validate input.
    if let Err(err) = helper.validate_input(&original, &round, round_limits) {
        return finish_err(
            clean_canister,
            helper.instructions_left(),
            original,
            round,
            err,
            helper.take_canister_log(),
        );
    }

    // Stage 1: invoke `canister_pre_upgrade()` (if present) using the old code.

    // Validate that the Wasm module is present.
    let canister_id = context.canister_id;
    let execution_state = match helper.canister().execution_state.as_ref() {
        Some(es) => es,
        None => {
            return finish_err(
                clean_canister,
                helper.instructions_left(),
                original,
                round,
                (canister_id, HypervisorError::WasmModuleNotFound).into(),
                helper.take_canister_log(),
            );
        }
    };

    let method = WasmMethod::System(SystemMethod::CanisterPreUpgrade);
    let skip_pre_upgrade = match context.mode {
        CanisterInstallModeV2::Upgrade(Some(upgrade_option)) => {
            upgrade_option.skip_pre_upgrade.unwrap_or(false)
        }
        _ => false,
    };

    if skip_pre_upgrade || !execution_state.exports_method(&method) {
        // If the Wasm module does not export the method, or skip_pre_upgrade
        // is enabled then this execution succeeds as a no-op.
        upgrade_stage_2_and_3a_create_execution_state_and_call_start(
            context,
            clean_canister,
            helper,
            original,
            round,
            round_limits,
        )
    } else {
        let wasm_execution_result = round.hypervisor.execute_dts(
            ApiType::pre_upgrade(original.time, context.sender()),
            execution_state,
            &helper.canister().system_state,
            helper.canister_memory_usage(),
            helper.canister_message_memory_usage(),
            helper.execution_parameters().clone(),
            FuncRef::Method(method),
            RequestMetadata::for_new_call_tree(original.time),
            round_limits,
            round.network_topology,
        );

        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
                update_round_limits(round_limits, &slice);
                upgrade_stage_1_process_pre_upgrade_result(
                    canister_state_changes,
                    output,
                    context,
                    clean_canister,
                    helper,
                    original,
                    round,
                    round_limits,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                info!(
                    round.log,
                    "[DTS] Pausing (canister_pre_upgrade) execution of canister {} after {} instructions.",
                    clean_canister.canister_id(),
                    slice.executed_instructions,
                );
                update_round_limits(round_limits, &slice);
                let ingress_status =
                    ingress_status_with_processing_state(&original.message, original.time);
                let paused_execution = Box::new(PausedPreUpgradeExecution {
                    paused_wasm_execution,
                    paused_helper: helper.pause(),
                    context,
                    original,
                });
                DtsInstallCodeResult::Paused {
                    canister: clean_canister,
                    paused_execution,
                    ingress_status,
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn upgrade_stage_1_process_pre_upgrade_result(
    canister_state_changes: Option<CanisterStateChanges>,
    output: WasmExecutionOutput,
    context: InstallCodeContext,
    clean_canister: CanisterState,
    mut helper: InstallCodeHelper,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> DtsInstallCodeResult {
    let (instructions_consumed, result) =
        helper.handle_wasm_execution(canister_state_changes, output, &original, &round);

    info!(
        round.log,
        "Executing (canister_pre_upgrade) on canister {} consumed {} instructions.  {} instructions are left.",
        helper.canister().canister_id(),
        instructions_consumed,
        helper.instructions_left(),
    );

    if let Err(err) = result {
        let instructions_left = helper.instructions_left();
        return finish_err(
            clean_canister,
            instructions_left,
            original,
            round,
            err,
            helper.take_canister_log(),
        );
    }

    upgrade_stage_2_and_3a_create_execution_state_and_call_start(
        context,
        clean_canister,
        helper,
        original,
        round,
        round_limits,
    )
}

#[allow(clippy::too_many_arguments)]
fn upgrade_stage_2_and_3a_create_execution_state_and_call_start(
    context: InstallCodeContext,
    clean_canister: CanisterState,
    mut helper: InstallCodeHelper,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> DtsInstallCodeResult {
    let canister_id = helper.canister().canister_id();
    let context_sender = context.sender();

    let instructions_to_assemble = context.wasm_source.instructions_to_assemble();
    helper.charge_for_large_wasm_assembly(instructions_to_assemble);
    round_limits.instructions -= as_round_instructions(instructions_to_assemble);
    let wasm_module = match context.wasm_source.into_canister_module() {
        Ok(wasm_module) => wasm_module,
        Err(err) => {
            return finish_err(
                clean_canister,
                helper.instructions_left(),
                original,
                round,
                err,
                helper.take_canister_log(),
            );
        }
    };

    let module_hash = wasm_module.module_hash();
    // Stage 2: create a new execution state based on the new Wasm code, deactivate global timer, and bump canister version.
    // Replace the execution state of the canister with a new execution state, but
    // persist the stable memory (if it exists).
    let layout = canister_layout(&original.canister_layout_path, &canister_id);
    let (instructions_from_compilation, result) = round.hypervisor.create_execution_state(
        wasm_module,
        layout.raw_path(),
        canister_id,
        round_limits,
        original.compilation_cost_handling,
    );

    let main_memory_handling = match determine_main_memory_handling(
        context.mode,
        &helper.canister().execution_state,
        &result,
    ) {
        Ok(memory_handling) => memory_handling,
        Err(err) => {
            let instructions_left = helper.instructions_left();
            return finish_err(
                clean_canister,
                instructions_left,
                original,
                round,
                err,
                helper.take_canister_log(),
            );
        }
    };

    let memory_handling = CanisterMemoryHandling {
        stable_memory_handling: MemoryHandling::Keep,
        main_memory_handling,
    };

    if let Err(err) = helper.replace_execution_state_and_allocations(
        instructions_from_compilation,
        result,
        memory_handling,
        &original,
    ) {
        let instructions_left = helper.instructions_left();
        return finish_err(
            clean_canister,
            instructions_left,
            original,
            round,
            err,
            helper.take_canister_log(),
        );
    }

    helper.deactivate_global_timer();
    helper.bump_canister_version();
    helper.add_canister_change(round.time, context.origin, context.mode, module_hash.into());

    // Stage 3: invoke the `start()` method (if present).
    let method = WasmMethod::System(SystemMethod::CanisterStart);

    // The execution state is present because we just put it there.
    let execution_state = helper.canister().execution_state.as_ref().unwrap();
    if !execution_state.exports_method(&method) {
        // If the Wasm module does not export the method, then this execution
        // succeeds as a no-op.
        upgrade_stage_4a_call_post_upgrade(
            context_sender,
            context.arg,
            clean_canister,
            helper,
            original,
            round,
            round_limits,
        )
    } else {
        let wasm_execution_result = round.hypervisor.execute_dts(
            ApiType::start(original.time),
            execution_state,
            &helper.canister().system_state,
            helper.canister_memory_usage(),
            helper.canister_message_memory_usage(),
            helper.execution_parameters().clone(),
            FuncRef::Method(method),
            RequestMetadata::for_new_call_tree(original.time),
            round_limits,
            round.network_topology,
        );

        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
                update_round_limits(round_limits, &slice);
                upgrade_stage_3b_process_start_result(
                    canister_state_changes,
                    output,
                    context_sender,
                    context.arg,
                    clean_canister,
                    helper,
                    original,
                    round,
                    round_limits,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                info!(
                    round.log,
                    "[DTS] Pausing (start) execution of canister {} after {} instructions.",
                    clean_canister.canister_id(),
                    slice.executed_instructions,
                );
                update_round_limits(round_limits, &slice);
                let ingress_status =
                    ingress_status_with_processing_state(&original.message, original.time);
                let paused_execution = Box::new(PausedStartExecutionDuringUpgrade {
                    paused_wasm_execution,
                    paused_helper: helper.pause(),
                    context_sender,
                    context_arg: context.arg,
                    original,
                });
                DtsInstallCodeResult::Paused {
                    canister: clean_canister,
                    paused_execution,
                    ingress_status,
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn upgrade_stage_3b_process_start_result(
    canister_state_changes: Option<CanisterStateChanges>,
    output: WasmExecutionOutput,
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    clean_canister: CanisterState,
    mut helper: InstallCodeHelper,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> DtsInstallCodeResult {
    let (instructions_consumed, result) =
        helper.handle_wasm_execution(canister_state_changes, output, &original, &round);

    info!(
        round.log,
        "Executing (start) on canister {} consumed {} instructions.  {} instructions are left.",
        helper.canister().canister_id(),
        instructions_consumed,
        helper.instructions_left(),
    );

    if let Err(err) = result {
        let instructions_left = helper.instructions_left();
        return finish_err(
            clean_canister,
            instructions_left,
            original,
            round,
            err,
            helper.take_canister_log(),
        );
    }

    upgrade_stage_4a_call_post_upgrade(
        context_sender,
        context_arg,
        clean_canister,
        helper,
        original,
        round,
        round_limits,
    )
}

#[allow(clippy::too_many_arguments)]
fn upgrade_stage_4a_call_post_upgrade(
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    clean_canister: CanisterState,
    helper: InstallCodeHelper,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> DtsInstallCodeResult {
    // Stage 4: invoke the `canister_post_upgrade()` method (if present).

    let method = WasmMethod::System(SystemMethod::CanisterPostUpgrade);

    // The execution state is guaranteed to be present because this function is
    // called after creating a new execution state.
    let execution_state = helper.canister().execution_state.as_ref().unwrap();
    if !execution_state.exports_method(&method) {
        // If the Wasm module does not export the method, then this execution
        // succeeds as a no-op.
        return helper.finish(clean_canister, original, round, round_limits);
    }

    let wasm_execution_result = round.hypervisor.execute_dts(
        ApiType::init(original.time, context_arg, context_sender),
        execution_state,
        &helper.canister().system_state,
        helper.canister_memory_usage(),
        helper.canister_message_memory_usage(),
        helper.execution_parameters().clone(),
        FuncRef::Method(method),
        RequestMetadata::for_new_call_tree(original.time),
        round_limits,
        round.network_topology,
    );
    match wasm_execution_result {
        WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
            update_round_limits(round_limits, &slice);
            upgrade_stage_4b_process_post_upgrade_result(
                canister_state_changes,
                output,
                clean_canister,
                helper,
                original,
                round,
                round_limits,
            )
        }
        WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
            info!(
                round.log,
                "[DTS] Pausing (canister_post_upgrade) execution of canister {} after {} instructions.",
                clean_canister.canister_id(),
                slice.executed_instructions,
            );
            update_round_limits(round_limits, &slice);
            let ingress_status =
                ingress_status_with_processing_state(&original.message, original.time);
            let paused_execution = Box::new(PausedPostUpgradeExecution {
                paused_wasm_execution,
                paused_helper: helper.pause(),
                original,
            });
            DtsInstallCodeResult::Paused {
                canister: clean_canister,
                paused_execution,
                ingress_status,
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn upgrade_stage_4b_process_post_upgrade_result(
    canister_state_changes: Option<CanisterStateChanges>,
    output: WasmExecutionOutput,
    clean_canister: CanisterState,
    mut helper: InstallCodeHelper,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> DtsInstallCodeResult {
    let (instructions_consumed, result) =
        helper.handle_wasm_execution(canister_state_changes, output, &original, &round);
    info!(
        round.log,
        "Executing (canister_post_upgrade) on canister {} consumed {} instructions.  {} instructions are left.",
        helper.canister().canister_id(),
        instructions_consumed,
        helper.instructions_left();
    );
    if let Err(err) = result {
        let instructions_left = helper.instructions_left();
        return finish_err(
            clean_canister,
            instructions_left,
            original,
            round,
            err,
            helper.take_canister_log(),
        );
    }
    helper.finish(clean_canister, original, round, round_limits)
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of canister upgrade.
/// Pre upgrade is the first stage of the upgrade procedure.
#[derive(Debug)]
struct PausedPreUpgradeExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    paused_helper: PausedInstallCodeHelper,
    context: InstallCodeContext,
    original: OriginalContext,
}

impl PausedInstallCodeExecution for PausedPreUpgradeExecution {
    fn resume(
        self: Box<Self>,
        clean_canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> DtsInstallCodeResult {
        info!(
            round.log,
            "[DTS] Resuming (canister_pre_upgrade) execution of canister {}.",
            clean_canister.canister_id(),
        );
        let helper = match InstallCodeHelper::resume(
            &clean_canister,
            self.paused_helper,
            &self.original,
            &round,
            round_limits,
        ) {
            Ok(helper) => helper,
            Err((err, instructions_left, new_canister_log)) => {
                warn!(
                    round.log,
                    "[DTS] Canister {} failed to resume paused (canister_pre_upgrade) execution: {:?}.",
                    clean_canister.canister_id(),
                    err
                );
                self.paused_wasm_execution.abort();
                return finish_err(
                    clean_canister,
                    instructions_left,
                    self.original,
                    round,
                    err,
                    new_canister_log,
                );
            }
        };
        let execution_state = helper.canister().execution_state.as_ref().unwrap();
        let wasm_execution_result = self.paused_wasm_execution.resume(execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
                update_round_limits(round_limits, &slice);
                upgrade_stage_1_process_pre_upgrade_result(
                    canister_state_changes,
                    output,
                    self.context,
                    clean_canister,
                    helper,
                    self.original,
                    round,
                    round_limits,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                info!(
                    round.log,
                    "[DTS] Pausing (canister_pre_upgrade) execution of canister {} after {} instructions.",
                    clean_canister.canister_id(),
                    slice.executed_instructions,
                );
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedPreUpgradeExecution {
                    paused_wasm_execution,
                    paused_helper: helper.pause(),
                    ..*self
                });
                DtsInstallCodeResult::Paused {
                    canister: clean_canister,
                    paused_execution,
                    // Pausing a resumed execution doesn't change the ingress
                    // status.
                    ingress_status: None,
                }
            }
        }
    }

    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (CanisterCall, InstallCodeCallId, Cycles) {
        info!(
            log,
            "[DTS] Aborting (canister_pre_upgrade) execution of canister {}.",
            self.original.canister_id
        );
        self.paused_wasm_execution.abort();
        (
            self.original.message,
            self.original.call_id,
            self.original.prepaid_execution_cycles,
        )
    }
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of canister upgrade.
/// Start is the second stage of the upgrade procedure.
#[derive(Debug)]
struct PausedStartExecutionDuringUpgrade {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    paused_helper: PausedInstallCodeHelper,
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    original: OriginalContext,
}

impl PausedInstallCodeExecution for PausedStartExecutionDuringUpgrade {
    fn resume(
        self: Box<Self>,
        clean_canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> DtsInstallCodeResult {
        info!(
            round.log,
            "[DTS] Resuming (start) execution of canister {}.",
            clean_canister.canister_id(),
        );
        let helper = match InstallCodeHelper::resume(
            &clean_canister,
            self.paused_helper,
            &self.original,
            &round,
            round_limits,
        ) {
            Ok(helper) => helper,
            Err((err, instructions_left, new_canister_log)) => {
                warn!(
                    round.log,
                    "[DTS] Canister {} failed to resume paused (start) execution: {:?}.",
                    clean_canister.canister_id(),
                    err
                );
                self.paused_wasm_execution.abort();
                return finish_err(
                    clean_canister,
                    instructions_left,
                    self.original,
                    round,
                    err,
                    new_canister_log,
                );
            }
        };
        let execution_state = helper.canister().execution_state.as_ref().unwrap();
        let wasm_execution_result = self.paused_wasm_execution.resume(execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
                update_round_limits(round_limits, &slice);
                upgrade_stage_3b_process_start_result(
                    canister_state_changes,
                    output,
                    self.context_sender,
                    self.context_arg,
                    clean_canister,
                    helper,
                    self.original,
                    round,
                    round_limits,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                info!(
                    round.log,
                    "[DTS] Pausing (start) execution of canister {} after {} instructions.",
                    clean_canister.canister_id(),
                    slice.executed_instructions,
                );
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedStartExecutionDuringUpgrade {
                    paused_wasm_execution,
                    paused_helper: helper.pause(),
                    ..*self
                });
                DtsInstallCodeResult::Paused {
                    canister: clean_canister,
                    paused_execution,
                    // Pausing a resumed execution doesn't change the ingress
                    // status.
                    ingress_status: None,
                }
            }
        }
    }

    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (CanisterCall, InstallCodeCallId, Cycles) {
        info!(
            log,
            "[DTS] Aborting (start) execution of canister {}.", self.original.canister_id
        );

        self.paused_wasm_execution.abort();
        (
            self.original.message,
            self.original.call_id,
            self.original.prepaid_execution_cycles,
        )
    }
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of canister upgrade.
/// Post upgrade is the third stage of the upgrade procedure.
#[derive(Debug)]
struct PausedPostUpgradeExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    paused_helper: PausedInstallCodeHelper,
    original: OriginalContext,
}

impl PausedInstallCodeExecution for PausedPostUpgradeExecution {
    fn resume(
        self: Box<Self>,
        clean_canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> DtsInstallCodeResult {
        info!(
            round.log,
            "[DTS] Resuming (canister_post_upgrade) execution of canister {}.",
            clean_canister.canister_id(),
        );
        let helper = match InstallCodeHelper::resume(
            &clean_canister,
            self.paused_helper,
            &self.original,
            &round,
            round_limits,
        ) {
            Ok(helper) => helper,
            Err((err, instructions_left, new_canister_log)) => {
                warn!(
                    round.log,
                    "[DTS] Canister {} failed to resume paused (canister_post_upgrade) execution: {:?}.",
                    clean_canister.canister_id(),
                    err
                );
                self.paused_wasm_execution.abort();
                return finish_err(
                    clean_canister,
                    instructions_left,
                    self.original,
                    round,
                    err,
                    new_canister_log,
                );
            }
        };
        let execution_state = helper.canister().execution_state.as_ref().unwrap();
        let wasm_execution_result = self.paused_wasm_execution.resume(execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
                update_round_limits(round_limits, &slice);
                upgrade_stage_4b_process_post_upgrade_result(
                    canister_state_changes,
                    output,
                    clean_canister,
                    helper,
                    self.original,
                    round,
                    round_limits,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                info!(
                    round.log,
                    "[DTS] Pausing (canister_post_upgrade) execution of canister {} after {} instructions.",
                    clean_canister.canister_id(),
                    slice.executed_instructions,
                );
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedPostUpgradeExecution {
                    paused_wasm_execution,
                    paused_helper: helper.pause(),
                    ..*self
                });
                DtsInstallCodeResult::Paused {
                    canister: clean_canister,
                    paused_execution,
                    // Pausing a resumed execution doesn't change the ingress
                    // status.
                    ingress_status: None,
                }
            }
        }
    }

    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (CanisterCall, InstallCodeCallId, Cycles) {
        info!(
            log,
            "[DTS] Aborting (canister_post_upgrade) execution of canister {}.",
            self.original.canister_id,
        );
        self.paused_wasm_execution.abort();
        (self.original.message, self.original.call_id, Cycles::zero())
    }
}

/// Determines main memory handling based on the `wasm_memory_persistence` upgrade options.
/// Integrates two safety checks:
/// - The `wasm_memory_persistence` upgrade option is not omitted in error, when
///   the old canister implementation uses enhanced orthogonal persistence.
/// - The `wasm_memory_persistence: opt keep` option is not applied to a new canister
///   implementation that does not support enhanced orthogonal persistence.
fn determine_main_memory_handling(
    install_mode: CanisterInstallModeV2,
    old_state: &Option<ExecutionState>,
    new_state_candidate: &HypervisorResult<ExecutionState>,
) -> Result<MemoryHandling, CanisterManagerError> {
    let old_state_uses_orthogonal_persistence = || {
        old_state
            .as_ref()
            .map_or(false, expects_enhanced_orthogonal_persistence)
    };
    let new_state_uses_classical_persistence = || {
        new_state_candidate.is_ok()
            && !expects_enhanced_orthogonal_persistence(new_state_candidate.as_ref().unwrap())
    };

    match install_mode {
        CanisterInstallModeV2::Upgrade(None)
        | CanisterInstallModeV2::Upgrade(Some(CanisterUpgradeOptions {
            wasm_memory_persistence: None,
            ..
        })) => {
            // Safety guard checking that the `wasm_memory_persistence` upgrade option has not been omitted in error.
            if old_state_uses_orthogonal_persistence() {
                let message = "Enhanced orthogonal persistence requires the `wasm_memory_persistence` upgrade option.".to_string();
                return Err(CanisterManagerError::MissingUpgradeOptionError { message });
            }
            Ok(MemoryHandling::Replace)
        }
        CanisterInstallModeV2::Upgrade(Some(CanisterUpgradeOptions {
            wasm_memory_persistence: Some(WasmMemoryPersistence::Keep),
            ..
        })) => {
            // Safety guard checking that the enhanced orthogonal persistence upgrade option is only applied to canisters that support such.
            if new_state_uses_classical_persistence() {
                let message = "The `wasm_memory_persistence: opt Keep` upgrade option requires that the new canister module supports enhanced orthogonal persistence.".to_string();
                return Err(CanisterManagerError::InvalidUpgradeOptionError { message });
            }
            Ok(MemoryHandling::Keep)
        }
        CanisterInstallModeV2::Upgrade(Some(CanisterUpgradeOptions {
            wasm_memory_persistence: Some(WasmMemoryPersistence::Replace),
            ..
        })) => Ok(MemoryHandling::Replace),
        // These two modes cannot occur during an upgrade.
        CanisterInstallModeV2::Install | CanisterInstallModeV2::Reinstall => unreachable!(),
    }
}

/// Helper function to check whether the state expects enhanced orthogonal persistence.
fn expects_enhanced_orthogonal_persistence(execution_state: &ExecutionState) -> bool {
    execution_state
        .metadata
        .get_custom_section(ENHANCED_ORTHOGONAL_PERSISTENCE_SECTION)
        .is_some()
}
