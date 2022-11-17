// This module defines how the `install_code` IC method in mode
// `install`/`reinstall` is executed.
// See https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-install_code
use crate::canister_manager::{
    DtsInstallCodeResult, InstallCodeContext, PausedInstallCodeExecution,
};
use crate::execution::common::{ingress_status_with_processing_state, update_round_limits};
use crate::execution::install_code::{
    canister_layout, finish_err, InstallCodeHelper, OriginalContext, PausedInstallCodeHelper,
    StableMemoryHandling,
};
use crate::execution_environment::{RoundContext, RoundLimits};
use ic_base_types::PrincipalId;
use ic_embedders::wasm_executor::{CanisterStateChanges, PausedWasmExecution, WasmExecutionResult};
use ic_interfaces::execution_environment::WasmExecutionOutput;
use ic_interfaces::messages::RequestOrIngress;
use ic_logger::{info, warn, ReplicaLogger};
use ic_replicated_state::{CanisterState, SystemState};
use ic_system_api::ApiType;
use ic_types::funds::Cycles;
use ic_types::methods::{FuncRef, SystemMethod, WasmMethod};

/// Installs a new code in canister. The algorithm consists of five stages:
/// - Stage 0: validate input.
/// - Stage 1: create a new execution state based on the new Wasm code and deactivate global timer.
/// - Stage 2: invoke the `start()` method (if present).
/// - Stage 3: invoke the `canister_init()` method (if present).
/// - Stage 4: finalize execution and refund execution cycles.
///
/// With deterministic time slicing stages 2 and 3 may require multiple rounds
/// to complete. In order to support that, the algorithm is implemented as a
/// state machine:
/// ```text
/// [begin]
///   │
///   ▼
/// [validate input]
///   │
///   │
///   ▼
/// [create new execution state and deactivate global timer]
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
/// [finalize execution and refund execution cycles]
///   │
///   │
///   ▼
/// [end]
///```
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_install(
    context: InstallCodeContext,
    clean_canister: CanisterState,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> DtsInstallCodeResult {
    let mut helper = InstallCodeHelper::new(&clean_canister, &original);

    // Stage 0: validate input.

    if let Err(err) = helper.validate_input(&original, round_limits) {
        let instructions_left = helper.instructions_left();
        return finish_err(clean_canister, instructions_left, original, round, err);
    }

    // Stage 1: create a new execution state based on the new Wasm binary and deactivate global timer.
    let canister_id = helper.canister().canister_id();
    let layout = canister_layout(&original.canister_layout_path, &canister_id);
    let (instructions_from_compilation, result) = round.hypervisor.create_execution_state(
        context.wasm_module,
        layout.raw_path(),
        canister_id,
        round_limits,
        original.compilation_cost_handling,
    );
    if let Err(err) = helper.replace_execution_state_and_allocations(
        instructions_from_compilation,
        result,
        StableMemoryHandling::Replace,
        &original,
    ) {
        let instructions_left = helper.instructions_left();
        return finish_err(clean_canister, instructions_left, original, round, err);
    }
    helper.deactivate_global_timer();

    // Stage 2: invoke the `start()` method of the Wasm module (if present).
    let method = WasmMethod::System(SystemMethod::CanisterStart);

    // The execution state is present because we just put it there.
    let execution_state = helper.canister().execution_state.as_ref().unwrap();
    if !execution_state.exports_method(&method) {
        // If the Wasm module does not export the method, then this execution
        // succeeds as a no-op.
        install_stage_2b_continue_install_after_start(
            context.sender,
            context.arg,
            clean_canister,
            helper,
            original,
            round,
            round_limits,
        )
    } else {
        let wasm_execution_result = round.hypervisor.execute_dts(
            ApiType::start(),
            execution_state,
            &SystemState::new_for_start(canister_id),
            helper.canister_memory_usage(),
            helper.execution_parameters().clone(),
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
                let paused_execution = Box::new(PausedStartExecutionDuringInstall {
                    paused_wasm_execution,
                    paused_helper: helper.pause(),
                    context_sender: context.sender,
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
fn install_stage_2a_process_start_result(
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
    let result = helper.handle_wasm_execution(canister_state_changes, output, &original, &round);

    info!(
        round.log,
        "Executing (start) on canister {} consumed {} instructions.  {} instructions are left.",
        helper.canister().canister_id(),
        helper.instructions_consumed(),
        helper.instructions_left(),
    );

    if let Err(err) = result {
        let instructions_left = helper.instructions_left();
        return finish_err(clean_canister, instructions_left, original, round, err);
    }

    install_stage_2b_continue_install_after_start(
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
fn install_stage_2b_continue_install_after_start(
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    clean_canister: CanisterState,
    helper: InstallCodeHelper,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> DtsInstallCodeResult {
    // Stage 3: invoke the `canister_init()` method of the Wasm module (if present).
    let method = WasmMethod::System(SystemMethod::CanisterInit);

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
        helper.execution_parameters().clone(),
        FuncRef::Method(method),
        round_limits,
        round.network_topology,
    );
    match wasm_execution_result {
        WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
            update_round_limits(round_limits, &slice);
            install_stage_3_process_init_result(
                canister_state_changes,
                clean_canister,
                helper,
                output,
                original,
                round,
                round_limits,
            )
        }
        WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
            update_round_limits(round_limits, &slice);
            info!(
                round.log,
                "[DTS] Pausing (canister_init) execution of canister {} after {} instructions.",
                clean_canister.canister_id(),
                slice.executed_instructions,
            );
            let ingress_status =
                ingress_status_with_processing_state(&original.message, original.time);
            let paused_execution = Box::new(PausedInitExecution {
                paused_helper: helper.pause(),
                paused_wasm_execution,
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
fn install_stage_3_process_init_result(
    canister_state_changes: Option<CanisterStateChanges>,
    clean_canister: CanisterState,
    mut helper: InstallCodeHelper,
    output: WasmExecutionOutput,
    original: OriginalContext,
    round: RoundContext,
    round_limits: &mut RoundLimits,
) -> DtsInstallCodeResult {
    let result = helper.handle_wasm_execution(canister_state_changes, output, &original, &round);
    info!(
        round.log,
        "Executing (canister_init) on canister {} consumed {} instructions.  {} instructions are left.",
        helper.canister().canister_id(),
        helper.instructions_consumed(),
        helper.instructions_left();
    );
    if let Err(err) = result {
        let instructions_left = helper.instructions_left();
        return finish_err(clean_canister, instructions_left, original, round, err);
    }
    helper.finish(clean_canister, original, round, round_limits)
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of canister install.
#[derive(Debug)]
struct PausedInitExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    paused_helper: PausedInstallCodeHelper,
    original: OriginalContext,
}

impl PausedInstallCodeExecution for PausedInitExecution {
    fn resume(
        self: Box<Self>,
        clean_canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> DtsInstallCodeResult {
        info!(
            round.log,
            "[DTS] Resuming (canister_init) execution of canister {}.",
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
            Err((err, instructions_left)) => {
                warn!(
                    round.log,
                    "[DTS] Canister {} failed to resume paused (canister_init) execution: {:?}.",
                    clean_canister.canister_id(),
                    err
                );
                self.paused_wasm_execution.abort();
                return finish_err(clean_canister, instructions_left, self.original, round, err);
            }
        };

        let execution_state = helper.canister().execution_state.as_ref().unwrap();
        let wasm_execution_result = self.paused_wasm_execution.resume(execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
                update_round_limits(round_limits, &slice);
                install_stage_3_process_init_result(
                    canister_state_changes,
                    clean_canister,
                    helper,
                    output,
                    self.original,
                    round,
                    round_limits,
                )
            }
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                info!(
                    round.log,
                    "[DTS] Pausing (canister_init) execution of canister {} after {} instructions.",
                    clean_canister.canister_id(),
                    slice.executed_instructions,
                );
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedInitExecution {
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

    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (RequestOrIngress, Cycles) {
        info!(
            log,
            "[DTS] Aborting (canister_init) execution of canister {}.", self.original.canister_id
        );
        self.paused_wasm_execution.abort();
        (
            self.original.message,
            self.original.prepaid_execution_cycles,
        )
    }
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of canister install.
#[derive(Debug)]
struct PausedStartExecutionDuringInstall {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    paused_helper: PausedInstallCodeHelper,
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    original: OriginalContext,
}

impl PausedInstallCodeExecution for PausedStartExecutionDuringInstall {
    fn resume(
        self: Box<Self>,
        clean_canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> DtsInstallCodeResult {
        info!(
            round.log,
            "[DTS] Resuming (start) execution of canister {}",
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
            Err((err, instructions_left)) => {
                warn!(
                    round.log,
                    "[DTS] Canister {} failed to resume paused (start) execution: {:?}",
                    clean_canister.canister_id(),
                    err
                );
                self.paused_wasm_execution.abort();
                return finish_err(clean_canister, instructions_left, self.original, round, err);
            }
        };
        let execution_state = helper.canister().execution_state.as_ref().unwrap();
        let wasm_execution_result = self.paused_wasm_execution.resume(execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(slice, output, canister_state_changes) => {
                update_round_limits(round_limits, &slice);
                install_stage_2a_process_start_result(
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
                update_round_limits(round_limits, &slice);
                info!(
                    round.log,
                    "[DTS] Pausing (start) execution of canister {} after {} instructions.",
                    clean_canister.canister_id(),
                    slice.executed_instructions,
                );
                let paused_execution = Box::new(PausedStartExecutionDuringInstall {
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

    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (RequestOrIngress, Cycles) {
        info!(
            log,
            "[DTS] Aborting (start) execution of canister {}.", self.original.canister_id,
        );
        self.paused_wasm_execution.abort();
        (
            self.original.message,
            self.original.prepaid_execution_cycles,
        )
    }
}
