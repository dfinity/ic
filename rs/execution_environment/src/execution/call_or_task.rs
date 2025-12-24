// This module defines how replicated calls to update or query methods and canister tasks are executed.
// See https://internetcomputer.org/docs/interface-spec/index.html#rule-message-execution

use crate::execution::common::{
    action_to_response, apply_canister_state_changes, finish_call_with_error,
    ingress_status_with_processing_state, log_dirty_pages, update_round_limits, validate_message,
    wasm_result_to_query_response,
};
use crate::execution_environment::{
    ExecuteMessageResult, PausedExecution, RoundContext, RoundLimits,
};
use crate::metrics::CallTreeMetrics;
use ic_base_types::CanisterId;
use ic_config::flag_status::FlagStatus;
use ic_embedders::{
    wasm_executor::{CanisterStateChanges, PausedWasmExecution, WasmExecutionResult},
    wasmtime_embedder::system_api::{ApiType, ExecutionParameters},
};
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::{
    CanisterOutOfCyclesError, HypervisorError, WasmExecutionOutput,
};
use ic_logger::{ReplicaLogger, info};
use ic_replicated_state::{
    CallContextAction, CallOrigin, CanisterState,
    canister_state::execution_state::WasmExecutionMode, num_bytes_try_from,
};
use ic_types::messages::{
    CallContextId, CanisterCall, CanisterCallOrTask, CanisterMessage, CanisterMessageOrTask,
    CanisterTask, RequestMetadata,
};
use ic_types::methods::{FuncRef, SystemMethod, WasmMethod};
use ic_types::{CanisterTimer, Cycles, NumBytes, NumInstructions, Time};
use ic_utils_thread::deallocator_thread::DeallocationSender;
use ic_wasm_types::WasmEngineError::FailedToApplySystemChanges;

#[cfg(test)]
mod tests;

// Execute an inter-canister call message or a canister task.
#[allow(clippy::too_many_arguments)]
pub fn execute_call_or_task(
    clean_canister: CanisterState,
    call_or_task: CanisterCallOrTask,
    method: WasmMethod,
    prepaid_execution_cycles: Option<Cycles>,
    execution_parameters: ExecutionParameters,
    time: Time,
    round: RoundContext,
    round_limits: &mut RoundLimits,
    subnet_size: usize,
    call_tree_metrics: &dyn CallTreeMetrics,
    log_dirty_pages: FlagStatus,
    deallocation_sender: &DeallocationSender,
) -> ExecuteMessageResult {
    let (clean_canister, prepaid_execution_cycles, resuming_aborted) =
        match prepaid_execution_cycles {
            Some(prepaid_execution_cycles) => (clean_canister, prepaid_execution_cycles, true),
            None => {
                let mut canister = clean_canister;
                let memory_usage = canister.memory_usage();
                let message_memory_usage = canister.message_memory_usage();
                let reveal_top_up = call_or_task
                    .caller()
                    .map(|caller| canister.controllers().contains(&caller))
                    .unwrap_or_default();

                let wasm_execution_mode = canister
                    .execution_state
                    .as_ref()
                    .map_or(WasmExecutionMode::Wasm32, |es| es.wasm_execution_mode);

                let prepaid_execution_cycles = match round
                    .cycles_account_manager
                    .prepay_execution_cycles(
                        &mut canister.system_state,
                        memory_usage,
                        message_memory_usage,
                        execution_parameters.compute_allocation,
                        execution_parameters.instruction_limits.message(),
                        subnet_size,
                        round.cost_schedule,
                        reveal_top_up,
                        wasm_execution_mode,
                    ) {
                    Ok(cycles) => cycles,
                    Err(err) => {
                        if call_or_task == CanisterCallOrTask::Task(CanisterTask::OnLowWasmMemory) {
                            //`OnLowWasmMemoryHook` is taken from task_queue (i.e. `OnLowWasmMemoryHookStatus` is `Executed`),
                            // but it was not executed due to the freezing of the canister. To ensure that the hook is executed
                            // when the canister is unfrozen we need to set `OnLowWasmMemoryHookStatus` to `Ready`. Because of
                            // the way `OnLowWasmMemoryHookStatus::update` is implemented we first need to remove it from the
                            // task_queue (which calls `OnLowWasmMemoryHookStatus::update(false)`) followed with `enqueue`
                            // (which calls `OnLowWasmMemoryHookStatus::update(true)`) to ensure desired behavior.
                            canister
                                .system_state
                                .task_queue
                                .remove(ic_replicated_state::ExecutionTask::OnLowWasmMemory);
                            canister
                                .system_state
                                .task_queue
                                .enqueue(ic_replicated_state::ExecutionTask::OnLowWasmMemory);
                        }
                        return finish_call_with_error(
                            UserError::new(ErrorCode::CanisterOutOfCycles, err),
                            canister,
                            call_or_task,
                            NumInstructions::from(0),
                            round.time,
                            execution_parameters.subnet_type,
                            round.log,
                        );
                    }
                };
                (canister, prepaid_execution_cycles, false)
            }
        };

    let freezing_threshold = round.cycles_account_manager.freeze_threshold_cycles(
        clean_canister.system_state.freeze_threshold,
        clean_canister.system_state.memory_allocation,
        clean_canister.memory_usage(),
        clean_canister.message_memory_usage(),
        clean_canister.compute_allocation(),
        subnet_size,
        round.cost_schedule,
        clean_canister.system_state.reserved_balance(),
    );

    let request_metadata = match &call_or_task {
        CanisterCallOrTask::Update(CanisterCall::Request(request))
        | CanisterCallOrTask::Query(CanisterCall::Request(request)) => {
            request.metadata.for_downstream_call()
        }
        CanisterCallOrTask::Update(CanisterCall::Ingress(_))
        | CanisterCallOrTask::Query(CanisterCall::Ingress(_))
        | CanisterCallOrTask::Task(_) => RequestMetadata::for_new_call_tree(time),
    };

    let original = OriginalContext {
        call_origin: CallOrigin::from(&call_or_task),
        method,
        call_or_task,
        prepaid_execution_cycles,
        execution_parameters,
        subnet_size,
        time,
        request_metadata,
        freezing_threshold,
        canister_id: clean_canister.canister_id(),
        log_dirty_pages,
    };

    let helper = match CallOrTaskHelper::new(&clean_canister, &original, deallocation_sender) {
        Ok(helper) => helper,
        Err(err) => {
            return finish_err(
                clean_canister,
                original.execution_parameters.instruction_limits.message(),
                err,
                original,
                round,
            );
        }
    };

    let api_type = match &original.call_or_task {
        CanisterCallOrTask::Update(msg) => ApiType::update(
            time,
            msg.method_payload().to_vec(),
            msg.cycles(),
            *msg.sender(),
            helper.call_context_id(),
        ),
        CanisterCallOrTask::Query(msg) => ApiType::replicated_query(
            time,
            msg.method_payload().to_vec(),
            *msg.sender(),
            helper.call_context_id(),
        ),
        CanisterCallOrTask::Task(CanisterTask::Heartbeat) => ApiType::system_task(
            SystemMethod::CanisterHeartbeat,
            time,
            helper.call_context_id(),
        ),
        CanisterCallOrTask::Task(CanisterTask::GlobalTimer) => ApiType::system_task(
            SystemMethod::CanisterGlobalTimer,
            time,
            helper.call_context_id(),
        ),
        CanisterCallOrTask::Task(CanisterTask::OnLowWasmMemory) => ApiType::system_task(
            SystemMethod::CanisterOnLowWasmMemory,
            time,
            helper.call_context_id(),
        ),
    };

    let memory_usage = helper.canister().memory_usage();
    let message_memory_usage = helper.canister().message_memory_usage();
    let result = round.hypervisor.execute_dts(
        api_type,
        helper.canister().execution_state.as_ref().unwrap(),
        &helper.canister().system_state,
        memory_usage,
        message_memory_usage,
        original.execution_parameters.clone(),
        FuncRef::Method(original.method.clone()),
        original.request_metadata.clone(),
        round_limits,
        round.network_topology,
        round.cost_schedule,
    );
    match result {
        WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
            info!(
                round.log,
                "[DTS] Pausing {:?} execution of canister {} after {} instructions.",
                original.method,
                clean_canister.canister_id(),
                slice.executed_instructions,
            );
            update_round_limits(round_limits, &slice);

            let ingress_status = match (resuming_aborted, &original.call_or_task) {
                (true, _) => {
                    // Resuming an aborted execution doesn't change the ingress
                    // status.
                    None
                }
                (false, CanisterCallOrTask::Task(_)) => {
                    // Canister tasks do not have ingress status.
                    None
                }
                (false, CanisterCallOrTask::Update(call))
                | (false, CanisterCallOrTask::Query(call)) => {
                    ingress_status_with_processing_state(call, original.time)
                }
            };
            let paused_execution = Box::new(PausedCallOrTaskExecution {
                paused_wasm_execution,
                paused_helper: helper.pause(),
                original,
            });
            ExecuteMessageResult::Paused {
                canister: clean_canister,
                paused_execution,
                ingress_status,
            }
        }
        WasmExecutionResult::Finished(slice, output, state_changes) => {
            update_round_limits(round_limits, &slice);
            helper.finish(
                output,
                clean_canister,
                state_changes,
                original,
                round,
                round_limits,
                call_tree_metrics,
            )
        }
    }
}

/// Finishes an update call execution early due to an error. The only state
/// change that is applied to the clean canister state is refunding the prepaid
/// execution cycles.
fn finish_err(
    clean_canister: CanisterState,
    instructions_left: NumInstructions,
    err: UserError,
    original: OriginalContext,
    round: RoundContext,
) -> ExecuteMessageResult {
    let mut canister = clean_canister;

    canister.system_state.apply_ingress_induction_cycles_debit(
        canister.canister_id(),
        round.log,
        round.counters.charging_from_balance_error,
    );

    let wasm_execution_mode = canister
        .execution_state
        .as_ref()
        .map_or(WasmExecutionMode::Wasm32, |es| es.wasm_execution_mode);

    let instruction_limit = original.execution_parameters.instruction_limits.message();
    round.cycles_account_manager.refund_unused_execution_cycles(
        &mut canister.system_state,
        instructions_left,
        instruction_limit,
        original.prepaid_execution_cycles,
        round.counters.execution_refund_error,
        original.subnet_size,
        round.cost_schedule,
        wasm_execution_mode,
        round.log,
    );
    let instructions_used = instruction_limit - instructions_left;
    finish_call_with_error(
        err,
        canister,
        original.call_or_task,
        instructions_used,
        round.time,
        original.execution_parameters.subnet_type,
        round.log,
    )
}

/// Context variables that remain the same throughout the entire deterministic
/// time slicing execution of an update call execution.
#[derive(Debug)]
struct OriginalContext {
    call_origin: CallOrigin,
    call_or_task: CanisterCallOrTask,
    prepaid_execution_cycles: Cycles,
    method: WasmMethod,
    execution_parameters: ExecutionParameters,
    subnet_size: usize,
    time: Time,
    request_metadata: RequestMetadata,
    freezing_threshold: Cycles,
    canister_id: CanisterId,
    log_dirty_pages: FlagStatus,
}

/// Contains fields of `CallOrTaskHelper` that are necessary for resuming an update
/// call execution.
#[derive(Debug)]
struct PausedCallOrTaskHelper {
    call_context_id: CallContextId,
    initial_cycles_balance: Cycles,
}

/// A helper that implements and keeps track of update call steps.
/// It is used to safely pause and resume an update call execution.
struct CallOrTaskHelper {
    canister: CanisterState,
    call_context_id: CallContextId,
    initial_cycles_balance: Cycles,
    deallocation_sender: DeallocationSender,
}

impl CallOrTaskHelper {
    /// Applies the initial state changes and performs the initial validation.
    fn new(
        clean_canister: &CanisterState,
        original: &OriginalContext,
        deallocation_sender: &DeallocationSender,
    ) -> Result<Self, UserError> {
        let mut canister = clean_canister.clone();

        validate_message(&canister, &original.method)?;

        match original.call_or_task {
            CanisterCallOrTask::Update(_) => {
                let wasm_memory_usage = canister
                    .execution_state
                    .as_ref()
                    .map_or(NumBytes::new(0), |es| {
                        num_bytes_try_from(es.wasm_memory.size).unwrap()
                    });

                if let Some(wasm_memory_limit) = clean_canister.system_state.wasm_memory_limit {
                    // A Wasm memory limit of 0 means unlimited.
                    if wasm_memory_limit.get() != 0 && wasm_memory_usage > wasm_memory_limit {
                        let err = HypervisorError::WasmMemoryLimitExceeded {
                            bytes: wasm_memory_usage,
                            limit: wasm_memory_limit,
                        };
                        return Err(err.into_user_error(&canister.canister_id()));
                    }
                }
            }
            // TODO(RUN-957): Enforce the `wasm_memory_limit` in heartbeat and timer after
            // canister logging ships.
            CanisterCallOrTask::Task(_) => (),
            CanisterCallOrTask::Query(_) => {
                if let WasmMethod::CompositeQuery(_) = &original.method {
                    let user_error = UserError::new(
                        ErrorCode::CompositeQueryCalledInReplicatedMode,
                        "Composite query cannot be called in replicated mode",
                    );
                    return Err(user_error);
                }
            }
        }

        let call_context_id = canister
            .system_state
            .new_call_context(
                original.call_origin.clone(),
                original.call_or_task.cycles(),
                original.time,
                original.request_metadata.clone(),
            )
            .unwrap();

        let initial_cycles_balance = canister.system_state.balance();

        match original.call_or_task {
            CanisterCallOrTask::Update(_)
            | CanisterCallOrTask::Query(_)
            | CanisterCallOrTask::Task(CanisterTask::Heartbeat)
            | CanisterCallOrTask::Task(CanisterTask::OnLowWasmMemory) => {}
            CanisterCallOrTask::Task(CanisterTask::GlobalTimer) => {
                // The global timer is one-off.
                canister.system_state.global_timer = CanisterTimer::Inactive;
            }
        }

        Ok(Self {
            canister,
            call_context_id,
            initial_cycles_balance,
            deallocation_sender: deallocation_sender.clone(),
        })
    }

    /// Returns a struct with all the necessary information to replay the
    /// performed update call steps in subsequent rounds.
    fn pause(self) -> PausedCallOrTaskHelper {
        self.deallocation_sender.send(Box::new(self.canister));
        PausedCallOrTaskHelper {
            call_context_id: self.call_context_id,
            initial_cycles_balance: self.initial_cycles_balance,
        }
    }

    /// Replays the previous update call steps on the given clean canister.
    /// Returns an error if any step fails. Otherwise, it returns an instance of
    /// the helper that can be used to continue the update call execution.
    fn resume(
        clean_canister: &CanisterState,
        original: &OriginalContext,
        paused: PausedCallOrTaskHelper,
        deallocation_sender: &DeallocationSender,
    ) -> Result<Self, UserError> {
        let helper = Self::new(clean_canister, original, deallocation_sender)?;
        if helper.initial_cycles_balance != paused.initial_cycles_balance {
            let msg = match original.call_or_task {
                CanisterCallOrTask::Update(_) => {
                    "Mismatch in cycles balance when resuming an update call".to_string()
                }
                CanisterCallOrTask::Query(_) => {
                    "Mismatch in cycles balance when resuming a replicated query".to_string()
                }
                CanisterCallOrTask::Task(_) => {
                    "Mismatch in cycles balance when resuming a canister task".to_string()
                }
            };
            let err = HypervisorError::WasmEngineError(FailedToApplySystemChanges(msg));
            return Err(err.into_user_error(&clean_canister.canister_id()));
        }
        if helper.call_context_id != paused.call_context_id {
            let msg = match original.call_or_task {
                CanisterCallOrTask::Update(_) => {
                    "Mismatch in call context id when resuming an update call".to_string()
                }
                CanisterCallOrTask::Query(_) => {
                    "Mismatch in call context id when resuming a replicated query".to_string()
                }
                CanisterCallOrTask::Task(_) => {
                    "Mismatch in call context id when resuming a canister task".to_string()
                }
            };
            let err = HypervisorError::WasmEngineError(FailedToApplySystemChanges(msg));
            return Err(err.into_user_error(&clean_canister.canister_id()));
        }
        Ok(helper)
    }

    /// Finishes an update call execution that could have run multiple rounds
    /// due to deterministic time slicing.
    fn finish(
        mut self,
        mut output: WasmExecutionOutput,
        clean_canister: CanisterState,
        canister_state_changes: CanisterStateChanges,
        original: OriginalContext,
        round: RoundContext,
        round_limits: &mut RoundLimits,
        call_tree_metrics: &dyn CallTreeMetrics,
    ) -> ExecuteMessageResult {
        self.canister
            .system_state
            .apply_ingress_induction_cycles_debit(
                self.canister.canister_id(),
                round.log,
                round.counters.charging_from_balance_error,
            );

        // Check that the cycles balance does not go below the freezing
        // threshold after applying the Wasm execution state changes.
        let old_balance = self.canister.system_state.balance();
        let requested = canister_state_changes
            .system_state_modifications
            .removed_cycles();
        let new_memory_usage = output
            .new_memory_usage
            .unwrap_or_else(|| clean_canister.memory_usage());
        let new_message_memory_usage = output
            .new_message_memory_usage
            .unwrap_or_else(|| clean_canister.message_memory_usage());
        let new_reserved_balance = clean_canister.system_state.reserved_balance()
            + canister_state_changes
                .system_state_modifications
                .reserved_cycles();
        let freezing_threshold = round.cycles_account_manager.freeze_threshold_cycles(
            clean_canister.system_state.freeze_threshold,
            clean_canister.system_state.memory_allocation,
            new_memory_usage,
            new_message_memory_usage,
            clean_canister.compute_allocation(),
            original.subnet_size,
            round.cost_schedule,
            new_reserved_balance,
        );
        let reveal_top_up = self
            .canister
            .controllers()
            .contains(&original.call_origin.get_principal());
        if old_balance < requested + freezing_threshold {
            let err = CanisterOutOfCyclesError {
                canister_id: self.canister.canister_id(),
                available: old_balance,
                requested,
                threshold: original.freezing_threshold,
                reveal_top_up,
            };
            let err = UserError::new(ErrorCode::CanisterOutOfCycles, err);
            info!(
                round.log,
                "[DTS] Failed {:?} execution of canister {} due to concurrent cycle change: {:?}.",
                original.method,
                clean_canister.canister_id(),
                err,
            );
            self.deallocation_sender.send(Box::new(self.canister));
            // Perf counter: no need to update the call context, as it won't be saved.
            return finish_err(
                clean_canister,
                output.num_instructions_left,
                err,
                original,
                round,
            );
        }

        let is_composite_query = matches!(original.method, WasmMethod::CompositeQuery(_));
        let heap_delta = match original.call_or_task {
            // Update methods and tasks can persist changes to the canister's state.
            CanisterCallOrTask::Update(_) | CanisterCallOrTask::Task(_) => {
                apply_canister_state_changes(
                    canister_state_changes,
                    self.canister.execution_state.as_mut().unwrap(),
                    &mut self.canister.system_state,
                    &mut output,
                    round_limits,
                    round.time,
                    round.network_topology,
                    round.hypervisor.subnet_id(),
                    round.log,
                    round.counters.state_changes_error,
                    call_tree_metrics,
                    original.time,
                    is_composite_query,
                    &|system_state| self.deallocation_sender.send(Box::new(system_state)),
                );

                if output.wasm_result.is_ok() {
                    NumBytes::from((output.instance_stats.dirty_pages() * ic_sys::PAGE_SIZE) as u64)
                } else {
                    NumBytes::from(0)
                }
            }
            // Query methods only persist certain changes to the canister's state.
            CanisterCallOrTask::Query(_) => {
                if let Err(err) = canister_state_changes
                    .system_state_modifications
                    .apply_changes(
                        round.time,
                        &mut self.canister.system_state,
                        &mut round_limits.subnet_available_memory,
                        round.network_topology,
                        round.hypervisor.subnet_id(),
                        is_composite_query,
                        round.log,
                    )
                {
                    return finish_err(
                        clean_canister,
                        output.num_instructions_left,
                        err.into_user_error(&original.canister_id),
                        original,
                        round,
                    );
                }
                NumBytes::from(0)
            }
        };

        self.deallocation_sender.send(Box::new(clean_canister));

        let instructions_used = NumInstructions::from(
            original
                .execution_parameters
                .instruction_limits
                .message()
                .get()
                .saturating_sub(output.num_instructions_left.get()),
        );
        let (action, call_context) = self
            .canister
            .system_state
            .on_canister_result(
                self.call_context_id,
                None,
                output.wasm_result.clone(),
                instructions_used,
            )
            .unwrap();

        let response = match original.call_or_task {
            CanisterCallOrTask::Update(_) | CanisterCallOrTask::Task(_) => action_to_response(
                &self.canister,
                action,
                original.call_origin,
                round.time,
                round.log,
                round.counters.ingress_with_cycles_error,
            ),
            CanisterCallOrTask::Query(_) => {
                let result = output
                    .wasm_result
                    .map_err(|err| err.into_user_error(&self.canister.canister_id()));
                let refund = match action {
                    CallContextAction::Reply { refund, .. }
                    | CallContextAction::Reject { refund, .. }
                    | CallContextAction::NoResponse { refund, .. }
                    | CallContextAction::Fail { refund, .. } => refund,
                    CallContextAction::NotYetResponded | CallContextAction::AlreadyResponded => {
                        original.call_or_task.cycles()
                    }
                };
                wasm_result_to_query_response(
                    result,
                    &self.canister,
                    round.time,
                    original.call_origin,
                    round.log,
                    refund,
                )
            }
        };

        let wasm_execution_mode = self
            .canister
            .execution_state
            .as_ref()
            .map_or(WasmExecutionMode::Wasm32, |es| es.wasm_execution_mode);

        round.cycles_account_manager.refund_unused_execution_cycles(
            &mut self.canister.system_state,
            output.num_instructions_left,
            original.execution_parameters.instruction_limits.message(),
            original.prepaid_execution_cycles,
            round.counters.execution_refund_error,
            original.subnet_size,
            round.cost_schedule,
            wasm_execution_mode,
            round.log,
        );

        if original.log_dirty_pages == FlagStatus::Enabled {
            log_dirty_pages(
                round.log,
                &original.canister_id,
                &original.method.name(),
                output.instance_stats.dirty_pages(),
                instructions_used,
            );
        }

        ExecuteMessageResult::Finished {
            canister: self.canister,
            response,
            instructions_used,
            heap_delta,
            call_duration: call_context
                .map(|call_context| round.time.saturating_duration_since(call_context.time())),
        }
    }

    fn canister(&self) -> &CanisterState {
        &self.canister
    }

    fn call_context_id(&self) -> CallContextId {
        self.call_context_id
    }
}

#[derive(Debug)]
struct PausedCallOrTaskExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    paused_helper: PausedCallOrTaskHelper,
    original: OriginalContext,
}

impl PausedExecution for PausedCallOrTaskExecution {
    fn resume(
        self: Box<Self>,
        clean_canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
        _subnet_size: usize,
        call_tree_metrics: &dyn CallTreeMetrics,
        deallocation_sender: &DeallocationSender,
    ) -> ExecuteMessageResult {
        info!(
            round.log,
            "[DTS] Resuming {:?} execution of canister {}.",
            self.original.method,
            clean_canister.canister_id(),
        );
        let helper = match CallOrTaskHelper::resume(
            &clean_canister,
            &self.original,
            self.paused_helper,
            deallocation_sender,
        ) {
            Ok(helper) => helper,
            Err(err) => {
                info!(
                    round.log,
                    "[DTS] Failed to resume {:?} execution of canister {}: {:?}.",
                    self.original.method,
                    clean_canister.canister_id(),
                    err,
                );
                self.paused_wasm_execution.abort();
                return finish_err(
                    clean_canister,
                    self.original
                        .execution_parameters
                        .instruction_limits
                        .message(),
                    err,
                    self.original,
                    round,
                );
            }
        };

        let execution_state = helper.canister().execution_state.as_ref().unwrap();
        let result = self.paused_wasm_execution.resume(execution_state);
        match result {
            WasmExecutionResult::Paused(slice, paused_wasm_execution) => {
                info!(
                    round.log,
                    "[DTS] Pausing {:?} execution of canister {} after {} instructions.",
                    self.original.method,
                    clean_canister.canister_id(),
                    slice.executed_instructions,
                );
                update_round_limits(round_limits, &slice);
                let paused_execution = Box::new(PausedCallOrTaskExecution {
                    paused_wasm_execution,
                    paused_helper: helper.pause(),
                    original: self.original,
                });
                ExecuteMessageResult::Paused {
                    canister: clean_canister,
                    paused_execution,
                    // Pausing a resumed execution doesn't change the ingress
                    // status.
                    ingress_status: None,
                }
            }
            WasmExecutionResult::Finished(slice, output, state_changes) => {
                let instructions_consumed = self
                    .original
                    .execution_parameters
                    .instruction_limits
                    .message()
                    - output.num_instructions_left;
                info!(
                    round.log,
                    "[DTS] Finished {:?} execution of canister {} after {} / {} instructions.",
                    self.original.method,
                    clean_canister.canister_id(),
                    slice.executed_instructions.display(),
                    instructions_consumed.display(),
                );
                update_round_limits(round_limits, &slice);
                helper.finish(
                    output,
                    clean_canister,
                    state_changes,
                    self.original,
                    round,
                    round_limits,
                    call_tree_metrics,
                )
            }
        }
    }

    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (CanisterMessageOrTask, Cycles) {
        info!(
            log,
            "[DTS] Aborting {:?} execution of canister {}",
            self.original.method,
            self.original.canister_id,
        );
        self.paused_wasm_execution.abort();
        let message_or_task = into_message_or_task(self.original.call_or_task);
        (message_or_task, self.original.prepaid_execution_cycles)
    }

    fn input(&self) -> CanisterMessageOrTask {
        into_message_or_task(self.original.call_or_task.clone())
    }
}

fn into_message_or_task(call_or_task: CanisterCallOrTask) -> CanisterMessageOrTask {
    match call_or_task {
        CanisterCallOrTask::Update(CanisterCall::Request(r))
        | CanisterCallOrTask::Query(CanisterCall::Request(r)) => {
            CanisterMessageOrTask::Message(CanisterMessage::Request(r))
        }
        CanisterCallOrTask::Update(CanisterCall::Ingress(i))
        | CanisterCallOrTask::Query(CanisterCall::Ingress(i)) => {
            CanisterMessageOrTask::Message(CanisterMessage::Ingress(i))
        }
        CanisterCallOrTask::Task(task) => CanisterMessageOrTask::Task(task),
    }
}
