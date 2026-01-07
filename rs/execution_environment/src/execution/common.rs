// This module defines common helper functions.
// TODO(RUN-60): Move helper functions here.

use crate::execution_environment::ExecutionResponse;
use crate::{ExecuteMessageResult, RoundLimits, metrics::CallTreeMetrics};
use ic_base_types::{CanisterId, NumBytes, SubnetId};
use ic_embedders::{
    wasm_executor::{CanisterStateChanges, ExecutionStateChanges, SliceExecutionOutput},
    wasmtime_embedder::system_api::sandbox_safe_system_state::{
        RequestMetadataStats, SystemStateModifications,
    },
};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, SubnetAvailableMemory, WasmExecutionOutput,
};
use ic_logger::{ReplicaLogger, error, fatal, info, warn};
use ic_management_canister_types_private::CanisterStatusType;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallContext, CallContextAction, CallOrigin, CanisterState, ExecutionState, NetworkTopology,
    SystemState,
};
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use ic_types::messages::{
    CallContextId, CallbackId, CanisterCall, CanisterCallOrTask, MessageId, Payload, RejectContext,
    Response,
};
use ic_types::methods::{Callback, WasmMethod};
use ic_types::time::CoarseTime;
use ic_types::{Cycles, NumInstructions, Time, UserId};
use lazy_static::lazy_static;
use prometheus::IntCounter;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

lazy_static! {
    /// Track how many system task errors have been encountered
    /// so that we can restrict logging to a sample of them.
    static ref SYSTEM_TASK_ERROR_COUNT: AtomicU64 = AtomicU64::new(0);
}

/// How often system task errors should be logged to avoid overloading the logs.
const LOG_ONE_SYSTEM_TASK_OUT_OF: u64 = 100;
/// How many first system task messages to log unconditionally.
const LOG_FIRST_N_SYSTEM_TASKS: u64 = 50;

pub(crate) fn validate_canister(canister: &CanisterState) -> Result<(), UserError> {
    if CanisterStatusType::Running != canister.status() {
        let canister_id = canister.canister_id();
        let err_code = match canister.status() {
            CanisterStatusType::Running => unreachable!(),
            CanisterStatusType::Stopping => ErrorCode::CanisterStopping,
            CanisterStatusType::Stopped => ErrorCode::CanisterStopped,
        };
        let err_msg = format!("Canister {canister_id} is not running");
        return Err(UserError::new(err_code, err_msg));
    }
    Ok(())
}

pub(crate) fn action_to_response(
    canister: &CanisterState,
    action: CallContextAction,
    call_origin: CallOrigin,
    time: Time,
    log: &ReplicaLogger,
    ingress_with_cycles_error: &IntCounter,
) -> ExecutionResponse {
    match call_origin {
        CallOrigin::Ingress(user_id, message_id, _method_name) => action_to_ingress_response(
            &canister.canister_id(),
            user_id,
            action,
            message_id,
            time,
            log,
            ingress_with_cycles_error,
        ),
        CallOrigin::CanisterUpdate(caller_canister_id, callback_id, deadline, _method_name) => {
            action_to_request_response(canister, action, caller_canister_id, callback_id, deadline)
        }
        CallOrigin::CanisterQuery(..) | CallOrigin::Query(..) => fatal!(
            log,
            "The update path should not have created a callback with a query origin",
        ),
        CallOrigin::SystemTask => {
            // System task is either a Heartbeat or a GlobalTimer.
            // Since system tasks are invoked by the system as opposed
            // to a principal, they cannot respond since there's no one to
            // respond to. Do nothing.
            ExecutionResponse::Empty
        }
    }
}

pub(crate) fn action_to_request_response(
    canister: &CanisterState,
    action: CallContextAction,
    originator: CanisterId,
    reply_callback_id: CallbackId,
    deadline: CoarseTime,
) -> ExecutionResponse {
    let (response_payload, refund) = match action {
        CallContextAction::NotYetResponded | CallContextAction::AlreadyResponded => {
            return ExecutionResponse::Empty;
        }

        CallContextAction::NoResponse { refund } => (
            Payload::Reject(RejectContext::new(RejectCode::CanisterError, "No response")),
            refund,
        ),

        CallContextAction::Reject { payload, refund } => (
            Payload::Reject(RejectContext::new(RejectCode::CanisterReject, payload)),
            refund,
        ),

        CallContextAction::Reply { payload, refund } => (Payload::Data(payload), refund),

        CallContextAction::Fail { error, refund } => {
            let user_error = error.into_user_error(&canister.canister_id());
            (
                Payload::Reject(RejectContext::new(user_error.reject_code(), user_error)),
                refund,
            )
        }
    };

    ExecutionResponse::Request(Response {
        originator,
        respondent: canister.canister_id(),
        originator_reply_callback: reply_callback_id,
        refund,
        response_payload,
        deadline,
    })
}

pub(crate) fn action_to_ingress_response(
    canister_id: &CanisterId,
    user_id: UserId,
    action: CallContextAction,
    message_id: MessageId,
    time: Time,
    log: &ReplicaLogger,
    ingress_with_cycles_error: &IntCounter,
) -> ExecutionResponse {
    let mut refund_amount = Cycles::zero();
    let receiver = canister_id.get();
    let ingress_status = match action {
        CallContextAction::NoResponse { refund } => {
            refund_amount = refund;
            Some(IngressStatus::Known {
                receiver,
                user_id,
                time,
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterDidNotReply,
                    format!("Canister {canister_id} did not reply to the call"),
                )),
            })
        }
        CallContextAction::Reply { payload, refund } => {
            refund_amount = refund;
            Some(IngressStatus::Known {
                receiver,
                user_id,
                time,
                state: IngressState::Completed(WasmResult::Reply(payload)),
            })
        }
        CallContextAction::Reject { payload, refund } => {
            refund_amount = refund;
            Some(IngressStatus::Known {
                receiver,
                user_id,
                time,
                state: IngressState::Completed(WasmResult::Reject(payload)),
            })
        }
        CallContextAction::Fail { error, refund } => {
            refund_amount = refund;
            Some(IngressStatus::Known {
                receiver,
                user_id,
                time,
                state: IngressState::Failed(error.into_user_error(canister_id)),
            })
        }
        CallContextAction::NotYetResponded => Some(IngressStatus::Known {
            receiver,
            user_id,
            time,
            state: IngressState::Processing,
        }),
        CallContextAction::AlreadyResponded => None,
    };
    debug_assert!(refund_amount.is_zero());
    if !refund_amount.is_zero() {
        ingress_with_cycles_error.inc();
        warn!(
            log,
            "[EXC-BUG] No funds can be included with an ingress message: user {}, canister_id {}, message_id {}.",
            user_id,
            canister_id,
            message_id
        );
    }
    match ingress_status {
        Some(status) => ExecutionResponse::Ingress((message_id, status)),
        None => ExecutionResponse::Empty,
    }
}

/// Returns an ingress status with the `Processing` ingress state if the
/// original message was an ingress message.
/// Otherwise, returns `None`.
pub(crate) fn ingress_status_with_processing_state(
    message: &CanisterCall,
    time: Time,
) -> Option<(MessageId, IngressStatus)> {
    match message {
        CanisterCall::Ingress(ingress) => Some((
            ingress.message_id.clone(),
            IngressStatus::Known {
                receiver: ingress.receiver.get(),
                user_id: ingress.source,
                time,
                state: IngressState::Processing,
            },
        )),
        CanisterCall::Request(_) => None,
    }
}

pub(crate) fn wasm_result_to_query_response(
    result: Result<Option<WasmResult>, UserError>,
    canister: &CanisterState,
    time: Time,
    call_origin: CallOrigin,
    log: &ReplicaLogger,
    refund: Cycles,
) -> ExecutionResponse {
    match call_origin {
        CallOrigin::Ingress(user_id, message_id, _method_name) => {
            wasm_result_to_ingress_response(result, canister, user_id, message_id, time)
        }
        CallOrigin::CanisterUpdate(caller_canister_id, callback_id, deadline, _method_name) => {
            let response = Response {
                originator: caller_canister_id,
                respondent: canister.canister_id(),
                originator_reply_callback: callback_id,
                refund,
                response_payload: Payload::from(result),
                deadline,
            };
            ExecutionResponse::Request(response)
        }
        CallOrigin::CanisterQuery(..) | CallOrigin::Query(..) => {
            fatal!(log, "The update path should not have a query origin",)
        }
        CallOrigin::SystemTask => {
            // System task is either a Heartbeat or a GlobalTimer.
            // Since system tasks are invoked by the system as opposed
            // to a principal, they cannot respond since there's no one to
            // respond to. Do nothing.
            ExecutionResponse::Empty
        }
    }
}

pub(crate) fn wasm_result_to_ingress_response(
    result: Result<Option<WasmResult>, UserError>,
    canister: &CanisterState,
    user_id: UserId,
    msg_id: MessageId,
    time: Time,
) -> ExecutionResponse {
    let ingress_status = match result {
        Ok(wasm_result) => match wasm_result {
            None => IngressStatus::Known {
                receiver: canister.canister_id().get(),
                user_id,
                time,
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterDidNotReply,
                    format!(
                        "Canister {} did not reply to the call",
                        canister.canister_id(),
                    ),
                )),
            },
            Some(wasm_result) => IngressStatus::Known {
                receiver: canister.canister_id().get(),
                user_id,
                time,
                state: IngressState::Completed(wasm_result),
            },
        },
        Err(user_error) => IngressStatus::Known {
            receiver: canister.canister_id().get(),
            user_id,
            time,
            state: IngressState::Failed(user_error),
        },
    };

    ExecutionResponse::Ingress((msg_id, ingress_status))
}

pub(crate) fn validate_method(
    method: &WasmMethod,
    canister: &CanisterState,
) -> Result<(), HypervisorError> {
    match canister.execution_state.as_ref() {
        None => return Err(HypervisorError::WasmModuleNotFound),
        Some(es) => {
            if !es.exports_method(method) {
                return Err(HypervisorError::MethodNotFound(method.clone()));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_message(
    canister: &CanisterState,
    wasm_method: &WasmMethod,
) -> Result<(), UserError> {
    validate_canister(canister)?;

    validate_method(wasm_method, canister)
        .map_err(|err| err.into_user_error(&canister.canister_id()))?;

    Ok(())
}

// Helper function that extracts the corresponding callback and call context
// from the `CallContextManager` without changing its state.
pub fn get_call_context_and_callback(
    canister: &CanisterState,
    response: &Response,
    logger: &ReplicaLogger,
    unexpected_response_error: &IntCounter,
) -> Option<(Callback, CallbackId, CallContext, CallContextId)> {
    debug_assert_ne!(canister.status(), CanisterStatusType::Stopped);
    let call_context_manager = match canister.status() {
        CanisterStatusType::Stopped => {
            // A canister by definition can only be stopped when no open call contexts.
            // Hence, if we receive a response for a stopped canister then that is
            // a either a bug in the code or potentially a faulty (or
            // malicious) subnet generating spurious messages.
            unexpected_response_error.inc();
            error!(
                logger,
                "[EXC-BUG] Stopped canister got a response.  originator {} respondent {}.",
                response.originator,
                response.respondent,
            );
            return None;
        }
        CanisterStatusType::Running | CanisterStatusType::Stopping => {
            // We are sure there's a call context manager since the canister isn't stopped.
            canister.system_state.call_context_manager().unwrap()
        }
    };

    let callback_id = response.originator_reply_callback;

    debug_assert!(call_context_manager.callback(callback_id).is_some());
    let callback = match call_context_manager.callback(callback_id) {
        Some(callback) => callback.clone(),
        None => {
            // Received an unknown callback ID. Nothing to do.
            unexpected_response_error.inc();
            error!(
                logger,
                "[EXC-BUG] Canister got a response with unknown callback ID {}.  originator {} respondent {}.",
                response.originator_reply_callback,
                response.originator,
                response.respondent,
            );
            return None;
        }
    };

    let call_context_id = callback.call_context_id;
    debug_assert!(call_context_manager.call_context(call_context_id).is_some());
    let call_context = match call_context_manager.call_context(call_context_id) {
        Some(call_context) => call_context.clone(),
        None => {
            // Unknown call context. Nothing to do.
            unexpected_response_error.inc();
            error!(
                logger,
                "[EXC-BUG] Canister got a response for unknown request.  originator {} respondent {} callback id {}.",
                response.originator,
                response.respondent,
                response.originator_reply_callback,
            );
            return None;
        }
    };

    Some((callback, callback_id, call_context, call_context_id))
}

pub fn update_round_limits(round_limits: &mut RoundLimits, slice: &SliceExecutionOutput) {
    round_limits.charge_instructions(slice.executed_instructions)
}

/// Tries to apply the given canister changes to the given system state and
/// subnet available memory. In case of an error, the partially applied changes
/// are not undone.
fn try_apply_canister_state_changes(
    system_state_modifications: SystemStateModifications,
    output: &WasmExecutionOutput,
    system_state: &mut SystemState,
    subnet_available_memory: &mut SubnetAvailableMemory,
    time: Time,
    network_topology: &NetworkTopology,
    subnet_id: SubnetId,
    is_composite_query: bool,
    log: &ReplicaLogger,
) -> HypervisorResult<RequestMetadataStats> {
    subnet_available_memory
        .try_decrement(
            output.allocated_bytes,
            output.allocated_guaranteed_response_message_bytes,
            NumBytes::from(0),
        )
        .map_err(|_| HypervisorError::OutOfMemory)?;

    system_state_modifications.apply_changes(
        time,
        system_state,
        network_topology,
        subnet_id,
        is_composite_query,
        log,
    )
}

/// Applies canister state change after Wasm execution if possible.
/// Otherwise, the function sets the corresponding error in
/// `output.wasm_result`.
/// Potential causes of failure:
/// - Changes in the environment such as subnet available memory while the
///   long-execution with deterministic time slicing was in progress.
/// - A mismatch between checks dones by the Wasm executor and checks done when
///   applying the changes due to a bug.
/// - An escape from the Wasm sandbox that corrupts the execution output.
#[allow(clippy::too_many_arguments)]
pub fn apply_canister_state_changes(
    canister_state_changes: CanisterStateChanges,
    execution_state: &mut ExecutionState,
    system_state: &mut SystemState,
    output: &mut WasmExecutionOutput,
    round_limits: &mut RoundLimits,
    time: Time,
    network_topology: &NetworkTopology,
    subnet_id: SubnetId,
    log: &ReplicaLogger,
    state_changes_error: &IntCounter,
    call_tree_metrics: &dyn CallTreeMetrics,
    call_context_creation_time: Time,
    is_composite_query: bool,
    deallocate: &dyn Fn(SystemState),
) {
    let CanisterStateChanges {
        execution_state_changes,
        system_state_modifications,
    } = canister_state_changes;

    let clean_system_state = system_state.clone();
    let clean_subnet_available_memory = round_limits.subnet_available_memory;
    let callbacks_created = system_state_modifications.callbacks_created();
    // Everything that is passed via a mutable reference in this function
    // should be cloned and restored in case of an error.
    match try_apply_canister_state_changes(
        system_state_modifications,
        output,
        system_state,
        &mut round_limits.subnet_available_memory,
        time,
        network_topology,
        subnet_id,
        is_composite_query,
        log,
    ) {
        Ok(request_stats) => {
            if let Some(ExecutionStateChanges {
                globals,
                wasm_memory,
                stable_memory,
            }) = execution_state_changes
            {
                execution_state.wasm_memory = wasm_memory;
                execution_state.stable_memory = stable_memory;
                execution_state.exported_globals = globals;
            }
            round_limits.subnet_available_callbacks -= callbacks_created as i64;
            deallocate(clean_system_state);

            call_tree_metrics.observe(request_stats, call_context_creation_time, time);
        }
        Err(err) => {
            debug_assert_eq!(err, HypervisorError::OutOfMemory);
            match &err {
                HypervisorError::WasmEngineError(err) => {
                    state_changes_error.inc();
                    error!(
                        log,
                        "[EXC-BUG]: Failed to apply state changes due to a bug: {}", err
                    )
                }
                HypervisorError::OutOfMemory => {
                    warn!(log, "Failed to apply state changes due to DTS: {}", err)
                }
                _ => {
                    state_changes_error.inc();
                    error!(
                        log,
                        "[EXC-BUG]: Failed to apply state changes due to an unexpected error: {}",
                        err
                    )
                }
            }
            let old_system_state = std::mem::replace(system_state, clean_system_state);
            deallocate(old_system_state);
            round_limits.subnet_available_memory = clean_subnet_available_memory;
            output.wasm_result = Err(err);
        }
    }
}

pub(crate) fn finish_call_with_error(
    user_error: UserError,
    canister: CanisterState,
    call_or_task: CanisterCallOrTask,
    instructions_used: NumInstructions,
    time: Time,
    subnet_type: SubnetType,
    log: &ReplicaLogger,
) -> ExecuteMessageResult {
    let response = match call_or_task {
        CanisterCallOrTask::Update(CanisterCall::Request(request))
        | CanisterCallOrTask::Query(CanisterCall::Request(request)) => {
            let response = Response {
                originator: request.sender,
                respondent: canister.canister_id(),
                originator_reply_callback: request.sender_reply_callback,
                refund: request.payment,
                response_payload: Payload::from(Err(user_error)),
                deadline: request.deadline,
            };
            ExecutionResponse::Request(response)
        }
        CanisterCallOrTask::Update(CanisterCall::Ingress(ingress))
        | CanisterCallOrTask::Query(CanisterCall::Ingress(ingress)) => {
            let status = IngressStatus::Known {
                receiver: canister.canister_id().get(),
                user_id: ingress.source,
                time,
                state: IngressState::Failed(user_error),
            };
            ExecutionResponse::Ingress((ingress.message_id.clone(), status))
        }
        CanisterCallOrTask::Task(task) => {
            // We should monitor all errors in the system subnets and only
            // system errors on other subnets.
            if subnet_type == SubnetType::System || user_error.is_system_error() {
                // We could improve the rate limiting using some kind of exponential backoff.
                let log_count = SYSTEM_TASK_ERROR_COUNT.fetch_add(1, Ordering::SeqCst);
                if log_count < LOG_FIRST_N_SYSTEM_TASKS
                    || log_count.is_multiple_of(LOG_ONE_SYSTEM_TASK_OUT_OF)
                {
                    warn!(
                        log,
                        "Error executing canister task {:?} on canister {} with failure `{}`",
                        task,
                        canister.canister_id(),
                        user_error;
                        messaging.canister_id => canister.canister_id().to_string(),
                    );
                }
            }
            ExecutionResponse::Empty
        }
    };
    ExecuteMessageResult::Finished {
        canister,
        response,
        instructions_used,
        heap_delta: NumBytes::from(0),
        call_duration: Some(Duration::from_secs(0)),
    }
}

/// Helper method for logging dirty pages.
pub fn log_dirty_pages(
    log: &ReplicaLogger,
    canister_id: &CanisterId,
    method_name: &str,
    dirty_pages: usize,
    instructions: NumInstructions,
) {
    let output_message = format!(
        "Executed {canister_id}::{method_name}: dirty_4kb_pages = {dirty_pages}, instructions = {instructions}"
    );
    info!(log, "{}", output_message.as_str());
    eprintln!("{output_message}");
}

#[cfg(test)]
mod test {
    use super::wasm_result_to_query_response;
    use crate::ExecutionResponse;
    use ic_base_types::{CanisterId, NumSeconds};
    use ic_error_types::UserError;
    use ic_logger::LoggerImpl;
    use ic_logger::ReplicaLogger;
    use ic_replicated_state::{CanisterState, SchedulerState, SystemState};
    use ic_types::Cycles;
    use ic_types::Time;
    use ic_types::messages::CallbackId;
    use ic_types::messages::NO_DEADLINE;

    #[test]
    fn test_wasm_result_to_query_response_refunds_correctly() {
        let scheduler_state = SchedulerState::default();
        let system_state = SystemState::new_running_for_testing(
            CanisterId::from_u64(42),
            CanisterId::from(100u64).into(),
            Cycles::new(1 << 36),
            NumSeconds::from(100_000),
        );

        let logger = LoggerImpl::new(&Default::default(), "test".to_string());
        let log = ReplicaLogger::new(logger.root.clone().into());

        let response = wasm_result_to_query_response(
            Err(UserError::new(
                ic_error_types::ErrorCode::CanisterCalledTrap,
                "",
            )),
            &CanisterState::new(system_state, None, scheduler_state),
            Time::from_nanos_since_unix_epoch(100),
            ic_replicated_state::CallOrigin::CanisterUpdate(
                CanisterId::from(123u64),
                CallbackId::new(2),
                NO_DEADLINE,
                String::from(""),
            ),
            &log,
            Cycles::from(1000u128),
        );

        if let ExecutionResponse::Request(response) = response {
            assert_eq!(response.refund, Cycles::from(1000u128));
        } else {
            panic!("Unexpected response.");
        }
    }
}
