use crate::types::Response;
use ic_base_types::SubnetId;
use ic_ic00_types::{CanisterStatusType, EmptyBlob, Payload as Ic00Payload, IC_00};
use ic_interfaces::execution_environment::IngressHistoryWriter;
use ic_logger::{error, info, ReplicaLogger};
use ic_replicated_state::{CanisterStatus, ReplicatedState};
use ic_types::{
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{Payload, StopCanisterCallId, StopCanisterContext},
    CanisterId,
};
use std::{mem, sync::Arc};

pub(crate) const GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(1);

/// Debug assert a condition, increase an error counter, and log the error.
///
/// Example usage:
///
/// ```ignore
/// debug_assert_or_critical_error!(a > b, metric, logger, "{} > {}", a, b);
/// ```
///
/// Which is equivalent to:
///
/// ```ignore
/// if !(a > b) {
///     debug_assert!(a > b);
///     metric.inc();
///     error!(logger, "{} > {}", a, b)
/// }
/// ```
macro_rules! debug_assert_or_critical_error {
    // debug_assert_or_critical_error!(a > b, metric, logger, "{} > {}", a, b);
    ($cond:expr, $metric:expr, $($arg:tt)*) => {{
        if !($cond) {
            debug_assert!($cond);
            $metric.inc();
            error!($($arg)*);
        }
    }};
}
pub(crate) use debug_assert_or_critical_error;

/// Sends responses to their callers.
///
/// * Ingress responses are written to ingress history.
/// * Canister responses are added to the sending canister's output queue.
pub fn process_responses(
    responses: Vec<Response>,
    state: &mut ReplicatedState,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    log: ReplicaLogger,
) {
    responses.into_iter().for_each(|response| match response {
        Response::Ingress(ingress_response) => {
            ingress_history_writer.set_status(
                state,
                ingress_response.message_id,
                ingress_response.status,
            );
        }
        Response::Canister(canister_response) => {
            if let Some(canister) = state.canister_state_mut(&canister_response.respondent) {
                canister.push_output_response(canister_response.into())
            } else {
                error!(log, "[EXC-BUG] Canister {} is attempting to send a response, but the canister doesn't exist in the state!", canister_response.respondent);
            }
        }
    });
}

/// Helper function to remove stop canister calls
/// from SubnetCallContextManager based on provided call id.
pub fn remove_stop_canister_call(
    state: &mut ReplicatedState,
    canister_id: CanisterId,
    call_id: Option<StopCanisterCallId>,
    log: &ReplicaLogger,
) {
    if let Some(call_id) = call_id {
        let stop_canister_call = state
            .metadata
            .subnet_call_context_manager
            .remove_stop_canister_call(call_id);
        if stop_canister_call.is_none() {
            info!(
                log,
                "Could not remove stop_canister call for call ID {} and canister {}",
                call_id,
                canister_id,
            );
        }
    }
}

/// Checks for stopping canisters and, if any of them are ready to stop,
/// transitions them to be fully stopped. Responses to the pending stop
/// message(s) are written to ingress history.
pub fn process_stopping_canisters(
    mut state: ReplicatedState,
    ingress_history_writer: &dyn IngressHistoryWriter<State = ReplicatedState>,
    own_subnet_id: SubnetId,
    log: &ReplicaLogger,
) -> ReplicatedState {
    let mut canister_states = state.take_canister_states();
    let time = state.time();

    for canister in canister_states.values_mut() {
        if !(canister.status() == CanisterStatusType::Stopping
            && canister.system_state.ready_to_stop())
        {
            // Canister is either not stopping or isn't ready to be stopped yet. Nothing to
            // do.
            continue;
        }

        // Transition the canister to "stopped".
        let stopping_status =
            mem::replace(&mut canister.system_state.status, CanisterStatus::Stopped);

        if let CanisterStatus::Stopping { stop_contexts, .. } = stopping_status {
            // Respond to the stop messages.
            for stop_context in stop_contexts {
                match stop_context {
                    StopCanisterContext::Ingress {
                        sender,
                        message_id,
                        call_id,
                    } => {
                        // Responding to stop_canister request from a user.
                        remove_stop_canister_call(&mut state, canister.canister_id(), call_id, log);
                        ingress_history_writer.set_status(
                            &mut state,
                            message_id,
                            IngressStatus::Known {
                                receiver: IC_00.get(),
                                user_id: sender,
                                time,
                                state: IngressState::Completed(WasmResult::Reply(
                                    EmptyBlob.encode(),
                                )),
                            },
                        )
                    }
                    StopCanisterContext::Canister {
                        sender,
                        reply_callback,
                        call_id,
                        cycles,
                    } => {
                        // Responding to stop_canister request from a canister.
                        let subnet_id_as_canister_id = CanisterId::from(own_subnet_id);
                        remove_stop_canister_call(&mut state, canister.canister_id(), call_id, log);

                        let response = ic_types::messages::Response {
                            originator: sender,
                            respondent: subnet_id_as_canister_id,
                            originator_reply_callback: reply_callback,
                            refund: cycles,
                            response_payload: Payload::Data(EmptyBlob.encode()),
                        };
                        state.push_subnet_output_response(response.into());
                    }
                }
            }
        }
    }
    state.put_canister_states(canister_states);
    state
}
