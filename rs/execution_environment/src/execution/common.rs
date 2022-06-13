// This module defines common helper functions.
// TODO(RUN-60): Move helper functions here.

use ic_base_types::CanisterId;
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_ic00_types::CanisterStatusType;
use ic_interfaces::execution_environment::HypervisorError;
use ic_logger::{fatal, warn, ReplicaLogger};
use ic_replicated_state::{CallContextAction, CallOrigin, CanisterState};
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use ic_types::messages::{CallbackId, MessageId, Payload, RejectContext, Response};
use ic_types::methods::WasmMethod;
use ic_types::{Cycles, Time, UserId};

use crate::execution_environment::ExecutionResponse;

pub(crate) fn validate_canister(canister: &CanisterState) -> Result<(), UserError> {
    if CanisterStatusType::Running != canister.status() {
        let canister_id = canister.canister_id();
        let err_code = match canister.status() {
            CanisterStatusType::Running => unreachable!(),
            CanisterStatusType::Stopping => ErrorCode::CanisterStopping,
            CanisterStatusType::Stopped => ErrorCode::CanisterStopped,
        };
        let err_msg = format!("Canister {} is not running", canister_id);
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
) -> ExecutionResponse {
    match call_origin {
        CallOrigin::Ingress(user_id, message_id) => action_to_ingress_response(
            &canister.canister_id(),
            user_id,
            action,
            message_id,
            time,
            log,
        ),
        CallOrigin::CanisterUpdate(caller_canister_id, callback_id) => {
            action_to_request_response(canister, action, caller_canister_id, callback_id)
        }
        CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => fatal!(
            log,
            "The update path should not have created a callback with a query origin",
        ),
        CallOrigin::Heartbeat => {
            // Since heartbeat messages are invoked by the system as opposed
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
) -> ExecutionResponse {
    let response_payload_and_refund = match action {
        CallContextAction::NotYetResponded | CallContextAction::AlreadyResponded => None,
        CallContextAction::NoResponse { refund } => Some((
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterError,
                message: "No response".to_string(),
            }),
            refund,
        )),

        CallContextAction::Reject { payload, refund } => Some((
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterReject,
                message: payload,
            }),
            refund,
        )),

        CallContextAction::Reply { payload, refund } => Some((Payload::Data(payload), refund)),

        CallContextAction::Fail { error, refund } => {
            let user_error = error.into_user_error(&canister.canister_id());
            Some((
                Payload::Reject(RejectContext {
                    code: user_error.reject_code(),
                    message: user_error.to_string(),
                }),
                refund,
            ))
        }
    };

    if let Some((response_payload, refund)) = response_payload_and_refund {
        ExecutionResponse::Request(Response {
            originator,
            respondent: canister.canister_id(),
            originator_reply_callback: reply_callback_id,
            refund,
            response_payload,
        })
    } else {
        ExecutionResponse::Empty
    }
}

pub(crate) fn action_to_ingress_response(
    canister_id: &CanisterId,
    user_id: UserId,
    action: CallContextAction,
    message_id: MessageId,
    time: Time,
    log: &ReplicaLogger,
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
                    format!("Canister {} did not reply to the call", canister_id),
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
    if !refund_amount.is_zero() {
        warn!(
            log,
            "[EXC-BUG] No funds can be included with an ingress message: user {}, canister_id {}, message_id {}.",
            user_id, canister_id, message_id
        );
    }
    match ingress_status {
        Some(status) => ExecutionResponse::Ingress((message_id, status)),
        None => ExecutionResponse::Empty,
    }
}

pub(crate) fn wasm_result_to_query_response(
    result: Result<Option<WasmResult>, UserError>,
    canister: &CanisterState,
    time: Time,
    call_origin: CallOrigin,
    log: &ReplicaLogger,
) -> ExecutionResponse {
    match call_origin {
        CallOrigin::Ingress(user_id, message_id) => {
            wasm_result_to_ingress_response(result, canister, user_id, message_id, time)
        }
        CallOrigin::CanisterUpdate(caller_canister_id, callback_id) => {
            let response = Response {
                originator: caller_canister_id,
                respondent: canister.canister_id(),
                originator_reply_callback: callback_id,
                refund: Cycles::zero(),
                response_payload: Payload::from(result),
            };
            ExecutionResponse::Request(response)
        }
        CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => {
            fatal!(log, "The update path should not have a query origin",)
        }
        CallOrigin::Heartbeat => {
            // Since heartbeat messages are invoked by the system as opposed
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
