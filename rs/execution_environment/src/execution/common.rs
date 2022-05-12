// This module defines common helper functions.
// TODO(RUN-60): Move helper functions here.

use ic_base_types::CanisterId;
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::ExecResult;
use ic_logger::{fatal, warn, ReplicaLogger};
use ic_replicated_state::{CallContextAction, CallOrigin, CanisterState};
use ic_types::ingress::{IngressStatus, WasmResult};
use ic_types::messages::{CallbackId, MessageId, Payload, RejectContext, Response};
use ic_types::{Cycles, Time, UserId};

pub(crate) fn action_to_result(
    canister: &CanisterState,
    action: CallContextAction,
    call_origin: CallOrigin,
    time: Time,
    log: &ReplicaLogger,
) -> ExecResult {
    match call_origin {
        CallOrigin::Ingress(user_id, message_id) => action_to_ingress_result(
            &canister.canister_id(),
            user_id,
            action,
            message_id,
            time,
            log,
        ),
        CallOrigin::CanisterUpdate(caller_canister_id, callback_id) => {
            action_to_request_result(canister, action, caller_canister_id, callback_id)
        }
        CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => fatal!(
            log,
            "The update path should not have created a callback with a query origin",
        ),
        CallOrigin::Heartbeat => {
            // Since heartbeat messages are invoked by the system as opposed
            // to a principal, they cannot respond since there's no one to
            // respond to. Do nothing.
            ExecResult::Empty
        }
    }
}

pub(crate) fn action_to_request_result(
    canister: &CanisterState,
    action: CallContextAction,
    originator: CanisterId,
    reply_callback_id: CallbackId,
) -> ExecResult {
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
        ExecResult::ResponseResult(Response {
            originator,
            respondent: canister.canister_id(),
            originator_reply_callback: reply_callback_id,
            refund,
            response_payload,
        })
    } else {
        ExecResult::Empty
    }
}

pub(crate) fn action_to_ingress_result(
    canister_id: &CanisterId,
    user_id: UserId,
    action: CallContextAction,
    message_id: MessageId,
    time: Time,
    log: &ReplicaLogger,
) -> ExecResult {
    let mut refund_amount = Cycles::zero();
    let receiver = canister_id.get();
    let ingress_status = match action {
        CallContextAction::NoResponse { refund } => {
            refund_amount = refund;
            Some(IngressStatus::Failed {
                receiver,
                user_id,
                error: UserError::new(
                    ErrorCode::CanisterDidNotReply,
                    format!("Canister {} did not reply to the call", canister_id),
                ),
                time,
            })
        }
        CallContextAction::Reply { payload, refund } => {
            refund_amount = refund;
            Some(IngressStatus::Completed {
                receiver,
                user_id,
                result: WasmResult::Reply(payload),
                time,
            })
        }
        CallContextAction::Reject { payload, refund } => {
            refund_amount = refund;
            Some(IngressStatus::Completed {
                receiver,
                user_id,
                result: WasmResult::Reject(payload),
                time,
            })
        }
        CallContextAction::Fail { error, refund } => {
            refund_amount = refund;
            Some(IngressStatus::Failed {
                receiver,
                user_id,
                error: error.into_user_error(canister_id),
                time,
            })
        }
        CallContextAction::NotYetResponded => Some(IngressStatus::Processing {
            receiver,
            user_id,
            time,
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
        Some(status) => ExecResult::IngressResult((message_id, status)),
        None => ExecResult::Empty,
    }
}
