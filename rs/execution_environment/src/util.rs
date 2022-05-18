use crate::types::Response;
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::{
    ExecResult, ExecuteMessageResult, IngressHistoryWriter,
};
use ic_logger::{error, ReplicaLogger};
use ic_replicated_state::{CanisterState, ReplicatedState};
use ic_types::CanisterId;
use std::sync::Arc;

pub(crate) const GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(1);

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
                canister.push_output_response(canister_response)
            } else {
                error!(log, "[EXC-BUG] Canister {} is attempting to send a response, but the canister doesn't exist in the state!", canister_response.respondent);
            }
        }
    });
}

pub fn process_response(
    mut res: ExecuteMessageResult<CanisterState>,
) -> ExecuteMessageResult<CanisterState> {
    if let ExecResult::ResponseResult(response) = res.result {
        debug_assert_eq!(
            response.respondent,
            res.canister.canister_id(),
            "Respondent mismatch"
        );
        res.canister.push_output_response(response);
        res.result = ExecResult::Empty;
    }
    res
}

pub fn candid_error_to_user_error(error: candid::Error) -> UserError {
    UserError::new(
        ErrorCode::CanisterContractViolation,
        format!("Error decoding candid: {}", error),
    )
}
