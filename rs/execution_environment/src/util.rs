use crate::types::Response;
use ic_interfaces::execution_environment::IngressHistoryWriter;
use ic_replicated_state::ReplicatedState;
use std::sync::Arc;

/// Sends responses to their callers.
///
/// * Ingress responses are written to ingress history.
/// * Canister responses are added to the sending canister's output queue.
#[doc(hidden)]
pub fn process_responses(
    responses: Vec<Response>,
    state: &mut ReplicatedState,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
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
            }
        }
    });
}
