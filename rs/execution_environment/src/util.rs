use crate::types::Response;
use ic_interfaces::execution_environment::IngressHistoryWriter;
use ic_logger::{ReplicaLogger, error};
use ic_replicated_state::ReplicatedState;
use ic_types::CanisterId;
use prometheus::IntCounter;
use std::sync::Arc;

pub(crate) const GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(1);
pub(crate) const MIGRATION_CANISTER_ID: CanisterId = CanisterId::from_u64(17);

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
    ($cond:expr_2021, $metric:expr_2021, $($arg:tt)*) => {{
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
    canister_not_found_error: &IntCounter,
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
                canister_not_found_error.inc();
                error!(log, "[EXC-BUG] Canister {} is attempting to send a response, but the canister doesn't exist in the state!", canister_response.respondent);
            }
        }
    });
}
