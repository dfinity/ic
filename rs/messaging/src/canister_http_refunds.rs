use ic_logger::{ReplicaLogger, info};
use ic_replicated_state::ReplicatedState;
use ic_types::batch::CanisterHttpRefund;

/// Accumulates the HTTP outcall refund shares carried by `refunds` into the
/// `refund_status` of the corresponding request contexts.
///
/// This mirrors how query stats are delivered: a direct mutation of
/// `ReplicatedState` in the messaging layer, with no separate queue and no
/// `SubnetMessage` variant. The accumulated `refunded_cycles` is later read by
/// the execution-environment response handler when it delivers the response to
/// the caller.
///
/// Each participating replica refunds the unused part of its per-replica
/// allowance. A node is credited at most once (tracked via `refunding_nodes`),
/// which makes this idempotent and forward-compatible with asynchronous refunds
/// that may arrive in a later block than the response. The per-replica
/// allowance is already enforced during payload validation.
pub(crate) fn deliver_canister_http_refunds(
    refunds: &[CanisterHttpRefund],
    state: &mut ReplicatedState,
    log: &ReplicaLogger,
) {
    let contexts = &mut state
        .metadata
        .subnet_call_context_manager
        .canister_http_request_contexts;

    for refund in refunds {
        let Some(context) = contexts.get_mut(&refund.callback) else {
            // The context may already be gone (e.g. the response was delivered
            // and the context cleaned up). Once asynchronous refunds are
            // supported the context will outlive response delivery; until then
            // we simply drop such refunds.
            info!(
                log,
                "Received HTTP outcall refund for callback {} with no matching request context; \
                 dropping it.",
                refund.callback
            );
            continue;
        };

        let refund_status = &mut context.refund_status;
        for (node_id, cycles) in &refund.shares {
            if refund_status.refunding_nodes.insert(*node_id) {
                refund_status.refunded_cycles += *cycles;
            }
        }
    }
}
