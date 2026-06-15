use ic_logger::{ReplicaLogger, info};
use ic_replicated_state::ReplicatedState;
use ic_types::batch::CanisterHttpRefunds;
use ic_types::messages::CallbackId;

/// Accumulates the HTTP outcall refunds carried by `refunds` into the
/// `refund_status` of the corresponding request contexts.
///
/// This mirrors how query stats are delivered: a direct mutation of
/// `ReplicatedState` in the messaging layer, with no separate queue and no
/// `SubnetMessage` variant. The accumulated `refunded_cycles` is later read by
/// the execution-environment response handler when it delivers the response to
/// the caller.
///
/// Two kinds of refunds are handled:
///  - *initial* refunds, where the set of nodes that produced a response
///    collectively refund one specific amount, delivered with the response;
///  - *asynchronous* refunds, where individual nodes each refund some cycles,
///    possibly in a later block than the response. A node is credited at most
///    once (tracked via `refunding_nodes`), which makes these idempotent. The
///    per-replica allowance is already enforced during payload validation.
pub(crate) fn deliver_canister_http_refunds(
    refunds: &CanisterHttpRefunds,
    state: &mut ReplicatedState,
    log: &ReplicaLogger,
) {
    let contexts = &mut state
        .metadata
        .subnet_call_context_manager
        .canister_http_request_contexts;

    // The context may already be gone (e.g. the response was delivered and the
    // context cleaned up). Once asynchronous refunds are supported the context
    // will outlive response delivery; until then we simply drop such refunds.
    let log_missing = |callback: CallbackId| {
        info!(
            log,
            "Received HTTP outcall refund for callback {} with no matching request context; \
             dropping it.",
            callback
        );
    };

    for refund in &refunds.initial {
        match contexts.get_mut(&refund.callback) {
            Some(context) => {
                let refund_status = &mut context.refund_status;
                refund_status.refunded_cycles += refund.amount;
                // Record the contributing nodes so that a later asynchronous
                // refund from any of them is not credited twice.
                refund_status.refunding_nodes.extend(refund.nodes.iter());
            }
            None => log_missing(refund.callback),
        }
    }

    for refund in &refunds.asynchronous {
        let Some(context) = contexts.get_mut(&refund.callback) else {
            log_missing(refund.callback);
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
