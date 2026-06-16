use ic_logger::{ReplicaLogger, error};
use ic_replicated_state::ReplicatedState;
use ic_types::messages::CallbackId;
use ic_types::{CanisterId, Time, batch::CanisterHttpRefunds};
use ic_types_cycles::Cycles;
use std::collections::BTreeMap;

/// Applies the HTTP outcall refunds carried by `refunds` to the calling
/// canisters by crediting their cycle balances directly.
///
/// Refunds are only applied to contexts that have already been responded to,
/// i.e. those in `delivered_canister_http_request_contexts`. This function must
/// therefore run *after* the round has executed and moved the just-responded
/// contexts into the delivered collection.
///
/// Two kinds of refunds are handled:
///  - *initial* refunds, where the set of nodes that produced a response
///    collectively refund one specific amount;
///  - *asynchronous* refunds, where individual nodes each refund some cycles,
///    possibly in a later block than the response. A node is credited at most
///    once (tracked via `refunding_nodes`), which makes these idempotent.
///
/// In all cases the accumulated `refunded_cycles` is capped so that it never
/// exceeds the context's `refundable_cycles`; only the amount actually applied
/// is credited to the canister.
pub(crate) fn deliver_canister_http_refunds(
    refunds: &CanisterHttpRefunds,
    state: &mut ReplicatedState,
    log: &ReplicaLogger,
) {
    // First update the contexts' refund status and accumulate the cycles to
    // credit per canister. Crediting happens in a second pass to avoid borrowing
    // both the subnet call context manager and the canister states at once.
    let mut credits: BTreeMap<CanisterId, Cycles> = BTreeMap::new();
    {
        let contexts = &mut state
            .metadata
            .subnet_call_context_manager
            .delivered_canister_http_request_contexts;

        // The context should still be around (delivered contexts are only
        // removed on timeout, which is long after the response). A missing
        // context means the refund arrived unexpectedly late; log and drop it.
        let log_missing = |callback: CallbackId| {
            error!(
                log,
                "Received HTTP outcall refund for callback {} with no matching delivered request \
                 context; dropping it.",
                callback
            );
        };

        for refund in &refunds.initial {
            let Some(context) = contexts.get_mut(&refund.callback) else {
                log_missing(refund.callback);
                continue;
            };
            // The initial refund is the collective refund of a set of nodes. Only
            // apply it if no node has refunded yet; otherwise some of its
            // contributing nodes may already have been credited (via an
            // asynchronous refund) and applying it would double-credit.
            if !context.refund_status.refunding_nodes.is_empty() {
                error!(
                    log,
                    "Received an initial HTTP outcall refund for callback {} but {} node(s) have \
                     already refunded; dropping it to avoid double-crediting.",
                    refund.callback,
                    context.refund_status.refunding_nodes.len()
                );
                continue;
            }
            let applied = apply_capped(
                &mut context.refund_status,
                refund.amount,
                refund.callback,
                log,
            );
            // Record the contributing nodes so that a later asynchronous refund
            // from any of them is not credited twice.
            context
                .refund_status
                .refunding_nodes
                .extend(refund.nodes.iter());
            *credits.entry(context.request.sender).or_default() += applied;
        }

        for refund in &refunds.asynchronous {
            let Some(context) = contexts.get_mut(&refund.callback) else {
                log_missing(refund.callback);
                continue;
            };
            let mut applied = Cycles::zero();
            for (node_id, cycles) in &refund.shares {
                if context.refund_status.refunding_nodes.insert(*node_id) {
                    applied +=
                        apply_capped(&mut context.refund_status, *cycles, refund.callback, log);
                } else {
                    error!(
                        log,
                        "Node {} attempted to refund again for HTTP outcall callback {}; \
                         ignoring the duplicate refund of {} cycles.",
                        node_id,
                        refund.callback,
                        cycles
                    );
                }
            }
            *credits.entry(context.request.sender).or_default() += applied;
        }
    }

    credit_canisters(state, credits, log);
}

/// Times out delivered `CanisterHttpRequestContext`s and refunds the calling
/// canister for the replicas that never responded.
///
/// Like [`deliver_canister_http_refunds`], this must run *after* the round has
/// executed, so that just-responded contexts have been moved into the delivered
/// collection.
///
/// A delivered context is kept around until it times out so that late refunds
/// can still be applied. The replicas that did respond refund their unused
/// per-replica allowance through [`deliver_canister_http_refunds`]; the
/// remaining `subnet_size - refunding_nodes.len()` replicas never did, so on
/// timeout their full per-replica allowance is returned to the caller (still
/// capped so that `refunded_cycles` never exceeds `refundable_cycles`).
pub(crate) fn refund_timed_out_canister_http_contexts(
    state: &mut ReplicatedState,
    current_time: Time,
    log: &ReplicaLogger,
) {
    let timed_out = state
        .metadata
        .subnet_call_context_manager
        .time_out_delivered_canister_http_request_contexts(current_time);

    let mut credits: BTreeMap<CanisterId, Cycles> = BTreeMap::new();
    for mut context in timed_out {
        let unresponsive_replicas = context
            .subnet_size
            .saturating_sub(context.refund_status.refunding_nodes.len());
        let refund = context.refund_status.per_replica_allowance * unresponsive_replicas;
        let applied = apply_capped(
            &mut context.refund_status,
            refund,
            context.request.sender_reply_callback,
            log,
        );
        *credits.entry(context.request.sender).or_default() += applied;
    }

    credit_canisters(state, credits, log);
}

/// Records `amount` as refunded against `refund_status`, capped so that
/// `refunded_cycles` never exceeds `refundable_cycles`. Returns the amount that
/// was actually applied (and therefore should be credited to the canister).
///
/// Capping is not expected to happen (the per-replica allowances are sized so
/// that the sum of all refunds stays within `refundable_cycles`), so an error
/// is logged if it does.
fn apply_capped(
    refund_status: &mut ic_types::canister_http::RefundStatus,
    amount: Cycles,
    callback: CallbackId,
    log: &ReplicaLogger,
) -> Cycles {
    let room = refund_status.refundable_cycles - refund_status.refunded_cycles;
    let applied = std::cmp::min(amount, room);
    if applied < amount {
        error!(
            log,
            "HTTP outcall refund for callback {} exceeded the refundable amount and was capped: \
             requested {}, applied {} (refundable_cycles {}, already refunded_cycles {}).",
            callback,
            amount,
            applied,
            refund_status.refundable_cycles,
            refund_status.refunded_cycles
        );
    }
    refund_status.refunded_cycles += applied;
    applied
}

/// Credits the accumulated per-canister refund `credits` to the corresponding
/// canisters' balances, logging any whose canister no longer exists.
///
/// `credits` is keyed by canister, so `canister_state_make_mut` (which heats the
/// canister and may clone its state) is called at most once per canister.
fn credit_canisters(
    state: &mut ReplicatedState,
    credits: BTreeMap<CanisterId, Cycles>,
    log: &ReplicaLogger,
) {
    for (sender, amount) in credits {
        if amount.is_zero() {
            continue;
        }
        match state.canister_state_make_mut(&sender) {
            Some(canister) => canister.system_state.add_cycles(amount),
            None => error!(
                log,
                "Canister {} for an HTTP outcall no longer exists; \
                 dropping refund of {} cycles.",
                sender,
                amount
            ),
        }
    }
}
