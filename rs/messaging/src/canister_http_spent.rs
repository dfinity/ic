use ic_logger::{ReplicaLogger, error};
use ic_replicated_state::ReplicatedState;
use ic_types::messages::CallbackId;
use ic_types::{CanisterId, Time, batch::CanisterHttpSpent, canister_http::Replication};
use ic_types_cycles::{CanisterCyclesCostSchedule, CompoundCycles, Cycles, HTTPOutcalls};
use std::collections::BTreeMap;

/// Per-canister amounts accumulated while delivering HTTP outcall spend reports.
#[derive(Default)]
struct CanisterAccounting {
    /// Real cycles to credit back to the caller (its unused per-replica
    /// allowance). Always zero on a free subnet.
    refund: Cycles,
    /// Nominal cycles the caller consumed, to report in its cost metrics. This
    /// is nonzero on free subnets too, which is the whole reason spend (rather
    /// than refund) is delivered.
    consumed: Cycles,
}

/// Applies the HTTP outcall spend reports carried by `spent` to the calling
/// canisters: it credits each caller the refund derived from its per-replica
/// allowance (`allowance − spent`) and reports the spent cycles as consumed.
///
/// Reports are only applied to contexts that have already been responded to,
/// i.e. those in `delivered_canister_http_request_contexts`. This function must
/// therefore run *after* the round has executed and moved the just-responded
/// contexts into the delivered collection.
///
/// Two kinds of reports are handled:
///  - *initial* reports, where the set of nodes that produced a response
///    collectively spent one specific amount;
///  - *asynchronous* reports, where individual nodes each spent some cycles,
///    possibly in a later block than the response. A node is accounted at most
///    once (tracked via `refunding_nodes`), which makes these idempotent.
///
/// In all cases the accumulated `refunded_cycles` is capped so that it never
/// exceeds the context's `refundable_cycles`; only the amount actually applied
/// is credited to the canister.
pub(crate) fn deliver_canister_http_spent(
    spent: &CanisterHttpSpent,
    state: &mut ReplicatedState,
    log: &ReplicaLogger,
) {
    let cost_schedule = state.get_own_cost_schedule();

    // First update the contexts' refund status and accumulate the amounts to
    // credit/report per canister. The crediting happens in a second pass to
    // avoid borrowing both the subnet call context manager and the canister
    // states at once.
    let mut credits: BTreeMap<CanisterId, CanisterAccounting> = BTreeMap::new();
    {
        let contexts = &mut state
            .metadata
            .subnet_call_context_manager
            .delivered_canister_http_request_contexts;

        // The context should still be around (delivered contexts are only
        // removed on timeout, which is long after the response). A missing
        // context means the report arrived unexpectedly late; log and drop it.
        let log_missing = |callback: CallbackId| {
            error!(
                log,
                "Received HTTP outcall spend report for callback {} with no matching delivered \
                 request context; dropping it.",
                callback
            );
        };

        for report in &spent.initial {
            let Some(context) = contexts.get_mut(&report.callback) else {
                log_missing(report.callback);
                continue;
            };
            // The initial report is the collective spend of a set of nodes. Only
            // apply it if no node has been accounted yet; otherwise some of its
            // contributing nodes may already have been accounted (via an
            // asynchronous report) and applying it would double-count.
            if !context.refund_status.refunding_nodes.is_empty() {
                error!(
                    log,
                    "Received an initial HTTP outcall spend report for callback {} but {} node(s) \
                     have already been accounted; dropping it to avoid double-counting.",
                    report.callback,
                    context.refund_status.refunding_nodes.len()
                );
                continue;
            }
            // The caller's refund for these nodes is their collective allowance
            // minus what they collectively spent. `Cycles::sub` saturates at
            // zero (e.g. on a free subnet, where the allowance is zero).
            let allowance = context.refund_status.per_replica_allowance;
            let refund = (allowance * report.nodes.len()) - report.amount;
            let applied = apply_capped(&mut context.refund_status, refund, report.callback, log);
            // Record the contributing nodes so that a later asynchronous report
            // from any of them is not accounted twice.
            context
                .refund_status
                .refunding_nodes
                .extend(report.nodes.iter());
            let entry = credits.entry(context.request.sender).or_default();
            entry.refund += applied;
            entry.consumed += report.amount;
        }

        for report in &spent.asynchronous {
            let Some(context) = contexts.get_mut(&report.callback) else {
                log_missing(report.callback);
                continue;
            };
            let allowance = context.refund_status.per_replica_allowance;
            let sender = context.request.sender;
            let mut refund_applied = Cycles::zero();
            let mut consumed = Cycles::zero();
            for (node_id, node_spent) in &report.shares {
                if context.refund_status.refunding_nodes.insert(*node_id) {
                    // `Cycles::sub` saturates at zero.
                    let refund = allowance - *node_spent;
                    refund_applied +=
                        apply_capped(&mut context.refund_status, refund, report.callback, log);
                    consumed += *node_spent;
                } else {
                    error!(
                        log,
                        "Node {} attempted to report spend again for HTTP outcall callback {}; \
                         ignoring the duplicate report of {} cycles.",
                        node_id,
                        report.callback,
                        node_spent
                    );
                }
            }
            let entry = credits.entry(sender).or_default();
            entry.refund += refund_applied;
            entry.consumed += consumed;
        }
    }

    apply_accounting(state, credits, cost_schedule, log);
}

/// Times out delivered `CanisterHttpRequestContext`s and refunds the calling
/// canister for the replicas that never responded.
///
/// Like [`deliver_canister_http_spent`], this must run *after* the round has
/// executed, so that just-responded contexts have been moved into the delivered
/// collection.
///
/// A delivered context is kept around until it times out so that late reports
/// can still be applied. The replicas that did respond refunded their unused
/// per-replica allowance through [`deliver_canister_http_spent`]; the remaining
/// `node_count − refunding_nodes.len()` replicas never did, so on timeout their
/// full per-replica allowance is returned to the caller (still capped so that
/// `refunded_cycles` never exceeds `refundable_cycles`). Non-responding replicas
/// did no work, so they contribute nothing to the consumed metric.
pub(crate) fn refund_timed_out_canister_http_contexts(
    state: &mut ReplicatedState,
    current_time: Time,
    log: &ReplicaLogger,
) {
    let cost_schedule = state.get_own_cost_schedule();
    // Node count for a fully-replicated request is the current subnet size.
    // Cost-schedule/registry changes that would alter it are exceedingly rare
    // and only affect the (zero-cycles-at-stake) refund split.
    let subnet_size = state.get_own_subnet_size();
    let timed_out = state
        .metadata
        .subnet_call_context_manager
        .time_out_delivered_canister_http_request_contexts(current_time);

    let mut credits: BTreeMap<CanisterId, CanisterAccounting> = BTreeMap::new();
    for mut context in timed_out {
        // The number of replicas assigned to the request; the responders already
        // refunded via `deliver_canister_http_spent`, the rest refund in full
        // here.
        let node_count = match &context.replication {
            Replication::FullyReplicated => subnet_size,
            Replication::Flexible { committee, .. } => committee.len(),
            Replication::NonReplicated(_) => 1,
        };
        let unresponsive_replicas =
            node_count.saturating_sub(context.refund_status.refunding_nodes.len());
        let refund = context.refund_status.per_replica_allowance * unresponsive_replicas;
        let applied = apply_capped(
            &mut context.refund_status,
            refund,
            context.request.sender_reply_callback,
            log,
        );
        credits.entry(context.request.sender).or_default().refund += applied;
    }

    apply_accounting(state, credits, cost_schedule, log);
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

/// Credits the accumulated per-canister `refund` to the corresponding canisters'
/// balances and reports the accumulated `consumed` cycles in their cost metrics,
/// logging any whose canister no longer exists.
///
/// `credits` is keyed by canister, so `canister_state_make_mut` (which heats the
/// canister and may clone its state) is called at most once per canister.
fn apply_accounting(
    state: &mut ReplicatedState,
    credits: BTreeMap<CanisterId, CanisterAccounting>,
    cost_schedule: CanisterCyclesCostSchedule,
    log: &ReplicaLogger,
) {
    for (sender, accounting) in credits {
        if accounting.refund.is_zero() && accounting.consumed.is_zero() {
            continue;
        }
        match state.canister_state_make_mut(&sender) {
            Some(canister) => {
                canister.system_state.add_cycles(accounting.refund);
                if !accounting.consumed.is_zero() {
                    // The consumed-cycles metric is a `NominalCycles`, which can
                    // only be minted via `CompoundCycles`. Its nominal part
                    // equals the amount regardless of cost schedule, so this
                    // reports the real spend on free subnets too (where the real
                    // cycles, and hence the refund, are zero).
                    let consumed =
                        CompoundCycles::<HTTPOutcalls>::new(accounting.consumed, cost_schedule)
                            .nominal();
                    canister
                        .system_state
                        .observe_consumed_cycles_for_https_outcall(consumed);
                }
            }
            None => error!(
                log,
                "Canister {} for an HTTP outcall no longer exists; dropping refund of {} cycles \
                 and consumed report of {} cycles.",
                sender,
                accounting.refund,
                accounting.consumed
            ),
        }
    }
}
