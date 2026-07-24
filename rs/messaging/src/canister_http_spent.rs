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
    /// is nonzero also on free subnets.
    consumed: Cycles,
    /// The cost schedule to use for this request.
    cost_schedule: CanisterCyclesCostSchedule,
}

impl CanisterAccounting {
    fn new(cost_schedule: CanisterCyclesCostSchedule) -> Self {
        Self {
            refund: Cycles::zero(),
            consumed: Cycles::zero(),
            cost_schedule,
        }
    }
}

/// Applies the HTTP outcall spend reports carried by `spent` to the calling
/// canisters: it credits each caller the refund derived from its per-replica
/// allowance (`allowance − spent`) and reports the spent cycles as consumed.
///
/// Reports are only applied to contexts that have already been responded to,
/// i.e. those in `delivered_canister_http_request_contexts`.
///
/// Two kinds of reports are handled:
///  - *initial* reports, where the set of nodes that produced a response
///    collectively spent one specific amount;
///  - *asynchronous* reports, where individual nodes each spent some cycles,
///    possibly in a later block than the response. A node is accounted at most
///    once (tracked via `refunding_nodes`), which makes these idempotent.
pub(crate) fn deliver_canister_http_spent(
    spent: &CanisterHttpSpent,
    state: &mut ReplicatedState,
    log: &ReplicaLogger,
) {
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

        // Initial spending
        for report in &spent.initial {
            let Some(context) = contexts.get_mut(&report.callback) else {
                continue;
            };
            // The initial report is the initial collective spend of a set of nodes to
            // produce the response. Only apply it if no node has been accounted yet.
            if !context.refund_status.refunding_nodes.is_empty() {
                error!(
                    log,
                    "Received an initial HTTP outcall spend report for callback {} but some node(s) \
                     {} have already been accounted.",
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
            let entry = credits
                .entry(context.request.sender)
                .or_insert_with(|| CanisterAccounting::new(context.cost_schedule));
            entry.refund += applied;
            entry.consumed += report.amount;
        }

        // Asynchronous spending
        for report in &spent.asynchronous {
            let Some(context) = contexts.get_mut(&report.callback) else {
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

    apply_accounting(state, credits, log);
}

/// Times out delivered `CanisterHttpRequestContext`s and refunds the calling
/// canister for the replicas that never responded.
///
/// A delivered context is kept around until it times out so that late reports
/// can still be applied. The replicas that did respond refunded their unused
/// per-replica allowance through [`deliver_canister_http_spent`]; the remaining
/// `node_count − refunding_nodes.len()` replicas never did, so on timeout their
/// full per-replica allowance is returned to the caller.
pub(crate) fn refund_timed_out_canister_http_contexts(
    state: &mut ReplicatedState,
    current_time: Time,
    log: &ReplicaLogger,
) {
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
            Replication::FullyReplicated => context.subnet_size.get() as usize,
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
        credits
            .entry(context.request.sender)
            .or_insert_with(|| CanisterAccounting::new(context.cost_schedule))
            .refund += applied;
    }

    apply_accounting(state, credits, log);
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
fn apply_accounting(
    state: &mut ReplicatedState,
    credits: BTreeMap<CanisterId, CanisterAccounting>,
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
                    let consumed = CompoundCycles::<HTTPOutcalls>::new(
                        accounting.consumed,
                        accounting.cost_schedule,
                    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::no_op_logger;
    use ic_replicated_state::ReplicatedState;
    use ic_test_utilities_state::{CanisterStateBuilder, ReplicatedStateBuilder};
    use ic_test_utilities_types::ids::{canister_test_id, node_test_id};
    use ic_test_utilities_types::messages::RequestBuilder;
    use ic_types::batch::{CanisterHttpAsyncSpent, CanisterHttpInitialSpent, CanisterHttpSpent};
    use ic_types::canister_http::{
        CanisterHttpMethod, CanisterHttpRequestContext, PricingVersion, RefundStatus, Replication,
    };
    use ic_types::messages::CallbackId;
    use ic_types::time::UNIX_EPOCH;
    use ic_types::{NodeId, NumberOfNodes, RegistryVersion};
    use ic_types_cycles::CyclesUseCase;
    use std::collections::BTreeSet;
    use std::time::Duration;

    const INITIAL_BALANCE: Cycles = Cycles::new(1_000_000_000_000);
    const CALLBACK: CallbackId = CallbackId::new(42);

    fn node_set(ids: &[u64]) -> BTreeSet<NodeId> {
        ids.iter().copied().map(node_test_id).collect()
    }

    /// Number of nodes on the (fully-replicated) subnet used in these tests. The
    /// request context's `subnet_size` drives the timeout refund of non-responders
    /// for a fully-replicated request; the state is created with a matching node
    /// set for consistency.
    const SUBNET_SIZE: u64 = 13;

    /// Builds a state holding a single caller canister (`canister_test_id(1)`) on
    /// a [`SUBNET_SIZE`]-node subnet and, if `context` is `Some`, a delivered
    /// `CanisterHttpRequestContext` registered under [`CALLBACK`].
    fn setup(context: Option<(Replication, RefundStatus)>) -> (ReplicatedState, CanisterId) {
        let caller = canister_test_id(1);
        let canister = CanisterStateBuilder::new()
            .with_canister_id(caller)
            .with_cycles(INITIAL_BALANCE)
            .build();
        let mut state = ReplicatedStateBuilder::new()
            .with_canister(canister)
            .with_node_ids((1..=SUBNET_SIZE).map(node_test_id).collect())
            .build();

        if let Some((replication, refund_status)) = context {
            let context = CanisterHttpRequestContext {
                request: RequestBuilder::default().sender(caller).build(),
                url: "https://example.com".to_string(),
                max_response_bytes: None,
                headers: Vec::new(),
                body: None,
                http_method: CanisterHttpMethod::GET,
                transform: None,
                time: UNIX_EPOCH,
                replication,
                pricing_version: PricingVersion::PayAsYouGo,
                refund_status,
                registry_version: RegistryVersion::from(1),
                subnet_size: NumberOfNodes::from(SUBNET_SIZE as u32),
                cost_schedule: CanisterCyclesCostSchedule::Normal,
            };
            state
                .metadata
                .subnet_call_context_manager
                .delivered_canister_http_request_contexts
                .insert(CALLBACK, context);
        }
        (state, caller)
    }

    fn refund_status(refundable: Cycles, per_replica_allowance: Cycles) -> RefundStatus {
        RefundStatus {
            refundable_cycles: refundable,
            per_replica_allowance,
            refunded_cycles: Cycles::zero(),
            refunding_nodes: BTreeSet::new(),
        }
    }

    fn balance(state: &ReplicatedState, caller: CanisterId) -> Cycles {
        state
            .canister_state(&caller)
            .unwrap()
            .system_state
            .balance()
    }

    /// The cycles reported as consumed for HTTPS outcalls by `caller`.
    fn consumed(state: &ReplicatedState, caller: CanisterId) -> u128 {
        state
            .canister_state(&caller)
            .unwrap()
            .system_state
            .canister_metrics()
            .consumed_cycles_by_use_cases_as_counters()
            .get(&CyclesUseCase::HTTPOutcalls)
            .map(|n| n.get())
            .unwrap_or(0)
    }

    fn status_after(state: &ReplicatedState) -> RefundStatus {
        state
            .metadata
            .subnet_call_context_manager
            .delivered_canister_http_request_contexts
            .get(&CALLBACK)
            .unwrap()
            .refund_status
            .clone()
    }

    /// An initial report on a normal subnet credits the collective refund
    /// (`allowance * nodes − spent`) and reports the spent cycles as consumed.
    #[test]
    fn initial_report_credits_refund_and_reports_consumed() {
        let allowance = Cycles::new(1_000);
        let spent = Cycles::new(9_500);
        let refundable = allowance * 13_usize; // 13_000
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            refund_status(refundable, allowance),
        )));

        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: spent,
                nodes: node_set(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&report, &mut state, &no_op_logger());

        // refund = 13 * 1_000 − 9_500 = 3_500.
        assert_eq!(
            balance(&state, caller),
            INITIAL_BALANCE + Cycles::new(3_500)
        );
        assert_eq!(consumed(&state, caller), spent.get());
        let status = status_after(&state);
        assert_eq!(status.refunded_cycles, Cycles::new(3_500));
        assert_eq!(status.refunding_nodes.len(), 13);
    }

    /// On a free subnet the per-replica allowance is zero, so nothing is
    /// refunded, but the spent cycles are still reported as consumed. This is the
    /// whole reason spend (rather than refund) is delivered.
    #[test]
    fn free_subnet_reports_consumed_without_refund() {
        let spent = Cycles::new(9_500);
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            refund_status(Cycles::zero(), Cycles::zero()),
        )));

        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: spent,
                nodes: node_set(&[1, 2, 3]),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&report, &mut state, &no_op_logger());

        assert_eq!(balance(&state, caller), INITIAL_BALANCE);
        assert_eq!(consumed(&state, caller), spent.get());
    }

    /// Asynchronous reports credit `allowance − spent` per node and report the
    /// per-node spend; a node that has already been accounted is ignored, making
    /// repeated reports idempotent.
    #[test]
    fn asynchronous_reports_are_idempotent_per_node() {
        let allowance = Cycles::new(1_000);
        let (mut state, caller) = setup(Some((
            Replication::Flexible {
                committee: node_set(&[1, 2, 3]),
                min_responses: 1,
                max_responses: 3,
            },
            refund_status(allowance * 3_usize, allowance),
        )));
        let log = no_op_logger();

        // First report accounts nodes 1 and 2.
        let first = CanisterHttpSpent {
            initial: vec![],
            asynchronous: vec![CanisterHttpAsyncSpent {
                callback: CALLBACK,
                shares: BTreeMap::from([
                    (node_test_id(1), Cycles::new(400)),
                    (node_test_id(2), Cycles::new(600)),
                ]),
            }],
        };
        deliver_canister_http_spent(&first, &mut state, &log);
        // refund = (1_000 − 400) + (1_000 − 600) = 1_000; consumed = 1_000.
        assert_eq!(
            balance(&state, caller),
            INITIAL_BALANCE + Cycles::new(1_000)
        );
        assert_eq!(consumed(&state, caller), 1_000);

        // Second report repeats node 1 (must be ignored) and adds node 3.
        let second = CanisterHttpSpent {
            initial: vec![],
            asynchronous: vec![CanisterHttpAsyncSpent {
                callback: CALLBACK,
                shares: BTreeMap::from([
                    (node_test_id(1), Cycles::new(999)),
                    (node_test_id(3), Cycles::new(700)),
                ]),
            }],
        };
        deliver_canister_http_spent(&second, &mut state, &log);
        // Only node 3 is newly accounted: refund += 1_000 − 700 = 300; consumed += 700.
        assert_eq!(
            balance(&state, caller),
            INITIAL_BALANCE + Cycles::new(1_300)
        );
        assert_eq!(consumed(&state, caller), 1_700);
        assert_eq!(status_after(&state).refunding_nodes.len(), 3);
    }

    /// An initial report is dropped (to avoid double-counting) if any node has
    /// already been accounted through an asynchronous report.
    #[test]
    fn initial_report_dropped_after_asynchronous() {
        let allowance = Cycles::new(1_000);
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            refund_status(allowance * 13_usize, allowance),
        )));
        let log = no_op_logger();

        let async_report = CanisterHttpSpent {
            initial: vec![],
            asynchronous: vec![CanisterHttpAsyncSpent {
                callback: CALLBACK,
                shares: BTreeMap::from([(node_test_id(1), Cycles::new(400))]),
            }],
        };
        deliver_canister_http_spent(&async_report, &mut state, &log);
        let balance_after_async = balance(&state, caller);
        let consumed_after_async = consumed(&state, caller);

        // An initial report now arrives for the same callback; it must be dropped.
        let initial_report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::new(5_000),
                nodes: node_set(&[1, 2, 3, 4, 5]),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&initial_report, &mut state, &log);

        assert_eq!(balance(&state, caller), balance_after_async);
        assert_eq!(consumed(&state, caller), consumed_after_async);
    }

    /// The credited refund is capped so that `refunded_cycles` never exceeds
    /// `refundable_cycles`, even if the reported allowances would sum to more.
    #[test]
    fn refund_is_capped_at_refundable() {
        let allowance = Cycles::new(1_000);
        // Refundable is deliberately smaller than allowance * nodes.
        let refundable = Cycles::new(2_500);
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            refund_status(refundable, allowance),
        )));

        // amount = 0 → uncapped refund would be 13 * 1_000 = 13_000.
        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::zero(),
                nodes: node_set(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&report, &mut state, &no_op_logger());

        assert_eq!(balance(&state, caller), INITIAL_BALANCE + refundable);
        assert_eq!(status_after(&state).refunded_cycles, refundable);
    }

    /// A report for an unknown callback is dropped without crediting anything.
    #[test]
    fn report_for_missing_context_is_dropped() {
        let (mut state, caller) = setup(None);
        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::new(1),
                nodes: node_set(&[1]),
            }],
            asynchronous: vec![CanisterHttpAsyncSpent {
                callback: CALLBACK,
                shares: BTreeMap::from([(node_test_id(2), Cycles::new(1))]),
            }],
        };
        deliver_canister_http_spent(&report, &mut state, &no_op_logger());

        assert_eq!(balance(&state, caller), INITIAL_BALANCE);
        assert_eq!(consumed(&state, caller), 0);
    }

    /// On timeout, the replicas that never responded are refunded their full
    /// per-replica allowance (here: all 13 of a fully-replicated request), and no
    /// consumed cycles are reported for them.
    #[test]
    fn timeout_refunds_full_allowance_of_nonresponders() {
        let allowance = Cycles::new(1_000);
        let refundable = allowance * 13_usize;
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            refund_status(refundable, allowance),
        )));

        let timeout = UNIX_EPOCH + Duration::from_secs(3 * 60); // > 2min timeout.
        refund_timed_out_canister_http_contexts(&mut state, timeout, &no_op_logger());

        // No node responded, so all 13 allowances are returned.
        assert_eq!(balance(&state, caller), INITIAL_BALANCE + refundable);
        assert_eq!(consumed(&state, caller), 0);
        // The context has been removed.
        assert!(
            state
                .metadata
                .subnet_call_context_manager
                .delivered_canister_http_request_contexts
                .is_empty()
        );
    }

    /// Timeout only refunds the replicas that did not already respond: a context
    /// where some replicas refunded through a spend report gets the remaining
    /// per-replica allowances back.
    #[test]
    fn timeout_refunds_only_remaining_nonresponders() {
        let allowance = Cycles::new(1_000);
        let refundable = allowance * 13_usize;
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            refund_status(refundable, allowance),
        )));
        let log = no_op_logger();

        // Three replicas respond (each spending nothing → refund of allowance).
        let report = CanisterHttpSpent {
            initial: vec![],
            asynchronous: vec![CanisterHttpAsyncSpent {
                callback: CALLBACK,
                shares: BTreeMap::from([
                    (node_test_id(1), Cycles::zero()),
                    (node_test_id(2), Cycles::zero()),
                    (node_test_id(3), Cycles::zero()),
                ]),
            }],
        };
        deliver_canister_http_spent(&report, &mut state, &log);
        assert_eq!(
            balance(&state, caller),
            INITIAL_BALANCE + allowance * 3_usize
        );

        let timeout = UNIX_EPOCH + Duration::from_secs(3 * 60);
        refund_timed_out_canister_http_contexts(&mut state, timeout, &log);

        // The remaining 10 replicas' allowances are refunded on timeout, for a
        // total of the full refundable amount.
        assert_eq!(balance(&state, caller), INITIAL_BALANCE + refundable);
    }
}
