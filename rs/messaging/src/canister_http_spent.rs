use ic_logger::{ReplicaLogger, error, info};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::messages::CallbackId;
use ic_types::{CanisterId, Time, batch::CanisterHttpSpent, canister_http::RefundStatus};
use ic_types_cycles::{
    CanisterCyclesCostSchedule, CompoundCycles, Cycles, CyclesUseCase, HTTPOutcalls, NominalCycles,
};
use prometheus::IntCounterVec;
use std::collections::BTreeMap;

const METRIC_ACCOUNTING_ERRORS_TOTAL: &str = "mr_canister_http_accounting_errors_total";

const LABEL_ERROR: &str = "error";

/// An initial spend report was received for a callback for which some node(s)
/// had already been accounted (through an asynchronous report).
const ERROR_INITIAL_AFTER_NODE_REPORT: &str = "initial_after_node_report";
/// A node reported its spend more than once for the same callback.
const ERROR_DUPLICATE_NODE_REPORT: &str = "duplicate_node_report";
/// A refund had to be capped, because it would have exceeded the context's
/// refundable amount.
const ERROR_REFUND_CAPPED: &str = "refund_capped";

const ERRORS: &[&str] = &[
    ERROR_INITIAL_AFTER_NODE_REPORT,
    ERROR_DUPLICATE_NODE_REPORT,
    ERROR_REFUND_CAPPED,
];

/// Metrics for the accounting of HTTP outcall spend reports and refunds.
#[derive(Clone)]
pub(crate) struct CanisterHttpSpentMetrics {
    /// Unexpected situations encountered while applying HTTP outcall spend
    /// reports and refunds, by error type. Each observation is paired with an
    /// error log message.
    accounting_errors: IntCounterVec,
}

impl CanisterHttpSpentMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        let accounting_errors = metrics_registry.int_counter_vec(
            METRIC_ACCOUNTING_ERRORS_TOTAL,
            "Count of unexpected situations encountered while accounting for HTTP outcall spend \
             reports and refunds, by error type.",
            &[LABEL_ERROR],
        );
        // Initialize all time series to zero.
        for error in ERRORS {
            accounting_errors.with_label_values(&[error]);
        }
        Self { accounting_errors }
    }

    fn observe_accounting_error(&self, error: &str) {
        self.accounting_errors.with_label_values(&[error]).inc();
    }
}

/// Per-canister amounts accumulated while delivering HTTP outcall spend reports.
#[derive(Default)]
struct CanisterAccounting {
    /// Real cycles to credit back to the caller (its unused per-replica
    /// allowance). Always zero on a free subnet.
    refund: Cycles,
    /// Nominal cycles the caller consumed, to report in its cost metrics. This
    /// is nonzero also on free subnets.
    consumed: NominalCycles,
}

impl CanisterAccounting {
    /// Accumulates `amount` as consumed by the caller, according to the cost
    /// schedule of the context the amount was reported for.
    fn observe_consumed(&mut self, amount: Cycles, cost_schedule: CanisterCyclesCostSchedule) {
        self.consumed += CompoundCycles::<HTTPOutcalls>::new(amount, cost_schedule).nominal();
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
    metrics: &CanisterHttpSpentMetrics,
) {
    // First update the contexts' refund status and accumulate the amounts to
    // credit/report per canister. The crediting happens in a second pass to
    // avoid borrowing both the subnet call context manager and the canister
    // states at once.
    let mut accounting: BTreeMap<CanisterId, CanisterAccounting> = BTreeMap::new();
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
                metrics.observe_accounting_error(ERROR_INITIAL_AFTER_NODE_REPORT);
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
            let applied = apply_capped(
                &mut context.refund_status,
                refund,
                report.callback,
                log,
                metrics,
            );
            // Record the contributing nodes so that a later asynchronous report
            // from any of them is not accounted twice.
            context
                .refund_status
                .refunding_nodes
                .extend(report.nodes.iter());
            let entry = accounting.entry(context.request.sender).or_default();
            entry.refund += applied;
            entry.observe_consumed(report.amount, context.cost_schedule);
        }

        // Asynchronous spending
        for report in &spent.asynchronous {
            let Some(context) = contexts.get_mut(&report.callback) else {
                continue;
            };
            let allowance = context.refund_status.per_replica_allowance;
            let cost_schedule = context.cost_schedule;
            let entry = accounting.entry(context.request.sender).or_default();
            for (node_id, node_spent) in &report.shares {
                if context.refund_status.refunding_nodes.insert(*node_id) {
                    // `Cycles::sub` saturates at zero.
                    let refund = allowance - *node_spent;
                    entry.refund += apply_capped(
                        &mut context.refund_status,
                        refund,
                        report.callback,
                        log,
                        metrics,
                    );
                    entry.observe_consumed(*node_spent, cost_schedule);
                } else {
                    metrics.observe_accounting_error(ERROR_DUPLICATE_NODE_REPORT);
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
        }
    }

    apply_accounting(state, accounting, log);
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
    metrics: &CanisterHttpSpentMetrics,
) {
    let timed_out = state
        .metadata
        .subnet_call_context_manager
        .time_out_delivered_canister_http_request_contexts(current_time);

    let mut accounting: BTreeMap<CanisterId, CanisterAccounting> = BTreeMap::new();
    for (callback, mut context) in timed_out {
        // The number of replicas assigned to the request; the responders already
        // refunded via `deliver_canister_http_spent`, the rest refund in full
        // here.
        let node_count = context.replication.node_count(context.subnet_size);
        let unresponsive_replicas =
            node_count.saturating_sub(context.refund_status.refunding_nodes.len());
        let refund = context.refund_status.per_replica_allowance * unresponsive_replicas;
        let applied = apply_capped(&mut context.refund_status, refund, callback, log, metrics);
        accounting.entry(context.request.sender).or_default().refund += applied;
    }

    apply_accounting(state, accounting, log);
}

/// Records `amount` as refunded against `refund_status`, capped so that
/// `refunded_cycles` never exceeds `refundable_cycles`. Returns the amount that
/// was actually applied (and therefore should be credited to the canister).
///
/// Capping is not expected to happen (the per-replica allowances are sized so
/// that the sum of all refunds stays within `refundable_cycles`), so an error
/// is logged and observed if it does.
fn apply_capped(
    refund_status: &mut RefundStatus,
    amount: Cycles,
    callback: CallbackId,
    log: &ReplicaLogger,
    metrics: &CanisterHttpSpentMetrics,
) -> Cycles {
    let room = refund_status.refundable_cycles - refund_status.refunded_cycles;
    let applied = std::cmp::min(amount, room);
    if applied < amount {
        metrics.observe_accounting_error(ERROR_REFUND_CAPPED);
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
/// balances and reports the accumulated `consumed` cycles in their cost metrics
/// as well as in the subnet's, logging any whose canister no longer exists.
fn apply_accounting(
    state: &mut ReplicatedState,
    accounting: BTreeMap<CanisterId, CanisterAccounting>,
    log: &ReplicaLogger,
) {
    let mut subnet_consumed = NominalCycles::zero();
    for (sender, accounting) in accounting {
        if accounting.refund.is_zero() && accounting.consumed.is_zero() {
            continue;
        }
        match state.canister_state_make_mut(&sender) {
            Some(canister) => {
                canister.system_state.add_cycles(accounting.refund);
                if !accounting.consumed.is_zero() {
                    canister
                        .system_state
                        .observe_consumed_cycles_for_https_outcall(accounting.consumed);
                    subnet_consumed += accounting.consumed;
                }
            }
            None => {
                info!(
                    log,
                    "Canister {} for an HTTP outcall no longer exists; dropping refund of {} \
                     cycles and consumed report of {} cycles.",
                    sender,
                    accounting.refund,
                    accounting.consumed
                )
            }
        }
    }

    if !subnet_consumed.is_zero() {
        state
            .metadata
            .subnet_metrics
            .observe_consumed_cycles_http_outcalls(subnet_consumed);
        state
            .metadata
            .subnet_metrics
            .observe_consumed_cycles_with_use_case(CyclesUseCase::HTTPOutcalls, subnet_consumed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::no_op_logger;
    use ic_replicated_state::ReplicatedState;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT;
    use ic_test_utilities_metrics::{Labels, MetricVec, fetch_int_counter_vec, labels};
    use ic_test_utilities_state::{CanisterStateBuilder, ReplicatedStateBuilder};
    use ic_test_utilities_types::ids::{canister_test_id, node_test_id};
    use ic_test_utilities_types::messages::RequestBuilder;
    use ic_types::batch::{CanisterHttpAsyncSpent, CanisterHttpInitialSpent, CanisterHttpSpent};
    use ic_types::canister_http::{
        CanisterHttpMethod, CanisterHttpRequestContext, PricingVersion, Replication,
    };
    use ic_types::time::UNIX_EPOCH;
    use ic_types::{NodeId, NumberOfNodes, RegistryVersion};
    use std::collections::BTreeSet;
    use std::time::Duration;

    const INITIAL_BALANCE: Cycles = Cycles::new(1_000_000_000_000);
    const CALLBACK: CallbackId = CallbackId::new(42);

    fn node_set(ids: &[u64]) -> BTreeSet<NodeId> {
        ids.iter().copied().map(node_test_id).collect()
    }

    /// Number of nodes on the subnet used in these tests.
    const SUBNET_SIZE: u64 = 13;

    /// All nodes of the subnet, i.e. the replicas assigned to a fully replicated
    /// request.
    fn all_nodes() -> BTreeSet<NodeId> {
        (1..=SUBNET_SIZE).map(node_test_id).collect()
    }

    /// Builds a state holding a single caller canister (`canister_test_id(1)`) on
    /// a [`SUBNET_SIZE`]-node subnet and, if `context` is `Some`, a delivered
    /// `CanisterHttpRequestContext` registered under [`CALLBACK`], with a
    /// [`CanisterCyclesCostSchedule::Normal`] cost schedule and the refund
    /// status of a request that paid the given refundable cycles (see
    /// [`refund_status()`]).
    fn setup(context: Option<(Replication, Cycles)>) -> (ReplicatedState, CanisterId) {
        setup_with_cost_schedule(context, CanisterCyclesCostSchedule::Normal)
    }

    /// Same as [`setup()`], except that the context is that of a request made on
    /// a free subnet.
    fn setup_free_subnet(context: Option<(Replication, Cycles)>) -> (ReplicatedState, CanisterId) {
        setup_with_cost_schedule(context, CanisterCyclesCostSchedule::Free)
    }

    fn setup_with_cost_schedule(
        context: Option<(Replication, Cycles)>,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> (ReplicatedState, CanisterId) {
        let (mut state, caller) = setup_state();
        if let Some((replication, refundable)) = context {
            let refund_status = refund_status(refundable, &replication);
            insert_context(
                &mut state,
                CALLBACK,
                caller,
                replication,
                refund_status,
                cost_schedule,
            );
        }
        (state, caller)
    }

    /// Same as [`setup()`], except that the refund status is provided as-is,
    /// rather than derived from the refundable cycles.
    fn setup_with_refund_status(
        replication: Replication,
        refund_status: RefundStatus,
    ) -> (ReplicatedState, CanisterId) {
        let (mut state, caller) = setup_state();
        insert_context(
            &mut state,
            CALLBACK,
            caller,
            replication,
            refund_status,
            CanisterCyclesCostSchedule::Normal,
        );
        (state, caller)
    }

    /// Builds a state holding a single caller canister (`canister_test_id(1)`)
    /// on a [`SUBNET_SIZE`]-node subnet, but no delivered contexts.
    fn setup_state() -> (ReplicatedState, CanisterId) {
        let caller = canister_test_id(1);
        let canister = CanisterStateBuilder::new()
            .with_canister_id(caller)
            .with_cycles(INITIAL_BALANCE)
            .build();
        let state = ReplicatedStateBuilder::new()
            .with_canister(canister)
            .with_node_ids(all_nodes().into_iter().collect())
            .build();
        (state, caller)
    }

    /// Registers a delivered `CanisterHttpRequestContext` for `sender` under
    /// `callback`.
    fn insert_context(
        state: &mut ReplicatedState,
        callback: CallbackId,
        sender: CanisterId,
        replication: Replication,
        refund_status: RefundStatus,
        cost_schedule: CanisterCyclesCostSchedule,
    ) {
        let context = CanisterHttpRequestContext {
            request: RequestBuilder::default().sender(sender).build(),
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
            cost_schedule,
        };
        state
            .metadata
            .subnet_call_context_manager
            .delivered_canister_http_request_contexts
            .insert(callback, context);
    }

    /// The refund status of a fresh request that paid `refundable` refundable
    /// cycles, with the per-replica allowance derived from the replicas assigned
    /// to the request, exactly as execution does when the request is made.
    fn refund_status(refundable: Cycles, replication: &Replication) -> RefundStatus {
        let node_count = replication.node_count(NumberOfNodes::from(SUBNET_SIZE as u32));
        RefundStatus {
            refundable_cycles: refundable,
            per_replica_allowance: refundable / node_count,
            refunded_cycles: Cycles::zero(),
            refunding_nodes: BTreeSet::new(),
        }
    }

    /// A refund status from its raw components, allowing to
    /// test inconsistent contexts.
    fn raw_refund_status(refundable: Cycles, per_replica_allowance: Cycles) -> RefundStatus {
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

    /// The cycles reported as consumed for HTTPS outcalls at the subnet level,
    /// both in the dedicated field and in the by-use-case map. The two must
    /// always agree, as they are observed together.
    fn subnet_consumed(state: &ReplicatedState) -> u128 {
        let subnet_metrics = &state.metadata.subnet_metrics;
        let http_outcalls = subnet_metrics.get_consumed_cycles_http_outcalls();
        let by_use_case = subnet_metrics
            .get_consumed_cycles_by_use_case()
            .get(&CyclesUseCase::HTTPOutcalls)
            .copied()
            .unwrap_or_else(NominalCycles::zero);
        assert_eq!(http_outcalls, by_use_case);
        http_outcalls.get()
    }

    fn get_refund_status(state: &ReplicatedState) -> RefundStatus {
        state
            .metadata
            .subnet_call_context_manager
            .delivered_canister_http_request_contexts
            .get(&CALLBACK)
            .unwrap()
            .refund_status
            .clone()
    }

    fn metrics() -> (MetricsRegistry, CanisterHttpSpentMetrics) {
        let metrics_registry = MetricsRegistry::new();
        let metrics = CanisterHttpSpentMetrics::new(&metrics_registry);
        (metrics_registry, metrics)
    }

    /// Asserts that exactly the given errors were observed, with the given
    /// counts. Error types missing from `expected` must have a count of zero.
    fn assert_errors(expected: &[(&str, u64)], metrics_registry: &MetricsRegistry) {
        let expected: MetricVec<u64> = ERRORS
            .iter()
            .map(|error| {
                let count = expected
                    .iter()
                    .find_map(|(expected_error, count)| (expected_error == error).then_some(*count))
                    .unwrap_or(0);
                (labels(&[(LABEL_ERROR, error)]) as Labels, count)
            })
            .collect();

        assert_eq!(
            expected,
            fetch_int_counter_vec(metrics_registry, METRIC_ACCOUNTING_ERRORS_TOTAL)
        );
    }

    /// An initial report on a normal subnet credits the collective refund
    /// (`allowance * nodes − spent`) and reports the spent cycles as consumed.
    #[test]
    fn initial_report_credits_refund_and_reports_consumed() {
        let allowance = Cycles::new(1_000);
        let spent = Cycles::new(9_500);
        let refundable = allowance * SUBNET_SIZE; // 13_000
        let (mut state, caller) = setup(Some((Replication::FullyReplicated, refundable)));
        let (metrics_registry, metrics) = metrics();

        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: spent,
                nodes: all_nodes(),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&report, &mut state, &no_op_logger(), &metrics);

        // refund = 13 * 1_000 − 9_500 = 3_500.
        assert_eq!(
            balance(&state, caller),
            INITIAL_BALANCE + Cycles::new(3_500)
        );
        assert_eq!(consumed(&state, caller), spent.get());
        // The spend is also reported at the subnet level, like the base fee.
        assert_eq!(subnet_consumed(&state), spent.get());
        let status = get_refund_status(&state);
        assert_eq!(status.refunded_cycles, Cycles::new(3_500));
        assert_eq!(status.refunding_nodes.len(), 13);
        assert_errors(&[], &metrics_registry);
    }

    /// On a free subnet the per-replica allowance is zero, so nothing is
    /// refunded, but the spent cycles are still reported as consumed. This is the
    /// whole reason spend (rather than refund) is delivered.
    #[test]
    fn free_subnet_initial_report_reports_consumed_without_refund() {
        let spent = Cycles::new(9_500);
        let (mut state, caller) =
            setup_free_subnet(Some((Replication::FullyReplicated, Cycles::zero())));
        let (metrics_registry, metrics) = metrics();

        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: spent,
                nodes: node_set(&[1, 2, 3]),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&report, &mut state, &no_op_logger(), &metrics);

        assert_eq!(balance(&state, caller), INITIAL_BALANCE);
        assert_eq!(consumed(&state, caller), spent.get());
        assert_eq!(subnet_consumed(&state), spent.get());
        assert_eq!(get_refund_status(&state).refunded_cycles, Cycles::zero());
        assert_errors(&[], &metrics_registry);
    }

    /// Same as above, for asynchronous reports: the per-node spend is reported
    /// as consumed, while the (zero) per-replica allowance refunds nothing.
    #[test]
    fn free_subnet_asynchronous_report_reports_consumed_without_refund() {
        let (mut state, caller) =
            setup_free_subnet(Some((Replication::FullyReplicated, Cycles::zero())));
        let (metrics_registry, metrics) = metrics();

        let report = CanisterHttpSpent {
            initial: vec![],
            asynchronous: vec![CanisterHttpAsyncSpent {
                callback: CALLBACK,
                shares: BTreeMap::from([
                    (node_test_id(1), Cycles::new(400)),
                    (node_test_id(2), Cycles::new(600)),
                ]),
            }],
        };
        deliver_canister_http_spent(&report, &mut state, &no_op_logger(), &metrics);

        assert_eq!(balance(&state, caller), INITIAL_BALANCE);
        assert_eq!(consumed(&state, caller), 1_000);
        assert_eq!(subnet_consumed(&state), 1_000);
        assert_eq!(get_refund_status(&state).refunded_cycles, Cycles::zero());
        assert_errors(&[], &metrics_registry);
    }

    /// On a free subnet there is nothing to refund on timeout either, as the
    /// per-replica allowance of the replicas that never responded is zero.
    #[test]
    fn free_subnet_timeout_refunds_nothing() {
        let (mut state, caller) =
            setup_free_subnet(Some((Replication::FullyReplicated, Cycles::zero())));
        let (metrics_registry, metrics) = metrics();

        let timeout = UNIX_EPOCH + Duration::from_secs(3 * 60); // > 2min timeout.
        refund_timed_out_canister_http_contexts(&mut state, timeout, &no_op_logger(), &metrics);

        assert_eq!(balance(&state, caller), INITIAL_BALANCE);
        assert_eq!(consumed(&state, caller), 0);
        assert!(
            state
                .metadata
                .subnet_call_context_manager
                .delivered_canister_http_request_contexts
                .is_empty()
        );
        assert_errors(&[], &metrics_registry);
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
            allowance * 3_usize,
        )));
        let log = no_op_logger();
        let (metrics_registry, metrics) = metrics();

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
        deliver_canister_http_spent(&first, &mut state, &log, &metrics);
        // refund = (1_000 − 400) + (1_000 − 600) = 1_000; consumed = 1_000.
        assert_eq!(
            balance(&state, caller),
            INITIAL_BALANCE + Cycles::new(1_000)
        );
        assert_eq!(consumed(&state, caller), 1_000);
        assert_errors(&[], &metrics_registry);

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
        deliver_canister_http_spent(&second, &mut state, &log, &metrics);
        // Only node 3 is newly accounted: refund += 1_000 − 700 = 300; consumed += 700.
        assert_eq!(
            balance(&state, caller),
            INITIAL_BALANCE + Cycles::new(1_300)
        );
        assert_eq!(consumed(&state, caller), 1_700);
        assert_eq!(get_refund_status(&state).refunding_nodes.len(), 3);
        // Node 1's repeated report was observed as an error.
        assert_errors(&[(ERROR_DUPLICATE_NODE_REPORT, 1)], &metrics_registry);
    }

    /// An initial report does not refund anything (to avoid refunding a node's
    /// allowance twice) if any node has already been accounted through an
    /// asynchronous report. Its nodes are still recorded as accounted, so that the
    /// timeout does not refund their allowance either; and its spend is still
    /// reported as consumed.
    #[test]
    fn initial_report_after_asynchronous_reports_consumed_without_refund() {
        let allowance = Cycles::new(1_000);
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            allowance * SUBNET_SIZE,
        )));
        let log = no_op_logger();
        let (metrics_registry, metrics) = metrics();

        let async_report = CanisterHttpSpent {
            initial: vec![],
            asynchronous: vec![CanisterHttpAsyncSpent {
                callback: CALLBACK,
                shares: BTreeMap::from([(node_test_id(1), Cycles::new(400))]),
            }],
        };
        deliver_canister_http_spent(&async_report, &mut state, &log, &metrics);
        let balance_after_async = balance(&state, caller);
        let consumed_after_async = consumed(&state, caller);

        // An initial report now arrives for the same callback; it must not refund.
        let initial_report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::new(5_000),
                nodes: node_set(&[1, 2, 3, 4, 5]),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&initial_report, &mut state, &log, &metrics);

        assert_eq!(balance(&state, caller), balance_after_async);
        assert_eq!(consumed(&state, caller), consumed_after_async + 5_000);
        // All 5 reported nodes plus node 1 (already accounted) are now accounted.
        assert_eq!(get_refund_status(&state).refunding_nodes.len(), 5);
        assert_errors(&[(ERROR_INITIAL_AFTER_NODE_REPORT, 1)], &metrics_registry);

        // The timeout therefore only refunds the remaining 8 replicas, rather than
        // handing out the allowance of nodes 1 to 5 a second time.
        let timeout = UNIX_EPOCH + Duration::from_secs(3 * 60);
        refund_timed_out_canister_http_contexts(&mut state, timeout, &log, &metrics);
        assert_eq!(
            balance(&state, caller),
            balance_after_async + allowance * 8_usize
        );
        assert_errors(&[(ERROR_INITIAL_AFTER_NODE_REPORT, 1)], &metrics_registry);
    }

    /// Conversely, a late asynchronous report from a node that was part of the
    /// preceding initial report is ignored, as that node was already accounted.
    #[test]
    fn asynchronous_report_after_initial_is_ignored() {
        let allowance = Cycles::new(1_000);
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            allowance * SUBNET_SIZE,
        )));
        let log = no_op_logger();
        let (metrics_registry, metrics) = metrics();

        let initial_report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::new(9_500),
                nodes: all_nodes(),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&initial_report, &mut state, &log, &metrics);
        let balance_after_initial = balance(&state, caller);
        let consumed_after_initial = consumed(&state, caller);

        // A late report from node 1, which the initial report already accounted.
        let async_report = CanisterHttpSpent {
            initial: vec![],
            asynchronous: vec![CanisterHttpAsyncSpent {
                callback: CALLBACK,
                shares: BTreeMap::from([(node_test_id(1), Cycles::new(400))]),
            }],
        };
        deliver_canister_http_spent(&async_report, &mut state, &log, &metrics);

        assert_eq!(balance(&state, caller), balance_after_initial);
        assert_eq!(consumed(&state, caller), consumed_after_initial);
        assert_errors(&[(ERROR_DUPLICATE_NODE_REPORT, 1)], &metrics_registry);
    }

    /// Reports for different callbacks of the same canister are accumulated and
    /// applied to it as a whole.
    #[test]
    fn reports_are_aggregated_per_canister() {
        const OTHER_CALLBACK: CallbackId = CallbackId::new(43);

        let allowance = Cycles::new(1_000);
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            allowance * SUBNET_SIZE,
        )));
        // A second request by the same canister, made to a 3-node committee.
        let other_replication = Replication::Flexible {
            committee: node_set(&[1, 2, 3]),
            min_responses: 1,
            max_responses: 3,
        };
        let other_refund_status = refund_status(allowance * 3_usize, &other_replication);
        insert_context(
            &mut state,
            OTHER_CALLBACK,
            caller,
            other_replication,
            other_refund_status,
            CanisterCyclesCostSchedule::Normal,
        );
        let (metrics_registry, metrics) = metrics();

        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::new(9_500),
                nodes: all_nodes(),
            }],
            asynchronous: vec![CanisterHttpAsyncSpent {
                callback: OTHER_CALLBACK,
                shares: BTreeMap::from([
                    (node_test_id(1), Cycles::new(400)),
                    (node_test_id(2), Cycles::new(600)),
                ]),
            }],
        };
        deliver_canister_http_spent(&report, &mut state, &no_op_logger(), &metrics);

        // refund = (13 * 1_000 − 9_500) + (1_000 − 400) + (1_000 − 600) = 4_500;
        // consumed = 9_500 + 400 + 600 = 10_500.
        assert_eq!(
            balance(&state, caller),
            INITIAL_BALANCE + Cycles::new(4_500)
        );
        assert_eq!(consumed(&state, caller), 10_500);
        assert_eq!(subnet_consumed(&state), 10_500);
        assert_errors(&[], &metrics_registry);
    }

    /// The credited refund is capped so that `refunded_cycles` never exceeds
    /// `refundable_cycles`, even if the reported allowances would sum to more.
    #[test]
    fn refund_is_capped_at_refundable() {
        let allowance = Cycles::new(1_000);
        // Refundable is deliberately smaller than allowance * nodes.
        let refundable = Cycles::new(2_500);
        let (mut state, caller) = setup_with_refund_status(
            Replication::FullyReplicated,
            raw_refund_status(refundable, allowance),
        );
        let (metrics_registry, metrics) = metrics();

        // amount = 0 → uncapped refund would be 13 * 1_000 = 13_000.
        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::zero(),
                nodes: all_nodes(),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&report, &mut state, &no_op_logger(), &metrics);

        assert_eq!(balance(&state, caller), INITIAL_BALANCE + refundable);
        assert_eq!(get_refund_status(&state).refunded_cycles, refundable);
        assert_errors(&[(ERROR_REFUND_CAPPED, 1)], &metrics_registry);
    }

    /// A report for an unknown callback is dropped without crediting anything.
    /// This is not an error: contexts of requests that were priced with
    /// [`PricingVersion::Legacy`] are not retained after they were responded to,
    /// but their responses still carry a spend report.
    #[test]
    fn report_for_missing_context_is_dropped() {
        let (mut state, caller) = setup(None);
        let (metrics_registry, metrics) = metrics();

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
        deliver_canister_http_spent(&report, &mut state, &no_op_logger(), &metrics);

        assert_eq!(balance(&state, caller), INITIAL_BALANCE);
        assert_eq!(consumed(&state, caller), 0);
        assert_eq!(subnet_consumed(&state), 0);
        assert_errors(&[], &metrics_registry);
    }

    /// A refund for a canister that no longer exists is dropped.
    #[test]
    fn report_for_missing_canister_is_dropped() {
        let allowance = Cycles::new(1_000);
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            allowance * SUBNET_SIZE,
        )));
        let (metrics_registry, metrics) = metrics();

        // The caller is deleted before its spend report is delivered.
        state.remove_canister(&caller);

        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::new(9_500),
                nodes: all_nodes(),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&report, &mut state, &no_op_logger(), &metrics);

        assert!(state.canister_state(&caller).is_none());
        // Nothing is reported at the subnet level either, as the cycles were never
        // credited back to (nor consumed by) an existing canister.
        assert_eq!(subnet_consumed(&state), 0);
        assert_errors(&[], &metrics_registry);
    }

    /// On timeout, the replicas that never responded are refunded their full
    /// per-replica allowance (here: all 13 of a fully-replicated request), and no
    /// consumed cycles are reported for them.
    #[test]
    fn timeout_refunds_full_allowance_of_nonresponders() {
        let allowance = Cycles::new(1_000);
        let refundable = allowance * SUBNET_SIZE;
        let (mut state, caller) = setup(Some((Replication::FullyReplicated, refundable)));

        let (metrics_registry, metrics) = metrics();

        let timeout = UNIX_EPOCH + Duration::from_secs(3 * 60); // > 2min timeout.
        refund_timed_out_canister_http_contexts(&mut state, timeout, &no_op_logger(), &metrics);

        // No node responded, so all 13 allowances are returned.
        assert_eq!(balance(&state, caller), INITIAL_BALANCE + refundable);
        assert_eq!(consumed(&state, caller), 0);
        assert_eq!(subnet_consumed(&state), 0);
        // The context has been removed.
        assert!(
            state
                .metadata
                .subnet_call_context_manager
                .delivered_canister_http_request_contexts
                .is_empty()
        );
        assert_errors(&[], &metrics_registry);
    }

    /// Timeout only refunds the replicas that did not already respond: a context
    /// where some replicas refunded through a spend report gets the remaining
    /// per-replica allowances back.
    #[test]
    fn timeout_refunds_only_remaining_nonresponders() {
        let allowance = Cycles::new(1_000);
        let refundable = allowance * SUBNET_SIZE;
        let (mut state, caller) = setup(Some((Replication::FullyReplicated, refundable)));
        let log = no_op_logger();
        let (metrics_registry, metrics) = metrics();

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
        deliver_canister_http_spent(&report, &mut state, &log, &metrics);
        assert_eq!(
            balance(&state, caller),
            INITIAL_BALANCE + allowance * 3_usize
        );

        let timeout = UNIX_EPOCH + Duration::from_secs(3 * 60);
        refund_timed_out_canister_http_contexts(&mut state, timeout, &log, &metrics);

        // The remaining 10 replicas' allowances are refunded on timeout, for a
        // total of the full refundable amount.
        assert_eq!(balance(&state, caller), INITIAL_BALANCE + refundable);
        assert_errors(&[], &metrics_registry);
    }

    /// A flexible request was only assigned to its committee, so only the
    /// committee's per-replica allowances (not the whole subnet's) are refunded
    /// on timeout.
    #[test]
    fn timeout_refunds_committee_allowances_of_flexible_request() {
        let allowance = Cycles::new(1_000);
        let refundable = allowance * 3_usize;
        let (mut state, caller) = setup(Some((
            Replication::Flexible {
                committee: node_set(&[1, 2, 3]),
                min_responses: 1,
                max_responses: 3,
            },
            refundable,
        )));
        let (metrics_registry, metrics) = metrics();

        let timeout = UNIX_EPOCH + Duration::from_secs(3 * 60);
        refund_timed_out_canister_http_contexts(&mut state, timeout, &no_op_logger(), &metrics);

        // The 3 committee members' allowances, not the 13 nodes of the subnet.
        assert_eq!(balance(&state, caller), INITIAL_BALANCE + refundable);
        assert_errors(&[], &metrics_registry);
    }

    /// A non-replicated request was assigned to a single replica, so a single
    /// per-replica allowance is refunded on timeout.
    #[test]
    fn timeout_refunds_single_allowance_of_non_replicated_request() {
        let allowance = Cycles::new(1_000);
        let (mut state, caller) = setup(Some((
            Replication::NonReplicated(node_test_id(1)),
            allowance,
        )));
        let (metrics_registry, metrics) = metrics();

        let timeout = UNIX_EPOCH + Duration::from_secs(3 * 60);
        refund_timed_out_canister_http_contexts(&mut state, timeout, &no_op_logger(), &metrics);

        assert_eq!(balance(&state, caller), INITIAL_BALANCE + allowance);
        assert_errors(&[], &metrics_registry);
    }

    /// A context that has not been around for long enough is retained (so that
    /// late reports can still be applied) and nothing is refunded for it. It is
    /// refunded as soon as the timeout has elapsed exactly.
    #[test]
    fn timeout_retains_contexts_that_have_not_expired() {
        let allowance = Cycles::new(1_000);
        let refundable = allowance * SUBNET_SIZE;
        let (mut state, caller) = setup(Some((Replication::FullyReplicated, refundable)));
        let log = no_op_logger();
        let (metrics_registry, metrics) = metrics();

        // One nanosecond short of the timeout.
        let before_timeout = UNIX_EPOCH
            + (DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT - Duration::from_nanos(1));
        refund_timed_out_canister_http_contexts(&mut state, before_timeout, &log, &metrics);

        assert_eq!(balance(&state, caller), INITIAL_BALANCE);
        assert_eq!(get_refund_status(&state).refunded_cycles, Cycles::zero());

        // Exactly at the timeout, the context is timed out and refunded.
        let at_timeout = UNIX_EPOCH + DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT;
        refund_timed_out_canister_http_contexts(&mut state, at_timeout, &log, &metrics);

        assert_eq!(balance(&state, caller), INITIAL_BALANCE + refundable);
        assert!(
            state
                .metadata
                .subnet_call_context_manager
                .delivered_canister_http_request_contexts
                .is_empty()
        );
        assert_errors(&[], &metrics_registry);
    }

    /// The refund on timeout is capped at the context's refundable amount, just
    /// like the refunds applied from spend reports.
    #[test]
    fn timeout_refund_is_capped_at_refundable() {
        let allowance = Cycles::new(1_000);
        // Refundable is deliberately smaller than allowance * subnet size.
        let refundable = Cycles::new(2_500);
        let (mut state, caller) = setup_with_refund_status(
            Replication::FullyReplicated,
            raw_refund_status(refundable, allowance),
        );
        let (metrics_registry, metrics) = metrics();

        let timeout = UNIX_EPOCH + Duration::from_secs(3 * 60);
        refund_timed_out_canister_http_contexts(&mut state, timeout, &no_op_logger(), &metrics);

        // Uncapped, the 13 non-responders would have been refunded 13_000.
        assert_eq!(balance(&state, caller), INITIAL_BALANCE + refundable);
        assert_errors(&[(ERROR_REFUND_CAPPED, 1)], &metrics_registry);
    }
}
