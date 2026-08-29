use ic_logger::{ReplicaLogger, error};
use ic_metrics::{
    MetricsRegistry,
    buckets::{decimal_buckets_with_zero, linear_buckets},
};
use ic_replicated_state::ReplicatedState;
use ic_types::messages::CallbackId;
use ic_types::{CanisterId, Time, batch::CanisterHttpSpent, canister_http::RefundStatus};
use ic_types_cycles::{
    CanisterCyclesCostSchedule, CompoundCycles, Cycles, CyclesUseCase, HTTPOutcalls, NominalCycles,
};
use prometheus::{HistogramVec, IntCounterVec};
use std::collections::BTreeMap;

const METRIC_ACCOUNTING_ERRORS_TOTAL: &str = "mr_canister_http_accounting_errors_total";
const METRIC_REFUNDED_CYCLES: &str = "mr_canister_http_refunded_cycles";
const METRIC_REFUNDED_FRACTION: &str = "mr_canister_http_refunded_fraction";

/// One billion cycles, the unit the cycle metrics are reported in.
const B_CYCLES: f64 = 1_000_000_000.0;

const LABEL_ERROR: &str = "error";
const LABEL_STATUS: &str = "status";

/// Every replica assigned to the request had reported its spend by the time the
/// context was dropped, so the refund was driven entirely by their reports.
const STATUS_COMPLETE: &str = "complete";
/// Some replicas never reported; their per-replica allowances were refunded in
/// full when the context was dropped.
const STATUS_INCOMPLETE: &str = "incomplete";

const STATUSES: &[&str] = &[STATUS_COMPLETE, STATUS_INCOMPLETE];

/// An initial spend report was received for a callback for which some node(s) had
/// already been accounted (through an early asynchronous, or duplicate initial report).
const ERROR_INITIAL_AFTER_NODE_REPORT: &str = "initial_after_node_report";
/// A node reported its spend more than once for the same callback.
const ERROR_DUPLICATE_NODE_REPORT: &str = "duplicate_node_report";
/// The reported spend exceeded the per-replica allowance(s) it was supposed to be
/// covered by, i.e. the caller ended up paying less than the outcall cost.
const ERROR_SPENT_EXCEEDS_ALLOWANCE: &str = "spent_exceeds_allowance";
/// A refund had to be capped, because it would have exceeded the context's
/// refundable amount.
const ERROR_REFUND_CAPPED: &str = "refund_capped";

const ERRORS: &[&str] = &[
    ERROR_INITIAL_AFTER_NODE_REPORT,
    ERROR_DUPLICATE_NODE_REPORT,
    ERROR_SPENT_EXCEEDS_ALLOWANCE,
    ERROR_REFUND_CAPPED,
];

/// Metrics for the accounting of HTTP outcall spend reports and refunds.
#[derive(Clone)]
pub(crate) struct CanisterHttpSpentMetrics {
    /// Unexpected situations encountered while applying HTTP outcall spend
    /// reports and refunds, by error type. Each observation is paired with an
    /// error log message.
    accounting_errors: IntCounterVec,

    /// How many cycles were refunded in total to the caller of a delivered
    /// `CanisterHttpRequestContext`, labeled by whether every replica assigned to
    /// the request had reported by then.
    refunded_cycles: HistogramVec,

    /// What fraction of a delivered `CanisterHttpRequestContext`'s refundable
    /// cycles was refunded to its caller, labeled by whether every replica
    /// assigned to the request had reported by then. Observed together with
    /// [`Self::refunded_cycles`], except for contexts with nothing to refund.
    refunded_fraction: HistogramVec,
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

        let refunded_cycles = metrics_registry.histogram_vec(
            METRIC_REFUNDED_CYCLES,
            "Cycles refunded in total to the caller of a delivered HTTP outcall context, in B cycles.",
            // Buckets: 0, 1M, 2M, 5M, ..., 10B, 20B, 50B. An outcall that spent its
            // full allowances refunds nothing at all, hence the zero bucket.
            decimal_buckets_with_zero(-3, 1),
            &[LABEL_STATUS],
        );

        let refunded_fraction = metrics_registry.histogram_vec(
            METRIC_REFUNDED_FRACTION,
            "Fraction of the refundable cycles of a delivered HTTP outcall context that was \
             refunded to its caller.",
            // Buckets: 0.0, 0.1, ..., 1.0. The fraction cannot exceed 1, refunds
            // being capped at the refundable cycles.
            linear_buckets(0.0, 0.1, 11),
            &[LABEL_STATUS],
        );

        // Initialize all time series to zero.
        for status in STATUSES {
            refunded_cycles.with_label_values(&[status]);
            refunded_fraction.with_label_values(&[status]);
        }

        Self {
            accounting_errors,
            refunded_cycles,
            refunded_fraction,
        }
    }

    fn observe_accounting_error(&self, error: &str) {
        self.accounting_errors.with_label_values(&[error]).inc();
    }

    /// Observes the final refund of a delivered context that is being dropped:
    /// how many cycles were refunded to its caller, and what fraction of the
    /// refundable cycles that was.
    fn observe_refunds(&self, status: &str, refund_status: &RefundStatus) {
        self.refunded_cycles
            .with_label_values(&[status])
            .observe(refund_status.refunded_cycles.get() as f64 / B_CYCLES);
        if refund_status.refundable_cycles.get() > 0 {
            self.refunded_fraction.with_label_values(&[status]).observe(
                refund_status.refunded_cycles.get() as f64
                    / refund_status.refundable_cycles.get() as f64,
            );
        }
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

/// Applies the HTTP outcall spend reports carried by `spent` to the calling
/// canisters: it refunds each caller the unspent part of its per-replica allowance
/// (`allowance − spent`) and reports the spent cycles as consumed.
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
    state: &mut ReplicatedState,
    spent: &CanisterHttpSpent,
    log: &ReplicaLogger,
    metrics: &CanisterHttpSpentMetrics,
) {
    // First update the contexts' refund status and accumulate the amounts to refund /
    // report per canister; the pooling happens in a second pass, in
    // `apply_accounting()`. This aggregates all reports of a canister into a single
    // pooled refund and metric update.
    let mut accounting: BTreeMap<CanisterId, CanisterAccounting> = BTreeMap::new();
    {
        let contexts = &mut state
            .metadata
            .subnet_call_context_manager
            .delivered_canister_http_request_contexts;

        // Initial spending must be handled before asynchronous spending, in case
        // a payload contains both an initial and an asynchronous report for the same request.
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
            // The reporting nodes are collectively covered by their per-replica
            // allowances.
            let allowance = context.refund_status.per_replica_allowance * report.nodes.len();
            let entry = accounting.entry(context.request.sender).or_default();
            apply_spend(
                report.amount,
                allowance,
                context.cost_schedule,
                &mut context.refund_status,
                entry,
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
        }

        // Asynchronous spending
        for report in &spent.asynchronous {
            let Some(context) = contexts.get_mut(&report.callback) else {
                continue;
            };
            let entry = accounting.entry(context.request.sender).or_default();
            for (node_id, node_spent) in &report.shares {
                if context.refund_status.refunding_nodes.insert(*node_id) {
                    // Each reporting node is covered by its own per-replica allowance.
                    apply_spend(
                        *node_spent,
                        context.refund_status.per_replica_allowance,
                        context.cost_schedule,
                        &mut context.refund_status,
                        entry,
                        report.callback,
                        log,
                        metrics,
                    );
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

    apply_accounting(state, accounting);
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
        // The number of replicas assigned to the request.
        let node_count = context.replication.node_count(context.subnet_size);
        // Unresponsive nodes (those who haven't already refunded via `deliver_canister_http_spent`)
        // are refunded in full here.
        let unresponsive_replicas =
            node_count.saturating_sub(context.refund_status.refunding_nodes.len());
        let refund = context.refund_status.per_replica_allowance * unresponsive_replicas;
        let applied = apply_capped(&mut context.refund_status, refund, callback, log, metrics);
        accounting.entry(context.request.sender).or_default().refund += applied;

        // The context is about to be dropped, so its refund is final: observe it
        // here, after the refund above has been applied, and record whether the
        // replicas' own reports covered all of it.
        let status = if unresponsive_replicas > 0 {
            STATUS_INCOMPLETE
        } else {
            STATUS_COMPLETE
        };
        metrics.observe_refunds(status, &context.refund_status);
    }

    apply_accounting(state, accounting);
}

/// Applies a reported spend of `amount`, covered by `allowance`, against the
/// request's `refund_status` and the calling canister's `accounting`:
///  * the unspent part of the allowance is recorded as refunded and accumulated as a
///    refund for the caller (capped at the request's refundable amount);
///  * the spend is accumulated as consumed by the caller;
///  * a spend exceeding the allowance is observed as an error.
#[allow(clippy::too_many_arguments)]
fn apply_spend(
    amount: Cycles,
    allowance: Cycles,
    cost_schedule: CanisterCyclesCostSchedule,
    refund_status: &mut RefundStatus,
    accounting: &mut CanisterAccounting,
    callback: CallbackId,
    log: &ReplicaLogger,
    metrics: &CanisterHttpSpentMetrics,
) {
    // The `real()` part of the spend is what the caller is actually charged, i.e. zero
    // where HTTP outcalls are free; the `nominal()` part is what the outcall cost,
    // charged or not.
    let spent = CompoundCycles::<HTTPOutcalls>::new(amount, cost_schedule);
    // A spend beyond the allowance is unexpected. The refund below saturates at zero
    // either way, so this only flags that it did.
    if spent.real() > allowance {
        metrics.observe_accounting_error(ERROR_SPENT_EXCEEDS_ALLOWANCE);
        error!(
            log,
            "HTTP outcall spend report for callback {} exceeds the allowance it is covered by: \
             spent {}, allowance {}.",
            callback,
            spent.real(),
            allowance
        );
    }
    // The caller is refunded whatever part of the allowance was not spent.
    let refund = allowance - spent.real();
    accounting.refund += apply_capped(refund_status, refund, callback, log, metrics);
    accounting.consumed += spent.nominal();
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

/// Pools the accumulated per-canister `refund`, for Message Routing to deliver to
/// the corresponding canisters; and reports the accumulated `consumed` cycles in
/// their cost metrics as well as in the subnet's.
///
/// Refunds are pooled rather than credited to the caller's balance directly, because
/// the caller need not be hosted here anymore: an HTTP outcall's refundable cycles
/// are only settled once its spend reports have been applied (or it has timed out),
/// by which time a subnet split may have migrated the caller to another subnet.
/// Message Routing delivers a pooled refund wherever the caller lives (via the
/// loopback stream, if that is still this subnet) and accounts for the cycles as
/// lost if the caller no longer exists at all.
///
/// The `consumed` cycles are reported on the caller only if it is still local. The
/// subnet-wide metrics are updated either way: the spend was consumed by the subnet
/// whether or not the caller is still around.
fn apply_accounting(
    state: &mut ReplicatedState,
    accounting: BTreeMap<CanisterId, CanisterAccounting>,
) {
    let mut subnet_consumed = NominalCycles::zero();
    for (sender, accounting) in accounting {
        subnet_consumed += accounting.consumed;
        state.add_refund(sender, accounting.refund);
        if !accounting.consumed.is_zero()
            && let Some(canister) = state.canister_state_make_mut(&sender)
        {
            canister
                .system_state
                .observe_consumed_cycles_for_https_outcall(accounting.consumed);
        }
    }

    let subnet_metrics = &mut state.metadata.subnet_metrics;
    if !subnet_consumed.is_zero() {
        subnet_metrics.observe_consumed_cycles_http_outcalls(subnet_consumed);
        subnet_metrics
            .observe_consumed_cycles_with_use_case(CyclesUseCase::HTTPOutcalls, subnet_consumed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::no_op_logger;
    use ic_replicated_state::ReplicatedState;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT;
    use ic_test_utilities_metrics::{
        HistogramStats, Labels, MetricVec, fetch_histogram_vec_stats, fetch_int_counter_vec, labels,
    };
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

    /// Cycles that the subnet has already observed as consumed for HTTP outcalls
    /// before the reports under test are delivered.
    ///
    /// The subnet-level metric is cumulative across all canisters, so seeding it
    /// ensures that it is never trivially equal to the caller's own metric (and that
    /// the reports are added to it rather than overwriting it).
    const SUBNET_CONSUMED_BEFORE: u128 = 7_000_000;

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
    /// `CanisterHttpRequestContext` registered under [`CALLBACK`], with the given
    /// replication, a [`CanisterCyclesCostSchedule::Normal`] cost schedule and the
    /// refund status of a request that paid the given refundable cycles (see
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
    /// on a [`SUBNET_SIZE`]-node subnet, but no delivered contexts. The subnet has
    /// already consumed [`SUBNET_CONSUMED_BEFORE`] cycles for HTTP outcalls.
    fn setup_state() -> (ReplicatedState, CanisterId) {
        let caller = canister_test_id(1);
        let canister = CanisterStateBuilder::new()
            .with_canister_id(caller)
            .with_cycles(INITIAL_BALANCE)
            .build();
        let mut state = ReplicatedStateBuilder::new()
            .with_canister(canister)
            .with_node_ids(all_nodes().into_iter().collect())
            .build();

        let consumed_before = CompoundCycles::<HTTPOutcalls>::new(
            Cycles::new(SUBNET_CONSUMED_BEFORE),
            CanisterCyclesCostSchedule::Normal,
        )
        .nominal();
        let subnet_metrics = &mut state.metadata.subnet_metrics;
        subnet_metrics.observe_consumed_cycles_http_outcalls(consumed_before);
        subnet_metrics
            .observe_consumed_cycles_with_use_case(CyclesUseCase::HTTPOutcalls, consumed_before);

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

    /// The cycles pooled to be refunded to `caller`; zero if none.
    fn refunded(state: &ReplicatedState, caller: CanisterId) -> Cycles {
        state
            .refunds()
            .iter()
            .find(|refund| refund.recipient() == caller)
            .map_or_else(Cycles::zero, |refund| refund.amount())
    }

    /// The whole refund pool, by recipient. As opposed to [`refunded()`], this also
    /// pins down which canisters have a pooled refund at all.
    fn pooled_refunds(state: &ReplicatedState) -> BTreeMap<CanisterId, Cycles> {
        state
            .refunds()
            .iter()
            .map(|refund| (refund.recipient(), refund.amount()))
            .collect()
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

    /// The cycles reported as consumed for HTTPS outcalls at the subnet level, in
    /// the dedicated field as well as in the by-use-case gauge and counter maps.
    /// All three must always agree, as they are observed together.
    fn subnet_consumed(state: &ReplicatedState) -> u128 {
        subnet_consumed_for(state, CyclesUseCase::HTTPOutcalls)
    }

    /// The cycles reported at the subnet level as lost because the calling canister
    /// was deleted.
    fn subnet_lost_by_deleted_canisters(state: &ReplicatedState) -> u128 {
        subnet_consumed_for(state, CyclesUseCase::DeletedCanisters)
    }

    /// The cycles reported as consumed for `use_case` at the subnet level, both in
    /// the by-use-case gauge and counter maps (which must agree). For the use cases
    /// that also have a dedicated field, that field must agree, too.
    fn subnet_consumed_for(state: &ReplicatedState, use_case: CyclesUseCase) -> u128 {
        let subnet_metrics = &state.metadata.subnet_metrics;
        let get = |map: &BTreeMap<CyclesUseCase, NominalCycles>| {
            map.get(&use_case)
                .copied()
                .unwrap_or_else(NominalCycles::zero)
        };
        let gauge = get(subnet_metrics.get_consumed_cycles_by_use_case());
        assert_eq!(
            gauge,
            get(subnet_metrics.get_consumed_cycles_by_use_case_as_counters())
        );
        match use_case {
            CyclesUseCase::HTTPOutcalls => {
                assert_eq!(gauge, subnet_metrics.get_consumed_cycles_http_outcalls())
            }
            CyclesUseCase::DeletedCanisters => assert_eq!(
                gauge,
                subnet_metrics.get_consumed_cycles_by_deleted_canisters()
            ),
            _ => {}
        }
        gauge.get()
    }

    fn get_refund_status(state: &ReplicatedState, refundable: Cycles) -> RefundStatus {
        let status = state
            .metadata
            .subnet_call_context_manager
            .delivered_canister_http_request_contexts
            .get(&CALLBACK)
            .unwrap()
            .refund_status
            .clone();
        assert_eq!(refundable, status.refundable_cycles);
        assert!(status.refunded_cycles <= status.refundable_cycles);
        status
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

    /// The count and sum of the observations of `name` labeled with `status`. All
    /// statuses are always present, having been initialized to zero.
    fn stats(metrics_registry: &MetricsRegistry, name: &str, status: &str) -> HistogramStats {
        *fetch_histogram_vec_stats(metrics_registry, name)
            .get(&(labels(&[(LABEL_STATUS, status)]) as Labels))
            .unwrap_or_else(|| panic!("no {name} observations labeled {status}"))
    }

    /// Asserts that the contexts dropped with `status` add up to `contexts` of
    /// them, having had `refunded` cycles refunded in total. `fractions` is the
    /// number of refunded-fraction observations and their sum, which differ from
    /// the above for contexts that had nothing to refund.
    fn assert_refunds(
        metrics_registry: &MetricsRegistry,
        status: &str,
        contexts: u64,
        refunded: Cycles,
        fractions: (u64, f64),
    ) {
        assert_eq!(
            HistogramStats {
                count: contexts,
                sum: refunded.get() as f64 / B_CYCLES
            },
            stats(metrics_registry, METRIC_REFUNDED_CYCLES, status),
            "{status}: unexpected refunded cycles"
        );
        assert_eq!(
            HistogramStats {
                count: fractions.0,
                sum: fractions.1
            },
            stats(metrics_registry, METRIC_REFUNDED_FRACTION, status),
            "{status}: unexpected refunded fraction"
        );
    }

    /// Asserts that no context was dropped with `status`.
    fn assert_no_refunds(metrics_registry: &MetricsRegistry, status: &str) {
        assert_refunds(metrics_registry, status, 0, Cycles::zero(), (0, 0.0));
    }

    /// An initial report on a normal subnet pools the collective refund
    /// (`allowance * nodes − spent`) and reports the spent cycles as consumed.
    #[test]
    fn initial_report_pools_refund_and_reports_consumed() {
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
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        // refund = 13 * 1_000 − 9_500 = 3_500.
        assert_eq!(refunded(&state, caller), Cycles::new(3_500));
        assert_eq!(consumed(&state, caller), spent.get());
        // The spend is also reported at the subnet level, like the base fee.
        assert_eq!(
            subnet_consumed(&state),
            SUBNET_CONSUMED_BEFORE + spent.get()
        );
        let status = get_refund_status(&state, refundable);
        assert_eq!(status.refunded_cycles, Cycles::new(3_500));
        assert_eq!(status.refunding_nodes, all_nodes());
        assert_errors(&[], &metrics_registry);
    }

    /// An asynchronous report on a normal subnet pools `allowance − spent` for
    /// each reporting node and reports the per-node spend as consumed. Only the
    /// reporting nodes are accounted; the rest are refunded on timeout.
    #[test]
    fn asynchronous_report_pools_refund_and_reports_consumed() {
        let allowance = Cycles::new(1_000);
        let refundable = allowance * SUBNET_SIZE; // 13_000
        let (mut state, caller) = setup(Some((Replication::FullyReplicated, refundable)));
        let (metrics_registry, metrics) = metrics();

        let report = CanisterHttpSpent {
            initial: vec![],
            asynchronous: vec![CanisterHttpAsyncSpent {
                callback: CALLBACK,
                shares: BTreeMap::from([
                    (node_test_id(1), Cycles::new(250)),
                    (node_test_id(2), Cycles::new(400)),
                    (node_test_id(3), Cycles::new(900)),
                ]),
            }],
        };
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        // refund = (1_000 − 250) + (1_000 − 400) + (1_000 − 900) = 1_450;
        // consumed = 250 + 400 + 900 = 1_550.
        assert_eq!(refunded(&state, caller), Cycles::new(1_450));
        assert_eq!(consumed(&state, caller), 1_550);
        assert_eq!(subnet_consumed(&state), SUBNET_CONSUMED_BEFORE + 1_550);
        let status = get_refund_status(&state, refundable);
        assert_eq!(status.refunded_cycles, Cycles::new(1_450));
        assert_eq!(status.refunding_nodes, node_set(&[1, 2, 3]));
        assert_errors(&[], &metrics_registry);
    }

    /// A charged-for outcall whose collective spend exceeds the allowance
    /// means the caller paid less than the outcall cost. Nothing is
    /// refunded, and the error is reported.
    #[test]
    fn initial_report_exceeding_allowance_is_reported() {
        let allowance = Cycles::new(1_000);
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            allowance * SUBNET_SIZE,
        )));
        let (metrics_registry, metrics) = metrics();

        // The 3 reporting nodes are covered by 3 * 1_000, but spent more than that.
        let spent = Cycles::new(4_200);
        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: spent,
                nodes: node_set(&[1, 2, 3]),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        assert_eq!(refunded(&state, caller), Cycles::zero());
        assert_eq!(consumed(&state, caller), spent.get());
        assert_eq!(
            get_refund_status(&state, allowance * SUBNET_SIZE).refunded_cycles,
            Cycles::zero()
        );
        assert_errors(&[(ERROR_SPENT_EXCEEDS_ALLOWANCE, 1)], &metrics_registry);
    }

    /// Same as above, per node, for an asynchronous report: only the nodes that
    /// exceeded their own per-replica allowance are reported.
    #[test]
    fn asynchronous_report_exceeding_allowance_is_reported() {
        let allowance = Cycles::new(1_000);
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            allowance * SUBNET_SIZE,
        )));
        let (metrics_registry, metrics) = metrics();

        // Nodes 2 and 3 exceed their per-replica allowance, node 1 does not.
        let report = CanisterHttpSpent {
            initial: vec![],
            asynchronous: vec![CanisterHttpAsyncSpent {
                callback: CALLBACK,
                shares: BTreeMap::from([
                    (node_test_id(1), Cycles::new(400)),
                    (node_test_id(2), Cycles::new(1_100)),
                    (node_test_id(3), Cycles::new(3_000)),
                ]),
            }],
        };
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        // Only node 1's unused allowance is refunded; the other two refund nothing.
        assert_eq!(refunded(&state, caller), Cycles::new(600));
        assert_eq!(consumed(&state, caller), 4_500);
        assert_errors(&[(ERROR_SPENT_EXCEEDS_ALLOWANCE, 2)], &metrics_registry);
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
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        assert_eq!(refunded(&state, caller), Cycles::zero());
        assert_eq!(consumed(&state, caller), spent.get());
        assert_eq!(
            subnet_consumed(&state),
            SUBNET_CONSUMED_BEFORE + spent.get()
        );
        let status = get_refund_status(&state, Cycles::zero());
        assert_eq!(status.refunded_cycles, Cycles::zero());
        assert_eq!(status.refunding_nodes, node_set(&[1, 2, 3]));
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
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        assert_eq!(refunded(&state, caller), Cycles::zero());
        assert_eq!(consumed(&state, caller), 1_000);
        assert_eq!(subnet_consumed(&state), SUBNET_CONSUMED_BEFORE + 1_000);
        let status = get_refund_status(&state, Cycles::zero());
        assert_eq!(status.refunded_cycles, Cycles::zero());
        assert_eq!(status.refunding_nodes, node_set(&[1, 2]));
        assert_errors(&[], &metrics_registry);
    }

    /// On a free subnet there is nothing to refund on timeout either, as the
    /// per-replica allowance of the replicas that never responded is zero.
    #[test]
    fn free_subnet_timeout_refunds_nothing() {
        let (mut state, caller) =
            setup_free_subnet(Some((Replication::FullyReplicated, Cycles::zero())));
        let (metrics_registry, metrics) = metrics();

        let timeout = UNIX_EPOCH + Duration::from_secs(2 * 60); // > 1min timeout.
        refund_timed_out_canister_http_contexts(&mut state, timeout, &no_op_logger(), &metrics);

        assert_eq!(refunded(&state, caller), Cycles::zero());
        assert_eq!(consumed(&state, caller), 0);
        assert_eq!(subnet_consumed(&state), SUBNET_CONSUMED_BEFORE);
        assert!(
            state
                .metadata
                .subnet_call_context_manager
                .delivered_canister_http_request_contexts
                .is_empty()
        );
        assert_errors(&[], &metrics_registry);
    }

    /// Asynchronous reports refund `allowance − spent` per node and report the
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
                    (node_test_id(2), Cycles::new(750)),
                ]),
            }],
        };
        deliver_canister_http_spent(&mut state, &first, &log, &metrics);
        // refund = (1_000 − 400) + (1_000 − 750) = 850; consumed = 1_150.
        assert_eq!(refunded(&state, caller), Cycles::new(850));
        assert_eq!(consumed(&state, caller), 1_150);
        assert_eq!(
            get_refund_status(&state, allowance * 3_usize).refunding_nodes,
            node_set(&[1, 2])
        );
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
        deliver_canister_http_spent(&mut state, &second, &log, &metrics);
        // Only node 3 is newly accounted: refund += 1_000 − 700 = 300; consumed += 700.
        assert_eq!(refunded(&state, caller), Cycles::new(1_150));
        assert_eq!(consumed(&state, caller), 1_850);
        assert_eq!(
            get_refund_status(&state, allowance * 3_usize).refunding_nodes,
            node_set(&[1, 2, 3])
        );
        // Node 1's repeated report was observed as an error.
        assert_errors(&[(ERROR_DUPLICATE_NODE_REPORT, 1)], &metrics_registry);
    }

    /// An initial report is dropped (to avoid refunding a node's allowance twice)
    /// if any node has already been accounted through an asynchronous report.
    #[test]
    fn initial_report_dropped_after_asynchronous() {
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
        deliver_canister_http_spent(&mut state, &async_report, &log, &metrics);
        let refunded_after_async = refunded(&state, caller);
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
        deliver_canister_http_spent(&mut state, &initial_report, &log, &metrics);

        assert_eq!(refunded(&state, caller), refunded_after_async);
        assert_eq!(consumed(&state, caller), consumed_after_async);
        // Only the node accounted by the asynchronous report is recorded.
        assert_eq!(
            get_refund_status(&state, allowance * SUBNET_SIZE).refunding_nodes,
            node_set(&[1])
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
        deliver_canister_http_spent(&mut state, &initial_report, &log, &metrics);
        let refunded_after_initial = refunded(&state, caller);
        let consumed_after_initial = consumed(&state, caller);

        // A late report from node 1, which the initial report already accounted.
        let async_report = CanisterHttpSpent {
            initial: vec![],
            asynchronous: vec![CanisterHttpAsyncSpent {
                callback: CALLBACK,
                shares: BTreeMap::from([(node_test_id(1), Cycles::new(400))]),
            }],
        };
        deliver_canister_http_spent(&mut state, &async_report, &log, &metrics);

        assert_eq!(refunded(&state, caller), refunded_after_initial);
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
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        // refund = (13 * 1_000 − 9_500) + (1_000 − 400) + (1_000 − 600) = 4_500;
        // consumed = 9_500 + 400 + 600 = 10_500.
        assert_eq!(refunded(&state, caller), Cycles::new(4_500));
        assert_eq!(consumed(&state, caller), 10_500);
        assert_eq!(subnet_consumed(&state), SUBNET_CONSUMED_BEFORE + 10_500);
        assert_errors(&[], &metrics_registry);
    }

    /// The refund is capped so that `refunded_cycles` never exceeds
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

        // The uncapped refund would be 13 * 1_000 − 500 = 12_500.
        let spent = Cycles::new(500);
        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: spent,
                nodes: all_nodes(),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        assert_eq!(refunded(&state, caller), refundable);
        // Capping the refund does not affect the reported spend.
        assert_eq!(consumed(&state, caller), spent.get());
        assert_eq!(
            subnet_consumed(&state),
            SUBNET_CONSUMED_BEFORE + spent.get()
        );
        assert_eq!(
            get_refund_status(&state, refundable).refunded_cycles,
            refundable
        );
        assert_errors(&[(ERROR_REFUND_CAPPED, 1)], &metrics_registry);
    }

    /// A report for an unknown callback is dropped without refunding anything.
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
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        assert_eq!(refunded(&state, caller), Cycles::zero());
        assert_eq!(consumed(&state, caller), 0);
        assert_eq!(subnet_consumed(&state), SUBNET_CONSUMED_BEFORE);
        assert_errors(&[], &metrics_registry);
    }

    /// A refund is pooled even for a canister that is not hosted here (whether it
    /// was deleted, or migrated away by a subnet split), because it is Message
    /// Routing that resolves where the recipient lives. It is also Message Routing
    /// that accounts for the cycles as lost, on induction, if the recipient turns
    /// out not to exist anywhere. The spend is reported as consumed as usual, but
    /// only at the subnet level: there is no local canister to report it on.
    #[test]
    fn report_for_missing_canister_is_pooled_for_message_routing() {
        let allowance = Cycles::new(1_000);
        let (mut state, caller) = setup(Some((
            Replication::FullyReplicated,
            allowance * SUBNET_SIZE,
        )));
        let (metrics_registry, metrics) = metrics();

        // The caller is gone by the time its spend report is delivered.
        state.remove_canister(&caller);

        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::new(9_500),
                nodes: all_nodes(),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        assert!(state.canister_state(&caller).is_none());
        // refund = 13 * 1_000 − 9_500 = 3_500, pooled rather than written off here.
        assert_eq!(refunded(&state, caller), Cycles::new(3_500));
        assert_eq!(subnet_consumed(&state), SUBNET_CONSUMED_BEFORE + 9_500);
        assert_eq!(subnet_lost_by_deleted_canisters(&state), 0);
        assert_errors(&[], &metrics_registry);
    }

    /// On a free subnet nothing was charged, so there is nothing to refund to a
    /// canister that is no longer hosted here; the spend is still reported as
    /// consumed.
    #[test]
    fn free_subnet_report_for_missing_canister_loses_nothing() {
        let (mut state, caller) =
            setup_free_subnet(Some((Replication::FullyReplicated, Cycles::zero())));
        let (metrics_registry, metrics) = metrics();

        state.remove_canister(&caller);

        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::new(9_500),
                nodes: all_nodes(),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        assert_eq!(refunded(&state, caller), Cycles::zero());
        assert_eq!(subnet_consumed(&state), SUBNET_CONSUMED_BEFORE + 9_500);
        assert_eq!(subnet_lost_by_deleted_canisters(&state), 0);
        assert_errors(&[], &metrics_registry);
    }

    /// Refunds are pooled for Message Routing to deliver, not credited to the
    /// caller's balance here. This is what lets them reach a caller that a subnet
    /// split has migrated to another subnet: by the time an outcall's refundable
    /// cycles are settled (once its spend reports have been applied, or it has
    /// timed out), the caller need not be hosted here anymore.
    #[test]
    fn refunds_are_pooled_rather_than_credited_directly() {
        let allowance = Cycles::new(1_000);
        let refundable = allowance * SUBNET_SIZE;
        let (mut state, caller) = setup(Some((Replication::FullyReplicated, refundable)));
        let (metrics_registry, metrics) = metrics();

        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::new(9_500),
                nodes: all_nodes(),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        // The balance is untouched...
        assert_eq!(balance(&state, caller), INITIAL_BALANCE);
        // ...the refund is in the pool, addressed to the caller...
        assert_eq!(
            pooled_refunds(&state),
            BTreeMap::from([(caller, Cycles::new(3_500))])
        );
        // ...and the consumed cycles are still reported on the caller itself.
        assert_eq!(consumed(&state, caller), 9_500);
        assert_errors(&[], &metrics_registry);
    }

    /// Refunds are pooled per recipient, so reports for different callers result in
    /// one pool entry each, rather than in a single merged refund.
    #[test]
    fn refunds_are_pooled_per_recipient() {
        const OTHER_CALLBACK: CallbackId = CallbackId::new(43);
        // A second caller, which need not be hosted here for its refund to be
        // pooled (see `report_for_missing_canister_is_pooled_for_message_routing`).
        let other_caller = canister_test_id(2);

        let allowance = Cycles::new(1_000);
        let refundable = allowance * SUBNET_SIZE;
        let (mut state, caller) = setup(Some((Replication::FullyReplicated, refundable)));
        let other_replication = Replication::FullyReplicated;
        let other_refund_status = refund_status(refundable, &other_replication);
        insert_context(
            &mut state,
            OTHER_CALLBACK,
            other_caller,
            other_replication,
            other_refund_status,
            CanisterCyclesCostSchedule::Normal,
        );
        let (metrics_registry, metrics) = metrics();

        let report = CanisterHttpSpent {
            initial: vec![
                CanisterHttpInitialSpent {
                    callback: CALLBACK,
                    amount: Cycles::new(9_500),
                    nodes: all_nodes(),
                },
                CanisterHttpInitialSpent {
                    callback: OTHER_CALLBACK,
                    amount: Cycles::new(12_000),
                    nodes: all_nodes(),
                },
            ],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&mut state, &report, &no_op_logger(), &metrics);

        // One pool entry per caller: 13_000 − 9_500 and 13_000 − 12_000.
        assert_eq!(
            pooled_refunds(&state),
            BTreeMap::from([
                (caller, Cycles::new(3_500)),
                (other_caller, Cycles::new(1_000)),
            ])
        );
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

        let timeout = UNIX_EPOCH + Duration::from_secs(2 * 60); // > 1min timeout.
        refund_timed_out_canister_http_contexts(&mut state, timeout, &no_op_logger(), &metrics);

        // No node responded, so all 13 allowances are returned.
        assert_eq!(refunded(&state, caller), refundable);
        // Pooled, rather than credited to the caller's balance, just like the
        // refunds applied from spend reports.
        assert_eq!(balance(&state, caller), INITIAL_BALANCE);
        assert_eq!(consumed(&state, caller), 0);
        assert_eq!(subnet_consumed(&state), SUBNET_CONSUMED_BEFORE);
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
        deliver_canister_http_spent(&mut state, &report, &log, &metrics);
        assert_eq!(refunded(&state, caller), allowance * 3_usize);

        let timeout = UNIX_EPOCH + Duration::from_secs(3 * 60);
        refund_timed_out_canister_http_contexts(&mut state, timeout, &log, &metrics);

        // The remaining 10 replicas' allowances are refunded on timeout, for a
        // total of the full refundable amount.
        assert_eq!(refunded(&state, caller), refundable);
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
        assert_eq!(refunded(&state, caller), refundable);
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

        assert_eq!(refunded(&state, caller), allowance);
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

        assert_eq!(refunded(&state, caller), Cycles::zero());
        assert_eq!(
            get_refund_status(&state, refundable).refunded_cycles,
            Cycles::zero()
        );

        // Exactly at the timeout, the context is timed out and refunded.
        let at_timeout = UNIX_EPOCH + DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT;
        refund_timed_out_canister_http_contexts(&mut state, at_timeout, &log, &metrics);

        assert_eq!(refunded(&state, caller), refundable);
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
        assert_eq!(refunded(&state, caller), refundable);
        assert_errors(&[(ERROR_REFUND_CAPPED, 1)], &metrics_registry);
    }

    /// A delivered context is observed when it is dropped, with the refund that
    /// its replicas' own reports produced. Until then it is not observed at all,
    /// however much of its refundable cycles has already been refunded.
    #[test]
    fn dropping_a_fully_reported_context_observes_its_refund_as_complete() {
        let allowance = Cycles::new(1_000);
        let refundable = allowance * SUBNET_SIZE; // 13_000
        let (mut state, caller) = setup(Some((Replication::FullyReplicated, refundable)));
        let log = no_op_logger();
        let (metrics_registry, metrics) = metrics();

        // All 13 replicas produced the response, spending 9_500 of their 13_000.
        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::new(9_500),
                nodes: all_nodes(),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&mut state, &report, &log, &metrics);

        // refund = 13_000 − 9_500 = 3_500, but the context is still around, so
        // nothing has been observed yet.
        assert_eq!(refunded(&state, caller), Cycles::new(3_500));
        assert_no_refunds(&metrics_registry, STATUS_COMPLETE);
        assert_no_refunds(&metrics_registry, STATUS_INCOMPLETE);

        // Dropping the context refunds nothing further -- every replica having
        // reported -- and observes the refund as complete.
        let at_timeout = UNIX_EPOCH + DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT;
        refund_timed_out_canister_http_contexts(&mut state, at_timeout, &log, &metrics);

        assert_eq!(refunded(&state, caller), Cycles::new(3_500));
        assert_refunds(
            &metrics_registry,
            STATUS_COMPLETE,
            1,
            Cycles::new(3_500),
            (1, 3_500.0 / 13_000.0),
        );
        assert_no_refunds(&metrics_registry, STATUS_INCOMPLETE);
        assert_errors(&[], &metrics_registry);
    }

    /// A context dropped with replicas that never reported is observed as
    /// incomplete, and its observation includes the allowances refunded for those
    /// replicas: it is observed only once the timeout refund has been applied.
    #[test]
    fn dropping_a_context_with_unresponsive_replicas_observes_its_refund_as_incomplete() {
        let allowance = Cycles::new(1_000);
        let refundable = allowance * SUBNET_SIZE; // 13_000
        let (mut state, caller) = setup(Some((Replication::FullyReplicated, refundable)));
        let log = no_op_logger();
        let (metrics_registry, metrics) = metrics();

        // 10 of the 13 replicas report, spending 5_000 of their collective 10_000.
        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::new(5_000),
                nodes: node_set(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&mut state, &report, &log, &metrics);

        // The remaining 3 never report, so their allowances are refunded in full
        // when the context is dropped.
        let at_timeout = UNIX_EPOCH + DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT;
        refund_timed_out_canister_http_contexts(&mut state, at_timeout, &log, &metrics);

        // refund = 5_000 + 3 * 1_000 = 8_000.
        assert_eq!(refunded(&state, caller), Cycles::new(8_000));
        assert_no_refunds(&metrics_registry, STATUS_COMPLETE);
        assert_refunds(
            &metrics_registry,
            STATUS_INCOMPLETE,
            1,
            Cycles::new(8_000),
            (1, 8_000.0 / 13_000.0),
        );
        assert_errors(&[], &metrics_registry);
    }

    /// A context made on a free subnet has nothing to refund, so it is observed as
    /// having refunded nothing, but contributes no fraction, there being no
    /// refundable cycles to take a fraction of.
    #[test]
    fn dropping_a_free_subnet_context_observes_no_fraction() {
        let (mut state, caller) =
            setup_free_subnet(Some((Replication::FullyReplicated, Cycles::zero())));
        let log = no_op_logger();
        let (metrics_registry, metrics) = metrics();

        let report = CanisterHttpSpent {
            initial: vec![CanisterHttpInitialSpent {
                callback: CALLBACK,
                amount: Cycles::new(9_500),
                nodes: all_nodes(),
            }],
            asynchronous: vec![],
        };
        deliver_canister_http_spent(&mut state, &report, &log, &metrics);
        let at_timeout = UNIX_EPOCH + DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT;
        refund_timed_out_canister_http_contexts(&mut state, at_timeout, &log, &metrics);

        assert_eq!(refunded(&state, caller), Cycles::zero());
        assert_refunds(
            &metrics_registry,
            STATUS_COMPLETE,
            1,
            Cycles::zero(),
            (0, 0.0),
        );
        assert_no_refunds(&metrics_registry, STATUS_INCOMPLETE);
        assert_errors(&[], &metrics_registry);
    }
}
