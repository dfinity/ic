use ic_metrics::{MetricsRegistry, buckets::decimal_buckets};
use prometheus::{Histogram, HistogramVec, IntCounter};

#[derive(Clone)]
pub(crate) struct DelegationManagerMetrics {
    pub(crate) fetch_duration: Histogram,
    pub(crate) delegation_size: HistogramVec,
    pub(crate) updates: IntCounter,
    pub(crate) fetch_errors: IntCounter,
    pub(crate) state_comparison_errors: IntCounter,
    pub(crate) held_back_delegations: IntCounter,
    pub(crate) reactive_fetches: IntCounter,
}

impl DelegationManagerMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            updates: metrics_registry.int_counter(
                "nns_delegation_manager_updates_total",
                "How many times has the nns delegation been updated",
            ),
            fetch_duration: metrics_registry.histogram(
                "nns_delegation_manager_fetch_duration_seconds",
                "How long it took to fetch the nns delegation, in seconds",
                // (1ms, 2ms, 5ms, ..., 10s, 20s, 50s)
                decimal_buckets(-3, 1),
            ),
            delegation_size: metrics_registry.histogram_vec(
                "nns_delegation_manager_delegation_size_bytes",
                "How big is the delegation, in bytes",
                // (1, 2, 5, ..., 1MB, 2MB, 5MB)
                decimal_buckets(0, 6),
                &["delegation_format"],
            ),
            fetch_errors: metrics_registry.int_counter(
                "nns_delegation_manager_fetch_errors_total",
                "Number of errors encountered while fetching nns delegations",
            ),
            state_comparison_errors: metrics_registry.int_counter(
                "nns_delegation_manager_state_comparison_errors_total",
                "Number of errors encountered while comparing an nns delegation with the latest certified state",
            ),
            held_back_delegations: metrics_registry.int_counter(
                "nns_delegation_manager_held_back_delegations_total",
                "Number of delegations that were held back due to not matching the latest certified state",
            ),
            reactive_fetches: metrics_registry.int_counter(
                "nns_delegation_manager_reactive_fetches_total",
                "Number of times the delegation manager fetched a delegation reactively due to a mismatch with the latest certified state",
            ),
        }
    }
}
