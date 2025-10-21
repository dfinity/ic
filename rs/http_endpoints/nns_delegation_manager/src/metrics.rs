use ic_metrics::{MetricsRegistry, buckets::decimal_buckets};
use prometheus::{Histogram, HistogramVec, IntCounter};

#[derive(Clone)]
pub(crate) struct DelegationManagerMetrics {
    pub(crate) update_duration: Histogram,
    pub(crate) delegation_size: HistogramVec,
    pub(crate) updates: IntCounter,
    pub(crate) errors: IntCounter,
}

impl DelegationManagerMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            updates: metrics_registry.int_counter(
                "nns_delegation_manager_updates_total",
                "How many times has the nns delegation been updated",
            ),
            update_duration: metrics_registry.histogram(
                "nns_delegation_manager_update_duration_seconds",
                "How long it took to update the nns delegation, in seconds",
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
            errors: metrics_registry.int_counter(
                "nns_delegation_manager_errors_total",
                "Number of errors encountered while fetching nns delegations",
            ),
        }
    }
}
