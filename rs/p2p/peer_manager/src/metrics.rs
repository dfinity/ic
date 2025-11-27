use ic_metrics::{MetricsRegistry, buckets::exponential_buckets};
use prometheus::{Histogram, IntCounter, IntCounterVec, IntGauge};

#[derive(Clone, Debug)]
pub(crate) struct PeerManagerMetrics {
    pub(crate) topology_updates: IntCounter,
    pub(crate) earliest_registry_version: IntGauge,
    pub(crate) latest_registry_version: IntGauge,
    pub(crate) topology_watcher_update_duration: Histogram,
    pub(crate) topology_update_duration: Histogram,
    // An alert will be triggered if this is incremented.
    pub(crate) topology_watcher_errors: IntCounterVec,
}

impl PeerManagerMetrics {
    /// The constructor returns a `PeerManagerMetrics` instance.
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            topology_updates: metrics_registry.int_counter(
                "peer_manager_topology_updates_total",
                "Number of times registry is checked for topology updates.",
            ),
            earliest_registry_version: metrics_registry.int_gauge(
                "peer_manager_topology_earliest_registry_version",
                "Registry version of the earliest relevant subnet topology.",
            ),
            latest_registry_version: metrics_registry.int_gauge(
                "peer_manager_topology_latest_registry_version",
                "Registry version of the latest relevant subnet topology.",
            ),
            topology_watcher_update_duration: metrics_registry.histogram(
                "peer_manager_topology_watcher_update_duration_seconds",
                "Duration for updating the shared topology state.",
                // 0.1 ms, 1ms, 10ms, 100ms
                exponential_buckets(0.0001, 10.0, 4),
            ),
            topology_update_duration: metrics_registry.histogram(
                "peer_manager_topology_update_duration_seconds",
                "Duration for fetching new topology from the registry.",
                // 0.1 ms, 1ms, 10ms, 100ms
                exponential_buckets(0.0001, 10.0, 4),
            ),
            topology_watcher_errors: metrics_registry.int_counter_vec(
                "peer_manager_topology_watcher_errors_total",
                "Number of errors encountered while updating the peer list.",
                &["error_label"],
            ),
        }
    }
}
