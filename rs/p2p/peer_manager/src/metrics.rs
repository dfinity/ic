use ic_metrics::{MetricsRegistry, buckets::exponential_buckets};
use prometheus::{Histogram, IntCounter, IntGauge};

#[derive(Clone, Debug)]
pub struct PeerManagerMetrics {
    pub topology_updates: IntCounter,
    pub earliest_registry_version: IntGauge,
    pub latest_registry_version: IntGauge,
    pub topology_watcher_update_duration: Histogram,
    pub topology_update_duration: Histogram,
}

impl PeerManagerMetrics {
    /// The constructor returns a `PeerManagerMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
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
        }
    }
}
