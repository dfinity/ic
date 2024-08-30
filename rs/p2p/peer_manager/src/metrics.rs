use ic_metrics::{buckets::exponential_buckets, MetricsRegistry};
use prometheus::{Histogram, IntCounter};

#[derive(Debug, Clone)]
pub struct PeerManagerMetrics {
    pub topology_updates: IntCounter,
    pub topology_watcher_update_duration: Histogram,
    pub topology_update_duration: Histogram,
}

impl PeerManagerMetrics {
    /// The constructor returns a `GossipMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            topology_updates: metrics_registry.int_counter(
                "peer_manager_topology_updates_total",
                "Number of times registry is checked for topology updates.",
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
