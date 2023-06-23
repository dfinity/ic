use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use prometheus::{HistogramVec, IntCounter, IntGauge};

// Revisit this if we can make it &str
pub(crate) trait Label {
    fn label(&self) -> String;
}

#[derive(Debug, Clone)]
pub struct StateSyncManagerMetrics {
    pub state_syncs: IntCounter,
    pub ongoing_state_sync_metrics: OngoingStateSyncMetrics,
}

impl StateSyncManagerMetrics {
    /// The constructor returns a `GossipMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            state_syncs: metrics_registry.int_counter(
                "state_sync_manager_started_sync_total",
                "Number of started state syncs.",
            ),
            ongoing_state_sync_metrics: OngoingStateSyncMetrics::new(metrics_registry),
        }
    }
}
#[derive(Debug, Clone)]
pub struct StateSyncManagerHandlerMetrics {
    pub request_duration: HistogramVec,
}

impl StateSyncManagerHandlerMetrics {
    /// The constructor returns a `GossipMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            request_duration: metrics_registry.histogram_vec(
                "state_sync_manager_request_duration",
                "quic request serving duration. Without reading the request.",
                decimal_buckets(-3, 0),
                // 1ms, 2ms, 5ms, 10ms, 20ms, ..., 10s, 20s, 50s
                &["handler"],
            ),
        }
    }
}
#[derive(Debug, Clone)]
pub struct OngoingStateSyncMetrics {
    pub active_downloads: IntGauge,
}

impl OngoingStateSyncMetrics {
    /// The constructor returns a `GossipMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            active_downloads: metrics_registry.int_gauge(
                "state_sync_manager_ongoing_active_downloads",
                "Number of outstanding chunk download requests.",
            ),
        }
    }
}
