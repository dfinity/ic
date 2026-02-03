use ic_metrics::buckets::decimal_buckets;
use prometheus::{Histogram, IntCounterVec, IntGauge};

pub const PROMETHEUS_HTTP_PORT: u16 = 9092;

#[derive(Clone)]
pub struct RegistryReplicatorMetrics {
    pub poll_duration: Histogram,
    pub poll_count: IntCounterVec,
    pub registry_version: IntGauge,
}

impl RegistryReplicatorMetrics {
    pub fn new(metrics_registry: &ic_metrics::MetricsRegistry) -> Self {
        Self {
            poll_duration: metrics_registry.histogram(
                "replicator_poll_duration",
                "The time it took to execute internal_state.poll(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
            ),
            poll_count: metrics_registry.int_counter_vec(
                "replicator_poll_count",
                "The number of times of polling the NNS registry, for ok or error status.",
                &["status"],
            ),
            registry_version: metrics_registry.int_gauge(
                "replicator_registry_version",
                "Latest registry version pulled",
            ),
        }
    }
}
