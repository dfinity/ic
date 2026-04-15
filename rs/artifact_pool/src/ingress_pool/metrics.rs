use ic_metrics::MetricsRegistry;
use prometheus::{IntCounter, IntCounterVec};

/// Some ingress pool specific metrics.
pub(super) struct IngressPoolMetrics {
    pub ingress_messages_throttled: IntCounter,
    pub ingress_messages_expired: IntCounterVec,
}

impl IngressPoolMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            ingress_messages_throttled: metrics_registry.int_counter(
                "ingress_messages_throttled",
                "Number of throttled ingress messages",
            ),
            ingress_messages_expired: metrics_registry.int_counter_vec(
                "ingress_pool_messages_expired_total",
                "Total number of ingress messages which expired in the ingress pool",
                &["pool_type"],
            ),
        }
    }
}
