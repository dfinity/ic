use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use prometheus::{Histogram, IntGauge};

/// Keeps the metrics to be exported by the IngressManager
pub(crate) struct IngressManagerMetrics {
    pub(crate) ingress_handler_time: Histogram,
    pub(crate) ingress_selector_get_payload_time: Histogram,
    pub(crate) ingress_selector_validate_payload_time: Histogram,
    pub(crate) ingress_payload_cache_size: IntGauge,
}

impl IngressManagerMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            ingress_handler_time: metrics_registry.histogram(
                "ingress_handler_execution_time",
                "Ingress Handler execution time in seconds",
                decimal_buckets(-3, 1),
            ),
            ingress_selector_get_payload_time: metrics_registry.histogram(
                "ingress_selector_get_payload_time",
                "Ingress Selector get_payload execution time in seconds",
                decimal_buckets(-3, 1),
            ),
            ingress_selector_validate_payload_time: metrics_registry.histogram(
                "ingress_selector_validate_payload_time",
                "Ingress Selector validate_payload execution time in seconds",
                decimal_buckets(-3, 1),
            ),
            ingress_payload_cache_size: metrics_registry.int_gauge(
                "ingress_payload_cache_size",
                "The number of HashSets in payload builder's ingress payload cache.",
            ),
        }
    }
}
