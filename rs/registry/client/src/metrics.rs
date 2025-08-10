//! Metrics exported by the registry client

use ic_metrics::buckets::decimal_buckets;
use ic_metrics::MetricsRegistry;
use prometheus::{HistogramVec, IntGauge};

pub(crate) struct Metrics {
    /// Most recent registry version fetched by the client
    pub(crate) registry_version: IntGauge,
    pub(crate) api_call_duration: HistogramVec,
}

impl Metrics {
    pub(crate) fn new(r: &MetricsRegistry) -> Self {
        Self {
            api_call_duration: r.histogram_vec(
                "ic_registry_client_api_call_duration_seconds",
                "Duration of a RegistryClient API call in seconds.",
                // 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, …, 10s, 20s, 50s
                decimal_buckets(-3, 1),
                &["op"],
            ),

            registry_version: r.int_gauge(
                "ic_registry_client_registry_version",
                "Most recent registry version fetched by the client",
            ),
        }
    }
}
