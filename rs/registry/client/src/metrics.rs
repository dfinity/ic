//! Metrics exported by the registry client

use ic_metrics::MetricsRegistry;
use prometheus::IntGauge;

pub struct Metrics {
    /// Most recent registry version fetched by the client
    pub ic_registry_client_registry_version: IntGauge,
}

impl Metrics {
    pub fn new(r: &MetricsRegistry) -> Self {
        Self {
            ic_registry_client_registry_version: r.int_gauge(
                "ic_registry_client_registry_version",
                "Most recent registry version fetched by the client",
            ),
        }
    }
}
