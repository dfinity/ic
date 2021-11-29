//! Metrics exported by ic_p8s_service_discovery

use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use prometheus::{HistogramVec, IntCounter, IntGauge};

pub struct Metrics {
    /// Histogram of service discovery operations
    pub ic_service_discovery_duration_seconds: HistogramVec,
    /// Count of updates that have been skipped
    pub ic_service_discovery_skipped_total: IntCounter,
    /// Registry version used to determine the topology
    pub ic_topology_registry_version: IntGauge,
}

impl Metrics {
    pub fn new(r: &MetricsRegistry) -> Self {
        Self {
            ic_service_discovery_duration_seconds: r.histogram_vec(
                "ic_service_discovery_duration_seconds",
                "Histogram of service discovery operations",
                decimal_buckets(-3, 1),
                &["status"],
            ),
            ic_service_discovery_skipped_total: r.int_counter(
                "ic_service_discovery_skipped_total",
                "Count of updates skipped because registry version did not change",
            ),
            ic_topology_registry_version: r.int_gauge(
                "ic_topology_registry_version",
                "Registry version used to determine the topology",
            ),
        }
    }
}
