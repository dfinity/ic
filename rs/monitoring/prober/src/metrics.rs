//! `ic-prober` process metrics.

use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use prometheus::HistogramVec;

const REQUEST_DURATION: &str = "prober_request_duration_seconds";
const PROBE_DURATION: &str = "prober_probe_duration_seconds";

pub struct ProberMetrics {
    /// Records the time it took to serve an HTTP request, by path and response
    /// status.
    pub request_duration: HistogramVec,

    /// Records the time it took to serve a `/probe` request, by probe name and
    /// response status.
    pub probe_duration: HistogramVec,
}

impl ProberMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            request_duration: metrics_registry.histogram_vec(
                REQUEST_DURATION,
                "The time it took to handle an HTTP request, by path and status.",
                // 1ms - 5s
                decimal_buckets(-3, 0),
                &["path", "status"],
            ),
            probe_duration: metrics_registry.histogram_vec(
                PROBE_DURATION,
                "The time it took to complete a probe, by probe name and status.",
                // 1ms - 5s
                decimal_buckets(-3, 0),
                &["probe", "status"],
            ),
        }
    }
}
