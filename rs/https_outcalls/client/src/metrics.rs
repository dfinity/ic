use ic_metrics::{MetricsRegistry, buckets::decimal_buckets};
use prometheus::{Histogram, HistogramVec, IntCounterVec};

// Constants for metric label names
const LABEL_STATUS_CODE: &str = "status_code";
const LABEL_HTTP_METHOD: &str = "http_method";
const LABEL_STATUS: &str = "status";

#[derive(Clone)]
pub struct Metrics {
    /// Execution time of transform function.
    pub transform_execution_duration: Histogram,
    /// Execution time of http request via adapter.
    pub http_request_duration: HistogramVec,
    /// Request results returned to consensus.
    pub request_total: IntCounterVec,
}

impl Metrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            transform_execution_duration: metrics_registry.histogram(
                "canister_http_transform_duration_seconds",
                "Execution time of response transformation.",
                // 10ms, 20ms, 50ms, …, 1s, 2s, 5s
                decimal_buckets(-2, 0),
            ),
            http_request_duration: metrics_registry.histogram_vec(
                "canister_http_external_http_request_duration_seconds",
                "Execution time of remote http call by adapter.",
                // 100ms, 200ms, 500ms, …, 10s, 20s, 50s
                decimal_buckets(-1, 1),
                &[LABEL_STATUS_CODE, LABEL_HTTP_METHOD],
            ),
            request_total: metrics_registry.int_counter_vec(
                "canister_http_requests_total",
                "Canister http request results returned to consensus.",
                &[LABEL_STATUS, LABEL_HTTP_METHOD],
            ),
        }
    }
}
