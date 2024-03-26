use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use prometheus::{HistogramVec, IntCounter, IntCounterVec};

pub const LABEL_DETAIL: &str = "detail";
pub const LABEL_PROTOCOL: &str = "protocol";
/// For requests defined in the interface specification, the request type label is extracted from
/// specified request part the CBOR-encoded request body.
pub const LABEL_REQUEST_TYPE: &str = "request_type";
pub const LABEL_STATUS: &str = "status";
pub const LABEL_HTTP_VERSION: &str = "http_version";
pub const LABEL_HEALTH_STATUS_BEFORE: &str = "before";
pub const LABEL_HEALTH_STATUS_AFTER: &str = "after";

/// Placeholder used when we can't determine the appropriate prometheus label.
pub const LABEL_UNKNOWN: &str = "unknown";

pub const STATUS_SUCCESS: &str = "success";
pub const STATUS_ERROR: &str = "error";

pub const REQUESTS_NUM_LABELS: usize = 2;
pub const REQUESTS_LABEL_NAMES: [&str; REQUESTS_NUM_LABELS] = [LABEL_REQUEST_TYPE, LABEL_STATUS];

// Struct holding only Prometheus metric objects. Hence, it is thread-safe iff
// the data members are thread-safe.
#[derive(Clone)]
pub struct HttpHandlerMetrics {
    pub requests: HistogramVec,
    pub request_http_version_counts: IntCounterVec,
    pub request_body_size_bytes: HistogramVec,
    pub response_body_size_bytes: HistogramVec,
    pub connections_total: IntCounter,
    pub health_status_transitions_total: IntCounterVec,
    pub connection_setup_duration: HistogramVec,
    pub connection_duration: HistogramVec,
}

// There is a mismatch between the labels and the public spec.
// The `type` label corresponds to the `request type` in the public spec.
// The `request_type` label corresponds to the API endpoint.
// Naming conventions:
//   1. If you include the `type` label, prefix your metric name with
// `replica_http`.
impl HttpHandlerMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            requests: metrics_registry.histogram_vec(
                "replica_http_request_duration_seconds",
                "HTTP/HTTPS request latencies in seconds. These do not include connection errors, see `replica_connection_errors` for those.",
                // We need more than what the default offers (max 10.0), so we
                // could better check the acceptance of our scenario tests. In
                // addition, this code uses decimal buckets just like all other
                // places that deal with request durations (for example, xnet
                // traffic). In addition, the buckets are extended by one more
                // value - 15s, needed for the scenario testcases.

                decimal_buckets(-3, 1),
                // 1ms, 2ms, 5ms, 10ms, 20ms, ..., 10s, 20s, 50s
                &REQUESTS_LABEL_NAMES,
            ),
            request_http_version_counts: metrics_registry.int_counter_vec(
                "replica_http_request_http_version_counts",
                "HTTP/HTTPS request counts by HTTP version.",
                &[LABEL_HTTP_VERSION],
            ),
            request_body_size_bytes: metrics_registry.histogram_vec(
                "replica_http_request_body_size_bytes",
                "HTTP/HTTPS request body sizes in bytes.",
                // 10 B - 50 MB
                decimal_buckets(1, 7),
                &REQUESTS_LABEL_NAMES,
            ),
            response_body_size_bytes: metrics_registry.histogram_vec(
                "replica_http_response_body_size_bytes",
                "Response body sizes in bytes.",
                // 10 B - 50 MB
                decimal_buckets(1, 7),
                &[LABEL_REQUEST_TYPE],
            ),
            connections_total: metrics_registry.int_counter(
                "replica_http_tcp_connections_total",
                "Total number of accepted TCP connections."
            ),
            health_status_transitions_total: metrics_registry.int_counter_vec(
                "replica_http_health_status_state_transitions_total",
                "Number of health status state transitions",
                &[LABEL_HEALTH_STATUS_BEFORE,LABEL_HEALTH_STATUS_AFTER]
            ),
            connection_setup_duration: metrics_registry.histogram_vec(
                "replica_http_connection_setup_duration_seconds",
                "HTTP connection setup durations, by status and detail (protocol on status=\"success\", error type on status=\"error\").",
                // 10ms, 20ms, ... 500s
                decimal_buckets(-2, 2),
                &[LABEL_STATUS, LABEL_DETAIL],
            ),
            connection_duration: metrics_registry.histogram_vec(
                "replica_http_connection_duration_seconds",
                "HTTP connection durations, by closing status and protocol (HTTP/HTTPS).",
                // 10ms, 20ms, ... 50000s
                decimal_buckets(-2, 4),
                &[LABEL_STATUS, LABEL_PROTOCOL],
            ),
        }
    }
}
