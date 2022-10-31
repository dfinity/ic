use crate::types::*;
use ic_metrics::{
    buckets::{add_bucket, decimal_buckets},
    MetricsRegistry,
};
use prometheus::{HistogramVec, IntCounter, IntCounterVec};
use tokio::time::Instant;

pub const LABEL_DETAIL: &str = "detail";
pub const LABEL_PROTOCOL: &str = "protocol";
pub const LABEL_REQUEST_TYPE: &str = "request_type";
pub const LABEL_STATUS: &str = "status";
pub const LABEL_TYPE: &str = "type";
pub const LABEL_HEALTH_STATUS_BEFORE: &str = "before";
pub const LABEL_HEALTH_STATUS_AFTER: &str = "after";

const STATUS_SUCCESS: &str = "success";
const STATUS_ERROR: &str = "error";

pub const REQUESTS_NUM_LABELS: usize = 3;
pub const REQUESTS_LABEL_NAMES: [&str; REQUESTS_NUM_LABELS] =
    [LABEL_TYPE, LABEL_REQUEST_TYPE, LABEL_STATUS];

// Struct holding only Prometheus metric objects. Hence, it is thread-safe iff
// the data members are thread-safe.
#[derive(Clone)]
pub(crate) struct HttpHandlerMetrics {
    pub(crate) requests: HistogramVec,
    pub(crate) requests_body_size_bytes: HistogramVec,
    pub(crate) connections_total: IntCounter,
    pub(crate) health_status_transitions_total: IntCounterVec,
    connection_setup_duration: HistogramVec,
    connection_duration: HistogramVec,
}

// There is a mismatch between the labels and the public spec.
// The `type` label corresponds to the `request type` in the public spec.
// The `request_type` label corresponds to the API endpoint.
// Naming conventions:
//   1. If you include the `type` label, prefix your metric name with
// `replica_http`.
impl HttpHandlerMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
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

                // NOTE: If you ever change this, consult and update scenario
                // tests in testnet/tests/scenario_tests These tests assume there
                // MUST be a bucket at 15s, AND one bucket above it, that is not
                // +Inf.
                add_bucket(15.0, decimal_buckets(-3, 1)),
                // 1ms, 2ms, 5ms, 10ms, 20ms, ..., 10s, 15s, 20s, 50s
                &REQUESTS_LABEL_NAMES,
            ),
            requests_body_size_bytes: metrics_registry.histogram_vec(
                "replica_http_request_body_size_bytes",
                "HTTP/HTTPS request body sizes in bytes.",
                // 10 B - 5 MB
                decimal_buckets(1, 6),
                &REQUESTS_LABEL_NAMES,
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
                decimal_buckets(-3, 1),
                &[LABEL_STATUS, LABEL_DETAIL],
            ),
            connection_duration: metrics_registry.histogram_vec(
                "replica_http_connection_duration_seconds",
                "HTTP connection durations, by closing status and protocol (HTTP/HTTPS).",
                decimal_buckets(-3, 3),
                &[LABEL_STATUS, LABEL_PROTOCOL],
            ),
        }
    }

    /// Records the duration of a failed connection setup, by error.
    pub(crate) fn observe_connection_error(&self, error: ConnectionError, start_time: Instant) {
        self.connection_setup_duration
            .with_label_values(&[STATUS_ERROR, error.into()])
            .observe(start_time.elapsed().as_secs_f64());
    }

    /// Records the duration of a successful connection setup, by app layer
    /// (protocol).
    pub(crate) fn observe_successful_connection_setup(
        &self,
        app_layer: AppLayer,
        start_time: Instant,
    ) {
        self.connection_setup_duration
            .with_label_values(&[STATUS_SUCCESS, app_layer.into()])
            .observe(start_time.elapsed().as_secs_f64());
    }

    pub(crate) fn observe_graceful_conn_termination(
        &self,
        app_layer: AppLayer,
        start_time: Instant,
    ) {
        self.connection_duration
            .with_label_values(&[STATUS_SUCCESS, app_layer.into()])
            .observe(start_time.elapsed().as_secs_f64());
    }

    pub(crate) fn observe_abrupt_conn_termination(&self, app_layer: AppLayer, start_time: Instant) {
        self.connection_duration
            .with_label_values(&[STATUS_ERROR, app_layer.into()])
            .observe(start_time.elapsed().as_secs_f64());
    }
}
