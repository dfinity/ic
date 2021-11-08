use crate::types::*;
use ic_metrics::{
    buckets::{add_bucket, decimal_buckets},
    MetricsRegistry,
};
use ic_types::time::{current_time_and_expiry_time, Time};
use prometheus::{HistogramVec, IntCounter, IntCounterVec, IntGauge};
use std::time::Duration;
use tokio::time::Instant;

pub const LABEL_DETAIL: &str = "detail";
pub const LABEL_PROTOCOL: &str = "protocol";
pub const LABEL_REASON: &str = "reason";
pub const LABEL_REQUEST_TYPE: &str = "request_type";
pub const LABEL_STATUS: &str = "status";
pub const LABEL_TYPE: &str = "type";
pub const LABEL_VERSION: &str = "version";

const STATUS_SUCCESS: &str = "success";
const STATUS_ERROR: &str = "error";

pub const REQUESTS_NUM_LABELS: usize = 3;
pub const REQUESTS_LABEL_NAMES: [&str; REQUESTS_NUM_LABELS] =
    [LABEL_TYPE, LABEL_REQUEST_TYPE, LABEL_STATUS];

// Struct holding only Prometheus metric objects. Hence, it is thread-safe iff
// the data members are thread-safe.
pub(crate) struct HttpHandlerMetrics {
    pub(crate) requests: HistogramVec,
    pub(crate) requests_body_size_bytes: HistogramVec,
    pub(crate) protocol_version_total: IntCounterVec,
    pub(crate) connections: IntGauge,
    pub(crate) connections_total: IntCounter,
    connection_setup_duration: HistogramVec,
    forbidden_requests: IntCounterVec,
    unreliable_request_acceptance_duration: HistogramVec,
    pub(crate) api_v1_requests: IntCounterVec,
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
            protocol_version_total: metrics_registry.int_counter_vec(
                "replica_http_requests_protocol_version_total",
                "Count of received requests, by protocol (HTTP/HTTPS) and version.",
                &[LABEL_PROTOCOL, LABEL_VERSION],
            ),
            forbidden_requests: metrics_registry.int_counter_vec(
                "replica_http_forbidden_requests_total",
                "The number of HTTP or HTTPS requests that were rejected with 403 code",
                &[LABEL_TYPE, LABEL_REASON],
            ),
            connections: metrics_registry.int_gauge(
                "replica_http_live_tcp_connections",
                "Number of open tcp connections."
            ),
            connections_total: metrics_registry.int_counter(
                "replica_http_tcp_connections_total",
                "Total number of accepted TCP connections."
            ),
            connection_setup_duration: metrics_registry.histogram_vec(
                "replica_http_connection_setup_duration_seconds",
                "HTTP connection setup durations, by status and detail (protocol on status=\"success\", error type on status=\"error\").",
                decimal_buckets(-3, 1),
                &[LABEL_STATUS, LABEL_DETAIL],
            ),
            unreliable_request_acceptance_duration: metrics_registry.histogram_vec(
                "replica_http_unreliable_request_acceptance_duration_seconds",
                "User request latencies upon parsing the request body, in seconds. The metric
                assumes expiration time is set by 'current_time_and_expiry_time'. In production this
                assumption is incorrect. However, this metric is useful for production test.",
                decimal_buckets(-3, 1),
                &[LABEL_TYPE, LABEL_REQUEST_TYPE],
            ),
            // This is temp counter for NET-738
            api_v1_requests: metrics_registry.int_counter_vec(
                "replica_http_api_v1_requests",
                "Counting the requests hitting legacy endpoints.",
                &[LABEL_TYPE],
            ),
        }
    }

    pub(crate) fn observe_forbidden_request(&self, request_type: &RequestType, reason: &str) {
        self.forbidden_requests
            .with_label_values(&[request_type.as_str(), reason])
            .inc();
    }

    /// Records the duration of a failed connection setup, by error.
    pub(crate) fn observe_connection_error(&self, error: ConnectionError, start_time: Instant) {
        self.connection_setup_duration
            .with_label_values(&[STATUS_ERROR, error.as_str()])
            .observe(start_time.elapsed().as_secs_f64());
    }

    /// Records the duration of a successful connection setup, by app layer
    /// (protocol).
    pub(crate) fn observe_connection_setup(&self, app_layer: AppLayer, start_time: Instant) {
        self.connection_setup_duration
            .with_label_values(&[STATUS_SUCCESS, app_layer.as_str()])
            .observe(start_time.elapsed().as_secs_f64());
    }

    pub(crate) fn observe_unreliable_request_acceptance_duration(
        &self,
        request_type: RequestType,
        api_req_type: ApiReqType,
        msg_expiry_time: Time,
    ) {
        let current_expiry_time = current_time_and_expiry_time().1;
        let expiry_delta = if current_expiry_time <= msg_expiry_time {
            Duration::from_secs(0)
        } else {
            current_expiry_time - msg_expiry_time
        };
        self.unreliable_request_acceptance_duration
            .with_label_values(&[request_type.as_str(), api_req_type.as_str()])
            .observe(expiry_delta.as_secs_f64());
    }
}
