use crate::types::*;
use hyper::StatusCode;
use ic_metrics::{
    buckets::{add_bucket, decimal_buckets},
    MetricsRegistry,
};
use ic_types::time::{current_time_and_expiry_time, Time};
use prometheus::{HistogramVec, IntCounter, IntCounterVec, IntGauge};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

const STATUS_SUCCESS: &str = "success";
const STATUS_ERROR: &str = "error";

// Struct holding only Prometheus metric objects. Hence, it is thread-safe iff
// the data members are thread-safe.
pub(crate) struct HttpHandlerMetrics {
    requests: Arc<HistogramVec>,
    requests_body_size_bytes: Arc<HistogramVec>,
    requests_total: Arc<IntCounterVec>,
    pub(crate) connections: Arc<IntGauge>,
    pub(crate) connections_total: Arc<IntCounter>,
    connection_setup_duration: Arc<HistogramVec>,
    forbidden_requests: Arc<IntCounterVec>,
    internal_errors: Arc<IntCounterVec>,
    unreliable_request_acceptance_duration: Arc<HistogramVec>,
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
            requests: Arc::new(metrics_registry.histogram_vec(
                // This metric will contain durations of HTTPS requests as well. The naming is
                // unfortunate.
                "replica_http_request_duration_seconds",
                "HTTP/HTTPS request latencies in seconds. These do not include connection errors, see `replica_connection_errors` for those.",
                // We need more than what the default offers (max 10.0), so we
                // could better check the acceptance of our scenario tests. In
                // addition, this code uses decimal buckets just like all other
                // places that deal with request durations (for example, xnet
                // traffic). In addition, the buckets are extended by one more
                // value - 15s, needed for the scenario testcases.

                // NOTE: If you ever change this, consult and update scenario
                // tests in prod/tests/scenario_tests These tests assume there
                // MUST be a bucket at 15s, AND one bucket above it, that is not
                // +Inf.
                add_bucket(15.0, decimal_buckets(-3, 1)),
                // 1ms, 2ms, 5ms, 10ms, 20ms, ..., 10s, 15s, 20s, 50s
                &["type", "status", "request_type"],
            )),
            requests_body_size_bytes: Arc::new(metrics_registry.histogram_vec(
                "replica_http_request_body_size_bytes",
                "HTTP/HTTPS request body sizes in bytes.",
                // 10 B - 5 MB
                decimal_buckets(1, 6),
                &["type", "status", "request_type"],
            )),
            requests_total: Arc::new(metrics_registry.int_counter_vec(
                "replica_http_requests_total",
                "Count of received requests, by protocol (HTTP/HTTPS) and version.",
                &["type", "protocol", "version"],
            )),
            forbidden_requests: Arc::new(metrics_registry.int_counter_vec(
                "replica_http_forbidden_requests_total",
                "The number of HTTP or HTTPS requests that were rejected with 403 code",
                &["type", "reason"],
            )),
            internal_errors: Arc::new(metrics_registry.int_counter_vec(
                "replica_http_internal_errors_total",
                "The number of different internal errors. Those are errors that must not happen.",
                &["type", "reason"],
            )),
            connections: Arc::new(metrics_registry.int_gauge(
                "replica_http_live_tcp_connections",
                "Number of open tcp connections."),
            ),
            connections_total: Arc::new(metrics_registry.int_counter(
                "replica_http_tcp_connections_total",
                "Total number of accepted TCP connections.")),
            connection_setup_duration: Arc::new(metrics_registry.histogram_vec(
                "replica_http_connection_setup_duration_seconds",
                "HTTP connection setup durations, by status and detail (protocol on status=\"success\", error type on status=\"error\").",
                decimal_buckets(-3, 1),
                &["status", "detail"],
            )),
            unreliable_request_acceptance_duration: Arc::new(metrics_registry.histogram_vec(
                "replica_http_unreliable_request_acceptance_duration_seconds",
                "User request latencies upon parsing the request body, in seconds. The metric
                assumes expiration time is set by 'current_time_and_expiry_time'. In production this
                assumption is incorrect. However, this metric is useful for production test.",
                decimal_buckets(-3, 1),
                &["type", "request_type"],
            )),
        }
    }

    pub(crate) fn observe_forbidden_request(&self, request_type: &RequestType, reason: &str) {
        self.forbidden_requests
            .with_label_values(&[request_type.as_str(), reason])
            .inc();
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn observe_request(
        &self,
        request_start_time: &Instant,
        request_body_size: usize,
        request_type: &str,
        api_req_type: &ApiReqType,
        status: &StatusCode,
        app_layer: &AppLayer,
        version: &hyper::Version,
    ) {
        self.requests
            .with_label_values(&[request_type, &status.to_string(), api_req_type.as_str()])
            .observe(request_start_time.elapsed().as_secs_f64());
        self.requests_body_size_bytes
            .with_label_values(&[request_type, &status.to_string(), api_req_type.as_str()])
            .observe(request_body_size as f64);
        self.requests_total
            .with_label_values(&[request_type, app_layer.as_str(), &format!("{:?}", version)])
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

    pub(crate) fn observe_internal_error(&self, request_type: &RequestType, error: InternalError) {
        self.internal_errors
            .with_label_values(&[request_type.as_str(), error.as_str()])
            .inc();
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
