use ic_metrics::{
    MetricsRegistry,
    buckets::{add_bucket, decimal_buckets, linear_buckets},
};
use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge};

pub const LABEL_DETAIL: &str = "detail";
pub const LABEL_PROTOCOL: &str = "protocol";
/// For requests defined in the interface specification, the request type label is extracted from
/// specified request part the CBOR-encoded request body.
pub const LABEL_REQUEST_TYPE: &str = "request_type";
pub const LABEL_HTTP_STATUS_CODE: &str = "status";
pub const LABEL_HTTP_VERSION: &str = "http_version";
pub const LABEL_HEALTH_STATUS_BEFORE: &str = "before";
pub const LABEL_HEALTH_STATUS_AFTER: &str = "after";

// Sync Call labels
// !!! Be careful to update alert queries in k8s repo if changing these constants.!!!
const LABEL_SYNC_CALL_CERTIFICATE_STATUS: &str = "status";
const LABEL_SYNC_CALL_EARLY_RESPONSE_TRIGGER: &str = "trigger";
pub const SYNC_CALL_EARLY_RESPONSE_INGRESS_WATCHER_NOT_RUNNING: &str =
    "ingress_watcher_not_running";
pub const SYNC_CALL_EARLY_RESPONSE_DUPLICATE_SUBSCRIPTION: &str = "duplicate_subscription";
pub const SYNC_CALL_EARLY_RESPONSE_SUBSCRIPTION_TIMEOUT: &str = "subscription_timeout";
pub const SYNC_CALL_EARLY_RESPONSE_CERTIFICATION_TIMEOUT: &str = "certification_timeout";
pub const SYNC_CALL_EARLY_RESPONSE_MESSAGE_ALREADY_IN_CERTIFIED_STATE: &str =
    "message_already_in_certified_state";
pub const SYNC_CALL_STATUS_IS_NOT_LEAF: &str = "not_leaf";
pub const SYNC_CALL_STATUS_IS_INVALID_UTF8: &str = "is_invalid_utf8";

/// Placeholder used when we can't determine the appropriate prometheus label.
pub const LABEL_UNKNOWN: &str = "unknown";

pub const STATUS_SUCCESS: &str = "success";
pub const STATUS_ERROR: &str = "error";

pub const LABEL_SECURE: &str = "secure";
pub const LABEL_INSECURE: &str = "insecure";
pub const LABEL_IO_ERROR: &str = "io";
pub const LABEL_TLS_ERROR: &str = "tls_handshake_failed";
pub const LABEL_TIMEOUT_ERROR: &str = "timeout";

pub const REQUESTS_NUM_LABELS: usize = 2;
pub const REQUESTS_LABEL_NAMES: [&str; REQUESTS_NUM_LABELS] =
    [LABEL_REQUEST_TYPE, LABEL_HTTP_STATUS_CODE];

// Struct holding only Prometheus metric objects. Hence, it is thread-safe iff
// the data members are thread-safe.
#[derive(Clone)]
pub struct HttpHandlerMetrics {
    pub requests: HistogramVec,
    pub request_http_version_counts: IntCounterVec,
    pub request_body_size_bytes: HistogramVec,
    pub response_body_size_bytes: HistogramVec,
    pub connections_total: IntCounter,
    pub closed_connections_total: IntCounter,
    pub health_status_transitions_total: IntCounterVec,
    pub connection_setup_duration: HistogramVec,
    pub connection_duration: HistogramVec,

    // Ingress watcher metrics
    pub ingress_watcher_tracked_messages: IntGauge,
    pub ingress_watcher_heights_waiting_for_certification: IntGauge,
    pub ingress_watcher_subscriptions_total: IntCounter,
    pub ingress_watcher_cancelled_subscriptions_total: IntCounter,
    pub ingress_watcher_duplicate_requests_total: IntCounter,
    pub ingress_watcher_subscription_latency_duration_seconds: Histogram,
    pub ingress_watcher_wait_for_certification_duration_seconds: Histogram,
    pub ingress_watcher_messages_completed_execution_channel_capacity: IntGauge,

    // sync call handler metrics
    pub sync_call_early_response_trigger_total: IntCounterVec,
    pub sync_call_certificate_status_total: IntCounterVec,
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
            closed_connections_total: metrics_registry.int_counter(
                "replica_http_tcp_closed_connections_total",
                "Total number closed connections."
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
                &[LABEL_HTTP_STATUS_CODE, LABEL_DETAIL],
            ),
            connection_duration: metrics_registry.histogram_vec(
                "replica_http_connection_duration_seconds",
                "HTTP connection durations, by closing status and protocol (HTTP/HTTPS).",
                // 10ms, 20ms, ... 50000s
                decimal_buckets(-2, 4),
                &[LABEL_PROTOCOL],
            ),
            // Ingress watcher metrics
            ingress_watcher_subscriptions_total: metrics_registry.int_counter(
                "replica_http_ingress_watcher_subscriptions_total",
                "Total number of subscriptions the ingress watcher has received."
            ),
            ingress_watcher_cancelled_subscriptions_total: metrics_registry.int_counter(
                "replica_http_ingress_watcher_cancelled_subscriptions_total",
                "Total number of subscriptions that have been cancelled."
            ),
            ingress_watcher_duplicate_requests_total: metrics_registry.int_counter(
                "replica_http_ingress_watcher_duplicate_requests_total",
                "Total number of duplicate requests the ingress watcher has received."
            ),
            ingress_watcher_tracked_messages: metrics_registry.int_gauge(
                "replica_http_ingress_watcher_tracked_messages",
                "The current number of messages being tracked in the ingress watcher \
                waiting for certification"
            ),
            ingress_watcher_heights_waiting_for_certification: metrics_registry.int_gauge(
                "replica_http_ingress_watcher_heights_waiting_for_certification",
                "The current number of unique heights that the ingress watcher \
                is waiting for certification on."
            ),
            ingress_watcher_subscription_latency_duration_seconds: metrics_registry.histogram(
                "replica_http_ingress_watcher_subscription_latency_duration_seconds",
                "The duration the sync call handler waits for subscribing to a message. \
                I.e. `IngressWatcherHandle::subscribe_for_certification()`.",
                // 0.1ms - 500ms
                decimal_buckets(-4, -1),
            ),
            ingress_watcher_messages_completed_execution_channel_capacity: metrics_registry.int_gauge(
                "replica_http_ingress_watcher_messages_completed_execution_channel_capacity",
                "The capacity of the channel that holds messages that have completed execution."
            ),
            ingress_watcher_wait_for_certification_duration_seconds: metrics_registry.histogram(
                "replica_http_ingress_watcher_wait_for_certification_duration_seconds",
                "The duration the sync call handler waits for a message to complete execution \
                at some height, h, and for h to become certified.",
                // 52 buckets
                // 0.50s - 0.60s - ... - 4.5s - 5.0s - 5.5s - ... - 12s - 14s - 16s
                {
                    let mut buckets = linear_buckets(0.5, 0.1, 40);
                    // Extend the buckets with 5.0s - 12.0s
                    for value in linear_buckets(5.0, 0.5, 10) {
                        buckets = add_bucket(value, buckets);
                    }

                    buckets = add_bucket(14.0, buckets);
                    buckets = add_bucket(16.0, buckets);

                    buckets
                },

            ),
            // TODO(CON-1576): rename the metric names and add `api_version` label to them
            sync_call_certificate_status_total: metrics_registry.int_counter_vec(
                "replica_http_call_v3_certificate_status_total",
                "The count of certificate states returned by the /{v3,v4}/.../call endpoint. I.e. replied, rejected, unknown, etc.",
                &[LABEL_SYNC_CALL_CERTIFICATE_STATUS],
            ),
            sync_call_early_response_trigger_total: metrics_registry.int_counter_vec(
                "replica_http_call_v3_early_response_trigger_total",
                "The count of early response triggers for the /{v3,v4}/.../call endpoint.",
                &[LABEL_SYNC_CALL_EARLY_RESPONSE_TRIGGER],
            ),
        }
    }
}
