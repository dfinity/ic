use ic_metrics::MetricsRegistry;
use prometheus::{IntCounter, IntCounterVec};

/// Labels for request errors
pub(crate) const LABEL_BODY_RECEIVE_SIZE: &str = "body_receive_size";
pub(crate) const LABEL_BODY_RECEIVE_TIMEOUT: &str = "body_receive_timeout";
pub(crate) const LABEL_HTTP_SCHEME: &str = "http_scheme";
pub(crate) const LABEL_HTTP_METHOD: &str = "http_method";
pub(crate) const LABEL_RESPONSE_HEADERS: &str = "response_headers";
pub(crate) const LABEL_REQUEST_HEADERS: &str = "request_headers";
pub(crate) const LABEL_CONNECT: &str = "connect";
pub(crate) const LABEL_URL_PARSE: &str = "url_parse";

#[derive(Debug, Clone)]
pub struct AdapterMetrics {
    /// The number of requests served by adapter.
    pub requests_total: IntCounter,
    /// Request failure types.
    pub request_errors_total: IntCounterVec,
}

impl AdapterMetrics {
    /// The constructor returns a `GossipMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            requests_total: metrics_registry.int_counter(
                "requests_total",
                "Total number of requests served by adapter",
            ),
            request_errors_total: metrics_registry.int_counter_vec(
                "request_errors_total",
                "Error types encountered in the adapter.",
                &["cause"],
            ),
        }
    }
}
