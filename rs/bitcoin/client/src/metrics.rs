use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use prometheus::HistogramVec;

pub const LABEL_REQUEST_TYPE: &str = "request_type";
pub const LABEL_STATUS: &str = "status";
pub const LABEL_GET_SUCCESSORS: &str = "get_successors";
pub const LABEL_SEND_TRANSACTION: &str = "send_transaction";
pub const OK_LABEL: &str = "OK";
pub const UNKNOWN_LABEL: &str = "unknown";

pub const REQUESTS_NUM_LABELS: usize = 2;
pub const REQUESTS_LABEL_NAMES: [&str; REQUESTS_NUM_LABELS] = [LABEL_REQUEST_TYPE, LABEL_STATUS];

#[derive(Clone)]
pub struct Metrics {
    pub(crate) requests: HistogramVec,
}

impl Metrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            requests: metrics_registry.histogram_vec(
                "replica_bitcoin_client_request_duration_seconds",
                "Request latencies in seconds.",
                decimal_buckets(-3, 1),
                // 1ms, 2ms, 5ms, 10ms, 20ms, ..., 10s, 20s, 50s
                &REQUESTS_LABEL_NAMES,
            ),
        }
    }
}
