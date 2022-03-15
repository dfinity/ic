use ic_metrics::{buckets::decimal_buckets, MetricsRegistry, Timer};
use prometheus::{Histogram, HistogramVec};

const LABEL_STATUS: &str = "status";
const LABEL_TYPE: &str = "type";
const METRIC_BUILD_PAYLOAD_DURATION: &str = "bitcoin_builder_build_payload_duration_seconds";
const METRIC_VALIDATE_PAYLOAD_DURATION: &str = "bitcoin_builder_validate_payload_duration_seconds";
const METRIC_ADAPTER_REQUEST_DURATION: &str = "bitcoin_builder_adapter_request_duration_seconds";
const METRIC_BLOCKS_PER_GET_SUCCESSORS_RESPONSE: &str =
    "bitcoin_builder_blocks_per_get_successors_response";
const METRIC_ADAPTER_RESPONSE_SIZE_BYTES: &str = "bitcoin_builder_adapter_response_size_bytes";

pub struct BitcoinPayloadBuilderMetrics {
    // Records the time it took to build the payload, by status.
    build_payload_duration: HistogramVec,
    // Records the time it took to validate a payload, by status.
    validate_payload_duration: HistogramVec,
    // Records the time it took to send a request to the Bitcoin
    // Adapter and receive the response, by status and type.
    adapter_request_duration: HistogramVec,
    // Records the number of blocks per `GetSuccessorsResponse`
    // received from the Bitcoin Adapter.
    blocks_per_get_successors_response: Histogram,
    // Records the size of responses received from the Bitcoin
    // Adapter.
    adapter_response_size_bytes: Histogram,
}

impl BitcoinPayloadBuilderMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            build_payload_duration: metrics_registry.histogram_vec(
                METRIC_BUILD_PAYLOAD_DURATION,
                "The time it took to build the payload, by status.",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &[LABEL_STATUS],
            ),
            validate_payload_duration: metrics_registry.histogram_vec(
                METRIC_VALIDATE_PAYLOAD_DURATION,
                "The time it took to validate a payload, by status.",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &[LABEL_STATUS],
            ),
            adapter_request_duration: metrics_registry.histogram_vec(
                METRIC_ADAPTER_REQUEST_DURATION,
                "The time it took to send a request to the Bitcoin Adapter and receive the response, by status and type.",
                // 1μs - 5s
                decimal_buckets(-6, 0),
                &[LABEL_STATUS, LABEL_TYPE],
            ),
            blocks_per_get_successors_response: metrics_registry.histogram(
                METRIC_BLOCKS_PER_GET_SUCCESSORS_RESPONSE,
                "Number of blocks included per get successors response",
                // 0, 1, 2, 5, 10, ..., 1000
                decimal_buckets(0, 3),
            ),
            adapter_response_size_bytes: metrics_registry.histogram(
                METRIC_ADAPTER_RESPONSE_SIZE_BYTES,
                "Size of responses received from the adapter in bytes.",
                // 0, 1, 2, 5, 10, ..., 10MB
                decimal_buckets(0, 7),
            ),
        }
    }

    // Records the status and duration of a `get_self_validating_payload()` call.
    pub fn observe_build_duration(&self, status: &str, timer: Timer) {
        self.build_payload_duration
            .with_label_values(&[status])
            .observe(timer.elapsed());
    }

    // Records the status and duration of a `validate_self_validating_payload()` call.
    pub fn observe_validate_duration(&self, status: &str, timer: Timer) {
        self.validate_payload_duration
            .with_label_values(&[status])
            .observe(timer.elapsed());
    }

    // Records the status, type and duration of a request made to the BitcoinAdapter.
    pub fn observe_adapter_request_duration(&self, status: &str, request_type: &str, timer: Timer) {
        self.adapter_request_duration
            .with_label_values(&[status, request_type])
            .observe(timer.elapsed());
    }

    // Records the number of blocks per `GetSuccessorsResponse`.
    pub fn observe_blocks_per_get_successors_response(&self, num_blocks: usize) {
        self.blocks_per_get_successors_response
            .observe(num_blocks as f64);
    }

    // Records the size of a response received from the Bitcoin Adapter.
    pub fn observe_adapter_response_size(&self, response_size: u64) {
        self.adapter_response_size_bytes
            .observe(response_size as f64);
    }
}
