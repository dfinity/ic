use ic_metrics::{buckets::decimal_buckets, MetricsRegistry, Timer};
use prometheus::HistogramVec;

const LABEL_STATUS: &str = "status";
const LABEL_TYPE: &str = "type";
const METRIC_BUILD_PAYLOAD_DURATION: &str = "bitcoin_builder_build_payload_duration_seconds";
const METRIC_VALIDATE_PAYLOAD_DURATION: &str = "bitcoin_builder_validate_payload_duration_seconds";
const METRIC_ADAPTER_REQUEST_DURATION: &str = "bitcoin_builder_adapter_request_duration_seconds";

pub struct BitcoinPayloadBuilderMetrics {
    // Records the time it took to build the payload, by status.
    build_payload_duration: HistogramVec,
    // Records the time it took to validate a payload, by status.
    validate_payload_duration: HistogramVec,
    // Records the time it took to send a request to the Bitcoin
    // Adapter and receive the response, by status and type.
    adapter_request_duration: HistogramVec,
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
}
