use ic_metrics::MetricsRegistry;
use prometheus::{IntCounter, IntCounterVec};

const PUBLISH_RESULT: &str = "publish_result";
const REQUEST_TYPE: &str = "request_type";
const ERROR_STATUS: &str = "error_status";

#[derive(Debug, Clone)]
pub struct OnchainObservabilityAdapterMetrics {
    pub reports_attempted: IntCounter,
    pub failed_crypto_signature: IntCounter,
    pub failed_grpc_request: IntCounterVec,
    pub reports_published_to_canister: IntCounterVec,
}

impl OnchainObservabilityAdapterMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            reports_attempted: metrics_registry.int_counter(
                "reports_attempted",
                "Counts the number of 'report-loop iterations' to measure how many reports are expected.  More precisely, it counts the number of times the reporting window elapsed.",
            ),
            failed_crypto_signature: metrics_registry.int_counter(
                "failed_crypto_signature",
                "Counts failures from attempting to sign the report.",
            ),
            failed_grpc_request: metrics_registry.int_counter_vec(
                "failed_grpc_request",
                "Tracks when gRPC request to replica fails, indexed on error type and whether request was sampled or non-sampled.",
                &[REQUEST_TYPE, ERROR_STATUS],
            ),
            reports_published_to_canister: metrics_registry.int_counter_vec(
                "reports_published_to_canister",
                "Tracks what fraction of reports are successfully published to the canister by querying the canister for report after a commit sequence.  'True' indicates a report was published successfully, and 'False' indicates a report is missing.",
                &[PUBLISH_RESULT],
            ),
        }
    }
}
