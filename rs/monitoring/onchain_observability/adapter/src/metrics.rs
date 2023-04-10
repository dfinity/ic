use ic_metrics::MetricsRegistry;
use prometheus::{IntCounter, IntCounterVec};

const REPORT_WAS_FOUND: &str = "report_was_found";
const REQUEST_TYPE: &str = "request_type";
const ERROR_STATUS: &str = "error_status";

#[derive(Debug, Clone)]
pub struct OnchainObservabilityAdapterMetrics {
    pub report_interval_elapsed_total: IntCounter,
    pub failed_crypto_signatures_total: IntCounter,
    pub failed_grpc_requests_total: IntCounterVec,
    pub reports_delayed_total: IntCounter,
    pub find_published_report_in_canister_requests_total: IntCounterVec,
}

// Note that all adapter metrics are automatically prefixed with "onchain_observability"
impl OnchainObservabilityAdapterMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            report_interval_elapsed_total: metrics_registry.int_counter(
                "report_interval_elapsed_total",
                "Counts the number of 'report-loop iterations' to measure how many reports are expected.",
            ),
            failed_crypto_signatures_total: metrics_registry.int_counter(
                "failed_crypto_signatures_total",
                "Counts failures from attempting to sign the report.",
            ),
            failed_grpc_requests_total: metrics_registry.int_counter_vec(
                "failed_grpc_requests_total",
                "Tracks when gRPC request to replica fails, indexed on error type and whether request was sampled or non-sampled. Note that this does not necessarily equate to a skipped report if retries succeed.",
                &[REQUEST_TYPE, ERROR_STATUS],
            ),
            reports_delayed_total: metrics_registry.int_counter(
                "reports_delayed_total",
                "Tracks when gRPC consistently fails to the point of re-attempting metric collection at the next interval.",
            ),
            find_published_report_in_canister_requests_total: metrics_registry.int_counter_vec(
                "find_published_report_in_canister_requests_total",
                "Tracks what fraction of reports are successfully published to the canister by querying the canister for report after a commit sequence.  'True' indicates a report was published successfully, and 'False' indicates a report is missing.",
                &[REPORT_WAS_FOUND],
            ),
        }
    }
}
