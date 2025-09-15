//! This module contains metric structs for components of the canister http feature

use ic_metrics::{MetricsRegistry, buckets::decimal_buckets};
use prometheus::{HistogramVec, IntCounter, IntGauge};

pub struct CanisterHttpPoolManagerMetrics {
    /// Records the time it took to perform an operation
    pub op_duration: HistogramVec,
    /// The total number of requests that are currently in flight according to
    /// the latest state.
    pub in_flight_requests: IntGauge,
    /// The total number of requests for which we are currently waiting for responses.
    pub in_client_requests: IntGauge,
    /// A count of the total number of shares signed.
    pub shares_signed: IntCounter,
    /// A count of the total number of shares validated.
    pub shares_validated: IntCounter,
    /// A count of the total number of shares marked invalid.
    pub shares_marked_invalid: IntCounter,
}

impl CanisterHttpPoolManagerMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            op_duration: metrics_registry.histogram_vec(
                "canister_http_pool_manager_op_duration",
                "The time it took the pool manager to perform an operation",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &["operation"],
            ),
            in_flight_requests: metrics_registry.int_gauge(
                "canister_http_in_flight_requests", "The total number of requests that are currently in flight according to the latest state."
            ),
            in_client_requests: metrics_registry.int_gauge(
                "canister_http_in_client_requests", "The total number of requests for which we are currently waiting for responses from the http client."
            ),
            shares_signed: metrics_registry.int_counter(
                "canister_http_shares_signed", "A count of the total number of shares signed."
            ),
            shares_validated: metrics_registry.int_counter(
                "canister_http_shares_validated", "A count of the total number of shares validated."
            ),
            shares_marked_invalid: metrics_registry.int_counter(
                "canister_http_shares_marked_invalid", "A count of the total number of shares marked invalid."
            )
        }
    }
}

pub struct CanisterHttpPayloadBuilderMetrics {
    /// Records the time it took to perform an operation
    pub op_duration: HistogramVec,
    /// The total number of validated shares in the pool
    pub total_shares: IntGauge,
    /// The number of shares which are not timed out or have ineligible registry
    /// versions.
    pub active_shares: IntGauge,
    /// The number of unique responses
    pub unique_responses: IntGauge,
    /// The number of unique responses which are includable in the latest
    /// attempt to create a block for which there are shares in the pool. In
    /// particular, these responses have met the threshold for inclusion.
    pub unique_includable_responses: IntGauge,
    /// The number of timeouts that have met the threshold for inclusion in
    /// the block.
    pub included_timeouts: IntGauge,
}

impl CanisterHttpPayloadBuilderMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            op_duration: metrics_registry.histogram_vec(
                "canister_http_payload_build_duration",
                "The time it took the payload builder to perform an operation",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &["operation"],
            ),
            total_shares: metrics_registry.int_gauge(
                "canister_http_total_validated_shares",
                "The total number of validated shares in the pool",
            ),
            active_shares: metrics_registry.int_gauge(
                "canister_http_total_active_validated_shares",
                "The total number of validated shares that are not timed out or made with invalid registry version."
            ),
            unique_responses: metrics_registry.int_gauge(
                "canister_http_unique_responses",
                "The total number of unique responses that are currently active"
            ),
            unique_includable_responses: metrics_registry.int_gauge(
                "canister_http_unique_includable_responses",
                "The total number of unique responses that could be included in a block"
            ),
            included_timeouts: metrics_registry.int_gauge(
                "canister_http_unique_timeouts",
                "The number of timeouts that could be included in a block"
            )
        }
    }
}
