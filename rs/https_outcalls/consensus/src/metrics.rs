//! This module contains metric structs for components of the canister http feature

use ic_metrics::{MetricsRegistry, buckets::decimal_buckets};
use prometheus::{HistogramVec, IntCounter, IntCounterVec, IntGauge};

/// The label whose value names the kind of event or error that was counted.
const LABEL_TYPE: &str = "type";

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
    /// Notable, but expected events observed by the pool manager, by kind.
    pool_manager_events: IntCounterVec,
    /// Operations the pool manager failed to perform, by kind.
    pool_manager_errors: IntCounterVec,
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
            ),
            pool_manager_events: metrics_registry.int_counter_vec(
                "canister_http_pool_manager_events",
                "Notable, but expected events observed by the pool manager, by kind.",
                &[LABEL_TYPE],
            ),
            pool_manager_errors: metrics_registry.int_counter_vec(
                "canister_http_pool_manager_errors",
                "Canister http pool manager related errors, by kind.",
                &[LABEL_TYPE],
            ),
        }
    }

    /// Records a notable, but expected event of the given kind.
    pub(crate) fn observe_pool_manager_event(&self, label: &str) {
        self.pool_manager_events.with_label_values(&[label]).inc();
    }

    /// Records a failed operation of the given kind.
    pub(crate) fn observe_pool_manager_error(&self, label: &str) {
        self.pool_manager_errors.with_label_values(&[label]).inc();
    }
}

pub struct CanisterHttpPayloadBuilderMetrics {
    /// Records the time it took to perform an operation
    pub op_duration: HistogramVec,
    /// The total number of validated shares in the pool
    pub total_shares: IntGauge,
    /// The number of validated shares whose request has not already been
    /// answered in the chain (i.e. shares that are still candidates for
    /// inclusion in a payload).
    pub active_shares: IntGauge,
    /// The number of times the initial spent exceeds the limit under
    /// legacy pricing.
    pub initial_spent_exceeds_limit: IntCounter,
    /// The number of payloads that hit the max response limit.
    pub max_responses_per_block_reached: IntCounter,
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
                "The total number of validated shares whose request has not already been answered in the chain."
            ),
            initial_spent_exceeds_limit: metrics_registry.int_counter(
                "canister_http_initial_spent_exceeds_limit",
                "The number of times the initial spent exceeds the limit under legacy pricing."
            ),
            max_responses_per_block_reached: metrics_registry.int_counter(
                "canister_http_max_responses_per_block_reached",
                "The number of payloads that hit the per-block limit on canister http responses."
            ),
        }
    }
}
