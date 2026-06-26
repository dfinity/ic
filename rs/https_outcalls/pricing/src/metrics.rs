use ic_metrics::MetricsRegistry;
use prometheus::IntCounterVec;

/// Label identifying the accounting step at which the shadow tracker ran out of cycles
/// before the real one.
pub const LABEL_STEP: &str = "step";

/// Label identifying the replication type of the request.
pub const LABEL_REPLICATION: &str = "replication";

#[derive(Clone)]
pub struct PricingMetrics {
    /// Total number of requests evaluated by the dark-launch budget tracker,
    /// by replication type.
    pub shadow_requests_total: IntCounterVec,
    /// Number of requests for which the shadow tracker ran out of cycles before the
    /// real tracker, by the accounting step at which the divergence was first
    /// observed and by replication type.
    ///
    /// The fraction `shadow_incompatible_total / shadow_requests_total` is the
    /// share of requests that would NOT be backwards compatible.
    pub shadow_incompatible_total: IntCounterVec,
}

impl PricingMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            shadow_requests_total: metrics_registry.int_counter_vec(
                "canister_http_pricing_shadow_requests_total",
                "Total canister http requests evaluated by the dark-launch budget tracker, by \
                 replication type.",
                &[LABEL_REPLICATION],
            ),
            shadow_incompatible_total: metrics_registry.int_counter_vec(
                "canister_http_pricing_shadow_incompatible_total",
                "Canister http requests for which the shadow tracker disagreed with the real \
                 tracker, by accounting step and replication type.",
                &[LABEL_STEP, LABEL_REPLICATION],
            ),
        }
    }
}
