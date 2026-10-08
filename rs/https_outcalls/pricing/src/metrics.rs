use ic_metrics::MetricsRegistry;
use prometheus::IntCounterVec;

/// Label identifying the accounting step at which the shadow tracker ran out of cycles
/// before the real one.
pub const LABEL_STEP: &str = "step";

/// Label identifying the replication kind of the request.
pub const LABEL_REPLICATION: &str = "replication";

#[derive(Clone)]
pub struct PricingMetrics {
    /// Number of requests for which the shadow tracker ran out of cycles before the
    /// real tracker, by the accounting step at which the incompatibility was first
    /// observed and by replication kind.
    pub shadow_incompatible_total: IntCounterVec,
}

impl PricingMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            shadow_incompatible_total: metrics_registry.int_counter_vec(
                "canister_http_pricing_shadow_incompatible_total",
                "Canister http requests that attached enough cycles to be compatible with the
                real tracker, but not for the shadow tracker.",
                &[LABEL_STEP, LABEL_REPLICATION],
            ),
        }
    }
}
