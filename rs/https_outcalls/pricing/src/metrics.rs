use ic_metrics::MetricsRegistry;
use prometheus::IntCounterVec;

/// Label identifying the accounting step at which the shadow tracker diverged
/// from the real one.
pub const LABEL_STEP: &str = "step";

/// Label indicating whether the diverging request was non-replicated.
pub const LABEL_NON_REPLICATED: &str = "non_replicated";

#[derive(Clone)]
pub struct PricingMetrics {
    /// Total number of requests evaluated by the dark-launch budget tracker,
    /// by whether the request is non-replicated.
    pub shadow_requests_total: IntCounterVec,
    /// Number of requests that would be rejected (pricing error) under the
    /// shadow pricing while succeeding under the real pricing, by the
    /// accounting step at which the divergence was first observed and whether
    /// the request is non-replicated.
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
                 whether the request is non-replicated.",
                &[LABEL_NON_REPLICATED],
            ),
            shadow_incompatible_total: metrics_registry.int_counter_vec(
                "canister_http_pricing_shadow_incompatible_total",
                "Canister http requests that would be rejected (pricing error) under the shadow \
                 pricing while succeeding under the real pricing, by accounting step and whether \
                 the request is non-replicated.",
                &[LABEL_STEP, LABEL_NON_REPLICATED],
            ),
        }
    }
}
