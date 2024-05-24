use prometheus::{IntCounter, IntGauge};

/// Metrics for the cache of successfully verified BLS12-381 threshold signatures.
pub struct SignatureMetrics {
    /// [`IntGauge`] for tracking the size of the cache. The size is expected
    /// to increase with the time and remain at its max value until the process ends.
    /// But if it happens that the cache size decreases, we want to know about that,
    /// therefore we use an [`IntGauge`] and not a [`Counter`].
    pub cache_size: IntGauge,
    /// [`Counter`] for tracking the cache hits.
    pub cache_hits: IntCounter,
    /// [`Counter`] for tracking the cache misses.
    pub cache_misses: IntCounter,
}

pub struct PkCheckMetrics {
    /// [`IntGauge`] for tracking the size of the cache. The size is expected
    /// to increase with the time and remain at its max value until the process ends.
    /// But if it happens that the cache size decreases, we want to know about that,
    /// therefore we use an [`IntGauge`] and not a [`Counter`].
    pub cache_size: IntGauge,
    /// [`Counter`] for tracking the cache hits.
    pub cache_hits: IntCounter,
    /// [`Counter`] for tracking the cache misses.
    pub cache_misses: IntCounter,
}
