use ic_metrics::buckets::{decimal_buckets, decimal_buckets_with_zero};
use ic_metrics::MetricsRegistry;
use prometheus::{histogram_opts, labels, opts, Histogram, HistogramVec, IntGauge};

pub const LABEL_POOL: &str = "pool";
pub const LABEL_POOL_TYPE: &str = "pool_type";
pub const POOL_TYPE_VALIDATED: &str = "validated";
pub const POOL_TYPE_UNVALIDATED: &str = "unvalidated";

/// Metrics for a given artifact pool's validated/unvalidated section.
#[derive(Clone)]
pub struct PoolMetrics {
    pub op_duration: HistogramVec,
    pub received_artifact_bytes: Histogram,
    pub pool_artifacts: IntGauge,
    pub pool_size_bytes: IntGauge,
}

impl PoolMetrics {
    pub fn new(metrics_registry: MetricsRegistry, pool: &str, pool_type: &str) -> Self {
        Self {
            op_duration: metrics_registry.register(
                HistogramVec::new(
                    histogram_opts!(
                        "artifact_pool_op_duration_seconds",
                        "The time it took to perform an operation on the given pool",
                        // 0.1ms - 500ms
                        decimal_buckets(-4, -1),
                        labels! {LABEL_POOL.to_string() => pool.to_string(), LABEL_POOL_TYPE.to_string() => pool_type.to_string()}
                    ),
                    &["op"],
                )
                .unwrap(),
            ),
            received_artifact_bytes: metrics_registry.register(
                Histogram::with_opts(histogram_opts!(
                    "artifact_pool_received_artifact_bytes",
                    "The byte size of all artifacts received by the given pool",
                    // 0, 1B - 50MB
                    decimal_buckets_with_zero(0, 7),
                    labels! {LABEL_POOL.to_string() => pool.to_string(), LABEL_POOL_TYPE.to_string() => pool_type.to_string()}
                ))
                .unwrap(),
            ),
            pool_artifacts: metrics_registry.register(
                IntGauge::with_opts(opts!(
                    "artifact_pool_artifacts",
                    "Current number of artifacts in the given pool",
                    labels! {LABEL_POOL => pool, LABEL_POOL_TYPE => pool_type}
                ))
                .unwrap(),
            ),
            pool_size_bytes: {
                metrics_registry.register(
                    IntGauge::with_opts(opts!(
                        "artifact_pool_artifact_bytes",
                        "Current byte size of artifacts in the given pool",
                        labels! {LABEL_POOL => pool, LABEL_POOL_TYPE => pool_type}
                    ))
                    .unwrap(),
                )
            },
        }
    }

    pub fn observe_insert(&self, size_bytes: usize) {
        self.received_artifact_bytes.observe(size_bytes as f64);
        self.pool_artifacts.inc();
        self.pool_size_bytes.add(size_bytes as i64);
    }

    pub fn observe_remove(&self, size_bytes: usize) {
        self.pool_artifacts.dec();
        self.pool_size_bytes.sub(size_bytes as i64);
    }
}
