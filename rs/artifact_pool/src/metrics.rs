use ic_metrics::MetricsRegistry;
use ic_metrics::buckets::{decimal_buckets, decimal_buckets_with_zero};
use prometheus::{HistogramVec, IntCounterVec, IntGaugeVec, histogram_opts, labels, opts};

pub const LABEL_POOL: &str = "pool";
pub const LABEL_POOL_TYPE: &str = "pool_type";
pub const POOL_TYPE_VALIDATED: &str = "validated";
pub const POOL_TYPE_UNVALIDATED: &str = "unvalidated";
pub const ARTIFACT_TYPE: &str = "artifact_type";

/// Metrics for a given artifact pool's validated/unvalidated section.
#[derive(Clone)]
pub struct PoolMetrics {
    pub op_duration: HistogramVec,
    pub received_artifact_bytes: HistogramVec,
    received_duplicate_artifacts: IntCounterVec,
    pub pool_artifacts: IntGaugeVec,
    pub pool_size_bytes: IntGaugeVec,
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
                HistogramVec::new(histogram_opts!(
                    "artifact_pool_received_artifact_bytes",
                    "The byte size of all artifacts received by the given pool",
                    // 0, 1B - 50MB
                    decimal_buckets_with_zero(0, 7),
                    labels! {LABEL_POOL.to_string() => pool.to_string(), LABEL_POOL_TYPE.to_string() => pool_type.to_string()}
                ), &[ARTIFACT_TYPE])
                .unwrap(),
            ),
            received_duplicate_artifacts: metrics_registry.register(
                IntCounterVec::new(opts!(
                    "artifact_pool_received_duplicate_artifacts",
                    "Duplicate artifacts received by the given pool",
                    labels! {LABEL_POOL => pool, LABEL_POOL_TYPE => pool_type}
                ), &[ARTIFACT_TYPE])
                .unwrap(),
            ),
            pool_artifacts: metrics_registry.register(
                IntGaugeVec::new(opts!(
                    "artifact_pool_artifacts",
                    "Current number of artifacts in the given pool",
                    labels! {LABEL_POOL => pool, LABEL_POOL_TYPE => pool_type}
                ), &[ARTIFACT_TYPE])
                .unwrap(),
            ),
            pool_size_bytes: {
                metrics_registry.register(
                    IntGaugeVec::new(opts!(
                        "artifact_pool_artifact_bytes",
                        "Current byte size of artifacts in the given pool",
                        labels! {LABEL_POOL => pool, LABEL_POOL_TYPE => pool_type}
                    ), &[ARTIFACT_TYPE])
                    .unwrap(),
                )
            },
        }
    }

    pub fn observe_insert(&self, size_bytes: usize, artifact_type: &str) {
        self.received_artifact_bytes
            .with_label_values(&[artifact_type])
            .observe(size_bytes as f64);
        self.pool_artifacts
            .with_label_values(&[artifact_type])
            .inc();
        self.pool_size_bytes
            .with_label_values(&[artifact_type])
            .add(size_bytes as i64);
    }

    pub fn observe_duplicate(&self, size_bytes: usize, artifact_type: &str) {
        self.received_duplicate_artifacts
            .with_label_values(&[artifact_type])
            .inc();
        self.pool_artifacts
            .with_label_values(&[artifact_type])
            .dec();
        self.pool_size_bytes
            .with_label_values(&[artifact_type])
            .sub(size_bytes as i64);
    }

    pub fn observe_remove(&self, size_bytes: usize, artifact_type: &str) {
        self.pool_artifacts
            .with_label_values(&[artifact_type])
            .dec();
        self.pool_size_bytes
            .with_label_values(&[artifact_type])
            .sub(size_bytes as i64);
    }
}

/// Metrics for IDKG pool's validated/unvalidated section.
#[derive(Clone)]
pub struct IDkgPoolMetrics {
    pool_artifacts: IntGaugeVec,
    persistence_errors: IntCounterVec,
}

impl IDkgPoolMetrics {
    pub fn new(metrics_registry: MetricsRegistry, pool: &str, pool_type: &str) -> Self {
        Self {
            pool_artifacts: metrics_registry.register(
                IntGaugeVec::new(
                    opts!(
                        "idkg_pool_artifacts",
                        "Current number of artifacts in the given pool, by artifact type",
                        labels! {LABEL_POOL => pool, LABEL_POOL_TYPE => pool_type}
                    ),
                    &["artifact_type"],
                )
                .unwrap(),
            ),
            persistence_errors: metrics_registry.register(
                IntCounterVec::new(
                    opts!(
                        "idkg_pool_persistence_errors",
                        "IDKG pool persistence related errors",
                        labels! {LABEL_POOL => pool, LABEL_POOL_TYPE => pool_type}
                    ),
                    &["type"],
                )
                .unwrap(),
            ),
        }
    }

    pub fn observe_insert(&self, artifact_type: &str) {
        self.pool_artifacts
            .with_label_values(&[artifact_type])
            .inc();
    }

    pub fn observe_remove(&self, artifact_type: &str) {
        self.pool_artifacts
            .with_label_values(&[artifact_type])
            .dec();
    }

    pub fn persistence_error(&self, label: &str) {
        self.persistence_errors.with_label_values(&[label]).inc();
    }
}
