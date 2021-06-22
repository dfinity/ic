//! Metrics exported by crypto

use ic_metrics::MetricsRegistry;
use prometheus::HistogramVec;
use std::time;
use std::time::Instant;

/// Provides metrics for the crypto component.
///
/// This struct allows metrics being disabled and enabled.
pub struct CryptoMetrics {
    metrics: Option<Metrics>,
}

impl CryptoMetrics {
    /// Constructs CryptoMetrics that are disabled.
    pub fn none() -> Self {
        Self { metrics: None }
    }

    /// Constructs CryptoMetrics that are enabled if the metrics registry is
    /// some.
    pub fn new(registry: Option<&MetricsRegistry>) -> Self {
        Self {
            metrics: registry.map(Metrics::new),
        }
    }

    /// Returns `Instant::now()` iff metrics are enabled.
    ///
    /// This is a performance optimization to avoid calling `Instant::now()` if
    /// metrics are disabled. This may be relevant for very fast and frequent
    /// operations.
    pub fn now(&self) -> Option<Instant> {
        self.metrics.as_ref().map(|_| time::Instant::now())
    }

    /// Observes a lock acquisition duration. The `access` label is either
    /// 'read' or 'write'.
    ///
    /// This only observes the lock acquisition duration if metrics are enabled
    /// and `start_time` is `Some`.
    pub fn observe_lock_acquisition_duration_seconds(
        &self,
        name: &str,
        access: &str,
        start_time: Option<Instant>,
    ) {
        if let (Some(metrics), Some(start_time)) = (&self.metrics, start_time) {
            metrics
                .ic_crypto_lock_acquisition_duration_seconds
                .with_label_values(&[name, access])
                .observe(start_time.elapsed().as_secs_f64());
        }
    }

    /// Observes an NI-DKG method duration. The `method_name` indicates the
    /// method's name, such as `load_transcript`.
    ///
    /// This only observes an NI-DKG method duration if metrics are enabled and
    /// `start_time` is `Some`.
    pub fn observe_ni_dkg_method_duration_seconds(
        &self,
        method_name: &str,
        start_time: Option<Instant>,
    ) {
        if let (Some(metrics), Some(start_time)) = (&self.metrics, start_time) {
            metrics
                .ic_crypto_ni_dkg_method_duration_seconds
                .with_label_values(&[method_name])
                .observe(start_time.elapsed().as_secs_f64());
        }
    }
}

struct Metrics {
    /// Histogram of crypto lock acquisition times. The 'access' label is either
    /// 'read' or 'write'.
    pub ic_crypto_lock_acquisition_duration_seconds: HistogramVec,
    /// Histogram of `NiDkgAlgorithm` method call times. The 'method_name' label
    /// indicates the method name, such as `load_transcript`.
    pub ic_crypto_ni_dkg_method_duration_seconds: HistogramVec,
}

impl Metrics {
    pub fn new(r: &MetricsRegistry) -> Self {
        Self {
            ic_crypto_lock_acquisition_duration_seconds: r.histogram_vec(
                "ic_crypto_lock_acquisition_duration_seconds",
                "Histogram of crypto lock acquisition times",
                vec![0.00001, 0.0001, 0.001, 0.01, 0.1, 1.0, 10.0],
                &["name", "access"],
            ),
            ic_crypto_ni_dkg_method_duration_seconds: r.histogram_vec(
                "ic_crypto_ni_dkg_method_duration_seconds",
                "Histogram of NiDkgAlgorithm method call durations",
                vec![
                    0.0001, 0.001, 0.01, 0.1, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0,
                    15.0, 20.0, 30.0, 40.0, 50.0,
                ],
                &["method_name"],
            ),
        }
    }
}
