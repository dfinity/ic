//! Metrics exported by crypto

use core::fmt;
use ic_metrics::MetricsRegistry;
use prometheus::{HistogramVec, IntCounter};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::time;
use std::time::Instant;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

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
                .crypto_lock_acquisition_duration_seconds
                .with_label_values(&[name, access])
                .observe(start_time.elapsed().as_secs_f64());
        }
    }

    /// Observes a CSP method duration, measuring the actual local cryptographic
    /// computation. `method_name` indicates the method's name, such as `BasicSignature::sign`.
    ///
    /// It observes the duration only if metrics are enabled, `start_time` is `Some`,
    /// and the metrics for `domain` are defined.
    pub fn observe_csp_local_duration_seconds(
        &self,
        domain: MetricsDomain,
        method_name: &str,
        start_time: Option<Instant>,
    ) {
        if let (Some(metrics), Some(start_time)) = (&self.metrics, start_time) {
            if let Some(domain_metrics) = metrics.crypto_csp_local_duration_seconds.get(&domain) {
                domain_metrics
                    .with_label_values(&[&format!("{}::{}", domain, method_name)])
                    .observe(start_time.elapsed().as_secs_f64());
            }
        }
    }

    /// Observes a crypto method duration, measuring the the full duration,
    /// which includes actual cryptographic computation and the potential RPC overhead.
    /// `method_name` indicates the method's name, such as `BasicSignature::sign`.
    ///
    /// It observes the duration only if metrics are enabled, `start_time` is `Some`,
    /// and the metrics for `domain` are defined.
    pub fn observe_full_duration_seconds(
        &self,
        domain: MetricsDomain,
        method_name: &str,
        start_time: Option<Instant>,
    ) {
        if let (Some(metrics), Some(start_time)) = (&self.metrics, start_time) {
            if let Some(domain_metrics) = metrics.crypto_full_duration_seconds.get(&domain) {
                domain_metrics
                    .with_label_values(&[&format!("{}::{}", domain, method_name)])
                    .observe(start_time.elapsed().as_secs_f64());
            }
        }
    }

    /// Observes the key counts of a node.
    ///
    /// Parameters:
    ///  - `num_pub_reg`: The number of node public keys (and TLS x.509 certificates) stored
    ///    in the registry
    ///  - `num_pub_local`: The number of node public keys (and TLS x.509 certificates) stored
    ///    locally
    ///  - `num_secret_local`: The number of node secret keys stored in the local secret key store
    pub fn observe_node_key_counts(
        &self,
        num_pub_reg: u8,
        num_pub_local: u8,
        num_secret_local: u8,
    ) {
        if let Some(metrics) = &self.metrics {
            metrics.crypto_key_counts[&KeyType::PublicLocal].inc_by(num_pub_local as u64);
            metrics.crypto_key_counts[&KeyType::PublicRegistry].inc_by(num_pub_reg as u64);
            metrics.crypto_key_counts[&KeyType::SecretSKS].inc_by(num_secret_local as u64);
        }
    }
}

#[derive(Copy, Clone, Debug, EnumIter, Eq, PartialOrd, Ord, PartialEq)]
pub enum KeyType {
    PublicRegistry,
    PublicLocal,
    SecretSKS,
}

#[derive(Copy, Clone, Debug, EnumIter, Eq, PartialOrd, Ord, PartialEq)]
pub enum MetricsDomain {
    BasicSignature,
    MultiSignature,
    ThresholdSignature,
    NiDkgAlgorithm,
    TlsHandshake,
    IDkgProtocol,
    ThresholdEcdsa,
    IcCanisterSignature,
}

struct Metrics {
    /// Histogram of crypto lock acquisition times. The 'access' label is either
    /// 'read' or 'write'.
    pub crypto_lock_acquisition_duration_seconds: HistogramVec,

    /// Histograms of CSP method call times of various functionalities, measuring
    /// the duration of the actual local crypto computation.
    ///
    /// The 'method_name' label indicates the functionality, such as `BasicSignature::sign`.
    pub crypto_csp_local_duration_seconds: BTreeMap<MetricsDomain, HistogramVec>,

    /// Histograms of crypto method call times of various functionalities, measuring the full
    /// duration of the call, i.e. both the local crypto computation, and the
    /// potential RPC overhead.
    /// The 'method_name' label indicates the functionality, such as `BasicSignature::sign`.
    pub crypto_full_duration_seconds: BTreeMap<MetricsDomain, HistogramVec>,

    /// Counters for the different types of keys and certificates of a node. The keys and
    /// certificates that are kept track of are:
    ///  - Node signing keys
    ///  - Committee signing keys
    ///  - NI-DKG keys
    ///  - iDKG keys
    ///  - TLS certificates and secret keys
    /// The above keys are not kept track of separately, merely a total number of stored keys.
    /// The counters keep track of which locations these keys are stored in:
    ///  - Registry
    ///  - Local public key store
    ///  - Local secret key store (SKS)
    pub crypto_key_counts: BTreeMap<KeyType, IntCounter>,
}

impl Display for MetricsDomain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str_snake_case())
    }
}

impl MetricsDomain {
    fn as_str_snake_case(&self) -> &str {
        match self {
            MetricsDomain::BasicSignature => "basic_signature",
            MetricsDomain::MultiSignature => "multi_signature",
            MetricsDomain::ThresholdSignature => "threshold_signature",
            MetricsDomain::NiDkgAlgorithm => "ni_dkg",
            MetricsDomain::TlsHandshake => "tls_handshake",
            MetricsDomain::IDkgProtocol => "idkg",
            MetricsDomain::ThresholdEcdsa => "threshold_ecdsa",
            MetricsDomain::IcCanisterSignature => "ic_canister_signature",
        }
    }

    fn local_metric_name(&self) -> String {
        format!("crypto_{}_local_duration_seconds", self)
    }

    fn local_metric_help(&self) -> String {
        format!(
            "Histogram of CSP {} method call durations, measuring the actual crypto computation",
            self
        )
    }

    fn full_metric_name(&self) -> String {
        format!("crypto_{}_full_duration_seconds", self)
    }

    fn full_metric_help(&self) -> String {
        format!("Histogram of {} method call durations, measuring both crypto computation and the potential RPC overhead", self)
    }
}

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str_snake_case())
    }
}

impl KeyType {
    fn as_str_snake_case(&self) -> &str {
        match self {
            KeyType::PublicLocal => "public_local",
            KeyType::PublicRegistry => "public_registry",
            KeyType::SecretSKS => "secret_sks",
        }
    }

    fn key_count_metric_name(&self) -> String {
        format!("crypto_{}_key_count", self)
    }

    fn key_count_metric_help(&self) -> String {
        format!("Number of crypto_{}_key_count", self)
    }
}

impl Metrics {
    pub fn new(r: &MetricsRegistry) -> Self {
        let default_buckets = vec![
            0.0001, 0.0002, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0,
            5.0, 10.0, 20.0, 50.0,
        ];
        let mut local_duration = BTreeMap::new();
        let mut full_duration = BTreeMap::new();
        for domain in MetricsDomain::iter() {
            local_duration.insert(
                domain,
                r.histogram_vec(
                    domain.local_metric_name(),
                    domain.local_metric_help(),
                    default_buckets.clone(),
                    &["method_name"],
                ),
            );
            full_duration.insert(
                domain,
                r.histogram_vec(
                    domain.full_metric_name(),
                    domain.full_metric_help(),
                    default_buckets.clone(),
                    &["method_name"],
                ),
            );
        }
        let mut key_counts = BTreeMap::new();
        for key_type in KeyType::iter() {
            key_counts.insert(
                key_type,
                r.int_counter(
                    key_type.key_count_metric_name(),
                    key_type.key_count_metric_help(),
                ),
            );
        }
        Self {
            crypto_lock_acquisition_duration_seconds: r.histogram_vec(
                "crypto_lock_acquisition_duration_seconds",
                "Histogram of crypto lock acquisition times",
                vec![0.00001, 0.0001, 0.001, 0.01, 0.1, 1.0, 10.0],
                &["name", "access"],
            ),
            crypto_csp_local_duration_seconds: local_duration,
            crypto_full_duration_seconds: full_duration,
            crypto_key_counts: key_counts,
        }
    }
}
