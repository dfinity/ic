//! Metrics exported by crypto

use core::fmt;
use ic_metrics::MetricsRegistry;
use prometheus::{HistogramVec, IntCounterVec, IntGauge};
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

    /// Observes a crypto method duration, measuring the the full duration,
    /// which includes actual cryptographic computation and the potential RPC overhead.
    /// `method_name` indicates the method's name, such as `BasicSignature::sign`.
    ///
    /// It observes the duration only if metrics are enabled, `start_time` is `Some`,
    /// and the metrics for `domain` are defined.
    pub fn observe_duration_seconds(
        &self,
        domain: MetricsDomain,
        scope: MetricsScope,
        method_name: &str,
        result: MetricsResult,
        start_time: Option<Instant>,
    ) {
        if let (Some(metrics), Some(start_time)) = (&self.metrics, start_time) {
            metrics
                .crypto_duration_seconds
                .with_label_values(&[
                    method_name,
                    &format!("{}", scope),
                    &format!("{}", domain),
                    &format!("{}", result),
                ])
                .observe(start_time.elapsed().as_secs_f64());
        }
    }

    /// Observes the key counts of a node. For more information about the types of keys contained
    /// in the `key_counts` parameter, see the [`KeyCounts`] documentation.
    pub fn observe_node_key_counts(&self, key_counts: KeyCounts) {
        if let Some(metrics) = &self.metrics {
            metrics.crypto_key_counts[&KeyType::PublicLocal].set(key_counts.get_pk_local() as i64);
            metrics.crypto_key_counts[&KeyType::PublicRegistry]
                .set(key_counts.get_pk_registry() as i64);
            metrics.crypto_key_counts[&KeyType::SecretSKS].set(key_counts.get_sk_local() as i64);
        }
    }

    pub fn observe_key_rotation_result(&self, result: KeyRotationResult) {
        if let Some(metrics) = &self.metrics {
            metrics
                .crypto_key_rotation_results
                .with_label_values(&[&format!("{}", result)])
                .inc();
        }
    }

    pub fn observe_boolean_result(&self, operation: BooleanOperation, result: BooleanResult) {
        if let Some(metrics) = &self.metrics {
            metrics
                .crypto_boolean_results
                .with_label_values(&[&format!("{}", operation), &format!("{}", result)])
                .inc();
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
    PublicSeed,
}

#[derive(Copy, Clone, Debug, EnumIter, Eq, PartialOrd, Ord, PartialEq)]
pub enum MetricsScope {
    Full,
    Local,
}

#[derive(Copy, Clone, Debug, EnumIter, Eq, PartialOrd, Ord, PartialEq)]
pub enum MetricsResult {
    Ok,
    Err,
}

impl<T, E> From<&Result<T, E>> for MetricsResult {
    fn from(original: &Result<T, E>) -> Self {
        match original {
            Ok(_) => MetricsResult::Ok,
            Err(_) => MetricsResult::Err,
        }
    }
}

#[derive(Copy, Clone, Debug, EnumIter, Eq, PartialOrd, Ord, PartialEq)]
pub enum KeyRotationResult {
    KeyRotated,
    LatestLocalRotationTooRecent,
    KeyGenerationError,
    RegistryError,
    KeyRotationNotEnabled,
    KeyNotRotated,
    RegistryKeyBadOrMissing,
}

/// Keeps track of the number of node keys. This information is collected and provided to the
/// metrics component. The type of keys for which the key counts are tracked are the following:
///  - `pk_registry`: The number of node public keys (and TLS x.509 certificates) stored
///    in the registry
///  - `pk_local`: The number of node public keys (and TLS x.509 certificates) stored
///    in the local public key store
///  - `sk_local`: The number of node secret keys stored in the local secret key store
pub struct KeyCounts {
    pk_registry: u8,
    pk_local: u8,
    sk_local: u8,
}

impl KeyCounts {
    pub fn new(pk_registry: u8, pk_local: u8, sk_local: u8) -> Self {
        KeyCounts {
            pk_registry,
            pk_local,
            sk_local,
        }
    }

    pub fn get_pk_registry(&self) -> u8 {
        self.pk_registry
    }

    pub fn get_pk_local(&self) -> u8 {
        self.pk_local
    }

    pub fn get_sk_local(&self) -> u8 {
        self.sk_local
    }
}

pub enum BooleanResult {
    True,
    False,
}

impl Display for BooleanResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str_snake_case())
    }
}

impl BooleanResult {
    fn as_str_snake_case(&self) -> &str {
        match self {
            BooleanResult::True => "true",
            BooleanResult::False => "false",
        }
    }
}

pub enum BooleanOperation {
    KeyInRegistryMissingLocally,
    LatestLocalIDkgKeyExistsInRegistry,
}

impl Display for BooleanOperation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str_snake_case())
    }
}

impl BooleanOperation {
    fn as_str_snake_case(&self) -> &str {
        match self {
            BooleanOperation::KeyInRegistryMissingLocally => "key_in_registry_missing_locally",
            BooleanOperation::LatestLocalIDkgKeyExistsInRegistry => {
                "latest_local_idkg_key_exists_in_registry"
            }
        }
    }
}

struct Metrics {
    /// Histogram of crypto lock acquisition times. The 'access' label is either
    /// 'read' or 'write'.
    pub crypto_lock_acquisition_duration_seconds: HistogramVec,

    /// Histograms of crypto method call times of various functionalities, measuring the full
    /// duration of the call, i.e. both the local crypto computation, and the
    /// potential RPC overhead.
    /// The 'method_name' label indicates the functionality, such as `sign`.
    /// The 'scope' label indicates the scope of the call, either `Full` or `Local`.
    /// The 'domain' label indicates the domain, e.g., `MetricsDomain::BasicSignature`.
    pub crypto_duration_seconds: HistogramVec,

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
    pub crypto_key_counts: BTreeMap<KeyType, IntGauge>,

    pub crypto_key_rotation_results: IntCounterVec,

    /// Counter vector for crypto results that can be expressed as booleans. An additional label
    /// is used to identify the type of operation.
    pub crypto_boolean_results: IntCounterVec,
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
            MetricsDomain::PublicSeed => "public_seed",
        }
    }
}

impl Display for MetricsScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str_snake_case())
    }
}

impl MetricsScope {
    fn as_str_snake_case(&self) -> &str {
        match self {
            MetricsScope::Full => "full",
            MetricsScope::Local => "local",
        }
    }
}

impl Display for MetricsResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str_snake_case())
    }
}

impl MetricsResult {
    fn as_str_snake_case(&self) -> &str {
        match self {
            MetricsResult::Ok => "ok",
            MetricsResult::Err => "err",
        }
    }
}

impl Display for KeyRotationResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str_snake_case())
    }
}

impl KeyRotationResult {
    fn as_str_snake_case(&self) -> &str {
        match self {
            KeyRotationResult::KeyRotated => "key_rotated",
            KeyRotationResult::LatestLocalRotationTooRecent => "latest_local_rotation_too_recent",
            KeyRotationResult::KeyGenerationError => "key_generation_error",
            KeyRotationResult::RegistryError => "registry_error",
            KeyRotationResult::KeyRotationNotEnabled => "key_rotation_not_enabled",
            KeyRotationResult::KeyNotRotated => "key_not_rotated",
            KeyRotationResult::RegistryKeyBadOrMissing => "registry_key_bad_or_missing",
        }
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
        let durations = r.histogram_vec(
            "crypto_duration_seconds",
            "Histogram of method call durations in seconds",
            ic_metrics::buckets::decimal_buckets(-4, 1),
            &["method_name", "scope", "domain", "result"],
        );
        let mut key_counts = BTreeMap::new();
        for key_type in KeyType::iter() {
            key_counts.insert(
                key_type,
                r.int_gauge(
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
            crypto_duration_seconds: durations,
            crypto_key_counts: key_counts,
            crypto_key_rotation_results: r.int_counter_vec(
                "crypto_key_rotation_results",
                "Result from iDKG dealing encryption key rotations",
                &["result"],
            ),
            crypto_boolean_results: r.int_counter_vec(
                "crypto_boolean_results",
                "Boolean results from crypto operations",
                &["operation", "result"],
            ),
        }
    }
}
