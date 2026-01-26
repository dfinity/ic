//! Metrics exported by crypto

mod bls12_381_g2_prep_cache;
mod bls12_381_point_cache;
mod bls12_381_sig_cache;

use ic_metrics::MetricsRegistry;
use prometheus::{
    Gauge, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};
use std::ops::Add;
use std::time::Instant;
use strum::{AsRefStr, EnumIter, IntoEnumIterator};
#[cfg(test)]
use strum_macros::IntoStaticStr;

/// Provides metrics for the crypto component.
///
/// This struct allows metrics being disabled and enabled.
pub struct CryptoMetrics {
    metrics: Option<Metrics>,
    metrics_registry: Option<MetricsRegistry>,
}

impl CryptoMetrics {
    /// Constructs CryptoMetrics that are disabled.
    pub fn none() -> Self {
        Self {
            metrics: None,
            metrics_registry: None,
        }
    }

    /// Constructs CryptoMetrics that are enabled if the metrics registry is
    /// some.
    pub fn new(registry: Option<&MetricsRegistry>) -> Self {
        Self {
            metrics: registry.map(Metrics::new),
            metrics_registry: registry.cloned(),
        }
    }

    /// Returns an `Option` of a reference to the metrics registry iff metrics are enabled.
    pub fn metrics_registry(&self) -> Option<&MetricsRegistry> {
        self.metrics_registry.as_ref()
    }

    /// Returns `Instant::now()` iff metrics are enabled.
    ///
    /// This is a performance optimization to avoid calling `Instant::now()` if
    /// metrics are disabled. This may be relevant for very fast and frequent
    /// operations.
    pub fn now(&self) -> Option<Instant> {
        self.metrics.as_ref().map(|_| Instant::now())
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
                    &format!("{scope}"),
                    &format!("{domain}"),
                    &format!("{result}"),
                ])
                .observe(start_time.elapsed().as_secs_f64());

            if method_name == "verify_dealing_private" {
                metrics
                    .crypto_fine_grained_verify_dealing_private_duration_seconds
                    .observe(start_time.elapsed().as_secs_f64());
            } else if method_name == "verify_dealing_public" {
                metrics
                    .crypto_fine_grained_verify_dealing_public_duration_seconds
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
    pub fn observe_iccsa_verification_duration_seconds(
        &self,
        result: MetricsResult,
        start_time: Option<Instant>,
    ) {
        if let (Some(metrics), Some(start_time)) = (&self.metrics, start_time) {
            metrics
                .crypto_iccsa_verification_duration_seconds
                .with_label_values(&[&format!("{result}")])
                .observe(start_time.elapsed().as_secs_f64());
        }
    }

    /// Observes the iDKG dealing encryption public key count of a node.
    pub fn observe_idkg_dealing_encryption_pubkey_count(
        &self,
        idkg_dealing_encryption_pubkey_count: usize,
        result: MetricsResult,
    ) {
        if let Some(metrics) = &self.metrics {
            metrics
                .crypto_idkg_dealing_encryption_pubkey_count
                .with_label_values(&[&format!("{result}")])
                .set(idkg_dealing_encryption_pubkey_count as i64);
        }
    }

    pub fn observe_idkg_load_transcript_error(&self, id: u64) {
        if let Some(metrics) = &self.metrics {
            metrics.crypto_idkg_load_transcript_error.set(id as i64);
        }
    }

    /// Observes the key counts of a node. For more information about the types of keys contained
    /// in the `key_counts` parameter, see the [`KeyCounts`] documentation. The `result` parameter
    /// is used to track whether the key counting operation was successful or not. If the `result`
    /// was an error, then the key count values cannot be relied upon, but it can be useful to know
    /// how often, and for how long, the key counting operation failed.
    pub fn observe_node_key_counts(&self, key_counts: &KeyCounts, result: MetricsResult) {
        if let Some(metrics) = &self.metrics {
            metrics
                .crypto_key_counts
                .with_label_values(&[&format!("{}", KeyType::PublicLocal), &format!("{result}")])
                .set(key_counts.get_pk_local() as i64);
            metrics
                .crypto_key_counts
                .with_label_values(&[
                    &format!("{}", KeyType::PublicRegistry),
                    &format!("{result}"),
                ])
                .set(key_counts.get_pk_registry() as i64);
            metrics
                .crypto_key_counts
                .with_label_values(&[&format!("{}", KeyType::SecretSKS), &format!("{result}")])
                .set(key_counts.get_sk_local() as i64);
        }
    }

    /// Observes results of iDKG dealing encryption key operations.
    pub fn observe_key_rotation_result(&self, result: KeyRotationResult) {
        if let Some(metrics) = &self.metrics {
            metrics
                .crypto_key_rotation_results
                .with_label_values(&[&format!("{result}")])
                .inc();
        }
    }

    /// Observes a situation where one or more keys in the registry are missing locally.
    pub fn observe_keys_in_registry_missing_locally(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.crypto_keys_in_registry_missing_locally_total.inc();
        }
    }

    /// Observes the results of operations returning a boolean.
    pub fn observe_boolean_result(&self, operation: BooleanOperation, result: BooleanResult) {
        if let Some(metrics) = &self.metrics {
            metrics
                .crypto_boolean_results
                .with_label_values(&[&format!("{operation}"), &format!("{result}")])
                .inc();
        }
    }

    /// Observes the parameter size of selected input parameters for crypto operations.
    ///
    /// # Parameters
    /// * `domain` the domain of the operation
    /// * `method_name` the name of the method for the operation
    /// * `parameter_name` the name of the parameter that is being observed
    /// * `parameter_size` the size of the parameter being observed, in bytes
    /// * `result` the result of the crypto operation
    pub fn observe_parameter_size(
        &self,
        domain: MetricsDomain,
        method_name: &str,
        parameter_name: &str,
        parameter_size: usize,
        result: MetricsResult,
    ) {
        if let Some(metrics) = &self.metrics {
            metrics
                .crypto_parameter_byte_sizes
                .with_label_values(&[
                    method_name,
                    parameter_name,
                    &format!("{domain}"),
                    &format!("{result}"),
                ])
                .observe(parameter_size as f64);
        }
    }

    pub fn observe_vault_message_serialization(
        &self,
        service_type: ServiceType,
        message_type: MessageType,
        domain: MetricsDomain,
        method_name: &str,
        message_size: usize,
        start_time: Option<Instant>,
    ) {
        if let Some(metrics) = &self.metrics {
            metrics
                .crypto_vault_message_sizes
                .with_label_values(&[
                    service_type.as_ref(),
                    message_type.as_ref(),
                    domain.as_ref(),
                    method_name,
                ])
                .observe(message_size as f64);

            if let Some(start_time) = start_time {
                metrics
                    .crypto_vault_message_serialization_duration_seconds
                    .with_label_values(&[
                        service_type.as_ref(),
                        message_type.as_ref(),
                        domain.as_ref(),
                        method_name,
                    ])
                    .observe(start_time.elapsed().as_secs_f64());
            }
        }
    }

    /// Observes the cache statistics for the verification of threshold BLS12-381 signatures.
    pub fn observe_bls12_381_sig_cache_stats(&self, size: usize, hits: u64, misses: u64) {
        if let Some(metrics) = &self.metrics {
            let m = &metrics.crypto_bls12_381_sig_cache_metrics;
            m.cache_size.set(size as i64);

            let prev_hits = m.cache_hits.get();
            if hits > prev_hits {
                m.cache_hits.inc_by(hits - prev_hits);
            }

            let prev_misses = m.cache_misses.get();
            if misses > prev_misses {
                m.cache_misses.inc_by(misses - prev_misses);
            }
        }
    }

    /// Observes the cache statistics for parsing of BLS12-381 points
    pub fn observe_bls12_381_point_cache_stats(&self, size: usize, hits: u64, misses: u64) {
        if let Some(metrics) = &self.metrics {
            let m = &metrics.crypto_bls12_381_point_cache_metrics;
            m.cache_size.set(size as i64);

            let prev_hits = m.cache_hits.get();
            if hits > prev_hits {
                m.cache_hits.inc_by(hits - prev_hits);
            }

            let prev_misses = m.cache_misses.get();
            if misses > prev_misses {
                m.cache_misses.inc_by(misses - prev_misses);
            }
        }
    }

    /// Observes the cache statistics for parsing of BLS12-381 G2Prepared
    pub fn observe_bls12_381_g2_prep_cache_stats(&self, size: usize, hits: u64, misses: u64) {
        if let Some(metrics) = &self.metrics {
            let m = &metrics.crypto_bls12_381_g2_prep_cache_metrics;
            m.cache_size.set(size as i64);

            let prev_hits = m.cache_hits.get();
            if hits > prev_hits {
                m.cache_hits.inc_by(hits - prev_hits);
            }

            let prev_misses = m.cache_misses.get();
            if misses > prev_misses {
                m.cache_misses.inc_by(misses - prev_misses);
            }
        }
    }

    /// Observes the minimum epoch in active NI-DKG transcripts
    pub fn observe_minimum_epoch_in_active_nidkg_transcripts(&self, epoch: u32) {
        if let Some(metrics) = &self.metrics {
            metrics
                .observe_minimum_epoch_in_active_nidkg_transcripts
                .set(epoch as f64);
        }
    }

    /// Observes the epoch in loaded NI-DKG transcript
    pub fn observe_epoch_in_loaded_nidkg_transcript(&self, epoch: u32) {
        if let Some(metrics) = &self.metrics {
            metrics
                .observe_epoch_in_loaded_nidkg_transcript
                .set(epoch as f64);
        }
    }

    /// Observes the minimum registry version in active iDKG transcripts.
    pub fn observe_minimum_registry_version_in_active_idkg_transcripts(
        &self,
        registry_version: u64,
    ) {
        if let Some(metrics) = &self.metrics {
            metrics
                .observe_minimum_registry_version_in_active_idkg_transcripts
                .set(registry_version as f64);
        }
    }

    /// Observes the latest iDKG dealing encryption public key too old, but not in registry. This
    /// serves as a warning that something is or was affecting iDKG dealing encryption key
    /// rotation. This situation may occur in the following situations (non-exhaustive list):
    /// - If a node goes offline in the middle of a key rotation operation, and continues to be
    ///   offline for an extended period of time
    /// - If there is an error in the logic for computing the key rotation period
    /// - If there is a bug in the registry that is not allowing nodes to register newly rotated
    ///   keys for an extended period of time
    pub fn observe_latest_idkg_dealing_encryption_public_key_too_old_but_not_in_registry(&self) {
        if let Some(metrics) = &self.metrics {
            metrics
                .crypto_latest_idkg_dealing_encryption_public_key_too_old_but_not_in_registry
                .inc();
        }
    }

    /// Observes errors while performing cleanup of a secret key store. Cleanup involves zeroizing
    /// the blocks of the old key store, and removing the file (unlinking it). If either one of
    /// these operations fails, then the cleanup is considered to have failed.
    pub fn observe_secret_key_store_cleanup_error(&self, increment: u64) {
        if let Some(metrics) = &self.metrics {
            metrics
                .crypto_secret_key_store_cleanup_error
                .inc_by(increment);
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, EnumIter, strum_macros::Display)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(test, derive(IntoStaticStr))]
pub enum KeyType {
    PublicRegistry,
    PublicLocal,
    SecretSKS,
    IdkgDealingEncryptionLocal,
}

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, EnumIter, strum_macros::Display, AsRefStr,
)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(test, derive(IntoStaticStr))]
pub enum MetricsDomain {
    BasicSignature,
    MultiSignature,
    ThresholdSignature,
    NiDkgAlgorithm,
    TlsHandshake,
    TlsConfig,
    IdkgProtocol,
    ThresholdEcdsa,
    ThresholdSchnorr,
    VetKd,
    PublicSeed,
    KeyManagement,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, EnumIter, strum_macros::Display)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(test, derive(IntoStaticStr))]
pub enum MetricsScope {
    Full,
    Local,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, EnumIter, strum_macros::Display)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(test, derive(IntoStaticStr))]
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

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, EnumIter, strum_macros::Display)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(test, derive(IntoStaticStr))]
pub enum KeyRotationResult {
    KeyRotated,
    LatestLocalRotationTooRecent,
    KeyGenerationError,
    RegistryError,
    KeyRotationNotEnabled,
    KeyNotRotated,
    RegistryKeyBadOrMissing,
    TransientInternalError,
    PublicKeyNotFound,
}

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, EnumIter, strum_macros::Display, AsRefStr,
)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(test, derive(IntoStaticStr))]
pub enum ServiceType {
    Client,
    Server,
}

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, EnumIter, strum_macros::Display, AsRefStr,
)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(test, derive(IntoStaticStr))]
pub enum MessageType {
    Request,
    Response,
}

/// Keeps track of the number of node keys. This information is collected and provided to the
/// metrics component. The type of keys for which the key counts are tracked are the following:
///  - `pk_registry`: The number of node public keys (and TLS x.509 certificates) stored
///    in the registry
///  - `pk_local`: The number of node public keys (and TLS x.509 certificates) stored
///    in the local public key store. For keys that may have multiple revisions, e.g., the iDKG
///    dealing encryption public keys, at most one is included in the `pk_local` count
///  - `sk_local`: The number of node secret keys stored in the local secret key store
#[derive(Eq, PartialEq, Debug)]
pub struct KeyCounts {
    pk_registry: u32,
    pk_local: u32,
    sk_local: u32,
}

impl KeyCounts {
    pub const ZERO: Self = KeyCounts::new(0, 0, 0);

    pub const ONE: Self = KeyCounts::new(1, 1, 1);

    pub const fn new(pk_registry: u32, pk_local: u32, sk_local: u32) -> Self {
        KeyCounts {
            pk_registry,
            pk_local,
            sk_local,
        }
    }

    pub fn get_pk_registry(&self) -> u32 {
        self.pk_registry
    }

    pub fn get_pk_local(&self) -> u32 {
        self.pk_local
    }

    pub fn get_sk_local(&self) -> u32 {
        self.sk_local
    }
}

/// Add two [`KeyCount`] structs, by adding the individual integer fields within the struct.
///
/// # Example
///```
///  # use std::ops::Add;
///  # use ic_crypto_internal_logmon::metrics::KeyCounts;
///  let lhs = KeyCounts::new(1, 2, 3);
///  let rhs = KeyCounts::new(5, 10, 15);
///  let result = lhs + rhs;
///  assert_eq!(result, KeyCounts::new(6, 12, 18));
///```
impl Add for KeyCounts {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        KeyCounts::new(
            self.pk_registry.add(rhs.pk_registry),
            self.pk_local.add(rhs.pk_local),
            self.sk_local.add(rhs.sk_local),
        )
    }
}

/// A result for operations returning booleans. Using an enum allows adding errors, and using
/// macros for deriving the string representation needed for the dashboards.
#[derive(EnumIter, strum_macros::Display)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(test, derive(IntoStaticStr))]
pub enum BooleanResult {
    True,
    False,
}

#[derive(EnumIter, strum_macros::Display)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(test, derive(IntoStaticStr))]
pub enum BooleanOperation {
    LatestLocalIdkgKeyExistsInRegistry,
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

    /// Histogram with fine-grained buckets for IDKG's verify dealing private call time.
    crypto_fine_grained_verify_dealing_private_duration_seconds: Histogram,

    /// Histogram with fine-grained buckets for IDKG's verify dealing public call time.
    crypto_fine_grained_verify_dealing_public_duration_seconds: Histogram,

    /// Histograms of canister signature verification call time.
    ///
    /// The 'result' label indicates if the result of the operation was an `Ok(_)`
    pub crypto_iccsa_verification_duration_seconds: HistogramVec,

    /// A gauge vector for the number of iDKG dealing encryption public keys stored locally.
    pub crypto_idkg_dealing_encryption_pubkey_count: IntGaugeVec,

    /// A gauge for the transcript ID in iDKG load_transcript errors that may cause the loss of the key.
    pub crypto_idkg_load_transcript_error: IntGauge,

    /// A gauge vector for the different types of keys and certificates of a node. The keys and
    /// certificates that are kept track of are:
    ///  - Node signing keys
    ///  - Committee signing keys
    ///  - NI-DKG keys
    ///  - iDKG keys
    ///  - TLS certificates and secret keys
    ///
    /// The above keys are not kept track of separately, merely a total number of stored keys.
    /// The counters keep track of which locations these keys are stored in:
    ///  - Registry
    ///  - Local public key store
    ///  - Local secret key store (SKS)
    ///
    /// Additionally, the number of iDKG dealing encryption public keys that are stored locally are
    /// also kept track of in the gauge vector.
    pub crypto_key_counts: IntGaugeVec,

    /// An counter vector for keeping track of key rotation results. Each time a key rotation is
    /// performed, the outcome of the operation is tracked in this counter vector.
    pub crypto_key_rotation_results: IntCounterVec,

    /// A counter for situations where one or more keys in the registry are missing locally.
    pub crypto_keys_in_registry_missing_locally_total: IntCounter,

    /// Counter vector for crypto results that can be expressed as booleans. An additional label
    /// is used to identify the type of operation.
    pub crypto_boolean_results: IntCounterVec,

    /// Histograms of crypto method parameter sizes.
    /// The 'method_name' label indicates the functionality, such as `sign`.
    /// The 'domain' label indicates the domain, e.g., `MetricsDomain::BasicSignature`.
    /// The 'parameter_name' indicates the name of the parameter, e.g., `message`.
    /// The 'parameter_size' indicates the size of the parameter in bytes.
    pub crypto_parameter_byte_sizes: HistogramVec,

    /// Histograms of messages' sizes sent between the CSP vault client and server via the RPC socket.
    /// The observed value is the size of the message in bytes.
    /// The 'method_name' label indicates the functionality, such as `sign` or `idkg_retain_active_keys`.
    /// The 'service_type' label indicates whether the observation is made by the `client` or `server`
    /// The 'message_type' label indicates whether the message is a request or a response.
    pub crypto_vault_message_sizes: HistogramVec,

    /// Histograms of messages' sizes sent between the CSP vault client and server via the RPC socket.
    /// The observed value is the size of the duration of (de)serialization in seconds.
    /// The 'method_name' label indicates the functionality, such as `sign` or `idkg_retain_active_keys`.
    /// The 'service_type' label indicates whether the observation is made by the `client` or `server`
    /// The 'message_type' label indicates whether the message is a request or a response.
    /// The 'result' label indicates if the result of the operation was an `Ok(_)`
    pub crypto_vault_message_serialization_duration_seconds: HistogramVec,

    /// Metrics for the cache of successfully verified BLS12-381 threshold signatures.
    pub crypto_bls12_381_sig_cache_metrics: bls12_381_sig_cache::Metrics,

    /// Metrics for the cache of successfully decoded BLS12-381 points
    pub crypto_bls12_381_point_cache_metrics: bls12_381_point_cache::Metrics,

    /// Metrics for the cache of successfully created BLS12-381 G2Prepared
    pub crypto_bls12_381_g2_prep_cache_metrics: bls12_381_g2_prep_cache::Metrics,

    /// Gauge for the minimum epoch in active NI-DKG transcripts.
    observe_minimum_epoch_in_active_nidkg_transcripts: Gauge,

    /// Gauge for the epoch in loaded NI-DKG transcripts.
    observe_epoch_in_loaded_nidkg_transcript: Gauge,

    /// Gauge for the minimum registry version in active iDKG transcripts.
    observe_minimum_registry_version_in_active_idkg_transcripts: Gauge,

    /// Counter for iDKG dealing encryption public key too old, but not in registry.
    crypto_latest_idkg_dealing_encryption_public_key_too_old_but_not_in_registry: IntCounter,

    /// Counter for secret key store cleanup errors.
    crypto_secret_key_store_cleanup_error: IntCounter,
}

impl Metrics {
    pub fn new(r: &MetricsRegistry) -> Self {
        let durations = r.histogram_vec(
            "crypto_duration_seconds",
            "Histogram of method call durations in seconds",
            ic_metrics::buckets::decimal_buckets(-4, 1),
            &["method_name", "scope", "domain", "result"],
        );
        let crypto_fine_grained_verify_dealing_private_duration_seconds = r.histogram(
            "crypto_fine_grained_verify_dealing_private_duration_seconds",
            "Histogram of a verify dealing private call durations in seconds",
            // The buckets are from 350 us to 1329 us (0.00035 * 1.1^14), which is
            // slightly larger than the range observed in the experiments for
            // subnets with 13 to 40 nodes.
            ic_metrics::buckets::exponential_buckets(0.00035, 1.1, 15),
        );
        let crypto_fine_grained_verify_dealing_public_duration_seconds = r.histogram(
            "crypto_fine_grained_verify_dealing_public_duration_seconds",
            "Histogram of a verify dealing private call durations in seconds",
            // The buckets are from 400 us to 1518 us (0.004 * 1.1^14), which is
            // slightly larger than the range observed in the experiments for
            // subnets with 13 to 40 nodes.
            ic_metrics::buckets::exponential_buckets(0.0004, 1.1, 15),
        );
        let idkg_dealing_encryption_pubkey_count = r.int_gauge_vec(
            "crypto_idkg_dealing_encryption_pubkey_count",
            "Number of iDKG dealing encryption public keys stored locally",
            &["result"],
        );
        for result in MetricsResult::iter() {
            idkg_dealing_encryption_pubkey_count.with_label_values(&[&format!("{result}")]);
        }
        let key_counts = r.int_gauge_vec(
            "crypto_key_counts",
            "Number of crypto keys stored locally and in the registry, and whether the key counting operation was successful or not",
            &["key_type", "result"],
        );
        for key_type in KeyType::iter() {
            for result in MetricsResult::iter() {
                key_counts.with_label_values(&[&format!("{key_type}"), &format!("{result}")]);
            }
        }
        let boolean_results = r.int_counter_vec(
            "crypto_boolean_results",
            "Boolean results from crypto operations",
            &["operation", "result"],
        );
        for operation in BooleanOperation::iter() {
            for result in BooleanResult::iter() {
                boolean_results.with_label_values(&[&format!("{operation}"), &format!("{result}")]);
            }
        }
        let rotation_results = r.int_counter_vec(
            "crypto_key_rotation_results",
            "Result from iDKG dealing encryption key rotations",
            &["result"],
        );
        for result in KeyRotationResult::iter() {
            rotation_results.with_label_values(&[&format!("{result}")]);
        }
        Self {
            crypto_lock_acquisition_duration_seconds: r.histogram_vec(
                "crypto_lock_acquisition_duration_seconds",
                "Histogram of crypto lock acquisition times",
                vec![0.00001, 0.0001, 0.001, 0.01, 0.1, 1.0, 10.0],
                &["name", "access"],
            ),
            crypto_duration_seconds: durations,
            crypto_fine_grained_verify_dealing_private_duration_seconds,
            crypto_fine_grained_verify_dealing_public_duration_seconds,
            crypto_iccsa_verification_duration_seconds: r.histogram_vec(
                "crypto_iccsa_verification_duration_seconds",
                "Histogram of a canister signature verification call durations in seconds",
                 {
                    // In the experiments, lower bound that has not been reached was 0.00001 and the upper bound was 0.2.
                    // Generate an exponential progression as `start * factor.pow(i)`, s.t. the biggest value is minimally
                    // larger than `threshold`.
                    let start = 0.00001f64;
                    let factor = 2.0f64;
                    let threshold = 0.2f64;
                    let count = 1 + (threshold / start).log(factor).ceil() as usize;
                    let buckets = ic_metrics::buckets::exponential_buckets(start, factor, count);
                    debug_assert_eq!(buckets[0], start);
                    debug_assert_eq!(buckets[buckets.len() - 1], start * factor.powi(count as i32 - 1));
                    debug_assert!((buckets[buckets.len() - 1] / factor) < threshold);
                    buckets
                },
                &["result"],
            ),
            crypto_idkg_dealing_encryption_pubkey_count: idkg_dealing_encryption_pubkey_count,
            crypto_idkg_load_transcript_error: r.int_gauge(
                "crypto_idkg_load_transcript_error",
                "Error while loading iDKG transcript",
            ),
            crypto_key_counts: key_counts,
            crypto_key_rotation_results: rotation_results,
            crypto_keys_in_registry_missing_locally_total: r.int_counter(
                "crypto_keys_in_registry_missing_locally_total",
                "One or more keys in the registry is missing locally. This may occur if an adversary manages to register its keys on behalf of a node."
            ),
            crypto_boolean_results: boolean_results,
            crypto_parameter_byte_sizes: r.histogram_vec(
                "crypto_parameter_byte_sizes",
                "Byte sizes of crypto operation parameters",
                vec![
                    1000.0, 10000.0, 100000.0, 1000000.0, 2000000.0, 4000000.0, 8000000.0,
                    16000000.0, 20000000.0, 24000000.0, 28000000.0, 30000000.0,
                ],
                &["method_name", "parameter_name", "domain", "result"],
            ),
            crypto_vault_message_sizes: r.histogram_vec(
                "crypto_vault_message_sizes",
                "Byte sizes of crypto vault messages",
                vec![
                    500.0, 1000.0, 5000.0, 10000.0, 50000.0, 100000.0, 250000.0,
                    500000.0, 1000000.0, 8000000.0, 16000000.0, 32000000.0,
                ],
                &["service_type", "message_type", "domain", "method_name"],
            ),
            crypto_vault_message_serialization_duration_seconds: r.histogram_vec(
                "crypto_vault_message_serialization_duration_seconds",
                "Duration in seconds of (de)serialization",
                vec![0.000_001, 0.000_01, 0.000_1, 0.001, 0.01, 0.1, 1.0, 10.0],
                &["service_type", "message_type", "domain", "method_name"],
            ),
            crypto_bls12_381_sig_cache_metrics: bls12_381_sig_cache::Metrics {
                cache_size: r.int_gauge(
                    "crypto_bls12_381_sig_cache_size",
                    "Size of cache for successfully verified BLS12-381 threshold signatures",
                ),
                cache_hits: r.int_counter(
                    "crypto_bls12_381_sig_cache_hits",
                "Number of cache hits for successfully verified BLS12-381 threshold signatures"),
                cache_misses: r.int_counter(
                    "crypto_bls12_381_sig_cache_misses",
                "Number of cache misses for successfully verified BLS12-381 threshold signatures"),
            },
            crypto_bls12_381_point_cache_metrics: bls12_381_point_cache::Metrics {
                cache_size: r.int_gauge(
                    "crypto_bls12_381_point_cache_size",
                    "Size of cache for successfully decoded BLS12-381 points",
                ),
                cache_hits: r.int_counter(
                    "crypto_bls12_381_point_cache_hits",
                "Number of cache hits for successfully decoded BLS12-381 points"),
                cache_misses: r.int_counter(
                    "crypto_bls12_381_point_cache_misses",
                "Number of cache misses for successfully decoded BLS12-381 points"),
            },
            crypto_bls12_381_g2_prep_cache_metrics: bls12_381_g2_prep_cache::Metrics {
                cache_size: r.int_gauge(
                    "crypto_bls12_381_g2_prep_cache_size",
                    "Size of cache of BLS12-381 G2Prepared",
                ),
                cache_hits: r.int_counter(
                    "crypto_bls12_381_g2_prep_cache_hits",
                "Number of cache hits of BLS12-381 G2Prepared cache"),
                cache_misses: r.int_counter(
                    "crypto_bls12_381_g2_prep_cache_misses",
                "Number of cache misses of BLS12-381 G2Prepared cache"),
            },
            observe_minimum_epoch_in_active_nidkg_transcripts: r.gauge(
                "crypto_minimum_epoch_in_active_nidkg_transcripts",
                "Minimum epoch in active NI-DKG transcripts"
            ),
            observe_epoch_in_loaded_nidkg_transcript: r.gauge(
                "crypto_epoch_in_loaded_nidkg_transcript",
                "Epoch in loaded NI-DKG transcript"
            ),
            observe_minimum_registry_version_in_active_idkg_transcripts: r.gauge(
                "crypto_minimum_registry_version_in_active_idkg_transcripts",
                "Minimum registry version in active iDKG transcripts"
            ),
            crypto_latest_idkg_dealing_encryption_public_key_too_old_but_not_in_registry: r.int_counter(
                "crypto_latest_idkg_dealing_encryption_public_key_too_old_but_not_in_registry",
                "latest iDKG dealing encryption public key too old, but not in registry"
            ),
            crypto_secret_key_store_cleanup_error: r.int_counter(
                "crypto_secret_key_store_cleanup_error",
                "Error while cleaning up secret key store"
            ),
        }
    }
}
