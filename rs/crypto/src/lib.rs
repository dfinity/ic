//! This crate provides the `CryptoComponent` and a set of static methods that
//! allows Internet Computer nodes to perform crypto operations such as key
//! generation, distributed key generation, hashing, signing, signature
//! verification, TLS handshakes, and random number generation.
//!
//! Please refer to the 'Trait Implementations' section of the
//! `CryptoComponentFatClient` to get an overview of the functionality offered
//! by the `CryptoComponent`.
//!
//! # Architecture Overview
//! TODO [CRP-1673](https://dfinity.atlassian.net/browse/CRP-1673)
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

mod common;
mod keygen;
mod sign;
mod tls;

pub use sign::utils::{
    ecdsa_p256_signature_from_der_bytes, ed25519_public_key_to_der, rsa_signature_from_bytes,
    threshold_sig_public_key_from_der, threshold_sig_public_key_to_der, user_public_key_from_bytes,
    verify_combined_threshold_sig, KeyBytesContentType,
};
pub use sign::{get_mega_pubkey, get_tecdsa_master_public_key, MegaKeyFromRegistryError};

use crate::sign::ThresholdSigDataStoreImpl;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_csp::api::NodePublicKeyData;
use ic_crypto_internal_csp::{CryptoServiceProvider, Csp};
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_node_key_generation::derive_node_id;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces::crypto::{BasicSigner, KeyManager, ThresholdSigVerifierByPublicKey};
use ic_interfaces::time_source::{SysTimeSource, TimeSource};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{new_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_types::consensus::CatchUpContentProtobufBytes;
use ic_types::crypto::{CryptoError, CryptoResult, KeyPurpose};
use ic_types::messages::MessageId;
use ic_types::{NodeId, RegistryVersion, Time};
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use rand::{CryptoRng, Rng};
use std::fmt;
use std::sync::Arc;

/// Defines the maximum number of entries contained in the
/// `ThresholdSigDataStore`.
pub const THRESHOLD_SIG_DATA_STORE_CAPACITY: usize = ThresholdSigDataStoreImpl::CAPACITY;

/// A type alias for `CryptoComponentFatClient<Csp>`.
/// See the Rust documentation of `CryptoComponentFatClient`.
pub type CryptoComponent = CryptoComponentFatClient<Csp>;

/// A crypto component that offers limited functionality and can be used outside
/// of the replica process.
///
/// This is an intermediate solution before crypto runs in a separate process.
///
/// This should be used whenever crypto is required on a node, but a
/// full-fledged `CryptoComponent` is not available. Example use cases are in
/// separate process such as ic-fe or the orchestrator.
///
/// Do not instantiate a CryptoComponent outside of the replica process, since
/// that may lead to problems with concurrent access to the secret key store.
/// `CryptoComponentForNonReplicaProcess` guarantees that only methods are
/// exposed that don't risk running into such concurrency issues, as they do not
/// modify the secret key store.
pub trait CryptoComponentForNonReplicaProcess:
    KeyManager
    + BasicSigner<MessageId>
    + ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes>
    + TlsHandshake
    + Send
    + Sync // TODO(CRP-606): add API for authenticating registry queries.
{
}

// Blanket implementation of `CryptoComponentForNonReplicaProcess` for all types
// that fulfill the requirements.
impl<T> CryptoComponentForNonReplicaProcess for T where
    T: KeyManager
        + BasicSigner<MessageId>
        + ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes>
        + TlsHandshake
        + Send
        + Sync
{
}

/// Allows Internet Computer nodes to perform crypto operations such as
/// distributed key generation, signing, signature verification, and TLS
/// handshakes.
pub struct CryptoComponentFatClient<C: CryptoServiceProvider> {
    lockable_threshold_sig_data_store: LockableThresholdSigDataStore,
    csp: C,
    registry_client: Arc<dyn RegistryClient>,
    // The node id of the node that instantiated this crypto component.
    node_id: NodeId,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
    time_source: Arc<dyn CryptoTime>,
}

/// A `ThresholdSigDataStore` that is wrapped by a `RwLock`.
///
/// This is a store for data required to verify threshold signatures, see the
/// Rust documentation of the `ThresholdSigDataStore` trait.
pub struct LockableThresholdSigDataStore {
    threshold_sig_data_store: RwLock<ThresholdSigDataStoreImpl>,
}

#[allow(clippy::new_without_default)] // we don't need a default impl
impl LockableThresholdSigDataStore {
    /// Creates a store.
    pub fn new() -> Self {
        Self {
            threshold_sig_data_store: RwLock::new(ThresholdSigDataStoreImpl::new()),
        }
    }

    /// Returns a write lock to the store.
    pub fn write(&self) -> RwLockWriteGuard<'_, ThresholdSigDataStoreImpl> {
        self.threshold_sig_data_store.write()
    }

    /// Returns a read lock to the store.
    pub fn read(&self) -> RwLockReadGuard<'_, ThresholdSigDataStoreImpl> {
        self.threshold_sig_data_store.read()
    }
}

impl CryptoComponentFatClient<Csp> {
    /// Creates a crypto component using the given `csprng` and fake `node_id`.
    /// Note that `R: 'static` is required so that `CspTlsHandshakeSignerProvider`
    /// can be implemented for [Csp]. See the documentation of the respective `impl`
    /// block for more details on the meaning of `R: 'static`.
    pub fn new_with_rng_and_fake_node_id<R: Rng + CryptoRng + Send + Sync + 'static>(
        csprng: R,
        config: &CryptoConfig,
        logger: ReplicaLogger,
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> Self {
        Self::new_with_csp_and_fake_node_id(
            Csp::new_with_rng(csprng, config),
            logger,
            registry_client,
            node_id,
        )
    }
}

impl<C: CryptoServiceProvider> CryptoComponentFatClient<C> {
    /// Creates a crypto component using the given `csp` and fake `node_id`.
    pub fn new_with_csp_and_fake_node_id(
        csp: C,
        logger: ReplicaLogger,
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> Self {
        CryptoComponentFatClient {
            lockable_threshold_sig_data_store: LockableThresholdSigDataStore::new(),
            csp,
            registry_client,
            node_id,
            logger,
            metrics: Arc::new(CryptoMetrics::none()),
            time_source: Arc::new(SysTimeSource::new()),
        }
    }
}

impl<C: CryptoServiceProvider> fmt::Debug for CryptoComponentFatClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CryptoComponentFatClient {{ csp: <OMITTED>, registry: <OMITTED> }}"
        )
    }
}

impl CryptoComponentFatClient<Csp> {
    /// Creates a new crypto component.
    ///
    /// This is the constructor to use to create the replica's / node's crypto
    /// component.
    ///
    /// Multiple crypto components must share the same state to avoid problems
    /// due to concurrent state access. To achieve this, we recommend to
    /// instantiate multiple components as in the example below.
    ///
    /// WARNING: Multiple crypto components must be instantiated with
    /// `Arc::clone` as in the example. Do not create multiple crypto
    /// components with the same config (as opposed to using `Arc::clone`),
    /// as this will lead to concurrency issues e.g. when the components
    /// access the secret key store simultaneously.
    ///
    /// If the `config`'s vault type is `UnixSocket`, a `tokio_runtime_handle`
    /// must be provided, which is then used for the `async`hronous
    /// communication with the vault via RPC for secret key operations. In most
    /// cases, this is done by calling `tokio::runtime::Handle::block_on` and
    /// it is the caller's responsibility to ensure that these calls to
    /// `block_on` do not panic. This can be achieved, for example, by ensuring
    /// that the crypto component's methods are not themselves called from
    /// within a call to `block_on` (because calls to `block_on` cannot be
    /// nested), or by wrapping them with `tokio::task::block_in_place`
    /// and accepting the performance implications.
    ///
    /// # Panics
    /// Panics if the `config`'s vault type is `UnixSocket` and
    /// `tokio_runtime_handle` is `None`.
    ///
    /// ```
    /// use ic_config::crypto::CryptoConfig;
    /// use ic_crypto::CryptoComponent;
    /// use ic_logger::replica_logger::no_op_logger;
    /// use std::sync::Arc;
    /// use ic_registry_client_fake::FakeRegistryClient;
    /// use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    /// use ic_metrics::MetricsRegistry;
    ///
    /// CryptoConfig::run_with_temp_config(|config| {
    ///     // instantiate a registry somehow
    ///     let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    ///
    ///     // get a logger and metrics registry
    ///     let logger = no_op_logger();
    ///     let metrics_registry = MetricsRegistry::new();
    ///
    ///     # // generate the node keys in the secret key store needed for this example to work:
    ///     # ic_crypto_node_key_generation::get_node_keys_or_generate_if_missing(&config, None);
    ///     let first_crypto_component = Arc::new(CryptoComponent::new(&config, None, Arc::new(registry_client), logger, Some(&metrics_registry)));
    ///     let second_crypto_component = Arc::clone(&first_crypto_component);
    /// });
    /// ```
    pub fn new(
        config: &CryptoConfig,
        tokio_runtime_handle: Option<tokio::runtime::Handle>,
        registry_client: Arc<dyn RegistryClient>,
        logger: ReplicaLogger,
        metrics_registry: Option<&MetricsRegistry>,
    ) -> Self {
        let metrics = Arc::new(CryptoMetrics::new(metrics_registry));
        let csp = Csp::new(
            config,
            tokio_runtime_handle,
            Some(new_logger!(&logger)),
            Arc::clone(&metrics),
        );
        let node_pks = csp.current_node_public_keys();
        let node_signing_pk = node_pks
            .node_signing_public_key
            .as_ref()
            .expect("Missing node signing public key");
        let node_id = derive_node_id(node_signing_pk);
        let latest_registry_version = registry_client.get_latest_version();
        let crypto_component = CryptoComponentFatClient {
            lockable_threshold_sig_data_store: LockableThresholdSigDataStore::new(),
            csp,
            registry_client,
            node_id,
            logger,
            metrics,
            time_source: Arc::new(SysTimeSource::new()),
        };
        crypto_component.collect_and_store_key_count_metrics(latest_registry_version);
        crypto_component
    }

    /// Creates a crypto component using a fake `node_id`.
    ///
    /// # Panics
    /// Panics if the `config`'s vault type is `UnixSocket` and
    /// `tokio_runtime_handle` is `None`.
    pub fn new_with_fake_node_id(
        config: &CryptoConfig,
        tokio_runtime_handle: Option<tokio::runtime::Handle>,
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
        logger: ReplicaLogger,
        time_source: Arc<dyn CryptoTime>,
    ) -> Self {
        let metrics = Arc::new(CryptoMetrics::none());
        CryptoComponentFatClient {
            lockable_threshold_sig_data_store: LockableThresholdSigDataStore::new(),
            csp: Csp::new(config, tokio_runtime_handle, None, Arc::clone(&metrics)),
            registry_client,
            node_id,
            logger,
            metrics,
            time_source,
        }
    }

    /// Creates a crypto component that offers limited functionality and can be
    /// used outside of the replica process.
    ///
    /// Please refer to the trait documentation of
    /// `CryptoComponentForNonReplicaProcess` for more details.
    ///
    /// If the `config`'s vault type is `UnixSocket`, a `tokio_runtime_handle`
    /// must be provided, which is then used for the `async`hronous
    /// communication with the vault via RPC for secret key operations. In most
    /// cases, this is done by calling `tokio::runtime::Handle::block_on` and
    /// it is the caller's responsibility to ensure that these calls to
    /// `block_on` do not panic. This can be achieved, for example, by ensuring
    /// that the crypto component's methods are not themselves called from
    /// within a call to `block_on` (because calls to `block_on` cannot be
    /// nested), or by wrapping them with `tokio::task::block_in_place`
    /// and accepting the performance implications.
    /// Because the asynchronous communication with the vault happens only for
    /// secret key operations, for the `CryptoComponentFatClient` the concerned
    /// methods are
    /// * `KeyManager::check_keys_with_registry`
    /// * `BasicSigner::sign_basic`
    ///
    /// The methods of the `TlsHandshake` trait are unaffected by this.
    ///
    /// # NOTE:
    /// Callers of this method are strongly encouraged to switch from using
    /// `CryptoComponentForNonReplicaProcess`, to using the full crypto component,
    /// by calling `new` instead of `new_for_non_replica_process`.
    ///
    /// # Panics
    /// Panics if the `config`'s vault type is `UnixSocket` and
    /// `tokio_runtime_handle` is `None`.
    pub fn new_for_non_replica_process(
        config: &CryptoConfig,
        tokio_runtime_handle: Option<tokio::runtime::Handle>,
        registry_client: Arc<dyn RegistryClient>,
        logger: ReplicaLogger,
        metrics_registry: Option<&MetricsRegistry>,
    ) -> impl CryptoComponentForNonReplicaProcess {
        CryptoComponentFatClient::new(
            config,
            tokio_runtime_handle,
            registry_client,
            logger,
            metrics_registry,
        )
    }

    /// Returns the `NodeId` of this crypto component.
    pub fn get_node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn registry_client(&self) -> &Arc<dyn RegistryClient> {
        &self.registry_client
    }
}

fn key_from_registry(
    registry: Arc<dyn RegistryClient>,
    node_id: NodeId,
    key_purpose: KeyPurpose,
    registry_version: RegistryVersion,
) -> CryptoResult<PublicKeyProto> {
    use ic_registry_client_helpers::crypto::CryptoRegistry;
    let maybe_pk_proto =
        registry.get_crypto_key_for_node(node_id, key_purpose, registry_version)?;
    match maybe_pk_proto {
        Some(pk_proto) => Ok(pk_proto),
        None => Err(CryptoError::PublicKeyNotFound {
            node_id,
            key_purpose,
            registry_version,
        }),
    }
}

/// Get an identifier to use with logging. If debug logging is not enabled for the caller, a
/// `log_id` of 0 is returned.
/// The main criteria for the identifier, and the generation thereof, are:
///  * Should be fast to generate
///  * Should not have too many collisions within a short time span (e.g., 5 minutes)
///  * The generation of the identifier should not block or panic
///  * The generation of the identifier should not require synchronization between threads
fn get_log_id(logger: &ReplicaLogger, module_path: &'static str) -> u64 {
    if logger.is_enabled_at(slog::Level::Debug, module_path) {
        ic_types::time::current_time().as_nanos_since_unix_epoch()
    } else {
        0
    }
}

pub trait CryptoTime: Send + Sync + TimeSource {
    fn get_current_time(&self) -> Time;
}

impl CryptoTime for SysTimeSource {
    fn get_current_time(&self) -> Time {
        self.update_time().expect("Cannot update crypto time");
        self.get_relative_time()
    }
}
