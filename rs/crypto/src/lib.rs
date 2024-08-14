//! This crate provides the `CryptoComponent` and a set of static methods that
//! allows Internet Computer nodes to perform crypto operations such as key
//! generation, distributed key generation, hashing, signing, signature
//! verification, TLS handshakes, and random number generation.
//!
//! Please refer to the 'Trait Implementations' section of the
//! `CryptoComponentImpl` to get an overview of the functionality offered
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

use ic_crypto_internal_csp::vault::api::CspVault;
pub use sign::{
    get_master_public_key_from_transcript, retrieve_mega_public_key_from_registry,
    MegaKeyFromRegistryError,
};

use crate::sign::ThresholdSigDataStoreImpl;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_csp::vault::vault_from_config;
use ic_crypto_internal_csp::{CryptoServiceProvider, Csp};
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_utils_basic_sig::conversions::derive_node_id;
use ic_interfaces::crypto::KeyManager;
use ic_interfaces::time_source::{SysTimeSource, TimeSource};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{new_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert};
use ic_types::crypto::{CryptoError, CryptoResult, KeyPurpose};
use ic_types::{NodeId, RegistryVersion};
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::fmt;
use std::sync::Arc;

/// Defines the maximum number of entries contained in the
/// `ThresholdSigDataStore` per tag, where tag is of type `NiDkgTag`.
pub const THRESHOLD_SIG_DATA_STORE_CAPACITY_PER_TAG: usize =
    ThresholdSigDataStoreImpl::CAPACITY_PER_TAG;

/// A type alias for `CryptoComponentImpl<Csp>`.
/// See the Rust documentation of `CryptoComponentImpl`.
pub type CryptoComponent = CryptoComponentImpl<Csp>;

/// Allows Internet Computer nodes to perform crypto operations such as
/// distributed key generation, signing, signature verification, and TLS
/// handshakes.
pub struct CryptoComponentImpl<C: CryptoServiceProvider> {
    lockable_threshold_sig_data_store: LockableThresholdSigDataStore,
    vault: Arc<dyn CspVault>,
    csp: C,
    registry_client: Arc<dyn RegistryClient>,
    // The node id of the node that instantiated this crypto component.
    node_id: NodeId,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
    time_source: Arc<dyn TimeSource>,
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

/// Methods required for testing. Ideally, this block would be `#[test]` code,
/// but this is not possible as the methods are required outside of the crate.
impl<C: CryptoServiceProvider> CryptoComponentImpl<C> {
    /// Creates a crypto component using the given `csp` and fake `node_id`.
    pub fn new_for_test(
        csp: C,
        vault: Arc<dyn CspVault>,
        logger: ReplicaLogger,
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
        metrics: Arc<CryptoMetrics>,
        time_source: Option<Arc<dyn TimeSource>>,
    ) -> Self {
        CryptoComponentImpl {
            lockable_threshold_sig_data_store: LockableThresholdSigDataStore::new(),
            csp,
            vault,
            registry_client,
            node_id,
            logger,
            metrics,
            time_source: time_source.unwrap_or_else(|| Arc::new(SysTimeSource::new())),
        }
    }
}

impl<C: CryptoServiceProvider> fmt::Debug for CryptoComponentImpl<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CryptoComponentImpl {{ csp: <OMITTED>, registry: <OMITTED> }}"
        )
    }
}

impl CryptoComponentImpl<Csp> {
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
    ///     # ic_crypto_node_key_generation::generate_node_keys_once(&config, None).expect("error generating node public keys");
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
        let vault = vault_from_config(
            config,
            tokio_runtime_handle,
            new_logger!(&logger),
            Arc::clone(&metrics),
        );
        let csp = Csp::new_from_vault(
            Arc::clone(&vault),
            new_logger!(&logger),
            Arc::clone(&metrics),
        );
        let node_pks = vault
            .current_node_public_keys()
            .expect("Failed to retrieve node public keys");
        let node_signing_pk = node_pks
            .node_signing_public_key
            .as_ref()
            .expect("Missing node signing public key");
        let node_id =
            derive_node_id(node_signing_pk).expect("Node signing public key should be valid");
        let latest_registry_version = registry_client.get_latest_version();
        let crypto_component = CryptoComponentImpl {
            lockable_threshold_sig_data_store: LockableThresholdSigDataStore::new(),
            csp,
            vault,
            registry_client,
            node_id,
            time_source: Arc::new(SysTimeSource::new()),
            logger,
            metrics,
        };
        crypto_component.collect_and_store_key_count_metrics(latest_registry_version);
        crypto_component
    }

    /// Returns the `NodeId` of this crypto component.
    pub fn get_node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn registry_client(&self) -> &Arc<dyn RegistryClient> {
        &self.registry_client
    }

    fn collect_and_store_key_count_metrics(&self, registry_version: RegistryVersion) {
        let _ = self.check_keys_with_registry(registry_version);
    }
}

fn key_from_registry(
    registry: &dyn RegistryClient,
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
fn get_log_id(logger: &ReplicaLogger) -> u64 {
    if logger.is_enabled_at(slog::Level::Debug) {
        ic_types::time::current_time().as_nanos_since_unix_epoch()
    } else {
        0
    }
}
