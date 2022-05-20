#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
//#![deny(missing_docs)]

//! Interface for the cryptographic service provider

pub mod api;
pub mod canister_threshold;
pub mod imported_test_utils;
pub mod imported_utilities;
pub mod public_key_store;
mod remaining_conversions;
pub mod secret_key_store;
pub mod threshold;
pub mod tls;
pub mod types;
pub mod vault;

pub use crate::vault::api::TlsHandshakeCspVault;
pub use crate::vault::local_csp_vault::LocalCspVault;
pub use crate::vault::remote_csp_vault::run_csp_vault_server;
use crate::vault::remote_csp_vault::RemoteCspVault;

use crate::api::{
    CspIDkgProtocol, CspKeyGenerator, CspSecretKeyStoreChecker, CspSigner,
    CspThresholdEcdsaSigVerifier, CspThresholdEcdsaSigner, CspTlsClientHandshake,
    CspTlsHandshakeSignerProvider, CspTlsServerHandshake, NiDkgCspClient, NodePublicKeyData,
    ThresholdSignatureCspClient,
};
use crate::keygen::{forward_secure_key_id, public_key_hash_as_key_id};
use crate::public_key_store::read_node_public_keys;
use crate::secret_key_store::volatile_store::VolatileSecretKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::types::CspPublicKey;
use crate::vault::api::CspVault;
use ic_config::crypto::{CryptoConfig, CspVaultType};
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPublicKey;
use ic_logger::{info, new_logger, replica_logger::no_op_logger, ReplicaLogger};
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_types::crypto::KeyId;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use secret_key_store::proto_store::ProtoSecretKeyStore;
use std::convert::TryFrom;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

const SKS_DATA_FILENAME: &str = "sks_data.pb";
const CANISTER_SKS_DATA_FILENAME: &str = "canister_sks_data.pb";

/// Describes the interface of the crypto service provider (CSP), e.g. for
/// signing and key generation. The Csp struct implements this trait.
pub trait CryptoServiceProvider:
    CspSigner
    + CspKeyGenerator
    + ThresholdSignatureCspClient
    + NiDkgCspClient
    + CspIDkgProtocol
    + CspThresholdEcdsaSigner
    + CspThresholdEcdsaSigVerifier
    + CspSecretKeyStoreChecker
    + CspTlsServerHandshake
    + CspTlsClientHandshake
    + CspTlsHandshakeSignerProvider
    + NodePublicKeyData
{
}

impl<T> CryptoServiceProvider for T where
    T: CspSigner
        + CspKeyGenerator
        + ThresholdSignatureCspClient
        + CspIDkgProtocol
        + CspThresholdEcdsaSigner
        + CspThresholdEcdsaSigVerifier
        + NiDkgCspClient
        + CspSecretKeyStoreChecker
        + CspTlsServerHandshake
        + CspTlsClientHandshake
        + CspTlsHandshakeSignerProvider
        + NodePublicKeyData
{
}

struct SksKeyIds {
    node_signing_key_id: Option<KeyId>,
    dkg_dealing_encryption_key_id: Option<KeyId>,
}

struct PublicKeyData {
    node_public_keys: NodePublicKeys,
    sks_key_ids: SksKeyIds,
}

impl PublicKeyData {
    fn new(node_public_keys: NodePublicKeys) -> Self {
        let node_signing_key_id = match node_public_keys.node_signing_pk.to_owned() {
            None => None,
            Some(node_signing_pk) => {
                let csp_pk = CspPublicKey::try_from(node_signing_pk)
                    .expect("Unsupported public key proto as node signing public key.");
                Some(public_key_hash_as_key_id(&csp_pk))
            }
        };

        let dkg_dealing_encryption_key_id = match node_public_keys
            .dkg_dealing_encryption_pk
            .to_owned()
        {
            None => None,
            Some(dkg_dealing_encryption_pk) => {
                let csp_pk = CspFsEncryptionPublicKey::try_from(dkg_dealing_encryption_pk)
                    .expect("Unsupported public key proto as dkg dealing encryption public key.");
                Some(forward_secure_key_id(&csp_pk))
            }
        };
        let sks_key_ids = SksKeyIds {
            node_signing_key_id,
            dkg_dealing_encryption_key_id,
        };
        PublicKeyData {
            node_public_keys,
            sks_key_ids,
        }
    }
}

/// Implements the CryptoServiceProvider for an RNG and a SecretKeyStore.
pub struct Csp<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> {
    // CSPRNG stands for cryptographically secure random number generator.
    csprng: CspRwLock<R>,
    csp_vault: Arc<dyn CspVault>,
    public_key_data: PublicKeyData,
    logger: ReplicaLogger,
    // TODO(CRP-1325): remove S, C generics.
    _marker: std::marker::PhantomData<(S, C)>,
}

/// This lock provides the option to add metrics about lock acquisition times.
struct CspRwLock<T> {
    name: String,
    rw_lock: RwLock<T>,
    metrics: Arc<CryptoMetrics>,
}

impl<T> CspRwLock<T> {
    pub fn new_for_rng(content: T, metrics: Arc<CryptoMetrics>) -> Self {
        // Note: The name will appear on metric dashboards and may be used in alerts, do
        // not change this unless you are also updating the monitoring.
        Self::new(content, "csprng".to_string(), metrics)
    }

    pub fn new_for_sks(content: T, metrics: Arc<CryptoMetrics>) -> Self {
        // Note: The name will appear on metric dashboards and may be used in alerts, do
        // not change this unless you are also updating the monitoring.
        Self::new(content, "secret_key_store".to_string(), metrics)
    }

    pub fn new_for_csks(content: T, metrics: Arc<CryptoMetrics>) -> Self {
        // Note: The name will appear on metric dashboards and may be used in alerts, do
        // not change this unless you are also updating the monitoring.
        Self::new(content, "canister_secret_key_store".to_string(), metrics)
    }

    fn new(content: T, lock_name: String, metrics: Arc<CryptoMetrics>) -> Self {
        Self {
            name: lock_name,
            rw_lock: RwLock::new(content),
            metrics,
        }
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        let start_time = self.metrics.now();
        let write_guard = self.rw_lock.write();
        self.observe(&self.metrics, "write", start_time);
        write_guard
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        let start_time = self.metrics.now();
        let read_guard = self.rw_lock.read();
        self.observe(&self.metrics, "read", start_time);
        read_guard
    }

    fn observe(&self, metrics: &CryptoMetrics, access: &str, start_time: Option<Instant>) {
        metrics.observe_lock_acquisition_duration_seconds(&self.name, access, start_time);
    }
}

// CRP-1248: inline the following methods
impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> Csp<R, S, C> {
    fn rng_write_lock(&self) -> RwLockWriteGuard<'_, R> {
        self.csprng.write()
    }
}

impl Csp<OsRng, ProtoSecretKeyStore, ProtoSecretKeyStore> {
    /// Creates a production-grade crypto service provider.
    pub fn new(
        config: &CryptoConfig,
        logger: Option<ReplicaLogger>,
        metrics: Arc<CryptoMetrics>,
    ) -> Self {
        match &config.csp_vault_type {
            CspVaultType::InReplica => Self::new_with_in_replica_vault(config, logger, metrics),
            CspVaultType::UnixSocket(socket_path) => {
                Self::new_with_unix_socket_vault(socket_path, config, logger, metrics)
            }
        }
    }

    fn new_with_in_replica_vault(
        config: &CryptoConfig,
        logger: Option<ReplicaLogger>,
        metrics: Arc<CryptoMetrics>,
    ) -> Self {
        let logger = logger.unwrap_or_else(no_op_logger);
        info!(
            logger,
            "Proceeding with an in-replica csp_vault, CryptoConfig: {:?}", config
        );
        let secret_key_store = ProtoSecretKeyStore::open(
            &config.crypto_root,
            SKS_DATA_FILENAME,
            Some(new_logger!(&logger)),
        );
        let canister_key_store = ProtoSecretKeyStore::open(
            &config.crypto_root,
            CANISTER_SKS_DATA_FILENAME,
            Some(new_logger!(&logger)),
        );
        let csp_vault = Arc::new(LocalCspVault::new(
            secret_key_store,
            canister_key_store,
            Arc::clone(&metrics),
            new_logger!(&logger),
        ));
        Self::csp_with(&config.crypto_root, logger, metrics, csp_vault)
    }

    fn new_with_unix_socket_vault(
        socket_path: &Path,
        config: &CryptoConfig,
        logger: Option<ReplicaLogger>,
        metrics: Arc<CryptoMetrics>,
    ) -> Self {
        let logger = logger.unwrap_or_else(no_op_logger);
        info!(
            logger,
            "Proceeding with a remote csp_vault, CryptoConfig: {:?}", config
        );
        let csp_vault = Arc::new(RemoteCspVault::new(socket_path).unwrap_or_else(|e| {
            panic!(
                "Could not connect to CspVault at socket {:?}: {:?}",
                socket_path, e
            )
        }));
        Self::csp_with(&config.crypto_root, logger, metrics, csp_vault)
    }

    fn csp_with(
        pk_path: &Path,
        logger: ReplicaLogger,
        metrics: Arc<CryptoMetrics>,
        csp_vault: Arc<dyn CspVault>,
    ) -> Self {
        let node_public_keys = read_node_public_keys(pk_path).unwrap_or_default();
        let public_key_data = PublicKeyData::new(node_public_keys);
        let csprng = CspRwLock::new_for_rng(OsRng::default(), metrics);
        Csp {
            csprng,
            public_key_data,
            csp_vault,
            logger,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<R: 'static + Rng + CryptoRng + Send + Sync + Clone>
    Csp<R, ProtoSecretKeyStore, VolatileSecretKeyStore>
{
    /// Creates a crypto service provider for testing.
    ///
    /// Note: This MUST NOT be used in production as the secrecy of the random
    /// number generator, hence the keys, is not guaranteed.
    pub fn new_with_rng(csprng: R, config: &CryptoConfig) -> Self {
        let node_public_keys = read_node_public_keys(&config.crypto_root).unwrap_or_default();
        let public_key_data = PublicKeyData::new(node_public_keys);
        Csp {
            csprng: CspRwLock::new_for_rng(csprng.clone(), Arc::new(CryptoMetrics::none())),
            public_key_data,
            csp_vault: Arc::new(LocalCspVault::new_for_test(
                csprng,
                ProtoSecretKeyStore::open(&config.crypto_root, SKS_DATA_FILENAME, None),
            )),
            logger: no_op_logger(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<R: Rng + CryptoRng + Send + Sync> Csp<R, VolatileSecretKeyStore, VolatileSecretKeyStore> {
    /// Resets public key data according to the given `NodePublicKeys`.
    ///
    /// Note: This is for testing only and MUST NOT be used in production.
    pub fn reset_public_key_data(&mut self, node_public_keys: NodePublicKeys) {
        self.public_key_data = PublicKeyData::new(node_public_keys);
    }
}

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> NodePublicKeyData
    for Csp<R, S, C>
{
    fn node_public_keys(&self) -> NodePublicKeys {
        self.public_key_data.node_public_keys.clone()
    }

    fn node_signing_key_id(&self) -> KeyId {
        self.public_key_data
            .sks_key_ids
            .node_signing_key_id
            .to_owned()
            .expect("Missing node signing key id")
    }

    fn dkg_dealing_encryption_key_id(&self) -> KeyId {
        self.public_key_data
            .sks_key_ids
            .dkg_dealing_encryption_key_id
            .to_owned()
            .expect("Missing dkg dealing encryption key id")
    }
}

impl<R: 'static + Rng + CryptoRng + Send + Sync + Clone, S: 'static + SecretKeyStore>
    Csp<R, S, VolatileSecretKeyStore>
{
    /// Creates a crypto service provider for testing.
    ///
    /// Note: This MUST NOT be used in production as the secrecy of the secret
    /// key store and the canister secret key store is not guaranteed.
    pub fn of(csprng: R, secret_key_store: S) -> Self {
        let node_public_keys = Default::default();
        let public_key_data = PublicKeyData::new(node_public_keys);
        let metrics = Arc::new(CryptoMetrics::none());
        Csp {
            csprng: CspRwLock::new_for_rng(csprng.clone(), metrics),
            public_key_data,
            csp_vault: Arc::new(LocalCspVault::new_for_test(csprng, secret_key_store)),
            logger: no_op_logger(),
            _marker: std::marker::PhantomData,
        }
    }
}

// Trait implementations:
pub mod keygen;
mod signer;
