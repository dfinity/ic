#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
//#![deny(missing_docs)]

//! Interface for the cryptographic service provider

pub mod api;
pub mod canister_threshold;
pub mod imported_test_utils;
pub mod imported_utilities;
pub mod key_id;
pub mod keygen;
pub mod public_key_store;
pub mod secret_key_store;
mod signer;
pub mod threshold;
pub mod tls;
pub mod types;
pub mod vault;

pub use crate::vault::api::TlsHandshakeCspVault;
pub use crate::vault::local_csp_vault::LocalCspVault;
pub use crate::vault::remote_csp_vault::run_csp_vault_server;
use crate::vault::remote_csp_vault::RemoteCspVault;

use crate::api::{
    CspIDkgProtocol, CspKeyGenerator, CspSecretKeyStoreChecker, CspSigVerifier, CspSigner,
    CspThresholdEcdsaSigVerifier, CspThresholdEcdsaSigner, CspTlsHandshakeSignerProvider,
    DkgDealingEncryptionKeyIdRetrievalError, NiDkgCspClient, NodePublicKeyData,
    NodePublicKeyDataError, ThresholdSignatureCspClient,
};
use crate::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::types::{CspPublicKey, ExternalPublicKeys};
use crate::vault::api::{CspPublicKeyStoreError, CspVault};
use ic_config::crypto::{CryptoConfig, CspVaultType};
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPublicKey;
use ic_logger::{info, new_logger, replica_logger::no_op_logger, ReplicaLogger};
use ic_types::crypto::CurrentNodePublicKeys;
use key_id::KeyId;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use rand::{CryptoRng, Rng};
use secret_key_store::proto_store::ProtoSecretKeyStore;
use std::convert::TryFrom;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

#[cfg(test)]
mod tests;

const SKS_DATA_FILENAME: &str = "sks_data.pb";
const PUBLIC_KEY_STORE_DATA_FILENAME: &str = "public_keys.pb";
const CANISTER_SKS_DATA_FILENAME: &str = "canister_sks_data.pb";

/// Describes the interface of the crypto service provider (CSP), e.g. for
/// signing and key generation. The Csp struct implements this trait.
pub trait CryptoServiceProvider:
    CspSigner
    + CspSigVerifier
    + CspKeyGenerator
    + ThresholdSignatureCspClient
    + NiDkgCspClient
    + CspIDkgProtocol
    + CspThresholdEcdsaSigner
    + CspThresholdEcdsaSigVerifier
    + CspSecretKeyStoreChecker
    + CspTlsHandshakeSignerProvider
    + NodePublicKeyData
{
}

impl<T> CryptoServiceProvider for T where
    T: CspSigner
        + CspSigVerifier
        + CspKeyGenerator
        + ThresholdSignatureCspClient
        + CspIDkgProtocol
        + CspThresholdEcdsaSigner
        + CspThresholdEcdsaSigVerifier
        + NiDkgCspClient
        + CspSecretKeyStoreChecker
        + CspTlsHandshakeSignerProvider
        + NodePublicKeyData
{
}

/// Implements `CryptoServiceProvider` that uses a `CspVault` for
/// storing and managing secret keys.
pub struct Csp {
    csp_vault: Arc<dyn CspVault>,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
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

    pub fn new_for_public_key_store(content: T, metrics: Arc<CryptoMetrics>) -> Self {
        // Note: The name will appear on metric dashboards and may be used in alerts, do
        // not change this unless you are also updating the monitoring.
        Self::new(content, "public_key_store".to_string(), metrics)
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

impl Csp {
    /// Creates a production-grade crypto service provider.
    ///
    /// If the `config`'s vault type is `UnixSocket`, a `tokio_runtime_handle`
    /// must be provided, which is then used for the `async`hronous
    /// communication with the vault via RPC.
    ///
    /// # Panics
    /// Panics if the `config`'s vault type is `UnixSocket` and
    /// `tokio_runtime_handle` is `None`.
    pub fn new(
        config: &CryptoConfig,
        tokio_runtime_handle: Option<tokio::runtime::Handle>,
        logger: Option<ReplicaLogger>,
        metrics: Arc<CryptoMetrics>,
    ) -> Self {
        match &config.csp_vault_type {
            CspVaultType::InReplica => Self::new_with_in_replica_vault(config, logger, metrics),
            CspVaultType::UnixSocket(socket_path) => Self::new_with_unix_socket_vault(
                socket_path,
                tokio_runtime_handle.expect("missing tokio runtime handle"),
                config,
                logger,
                metrics,
            ),
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
        let public_key_store = ProtoPublicKeyStore::open(
            &config.crypto_root,
            PUBLIC_KEY_STORE_DATA_FILENAME,
            new_logger!(&logger),
        );
        let csp_vault = Arc::new(LocalCspVault::new(
            secret_key_store,
            canister_key_store,
            public_key_store,
            metrics.clone(),
            new_logger!(&logger),
        ));
        Csp {
            csp_vault,
            logger,
            metrics,
        }
    }

    fn new_with_unix_socket_vault(
        socket_path: &Path,
        rt_handle: tokio::runtime::Handle,
        config: &CryptoConfig,
        logger: Option<ReplicaLogger>,
        metrics: Arc<CryptoMetrics>,
    ) -> Self {
        let logger = logger.unwrap_or_else(no_op_logger);
        info!(
            logger,
            "Proceeding with a remote csp_vault, CryptoConfig: {:?}", config
        );
        let csp_vault = RemoteCspVault::new(
            socket_path,
            rt_handle,
            new_logger!(&logger),
            metrics.clone(),
        )
        .unwrap_or_else(|e| {
            panic!(
                "Could not connect to CspVault at socket {:?}: {:?}",
                socket_path, e
            )
        });
        Csp {
            csp_vault: Arc::new(csp_vault),
            logger,
            metrics,
        }
    }
}

impl NodePublicKeyData for Csp {
    fn pks_contains(
        &self,
        public_keys: CurrentNodePublicKeys,
    ) -> Result<bool, NodePublicKeyDataError> {
        self.csp_vault.pks_contains(public_keys).map_err(
            |CspPublicKeyStoreError::TransientInternalError(internal_error)| {
                NodePublicKeyDataError::TransientInternalError(internal_error)
            },
        )
    }

    fn current_node_public_keys(&self) -> Result<CurrentNodePublicKeys, NodePublicKeyDataError> {
        let pks = self.csp_vault.current_node_public_keys()?;
        Ok(pks)
    }

    fn current_node_public_keys_with_timestamps(
        &self,
    ) -> Result<CurrentNodePublicKeys, NodePublicKeyDataError> {
        let pks = self.csp_vault.current_node_public_keys_with_timestamps()?;
        Ok(pks)
    }

    fn dkg_dealing_encryption_key_id(
        &self,
    ) -> Result<KeyId, DkgDealingEncryptionKeyIdRetrievalError> {
        let pk = CspFsEncryptionPublicKey::try_from(
            self.current_node_public_keys()?
                .dkg_dealing_encryption_public_key
                .ok_or(DkgDealingEncryptionKeyIdRetrievalError::KeyNotFound)?,
        )
        .map_err(
            |e| DkgDealingEncryptionKeyIdRetrievalError::MalformedPublicKey {
                key_bytes: e.key_bytes,
                details: format!(
                    "Unsupported public key proto as dkg dealing encryption public key: {}",
                    e.internal_error
                ),
            },
        )?;
        Ok(KeyId::from(&pk))
    }

    fn idkg_dealing_encryption_pubkeys_count(&self) -> Result<usize, NodePublicKeyDataError> {
        let idkg_key_count = self.csp_vault.idkg_dealing_encryption_pubkeys_count()?;
        Ok(idkg_key_count)
    }
}

impl Csp {
    /// Creates a crypto service provider for testing.
    ///
    /// Note: This MUST NOT be used in production as the secrecy of the secret
    /// key store and the canister secret key store is not guaranteed.
    pub fn of<
        R: Rng + CryptoRng + Send + Sync + 'static,
        S: SecretKeyStore + 'static,
        P: PublicKeyStore + 'static,
    >(
        csprng: R,
        secret_key_store: S,
        public_key_store: P,
    ) -> Self {
        Csp {
            csp_vault: Arc::new(LocalCspVault::new_for_test(
                csprng,
                secret_key_store,
                public_key_store,
            )),
            logger: no_op_logger(),
            metrics: Arc::new(CryptoMetrics::none()),
        }
    }

    pub fn with_rng<R: Rng + CryptoRng + Send + Sync + 'static>(rng: R) -> Self {
        Csp::of(rng, TempSecretKeyStore::new(), TempPublicKeyStore::new())
    }
}
