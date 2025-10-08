#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
//#![deny(missing_docs)]

//! Interface for the cryptographic service provider

pub mod api;
#[cfg(test)]
pub mod builder_for_test;
pub mod canister_threshold;
#[cfg(test)]
pub mod imported_test_utils;
pub mod key_id;
pub mod keygen;
pub mod public_key_store;
pub mod secret_key_store;
mod signer;
pub mod threshold;
pub mod types;
pub mod vault;

pub use crate::vault::api::TlsHandshakeCspVault;
pub use crate::vault::local_csp_vault::LocalCspVault;
pub use crate::vault::remote_csp_vault::RemoteCspVault;
pub use crate::vault::remote_csp_vault::run_csp_vault_server;

use crate::api::{CspSigner, NiDkgCspClient, ThresholdSignatureCspClient};
use crate::secret_key_store::SecretKeyStore;
use crate::types::{CspPublicKey, ExternalPublicKeys};
use crate::vault::api::CspVault;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_logger::{ReplicaLogger, new_logger, replica_logger::no_op_logger};
use key_id::KeyId;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::sync::Arc;
use std::time::Instant;

#[cfg(test)]
mod tests;

/// Describes the interface of the crypto service provider (CSP), e.g. for
/// signing and key generation. The Csp struct implements this trait.
pub trait CryptoServiceProvider: CspSigner + ThresholdSignatureCspClient + NiDkgCspClient {}

impl<T> CryptoServiceProvider for T where T: CspSigner + ThresholdSignatureCspClient + NiDkgCspClient
{}

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
    pub fn new_from_config(
        config: &CryptoConfig,
        tokio_runtime_handle: Option<tokio::runtime::Handle>,
        logger: Option<ReplicaLogger>,
        metrics: Arc<CryptoMetrics>,
    ) -> Self {
        let logger = logger.unwrap_or_else(no_op_logger);
        let vault = vault::vault_from_config(
            config,
            tokio_runtime_handle,
            new_logger!(&logger),
            Arc::clone(&metrics),
        );
        Self::new_from_vault(vault, logger, metrics)
    }

    pub fn new_from_vault(
        vault: Arc<dyn CspVault>,
        logger: ReplicaLogger,
        metrics: Arc<CryptoMetrics>,
    ) -> Self {
        Csp {
            csp_vault: vault,
            logger,
            metrics,
        }
    }
}
