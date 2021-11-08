mod basic_sig;
mod multi_sig;
mod ni_dkg;
mod secret_key_store;
mod threshold_sig;
mod tls;

use crate::secret_key_store::{SecretKeyStore, SecretKeyStoreError};
use crate::types::CspSecretKey;
use crate::CspRwLock;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_logger::replica_logger::no_op_logger;
use ic_logger::ReplicaLogger;
use ic_types::crypto::KeyId;
use parking_lot::{RwLockReadGuard, RwLockWriteGuard};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use std::sync::Arc;

/// An implementation of `CspServer`-trait that runs in-process
/// and uses a local storage for the secret keys.
pub struct LocalCspServer<R: Rng + CryptoRng, S: SecretKeyStore> {
    // CSPRNG stands for cryptographically secure random number generator.
    csprng: CspRwLock<R>,
    secret_key_store: CspRwLock<S>,
    logger: ReplicaLogger,
}

impl<S: SecretKeyStore> LocalCspServer<OsRng, S> {
    pub fn new(secret_key_store: S, metrics: Arc<CryptoMetrics>, logger: ReplicaLogger) -> Self {
        let csprng = OsRng::default();
        let csprng = CspRwLock::new_for_rng(csprng, Arc::clone(&metrics));
        LocalCspServer {
            csprng,
            secret_key_store: CspRwLock::new_for_sks(secret_key_store, metrics),
            logger,
        }
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> LocalCspServer<R, S> {
    /// Creates a local CSP server for testing.
    ///
    /// Note: This MUST NOT be used in production as the secrecy of the secret
    /// key store is not guaranteed.
    pub fn new_for_test(csprng: R, secret_key_store: S) -> Self {
        let metrics = Arc::new(CryptoMetrics::none());
        LocalCspServer {
            csprng: CspRwLock::new_for_rng(csprng, Arc::clone(&metrics)),
            secret_key_store: CspRwLock::new_for_sks(secret_key_store, metrics),
            logger: no_op_logger(),
        }
    }

    fn rng_write_lock(&self) -> RwLockWriteGuard<'_, R> {
        // TODO (CRP-696): inline this method
        self.csprng.write()
    }

    pub fn sks_write_lock(&self) -> RwLockWriteGuard<'_, S> {
        // TODO (CRP-696): inline this method
        self.secret_key_store.write()
    }

    pub fn sks_read_lock(&self) -> RwLockReadGuard<'_, S> {
        // TODO (CRP-696): inline this method
        self.secret_key_store.read()
    }

    fn store_secret_key_or_panic(&self, csp_secret_key: CspSecretKey, key_id: KeyId) {
        match &self.sks_write_lock().insert(key_id, csp_secret_key, None) {
            Ok(()) => {}
            Err(SecretKeyStoreError::DuplicateKeyId(key_id)) => {
                panic!("A key with ID {} has already been inserted", key_id);
            }
        };
    }
}
