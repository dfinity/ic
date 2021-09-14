mod threshold_sig;

use crate::secret_key_store::SecretKeyStore;
use crate::{CspRwLock, PublicKeyData};
#[cfg(test)]
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
#[cfg(test)]
use ic_logger::replica_logger::no_op_logger;
use ic_logger::ReplicaLogger;
use parking_lot::{RwLockReadGuard, RwLockWriteGuard};
use rand::{CryptoRng, Rng};
#[cfg(test)]
use std::sync::Arc;

/// An implementation of `CspServer`-trait that runs in-process
/// and uses a local storage for the secret keys.
pub struct LocalCspServer<R: Rng + CryptoRng, S: SecretKeyStore> {
    // CSPRNG stands for cryptographically secure random number generator.
    #[allow(dead_code)]
    csprng: CspRwLock<R>,
    secret_key_store: CspRwLock<S>,
    #[allow(dead_code)]
    public_key_data: PublicKeyData,
    #[allow(dead_code)]
    logger: ReplicaLogger,
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> LocalCspServer<R, S> {
    /// Creates a local CSP server for testing.
    ///
    /// Note: This MUST NOT be used in production as the secrecy of the secret
    /// key store is not guaranteed.
    #[cfg(test)]
    pub fn new_for_test(csprng: R, secret_key_store: S) -> Self {
        let node_public_keys = Default::default();
        let public_key_data = PublicKeyData::new(node_public_keys);
        let metrics = Arc::new(CryptoMetrics::none());
        LocalCspServer {
            csprng: CspRwLock::new_for_rng(csprng, Arc::clone(&metrics)),
            public_key_data,
            secret_key_store: CspRwLock::new_for_sks(secret_key_store, metrics),
            logger: no_op_logger(),
        }
    }

    #[allow(dead_code)]
    fn rng_write_lock(&self) -> RwLockWriteGuard<'_, R> {
        // TODO (CRP-696): inline this method
        self.csprng.write()
    }

    #[allow(dead_code)]
    fn sks_write_lock(&self) -> RwLockWriteGuard<'_, S> {
        // TODO (CRP-696): inline this method
        self.secret_key_store.write()
    }

    #[allow(dead_code)]
    fn sks_read_lock(&self) -> RwLockReadGuard<'_, S> {
        // TODO (CRP-696): inline this method
        self.secret_key_store.read()
    }
}
