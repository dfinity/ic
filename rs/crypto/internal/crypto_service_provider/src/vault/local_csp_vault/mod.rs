mod basic_sig;
mod idkg;
mod multi_sig;
mod ni_dkg;
mod public_key_store;
mod public_seed;
mod secret_key_store;
mod tecdsa;
#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;
mod threshold_sig;
mod tls;

use crate::key_id::KeyId;
use crate::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::proto_store::ProtoSecretKeyStore;
use crate::secret_key_store::volatile_store::VolatileSecretKeyStore;
use crate::secret_key_store::{SecretKeyStore, SecretKeyStoreError};
use crate::types::CspSecretKey;
use crate::CspRwLock;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_logger::replica_logger::no_op_logger;
use ic_logger::ReplicaLogger;
use parking_lot::{RwLockReadGuard, RwLockWriteGuard};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use std::collections::HashSet;
use std::fs;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

/// An implementation of `CspVault`-trait that runs in-process
/// and uses local secret key stores.
///
/// # Remarks
///
/// Public methods of this struct may be called by implementers of the
/// [crate::vault::remote_csp_vault::TarpcCspVault] trait in a separate
/// thread. Panicking should therefore be avoided not to kill that thread.
pub struct LocalCspVault<
    R: Rng + CryptoRng,
    S: SecretKeyStore,
    C: SecretKeyStore,
    P: PublicKeyStore,
> {
    // CSPRNG stands for cryptographically secure random number generator.
    csprng: CspRwLock<R>,
    node_secret_key_store: CspRwLock<S>,
    canister_secret_key_store: CspRwLock<C>,
    public_key_store: CspRwLock<P>,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
}

impl LocalCspVault<OsRng, ProtoSecretKeyStore, ProtoSecretKeyStore, ProtoPublicKeyStore> {
    /// Creates a production-grade local CSP vault.
    ///
    /// # Panics
    /// If the key stores (`node_secret_key_store`,`canister_secret_key_store` or `public_key_store`)
    /// do not use distinct files.
    pub fn new(
        node_secret_key_store: ProtoSecretKeyStore,
        canister_secret_key_store: ProtoSecretKeyStore,
        public_key_store: ProtoPublicKeyStore,
        metrics: Arc<CryptoMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        ensure_unique_paths(&[
            node_secret_key_store.proto_file_path(),
            canister_secret_key_store.proto_file_path(),
            public_key_store.proto_file_path(),
        ]);
        LocalCspVault::new_internal(
            OsRng,
            node_secret_key_store,
            canister_secret_key_store,
            public_key_store,
            metrics,
            logger,
        )
    }
}

impl<R: Rng + CryptoRng>
    LocalCspVault<R, ProtoSecretKeyStore, ProtoSecretKeyStore, ProtoPublicKeyStore>
{
    pub fn new_in_temp_dir(rng: R) -> (Self, TempDir) {
        let temp_dir = tempfile::Builder::new()
            .prefix("ic_crypto_")
            .tempdir()
            .expect("failed to create temporary crypto directory");
        fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o750)).unwrap_or_else(|_| {
            panic!(
                "failed to set permissions of crypto directory {}",
                temp_dir.path().display()
            )
        });
        let sks_file = "temp_sks_data.pb";
        let canister_sks_file = "temp_canister_sks_data.pb";
        let public_key_store_file = "temp_public_keys.pb";

        let sks = ProtoSecretKeyStore::open(temp_dir.path(), sks_file, None);
        let canister_sks = ProtoSecretKeyStore::open(temp_dir.path(), canister_sks_file, None);
        let public_key_store = ProtoPublicKeyStore::open(temp_dir.path(), public_key_store_file);

        let vault = Self::new_internal(
            rng,
            sks,
            canister_sks,
            public_key_store,
            Arc::new(CryptoMetrics::none()),
            no_op_logger(),
        );
        (vault, temp_dir)
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, VolatileSecretKeyStore, P>
{
    /// Creates a local CSP vault for testing.
    ///
    /// Note: This MUST NOT be used in production as the secrecy of the secret
    /// key store is not guaranteed.
    pub fn new_for_test(csprng: R, node_secret_key_store: S, public_key_store: P) -> Self {
        let metrics = Arc::new(CryptoMetrics::none());
        Self::new_internal(
            csprng,
            node_secret_key_store,
            VolatileSecretKeyStore::new(),
            public_key_store,
            metrics,
            no_op_logger(),
        )
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn new_internal(
        csprng: R,
        node_secret_key_store: S,
        canister_secret_key_store: C,
        public_key_store: P,
        metrics: Arc<CryptoMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        LocalCspVault {
            csprng: CspRwLock::new_for_rng(csprng, Arc::clone(&metrics)),
            node_secret_key_store: CspRwLock::new_for_sks(
                node_secret_key_store,
                Arc::clone(&metrics),
            ),
            canister_secret_key_store: CspRwLock::new_for_csks(
                canister_secret_key_store,
                Arc::clone(&metrics),
            ),
            public_key_store: CspRwLock::new_for_public_key_store(
                public_key_store,
                Arc::clone(&metrics),
            ),
            logger,
            metrics,
        }
    }
}

// CRP-1248: inline the following methods
impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn rng_write_lock(&self) -> RwLockWriteGuard<'_, R> {
        self.csprng.write()
    }

    fn sks_write_lock(&self) -> RwLockWriteGuard<'_, S> {
        self.node_secret_key_store.write()
    }

    fn sks_read_lock(&self) -> RwLockReadGuard<'_, S> {
        self.node_secret_key_store.read()
    }

    fn public_key_store_read_lock(&self) -> RwLockReadGuard<'_, P> {
        self.public_key_store.read()
    }

    fn public_key_store_write_lock(&self) -> RwLockWriteGuard<'_, P> {
        self.public_key_store.write()
    }

    fn canister_sks_write_lock(&self) -> RwLockWriteGuard<'_, C> {
        self.canister_secret_key_store.write()
    }

    fn canister_sks_read_lock(&self) -> RwLockReadGuard<'_, C> {
        self.canister_secret_key_store.read()
    }

    fn store_secret_key(
        &self,
        csp_secret_key: CspSecretKey,
        key_id: KeyId,
    ) -> Result<(), SecretKeyStoreError> {
        self.sks_write_lock().insert(key_id, csp_secret_key, None)
    }
}

fn ensure_unique_paths(paths: &[&Path]) {
    let mut distinct_paths: HashSet<&Path> = HashSet::new();
    for path in paths {
        if !distinct_paths.insert(*path) {
            panic!(
                "Expected key stores to use distinct files but {:?} is used more than once",
                path
            )
        }
    }
    assert_eq!(
        paths.len(),
        distinct_paths.len(),
        "Key stores do not use distinct files"
    );
}
