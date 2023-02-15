mod basic_sig;
mod idkg;
mod multi_sig;
mod ni_dkg;
mod public_and_secret_key_store;
mod public_key_store;
mod public_seed;
mod secret_key_store;
mod tecdsa;
#[cfg(test)]
mod tests;
mod threshold_sig;
mod tls;

use crate::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::proto_store::ProtoSecretKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::CspRwLock;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_seed::Seed;
use ic_crypto_utils_time::CurrentSystemTimeSource;
use ic_interfaces::time_source::TimeSource;
use ic_logger::{new_logger, ReplicaLogger};
use ic_protobuf::registry::crypto::v1::PublicKey;
use parking_lot::{RwLockReadGuard, RwLockWriteGuard};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

/// An implementation of `CspVault`-trait that runs in-process
/// and uses local secret key stores.
///
/// # Deadlock prevention when locking multiple resources
///
/// To avoid circular waits and thus deadlocks when locking multiple resources
/// simultaneously, we define the following total order that MUST be
/// respected when *acquiring* multiple locks at the same time:
/// 1. `csprng`
/// 2. `node_secret_key_store`
/// 3. `canister_secret_key_store`
/// 4. `public_key_store`
///
/// Note that it is really just the order in which the locks are *acquired*
/// that matters for preventing circular waits, and not the order in which
/// the locks are released (see, e.g., [1]).
///
/// [1] https://softwareengineering.stackexchange.com/questions/418568/is-releases-mutexes-in-reverse-order-required-to-make-this-deadlock-prevention
///
/// # Remarks
///
/// Public methods of this struct may be called by implementers of the
/// [crate::vault::remote_csp_vault::TarpcCspVault] trait in a separate
/// thread. Panicking should therefore be avoided not to kill that thread.
///
/// We deliberately chose the RNG and the key stores to be generic for
/// performance reasons to avoid the runtime costs associated with dynamic
/// dispatch. We did so because these costs are potentially significant (see,
/// e.g., [1], giving a factor between 1.2 and 3.4) and because the RNG and the
/// key stores are accessed frequently.
/// For the time source, we are using a trait object (i.e., dynamic dispatch)
/// because performance is secondary here as it is accessed very rarely (i.e.,
/// only during node key generation and rotation).
///
/// [1]: https://medium.com/digitalfrontiers/rust-dynamic-dispatching-deep-dive-236a5896e49b

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
    time_source: Arc<dyn TimeSource>,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
}

impl LocalCspVault<OsRng, ProtoSecretKeyStore, ProtoSecretKeyStore, ProtoPublicKeyStore> {
    /// Creates a production-grade local CSP vault.
    ///
    /// For test purposes, it might be more appropriate to use the provided builder.
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
            Arc::new(CurrentSystemTimeSource::new(new_logger!(&logger))),
            metrics,
            logger,
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
        time_source: Arc<dyn TimeSource>,
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
            time_source,
            logger,
            metrics,
        }
    }

    pub fn set_timestamp(&self, public_key: &mut PublicKey) {
        public_key.timestamp = Some(
            self.time_source
                .get_relative_time()
                .as_millis_since_unix_epoch(),
        );
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

    /// Acquires write locks for both the node secret key store and the public key store.
    ///
    /// The locks are acquired according to the total resource order defined in the
    /// section on deadlock prevention in the documentation of the `LocalCspVault`.
    fn sks_and_pks_write_locks(&self) -> (RwLockWriteGuard<'_, S>, RwLockWriteGuard<'_, P>) {
        let sks_write_lock = self.node_secret_key_store.write();
        let pks_write_lock = self.public_key_store.write();
        (sks_write_lock, pks_write_lock)
    }

    /// Acquires read locks for both the node secret key store and the public key store.
    ///
    /// The locks are acquired according to the total resource order defined in the
    /// section on deadlock prevention in the documentation of the `LocalCspVault`.
    fn sks_and_pks_read_locks(&self) -> (RwLockReadGuard<'_, S>, RwLockReadGuard<'_, P>) {
        let sks_read_lock = self.node_secret_key_store.read();
        let pks_read_lock = self.public_key_store.read();
        (sks_read_lock, pks_read_lock)
    }

    fn sks_read_lock(&self) -> RwLockReadGuard<'_, S> {
        self.node_secret_key_store.read()
    }

    fn public_key_store_read_lock(&self) -> RwLockReadGuard<'_, P> {
        self.public_key_store.read()
    }

    fn canister_sks_write_lock(&self) -> RwLockWriteGuard<'_, C> {
        self.canister_secret_key_store.write()
    }

    fn canister_sks_read_lock(&self) -> RwLockReadGuard<'_, C> {
        self.canister_secret_key_store.read()
    }

    fn generate_seed(&self) -> Seed {
        let intermediate_seed: [u8; 32] = self.csprng.write().gen(); // lock is released after this line
        Seed::from_bytes(&intermediate_seed) // use of intermediate seed minimizes locking time
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

#[cfg(test)]
pub mod builder {
    use super::*;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
    use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::FastForwardTimeSource;

    pub struct LocalCspVaultBuilder<R, S, C, P> {
        csprng: Box<dyn FnOnce() -> R>,
        node_secret_key_store: Box<dyn FnOnce() -> S>,
        canister_secret_key_store: Box<dyn FnOnce() -> C>,
        public_key_store: Box<dyn FnOnce() -> P>,
        time_source: Arc<dyn TimeSource>,
        logger: ReplicaLogger,
    }

    impl Default
        for LocalCspVaultBuilder<
            ReproducibleRng,
            TempSecretKeyStore,
            TempSecretKeyStore,
            TempPublicKeyStore,
        >
    {
        fn default() -> Self {
            LocalCspVaultBuilder {
                csprng: Box::new(|| ReproducibleRng::new()),
                node_secret_key_store: Box::new(|| TempSecretKeyStore::new()),
                canister_secret_key_store: Box::new(|| TempSecretKeyStore::new()),
                public_key_store: Box::new(|| TempPublicKeyStore::new()),
                time_source: FastForwardTimeSource::new(),
                logger: no_op_logger(),
            }
        }
    }

    impl LocalCspVault<ReproducibleRng, TempSecretKeyStore, TempSecretKeyStore, TempPublicKeyStore> {
        /// Builder for [`LocalCspVault`] for testing purposes.
        ///
        /// The instantiated builder comes with the following sensible defaults:
        /// * [`ReproducibleRng`] is used as source of randomness to make the test automatically reproducible.
        /// * [`TempSecretKeyStore`] is used as node secret key store and canister secret key store.
        ///   This is simply the productive implementation ([`ProtoSecretKeyStore`]) in a temporary directory.
        /// * [`TempPublicKeyStore`] is used for the public key store.
        ///   This is simply the productive implementation ([`ProtoPublicKeyStore`]) in a temporary directory.
        /// * [`no_op_logger`] is used to disable logging for testing.
        /// * Metrics is (currently) disabled.
        pub fn builder() -> LocalCspVaultBuilder<
            ReproducibleRng,
            TempSecretKeyStore,
            TempSecretKeyStore,
            TempPublicKeyStore,
        > {
            LocalCspVaultBuilder::default()
        }
    }

    impl<R, S, C, P> LocalCspVaultBuilder<R, S, C, P>
    where
        R: Rng + CryptoRng,
        S: SecretKeyStore,
        C: SecretKeyStore,
        P: PublicKeyStore,
    {
        pub fn with_rng<VaultRng: Rng + CryptoRng + 'static>(
            self,
            csprng: VaultRng,
        ) -> LocalCspVaultBuilder<VaultRng, S, C, P> {
            LocalCspVaultBuilder {
                csprng: Box::new(|| csprng),
                node_secret_key_store: self.node_secret_key_store,
                canister_secret_key_store: self.canister_secret_key_store,
                public_key_store: self.public_key_store,
                time_source: self.time_source,
                logger: self.logger,
            }
        }

        pub fn with_node_secret_key_store<VaultSks: SecretKeyStore + 'static>(
            self,
            node_secret_key_store: VaultSks,
        ) -> LocalCspVaultBuilder<R, VaultSks, C, P> {
            LocalCspVaultBuilder {
                csprng: self.csprng,
                node_secret_key_store: Box::new(|| node_secret_key_store),
                canister_secret_key_store: self.canister_secret_key_store,
                public_key_store: self.public_key_store,
                time_source: self.time_source,
                logger: self.logger,
            }
        }

        pub fn with_canister_secret_key_store<VaultCks: SecretKeyStore + 'static>(
            self,
            canister_secret_key_store: VaultCks,
        ) -> LocalCspVaultBuilder<R, S, VaultCks, P> {
            LocalCspVaultBuilder {
                csprng: self.csprng,
                node_secret_key_store: self.node_secret_key_store,
                canister_secret_key_store: Box::new(|| canister_secret_key_store),
                public_key_store: self.public_key_store,
                time_source: self.time_source,
                logger: self.logger,
            }
        }

        pub fn with_mock_stores(
            self,
        ) -> LocalCspVaultBuilder<R, MockSecretKeyStore, MockSecretKeyStore, MockPublicKeyStore>
        {
            self.with_canister_secret_key_store(MockSecretKeyStore::new())
                .with_node_secret_key_store(MockSecretKeyStore::new())
                .with_public_key_store(MockPublicKeyStore::new())
        }

        pub fn with_public_key_store<VaultPks: PublicKeyStore + 'static>(
            self,
            public_key_store: VaultPks,
        ) -> LocalCspVaultBuilder<R, S, C, VaultPks> {
            LocalCspVaultBuilder {
                csprng: self.csprng,
                node_secret_key_store: self.node_secret_key_store,
                canister_secret_key_store: self.canister_secret_key_store,
                public_key_store: Box::new(|| public_key_store),
                time_source: self.time_source,
                logger: self.logger,
            }
        }

        pub fn with_time_source(mut self, time_source: Arc<dyn TimeSource>) -> Self {
            self.time_source = time_source;
            self
        }

        pub fn with_logger(mut self, logger: ReplicaLogger) -> Self {
            self.logger = logger;
            self
        }

        pub fn build(self) -> LocalCspVault<R, S, C, P> {
            LocalCspVault::new_internal(
                (self.csprng)(),
                (self.node_secret_key_store)(),
                (self.canister_secret_key_store)(),
                (self.public_key_store)(),
                self.time_source,
                Arc::new(CryptoMetrics::none()),
                self.logger,
            )
        }
    }

    impl<R, S, C, P> LocalCspVaultBuilder<R, S, C, P>
    where
        R: Rng + CryptoRng + Send + Sync + 'static,
        S: SecretKeyStore + 'static,
        C: SecretKeyStore + 'static,
        P: PublicKeyStore + 'static,
    {
        pub fn build_into_arc(self) -> Arc<LocalCspVault<R, S, C, P>> {
            Arc::new(self.build())
        }
    }
}
