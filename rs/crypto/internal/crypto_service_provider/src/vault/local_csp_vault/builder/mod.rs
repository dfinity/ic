use super::*;
use rand::rngs::OsRng;

pub struct LocalCspVaultBuilder<R, S, C, P> {
    csprng: Box<dyn FnOnce() -> R>,
    node_secret_key_store: Box<dyn FnOnce() -> S>,
    canister_secret_key_store: Box<dyn FnOnce() -> C>,
    public_key_store: Box<dyn FnOnce() -> P>,
    time_source: Arc<dyn TimeSource>,
    metrics: Arc<CryptoMetrics>,
    logger: ReplicaLogger,
}

impl ProdLocalCspVault {
    pub fn builder(
        node_secret_key_store: ProtoSecretKeyStore,
        canister_secret_key_store: InMemorySecretKeyStore,
        public_key_store: ProtoPublicKeyStore,
        metrics: Arc<CryptoMetrics>,
        logger: ReplicaLogger,
    ) -> LocalCspVaultBuilder<OsRng, ProtoSecretKeyStore, InMemorySecretKeyStore, ProtoPublicKeyStore>
    {
        LocalCspVaultBuilder {
            csprng: Box::new(|| OsRng),
            node_secret_key_store: Box::new(|| node_secret_key_store),
            canister_secret_key_store: Box::new(|| canister_secret_key_store),
            public_key_store: Box::new(|| public_key_store),
            time_source: Arc::new(SysTimeSource::new()),
            metrics,
            logger,
        }
    }

    pub fn builder_in_dir(
        key_store_dir: &Path,
        metrics: Arc<CryptoMetrics>,
        logger: ReplicaLogger,
    ) -> LocalCspVaultBuilder<OsRng, ProtoSecretKeyStore, InMemorySecretKeyStore, ProtoPublicKeyStore>
    {
        const SKS_DATA_FILENAME: &str = "sks_data.pb";
        const PUBLIC_KEY_STORE_DATA_FILENAME: &str = "public_keys.pb";

        let node_secret_key_store = ProtoSecretKeyStore::open(
            key_store_dir,
            SKS_DATA_FILENAME,
            Some(new_logger!(logger)),
            Arc::clone(&metrics),
        );
        let canister_secret_key_store = InMemorySecretKeyStore::new(Some(new_logger!(logger)));
        let public_key_store = ProtoPublicKeyStore::open(
            key_store_dir,
            PUBLIC_KEY_STORE_DATA_FILENAME,
            new_logger!(logger),
        );

        Self::builder(
            node_secret_key_store,
            canister_secret_key_store,
            public_key_store,
            metrics,
            logger,
        )
    }
}

impl<R, S, C, P> LocalCspVaultBuilder<R, S, C, P>
where
    R: Rng + CryptoRng + 'static,
    S: SecretKeyStore + 'static,
    C: SecretKeyStore + 'static,
    P: PublicKeyStore + 'static,
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
            metrics: self.metrics,
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
            metrics: self.metrics,
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
            metrics: self.metrics,
            logger: self.logger,
        }
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
            metrics: self.metrics,
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
        LocalCspVault {
            csprng: CspRwLock::new_for_rng((self.csprng)(), Arc::clone(&self.metrics)),
            node_secret_key_store: CspRwLock::new_for_sks(
                (self.node_secret_key_store)(),
                Arc::clone(&self.metrics),
            ),
            canister_secret_key_store: CspRwLock::new_for_csks(
                (self.canister_secret_key_store)(),
                Arc::clone(&self.metrics),
            ),
            public_key_store: CspRwLock::new_for_public_key_store(
                (self.public_key_store)(),
                Arc::clone(&self.metrics),
            ),
            time_source: self.time_source,
            metrics: self.metrics,
            logger: self.logger,
        }
    }

    pub fn build_into_arc(self) -> Arc<LocalCspVault<R, S, C, P>> {
        Arc::new(self.build())
    }
}

#[cfg(test)]
mod test_utils {
    use super::*;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
    use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities_time::FastForwardTimeSource;

    impl Default
        for LocalCspVaultBuilder<
            ReproducibleRng,
            TempSecretKeyStore,
            TempSecretKeyStore,
            TempPublicKeyStore,
        >
    {
        fn default() -> Self {
            Self {
                csprng: Box::new(ReproducibleRng::new),
                node_secret_key_store: Box::new(TempSecretKeyStore::new),
                canister_secret_key_store: Box::new(TempSecretKeyStore::new),
                public_key_store: Box::new(TempPublicKeyStore::new),
                time_source: FastForwardTimeSource::new(),
                logger: no_op_logger(),
                metrics: Arc::new(CryptoMetrics::none()),
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
        pub fn builder_for_test() -> LocalCspVaultBuilder<
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
        R: Rng + CryptoRng + 'static,
        S: SecretKeyStore + 'static,
        C: SecretKeyStore + 'static,
        P: PublicKeyStore + 'static,
    {
        pub fn with_mock_stores(
            self,
        ) -> LocalCspVaultBuilder<R, MockSecretKeyStore, MockSecretKeyStore, MockPublicKeyStore>
        {
            self.with_canister_secret_key_store(MockSecretKeyStore::new())
                .with_node_secret_key_store(MockSecretKeyStore::new())
                .with_public_key_store(MockPublicKeyStore::new())
        }
    }
}
