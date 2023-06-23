use super::*;

pub struct CspBuilder<V> {
    vault: Box<dyn FnOnce() -> Arc<V>>,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
}

impl<V: CspVault + 'static> CspBuilder<V> {
    pub fn with_vault<I, W>(self, vault: I) -> CspBuilder<W>
    where
        I: VaultIntoArc<Item = W> + 'static,
        W: CspVault + 'static,
    {
        CspBuilder {
            vault: Box::new(|| vault.into_arc()),
            logger: self.logger,
            metrics: self.metrics,
        }
    }

    pub fn build(self) -> Csp {
        Csp {
            csp_vault: (self.vault)(),
            logger: self.logger,
            metrics: self.metrics,
        }
    }
}

impl Csp {
    pub fn builder<I, V>(
        vault: I,
        logger: ReplicaLogger,
        metrics: Arc<CryptoMetrics>,
    ) -> CspBuilder<V>
    where
        I: VaultIntoArc<Item = V> + 'static,
        V: CspVault + 'static,
    {
        CspBuilder {
            vault: Box::new(|| vault.into_arc()),
            logger,
            metrics,
        }
    }
}

pub trait VaultIntoArc {
    type Item;

    fn into_arc(self) -> Arc<Self::Item>;
}

impl<V: CspVault> VaultIntoArc for Arc<V> {
    type Item = V;

    fn into_arc(self) -> Arc<Self::Item> {
        self
    }
}

impl<V: CspVault> VaultIntoArc for V {
    type Item = V;

    fn into_arc(self) -> Arc<Self::Item> {
        Arc::new(self)
    }
}

#[cfg(test)]
mod test_utils {
    use super::*;
    use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
    use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
    use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;

    impl Csp {
        pub fn builder_for_test() -> CspBuilder<
            LocalCspVault<
                ReproducibleRng,
                TempSecretKeyStore,
                TempSecretKeyStore,
                TempPublicKeyStore,
            >,
        > {
            CspBuilder {
                vault: Box::new(|| LocalCspVault::builder_for_test().build_into_arc()),
                logger: no_op_logger(),
                metrics: Arc::new(CryptoMetrics::none()),
            }
        }
    }
}
