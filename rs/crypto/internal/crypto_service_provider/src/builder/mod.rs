use super::*;

pub struct CspBuilder<V> {
    vault: Box<dyn FnOnce() -> V>,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
}

impl<V: CspVault + 'static> CspBuilder<V> {
    pub fn with_vault<W: CspVault + 'static>(self, vault: W) -> CspBuilder<W> {
        CspBuilder {
            vault: Box::new(|| vault),
            logger: self.logger,
            metrics: self.metrics,
        }
    }

    pub fn build(self) -> Csp {
        Csp {
            csp_vault: Arc::new((self.vault)()),
            logger: self.logger,
            metrics: self.metrics,
        }
    }
}

impl Csp {
    pub fn builder<V: CspVault + 'static>(
        vault: V,
        logger: ReplicaLogger,
        metrics: Arc<CryptoMetrics>,
    ) -> CspBuilder<V> {
        CspBuilder {
            vault: Box::new(|| vault),
            logger,
            metrics,
        }
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
                vault: Box::new(|| LocalCspVault::builder_for_test().build()),
                logger: no_op_logger(),
                metrics: Arc::new(CryptoMetrics::none()),
            }
        }
    }
}
