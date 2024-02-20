use super::*;

pub struct CspBuilder {
    vault: Box<dyn FnOnce() -> Arc<dyn CspVault>>,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
}

impl CspBuilder {
    pub fn with_vault<I: IntoVaultArc + 'static>(self, vault: I) -> CspBuilder {
        CspBuilder {
            vault: Box::new(|| vault.into()),
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
    pub fn builder<I: IntoVaultArc + 'static>(
        vault: I,
        logger: ReplicaLogger,
        metrics: Arc<CryptoMetrics>,
    ) -> CspBuilder {
        CspBuilder {
            vault: Box::new(|| vault.into()),
            logger,
            metrics,
        }
    }
}

pub trait IntoVaultArc {
    fn into(self) -> Arc<dyn CspVault>;
}

impl<V: CspVault + 'static> IntoVaultArc for Arc<V> {
    fn into(self) -> Arc<dyn CspVault> {
        self
    }
}

impl<V: CspVault + 'static> IntoVaultArc for V {
    fn into(self) -> Arc<dyn CspVault> {
        Arc::new(self)
    }
}

impl IntoVaultArc for Arc<dyn CspVault> {
    fn into(self) -> Arc<dyn CspVault> {
        self
    }
}

#[cfg(test)]
mod test_utils {
    use super::*;

    impl Csp {
        pub fn builder_for_test() -> CspBuilder {
            CspBuilder {
                vault: Box::new(|| LocalCspVault::builder_for_test().build_into_arc()),
                logger: no_op_logger(),
                metrics: Arc::new(CryptoMetrics::none()),
            }
        }
    }
}
