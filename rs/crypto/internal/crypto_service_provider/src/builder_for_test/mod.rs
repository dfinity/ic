use super::*;

pub struct CspBuilderForTest {
    vault: Box<dyn FnOnce() -> Arc<dyn CspVault>>,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
}

impl CspBuilderForTest {
    pub fn with_vault<V: CspVault + 'static>(self, vault: V) -> Self {
        Self {
            vault: Box::new(|| Arc::new(vault)),
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
    pub fn builder_for_test() -> CspBuilderForTest {
        CspBuilderForTest {
            vault: Box::new(|| LocalCspVault::builder_for_test().build_into_arc()),
            logger: no_op_logger(),
            metrics: Arc::new(CryptoMetrics::none()),
        }
    }
}
