use crate::public_key_store::PublicKeyStore;
use crate::{
    LocalCspVault,
    secret_key_store::SecretKeyStore,
    vault::api::{PublicRandomSeedGenerator, PublicRandomSeedGeneratorError},
};
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_seed::Seed;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    PublicRandomSeedGenerator for LocalCspVault<R, S, C, P>
{
    fn new_public_seed(&self) -> Result<Seed, PublicRandomSeedGeneratorError> {
        let start_time = self.metrics.now();
        let result = Ok(self.generate_seed());
        self.metrics.observe_duration_seconds(
            MetricsDomain::PublicSeed,
            MetricsScope::Local,
            "new_public_seed",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }
}
