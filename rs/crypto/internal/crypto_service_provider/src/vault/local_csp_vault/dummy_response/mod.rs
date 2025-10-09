use crate::public_key_store::PublicKeyStore;
use crate::vault::api::DummySizedRandomResponseGenerator;
use crate::{LocalCspVault, secret_key_store::SecretKeyStore};
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use rand::{CryptoRng, Rng};

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    DummySizedRandomResponseGenerator for LocalCspVault<R, S, C, P>
{
    fn dummy_response(
        &self,
        _input: Vec<u8>,
        response_size_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        let start_time = self.metrics.now();
        let result = Ok(vec![42; response_size_bytes]);
        self.metrics.observe_duration_seconds(
            MetricsDomain::DummyResponse,
            MetricsScope::Local,
            "dummy_response",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }
}
