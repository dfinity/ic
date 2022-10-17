//! Basic Signature operations provided by the CSP vault.
use crate::key_id::KeyId;
use crate::secret_key_store::SecretKeyStore;
use crate::types::{CspPublicKey, CspSecretKey, CspSignature};
use crate::vault::api::{
    BasicSignatureCspVault, CspBasicSignatureError, CspBasicSignatureKeygenError,
};
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsScope};
use ic_types::crypto::AlgorithmId;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> BasicSignatureCspVault
    for LocalCspVault<R, S, C>
{
    fn sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError> {
        let start_time = self.metrics.now();
        let maybe_secret_key = self.sks_read_lock().get(&key_id);
        let secret_key: CspSecretKey =
            maybe_secret_key.ok_or(CspBasicSignatureError::SecretKeyNotFound {
                algorithm: algorithm_id,
                key_id,
            })?;
        let result = match algorithm_id {
            AlgorithmId::Ed25519 => match &secret_key {
                CspSecretKey::Ed25519(secret_key) => {
                    let sig_bytes = ed25519::sign(message, secret_key).map_err(|_e| {
                        CspBasicSignatureError::MalformedSecretKey {
                            algorithm: AlgorithmId::Ed25519,
                        }
                    })?;
                    Ok(CspSignature::Ed25519(sig_bytes))
                }
                _ => Err(CspBasicSignatureError::WrongSecretKeyType {
                    algorithm: algorithm_id,
                    secret_key_variant: secret_key.enum_variant().to_string(),
                }),
            },
            _ => Err(CspBasicSignatureError::UnsupportedAlgorithm {
                algorithm: algorithm_id,
            }),
        };
        self.metrics.observe_duration_seconds(
            MetricsDomain::BasicSignature,
            MetricsScope::Local,
            "sign",
            start_time,
        );
        result
    }

    fn gen_key_pair(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<CspPublicKey, CspBasicSignatureKeygenError> {
        let start_time = self.metrics.now();
        let (sk, pk) = match algorithm_id {
            AlgorithmId::Ed25519 => {
                let (sk_bytes, pk_bytes) = ed25519::keypair_from_rng(&mut *self.rng_write_lock());
                let sk = CspSecretKey::Ed25519(sk_bytes);
                let pk = CspPublicKey::Ed25519(pk_bytes);
                Ok((sk, pk))
            }
            _ => Err(CspBasicSignatureKeygenError::UnsupportedAlgorithm {
                algorithm: algorithm_id,
            }),
        }?;
        let sk_id = KeyId::from(&pk);
        self.store_secret_key(sk, sk_id)?;
        self.metrics.observe_duration_seconds(
            MetricsDomain::BasicSignature,
            MetricsScope::Local,
            "gen_key_pair",
            start_time,
        );
        Ok(pk)
    }
}
