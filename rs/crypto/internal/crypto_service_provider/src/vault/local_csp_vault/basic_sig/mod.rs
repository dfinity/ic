//! Basic Signature operations provided by the CSP vault.
use crate::key_id::KeyId;
use crate::keygen::utils::node_signing_pk_to_proto;
use crate::public_key_store::{PublicKeySetOnceError, PublicKeyStore};
use crate::secret_key_store::SecretKeyStore;
use crate::types::{CspPublicKey, CspSecretKey, CspSignature};
use crate::vault::api::{
    BasicSignatureCspVault, CspBasicSignatureError, CspBasicSignatureKeygenError,
};
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_types::crypto::AlgorithmId;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    BasicSignatureCspVault for LocalCspVault<R, S, C, P>
{
    fn sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError> {
        let start_time = self.metrics.now();
        let result = self.sign_internal(algorithm_id, message, key_id);
        self.metrics.observe_duration_seconds(
            MetricsDomain::BasicSignature,
            MetricsScope::Local,
            "sign",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    fn gen_node_signing_key_pair(&self) -> Result<CspPublicKey, CspBasicSignatureKeygenError> {
        let start_time = self.metrics.now();

        let (sk_bytes, pk_bytes) = ed25519::keypair_from_rng(&mut *self.rng_write_lock());
        let sk = CspSecretKey::Ed25519(sk_bytes);
        let pk = CspPublicKey::Ed25519(pk_bytes);

        let result = self
            .store_secret_key(KeyId::from(&pk), sk, None)
            .map_err(CspBasicSignatureKeygenError::from)
            .and_then(|()| {
                self.public_key_store_write_lock()
                    .set_once_node_signing_pubkey(node_signing_pk_to_proto(pk.clone()))
                    .map_err(|e| match e {
                        PublicKeySetOnceError::AlreadySet => {
                            CspBasicSignatureKeygenError::InternalError {
                                internal_error: "node signing public key already set".to_string(),
                            }
                        }
                        PublicKeySetOnceError::Io(io_error) => {
                            CspBasicSignatureKeygenError::TransientInternalError {
                                internal_error: format!("IO error: {}", io_error),
                            }
                        }
                    })
            });

        self.metrics.observe_duration_seconds(
            MetricsDomain::BasicSignature,
            MetricsScope::Local,
            "gen_node_signing_key_pair",
            MetricsResult::from(&result),
            start_time,
        );
        result.map(|()| pk)
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn sign_internal(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError> {
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
        result
    }
}
