//! Multi-Signature operations provided by the CSP vault.
use crate::key_id::KeyId;
use crate::keygen::public_key_hash_as_key_id;
use crate::secret_key_store::SecretKeyStore;
use crate::types::{CspPop, CspPublicKey, CspSecretKey, CspSignature, MultiBls12_381_Signature};
use crate::vault::api::{
    CspMultiSignatureError, CspMultiSignatureKeygenError, MultiSignatureCspVault,
};
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsScope};
use ic_crypto_internal_multi_sig_bls12381 as multi_bls12381;
use ic_types::crypto::{AlgorithmId, CryptoError};
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> MultiSignatureCspVault
    for LocalCspVault<R, S, C>
{
    fn multi_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspMultiSignatureError> {
        let start_time = self.metrics.now();
        let maybe_secret_key = self.sks_read_lock().get(&key_id);
        let secret_key: CspSecretKey =
            maybe_secret_key.ok_or(CspMultiSignatureError::SecretKeyNotFound {
                algorithm: algorithm_id,
                key_id,
            })?;

        let result = match algorithm_id {
            AlgorithmId::MultiBls12_381 => match secret_key {
                CspSecretKey::MultiBls12_381(key) => {
                    let sig = multi_bls12381::sign(message, key);
                    Ok(CspSignature::MultiBls12_381(
                        MultiBls12_381_Signature::Individual(sig),
                    ))
                }
                _ => Err(CspMultiSignatureError::WrongSecretKeyType {
                    algorithm: algorithm_id,
                    secret_key_variant: secret_key.enum_variant().to_string(),
                }),
            },
            _ => Err(CspMultiSignatureError::UnsupportedAlgorithm {
                algorithm: algorithm_id,
            }),
        };
        self.metrics.observe_duration_seconds(
            MetricsDomain::MultiSignature,
            MetricsScope::Local,
            "multi_sign",
            start_time,
        );
        result
    }

    fn gen_key_pair_with_pop(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey, CspPop), CspMultiSignatureKeygenError> {
        let start_time = self.metrics.now();
        let (sk, pk, pop) = match algorithm_id {
            AlgorithmId::MultiBls12_381 => {
                let (sk_bytes, pk_bytes) =
                    multi_bls12381::keypair_from_rng(&mut *self.rng_write_lock());
                let pop_bytes = multi_bls12381_pop(algorithm_id, sk_bytes, pk_bytes)?;

                let sk = CspSecretKey::MultiBls12_381(sk_bytes);
                let pk = CspPublicKey::MultiBls12_381(pk_bytes);
                let pop = CspPop::MultiBls12_381(pop_bytes);
                Ok((sk, pk, pop))
            }
            _ => Err(CspMultiSignatureKeygenError::UnsupportedAlgorithm {
                algorithm: algorithm_id,
            }),
        }?;
        let sk_id = public_key_hash_as_key_id(&pk);
        self.store_secret_key_or_panic(sk, sk_id);
        self.metrics.observe_duration_seconds(
            MetricsDomain::MultiSignature,
            MetricsScope::Local,
            "gen_key_pair_with_pop",
            start_time,
        );
        Ok((sk_id, pk, pop))
    }
}

fn multi_bls12381_pop(
    algorithm_id: AlgorithmId,
    sk_bytes: multi_bls12381::types::SecretKeyBytes,
    pk_bytes: multi_bls12381::types::PublicKeyBytes,
) -> Result<multi_bls12381::types::PopBytes, CspMultiSignatureKeygenError> {
    multi_bls12381::create_pop(pk_bytes, sk_bytes).map_err(|e| match e {
        CryptoError::MalformedPublicKey {
            algorithm,
            key_bytes,
            internal_error,
        } => CspMultiSignatureKeygenError::MalformedPublicKey {
            algorithm,
            key_bytes,
            internal_error,
        },
        _ => CspMultiSignatureKeygenError::MalformedPublicKey {
            algorithm: algorithm_id,
            key_bytes: Some(pk_bytes.0.to_vec()),
            internal_error: format!("Unexpected error returned from create_pop: {}", e),
        },
    })
}
