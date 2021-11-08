//! Multi-Signature operations provided by the CSP server.
use crate::keygen::public_key_hash_as_key_id;
use crate::secret_key_store::SecretKeyStore;
use crate::server::api::{
    CspMultiSignatureError, CspMultiSignatureKeygenError, MultiSignatureCspServer,
};
use crate::server::local_csp_server::LocalCspServer;
use crate::types::{CspPop, CspPublicKey, CspSecretKey, CspSignature, MultiBls12_381_Signature};
use ic_crypto_internal_multi_sig_bls12381 as multi_bls12381;
use ic_types::crypto::{AlgorithmId, CryptoError, KeyId};
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore> MultiSignatureCspServer for LocalCspServer<R, S> {
    fn multi_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspMultiSignatureError> {
        let secret_key: CspSecretKey =
            self.sks_read_lock()
                .get(&key_id)
                .ok_or(CspMultiSignatureError::SecretKeyNotFound {
                    algorithm: algorithm_id,
                    key_id,
                })?;

        match algorithm_id {
            AlgorithmId::MultiBls12_381 => match secret_key {
                CspSecretKey::MultiBls12_381(key) => {
                    let sig = multi_bls12381::sign(message, key).map_err(|e| {
                        CspMultiSignatureError::InternalError {
                            internal_error: format!("Failed to create signature: {}", e),
                        }
                    })?;
                    Ok(CspSignature::MultiBls12_381(
                        MultiBls12_381_Signature::Individual(sig),
                    ))
                }
                _ => Err(CspMultiSignatureError::WrongSecretKeyType {
                    algorithm: secret_key.algorithm_id(),
                }),
            },
            _ => Err(CspMultiSignatureError::UnsupportedAlgorithm {
                algorithm: algorithm_id,
            }),
        }
    }

    fn gen_key_pair_with_pop(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey, CspPop), CspMultiSignatureKeygenError> {
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
