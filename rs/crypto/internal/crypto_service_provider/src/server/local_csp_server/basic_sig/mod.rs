//! Basic Signature operations provided by the CSP server.
use crate::keygen::public_key_hash_as_key_id;
use crate::secret_key_store::SecretKeyStore;
use crate::secret_key_store::SecretKeyStoreError;
use crate::server::api::{
    BasicSignatureCspServer, CspBasicSignatureError, CspSignatureKeygenError,
};
use crate::server::local_csp_server::LocalCspServer;
use crate::types::{CspPublicKey, CspSecretKey, CspSignature};
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_types::crypto::{AlgorithmId, KeyId};
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore> BasicSignatureCspServer for LocalCspServer<R, S> {
    fn sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError> {
        let secret_key: CspSecretKey =
            self.sks_read_lock()
                .get(&key_id)
                .ok_or(CspBasicSignatureError::SecretKeyNotFound {
                    algorithm: algorithm_id,
                    key_id,
                })?;

        match algorithm_id {
            AlgorithmId::Ed25519 => match secret_key {
                CspSecretKey::Ed25519(secret_key) => {
                    let sig_bytes = ed25519::sign(message, &secret_key).map_err(|_e| {
                        CspBasicSignatureError::MalformedSecretKey {
                            algorithm: AlgorithmId::Ed25519,
                        }
                    })?;
                    Ok(CspSignature::Ed25519(sig_bytes))
                }
                _ => Err(CspBasicSignatureError::WrongSecretKeyType {
                    algorithm_id: secret_key.algorithm_id(),
                }),
            },
            _ => Err(CspBasicSignatureError::UnsupportedAlgorithm {
                algorithm: algorithm_id,
            }),
        }
    }

    fn gen_key_pair(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey), CspSignatureKeygenError> {
        let (sk, pk) = match algorithm_id {
            AlgorithmId::Ed25519 => {
                let (sk_bytes, pk_bytes) = ed25519::keypair_from_rng(&mut *self.rng_write_lock());
                let sk = CspSecretKey::Ed25519(sk_bytes);
                let pk = CspPublicKey::Ed25519(pk_bytes);
                Ok((sk, pk))
            }
            _ => Err(CspSignatureKeygenError::UnsupportedAlgorithm {
                algorithm: algorithm_id,
            }),
        }?;
        let sk_id = public_key_hash_as_key_id(&pk);
        match &self.sks_write_lock().insert(sk_id, sk, None) {
            Ok(()) => {}
            Err(SecretKeyStoreError::DuplicateKeyId(key_id)) => {
                panic!("A key with ID {} has already been inserted", key_id);
            }
        };
        Ok((sk_id, pk))
    }
}
