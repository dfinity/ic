//! Multi-Signature operations provided by the CSP vault.
use crate::key_id::KeyId;
use crate::keygen::utils::committee_signing_pk_to_proto;
use crate::public_key_store::{PublicKeySetOnceError, PublicKeyStore};
use crate::secret_key_store::{SecretKeyStore, SecretKeyStoreInsertionError};
use crate::types::{CspPop, CspPublicKey, CspSecretKey, CspSignature, MultiBls12_381_Signature};
use crate::vault::api::{
    CspMultiSignatureError, CspMultiSignatureKeygenError, MultiSignatureCspVault,
};
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_multi_sig_bls12381 as multi_bls12381;
use ic_crypto_node_key_validation::ValidCommitteeSigningPublicKey;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_types::crypto::{AlgorithmId, CryptoError};
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    MultiSignatureCspVault for LocalCspVault<R, S, C, P>
{
    fn multi_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspMultiSignatureError> {
        let start_time = self.metrics.now();
        let result = self.multi_sign_internal(algorithm_id, &message[..], key_id);
        self.metrics.observe_duration_seconds(
            MetricsDomain::MultiSignature,
            MetricsScope::Local,
            "multi_sign",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    fn gen_committee_signing_key_pair(
        &self,
    ) -> Result<(CspPublicKey, CspPop), CspMultiSignatureKeygenError> {
        let start_time = self.metrics.now();
        let result = self.gen_committee_signing_key_pair_internal();
        self.metrics.observe_duration_seconds(
            MetricsDomain::MultiSignature,
            MetricsScope::Local,
            "gen_committee_signing_key_pair",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn gen_committee_signing_key_pair_internal(
        &self,
    ) -> Result<(CspPublicKey, CspPop), CspMultiSignatureKeygenError> {
        let (secret_key, pk_and_pop) = self.gen_multi_bls12381_keypair_with_pop()?;
        let key_id = KeyId::from(&pk_and_pop.0);
        let committee_public_key_proto = committee_signing_pk_to_proto(pk_and_pop.clone());
        let valid_public_key = validate_committee_signing_public_key(committee_public_key_proto)?;
        self.store_committee_signing_key_pair(key_id, secret_key, valid_public_key.get().clone())?;
        Ok(pk_and_pop)
    }

    fn store_committee_signing_key_pair(
        &self,
        key_id: KeyId,
        secret_key: CspSecretKey,
        committee_public_key_proto: PublicKey,
    ) -> Result<(), CspMultiSignatureKeygenError> {
        let (mut sks_write_lock, mut pks_write_lock) = self.sks_and_pks_write_locks();
        sks_write_lock
            .insert(key_id, secret_key, None)
            .map_err(|sks_error| match sks_error {
                SecretKeyStoreInsertionError::DuplicateKeyId(key_id) => {
                    CspMultiSignatureKeygenError::DuplicateKeyId { key_id }
                }
                SecretKeyStoreInsertionError::SerializationError(serialization_error) => {
                    CspMultiSignatureKeygenError::InternalError {internal_error:
                    format!("Error persisting secret key store during CSP multi-signature key generation: {serialization_error}")}}
                SecretKeyStoreInsertionError::TransientError(io_error) => {
                    CspMultiSignatureKeygenError::TransientInternalError {internal_error:
                    format!("Error persisting secret key store during CSP multi-signature key generation: {io_error}")}
                }
            })
            .and_then(|()| {
                pks_write_lock
                    .set_once_committee_signing_pubkey(committee_public_key_proto)
                    .map_err(|e| match e {
                        PublicKeySetOnceError::AlreadySet => {
                            CspMultiSignatureKeygenError::InternalError {
                                internal_error: "committee signing public key already set"
                                    .to_string(),
                            }
                        }
                        PublicKeySetOnceError::Io(io_error) => {
                            CspMultiSignatureKeygenError::TransientInternalError {
                                internal_error: format!(
                                    "IO error persisting committee signing public key: {io_error}"
                                ),
                            }
                        }
                    })
            })
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn multi_sign_internal(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspMultiSignatureError> {
        let maybe_secret_key = self.sks_read_lock().get(&key_id);
        let secret_key: CspSecretKey =
            maybe_secret_key.ok_or(CspMultiSignatureError::SecretKeyNotFound {
                algorithm: algorithm_id,
                key_id,
            })?;

        match algorithm_id {
            AlgorithmId::MultiBls12_381 => match &secret_key {
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
        }
    }

    fn gen_multi_bls12381_keypair_with_pop(
        &self,
    ) -> Result<(CspSecretKey, (CspPublicKey, CspPop)), CspMultiSignatureKeygenError> {
        let (sk_bytes, pk_bytes) = multi_bls12381::keypair_from_rng(&mut *self.rng_write_lock());
        let pk = CspPublicKey::MultiBls12_381(pk_bytes);
        let sk = CspSecretKey::MultiBls12_381(sk_bytes.clone());

        let pop_bytes = multi_bls12381::create_pop(&pk_bytes, &sk_bytes).map_err(|e| match e {
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
                algorithm: AlgorithmId::MultiBls12_381,
                key_bytes: Some(pk_bytes.0.to_vec()),
                internal_error: format!("Unexpected error returned from create_pop: {e}"),
            },
        })?;
        let pop = CspPop::MultiBls12_381(pop_bytes);

        Ok((sk, (pk, pop)))
    }
}

fn validate_committee_signing_public_key(
    committee_public_key_proto: PublicKey,
) -> Result<ValidCommitteeSigningPublicKey, CspMultiSignatureKeygenError> {
    ValidCommitteeSigningPublicKey::try_from(committee_public_key_proto).map_err(|error| {
        CspMultiSignatureKeygenError::InternalError {
            internal_error: format!("Committee signing public key validation error: {error}"),
        }
    })
}
