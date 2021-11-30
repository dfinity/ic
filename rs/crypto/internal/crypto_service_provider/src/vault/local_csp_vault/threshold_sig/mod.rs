use crate::api::CspThresholdSignError;
use crate::secret_key_store::SecretKeyStore;
use crate::types::{CspPublicCoefficients, CspSecretKey};
use crate::types::{CspSignature, ThresBls12_381_Signature};
use crate::vault::api::CspThresholdSignatureKeygenError;
use crate::vault::api::ThresholdSignatureCspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_threshold_sig_bls12381 as bls12381_clib;
use ic_types::crypto::CryptoError;
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::Randomness;
use rand::{CryptoRng, Rng};
use std::convert::TryFrom;

#[cfg(test)]
pub(crate) mod tests;

impl From<CryptoError> for CspThresholdSignatureKeygenError {
    fn from(crypto_error: CryptoError) -> Self {
        match crypto_error {
            CryptoError::AlgorithmNotSupported { algorithm, .. } => {
                CspThresholdSignatureKeygenError::UnsupportedAlgorithm { algorithm }
            }
            CryptoError::InvalidArgument { message } => {
                CspThresholdSignatureKeygenError::InvalidArgument { message }
            }
            _ => CspThresholdSignatureKeygenError::InvalidArgument {
                message: crypto_error.to_string(),
            },
        }
    }
}

impl From<CspThresholdSignatureKeygenError> for CryptoError {
    fn from(keygen_error: CspThresholdSignatureKeygenError) -> Self {
        match keygen_error {
            CspThresholdSignatureKeygenError::UnsupportedAlgorithm { algorithm } => {
                CryptoError::AlgorithmNotSupported {
                    algorithm,
                    reason: "Unsupported".to_string(),
                }
            }
            CspThresholdSignatureKeygenError::InvalidArgument { message } => {
                CryptoError::InvalidArgument { message }
            }
            CspThresholdSignatureKeygenError::InternalError { internal_error } => {
                CryptoError::InvalidArgument {
                    message: internal_error,
                }
            }
        }
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore> ThresholdSignatureCspVault
    for LocalCspVault<R, S, C>
{
    /// See the trait for documentation.
    ///
    /// Warning: The secret key store has no transactions, so in the event of
    /// a failure it is possible that some but not all keys are written.
    fn threshold_keygen_for_test(
        &self,
        algorithm_id: AlgorithmId,
        threshold: ic_types::NumberOfNodes,
        signatory_eligibilty: &[bool],
    ) -> Result<(CspPublicCoefficients, Vec<Option<KeyId>>), CspThresholdSignatureKeygenError> {
        match algorithm_id {
            AlgorithmId::ThresBls12_381 => {
                let seed = Randomness::from(self.rng_write_lock().gen::<[u8; 32]>());
                let (public_coefficients, secret_keys) =
                    bls12381_clib::api::keygen(seed, threshold, signatory_eligibilty)?;
                let key_ids: Vec<Option<KeyId>> = secret_keys
                    .iter()
                    .map(|secret_key_maybe| {
                        secret_key_maybe.map(|secret_key| loop {
                            let key_id = KeyId::from(self.rng_write_lock().gen::<[u8; 32]>());
                            let csp_secret_key = CspSecretKey::ThresBls12_381(secret_key);
                            if self
                                .sks_write_lock()
                                .insert(key_id, csp_secret_key, None)
                                .is_ok()
                            {
                                break key_id;
                            }
                        })
                    })
                    .collect();
                let csp_public_coefficients = CspPublicCoefficients::Bls12_381(public_coefficients);
                Ok((csp_public_coefficients, key_ids))
            }
            _ => Err(CspThresholdSignatureKeygenError::UnsupportedAlgorithm {
                algorithm: algorithm_id,
            }),
        }
    }

    fn threshold_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError> {
        match algorithm_id {
            AlgorithmId::ThresBls12_381 => {
                let csp_key = self.sks_read_lock().get(&key_id).ok_or({
                    CspThresholdSignError::SecretKeyNotFound {
                        algorithm: AlgorithmId::ThresBls12_381,
                        key_id,
                    }
                })?;
                let clib_key = bls12381_clib::types::SecretKeyBytes::try_from(csp_key)?;
                let clib_individual_signature =
                    bls12381_clib::api::sign_message(message, &clib_key)?;
                Ok(CspSignature::ThresBls12_381(
                    ThresBls12_381_Signature::Individual(clib_individual_signature),
                ))
            }
            _ => Err(CspThresholdSignError::UnsupportedAlgorithm {
                algorithm: algorithm_id,
            }),
        }
    }
}
