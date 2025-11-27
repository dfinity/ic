use crate::api::CspThresholdSignError;
use crate::key_id::KeyId;
use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::types::{CspPublicCoefficients, CspSecretKey};
use crate::types::{CspSignature, ThresBls12_381_Signature};
use crate::vault::api::CspThresholdSignatureKeygenError;
use crate::vault::api::ThresholdSignatureCspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381 as bls12381_clib;
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::CryptoError;
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

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    /// Generates threshold keys.
    ///
    /// This interface is primarily of interest for testing and demos.
    ///
    /// # Arguments
    /// * `algorithm_id` indicates the algorithms to be used in the key
    ///   generation.
    /// * `threshold` is the minimum number of signatures that can be combined
    ///   to make a valid threshold signature.
    /// * `receivers` is the total number of receivers
    /// # Returns
    /// * `CspPublicCoefficients` can be used by the caller to verify
    ///   signatures.
    /// * `Vec<KeyId>` contains key identifiers.  The vector has the
    ///   same length as the number of `receivers`.
    /// # Panics
    /// * An implementation MAY panic if it is unable to access the secret key
    ///   store to save keys or if it cannot access a suitable random number
    ///   generator.
    /// # Errors
    /// * If `threshold > receivers` then it is impossible for
    ///   the signatories to create a valid combined signature, so
    ///   implementations MUST return an error.
    /// * An implementation MAY return an error if it is temporarily unable to
    ///   generate and store keys.
    ///
    /// Warning: The secret key store has no transactions, so in the event of
    /// a failure it is possible that some but not all keys are written.
    pub fn threshold_keygen_for_test(
        &self,
        algorithm_id: AlgorithmId,
        threshold: ic_types::NumberOfNodes,
        receivers: ic_types::NumberOfNodes,
    ) -> Result<(CspPublicCoefficients, Vec<KeyId>), CspThresholdSignatureKeygenError> {
        match algorithm_id {
            AlgorithmId::ThresBls12_381 => {
                let seed = Seed::from_rng(&mut *self.rng_write_lock());
                let (public_coefficients, secret_keys) =
                    bls12381_clib::api::generate_threshold_key(seed, threshold, receivers)?;
                let key_ids: Vec<KeyId> = secret_keys
                    .iter()
                    .map(|secret_key| {
                        loop {
                            let key_id = KeyId::from(self.rng_write_lock().r#gen::<[u8; 32]>());
                            let csp_secret_key = CspSecretKey::ThresBls12_381(secret_key.clone());
                            let result = self.sks_write_lock().insert(key_id, csp_secret_key, None);
                            if result.is_ok() {
                                break key_id;
                            }
                        }
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
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    ThresholdSignatureCspVault for LocalCspVault<R, S, C, P>
{
    fn threshold_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError> {
        let start_time = self.metrics.now();
        let result = self.threshold_sign_internal(algorithm_id, &message[..], key_id);
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdSignature,
            MetricsScope::Local,
            "threshold_sign",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn threshold_sign_internal(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError> {
        match algorithm_id {
            AlgorithmId::ThresBls12_381 => {
                let maybe_csp_key = self.sks_read_lock().get(&key_id);
                let csp_key = maybe_csp_key.ok_or({
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
