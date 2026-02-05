use crate::api::CspThresholdSignError;
use crate::key_id::KeyId;
use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::types::{CspSignature, ThresBls12_381_Signature};
use crate::vault::api::CspThresholdSignatureKeygenError;
use crate::vault::api::ThresholdSignatureCspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
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
