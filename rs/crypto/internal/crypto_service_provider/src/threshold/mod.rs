//! Threshold signature implementation for the CSP
use crate::api::{CspSecretKeyInjector, CspThresholdSignError, ThresholdSignatureCspClient};
use crate::secret_key_store::SecretKeyStore;
use crate::threshold::dkg::public_coefficients_key_id;
use crate::types::{CspPublicCoefficients, CspSecretKey, CspSignature, ThresBls12_381_Signature};
use crate::Csp;
use ic_crypto_internal_threshold_sig_bls12381 as clib;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult, KeyId};
use ic_types::NodeIndex;
use rand::{CryptoRng, Rng};
use std::convert::TryFrom;
pub mod dkg;
pub mod ni_dkg;

#[cfg(test)]
mod tests;

use ic_crypto_internal_threshold_sig_bls12381::types::public_coefficients::conversions::try_number_of_nodes_from_pub_coeff_bytes;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
#[cfg(test)]
use ic_types::Randomness;

impl<R: Rng + CryptoRng, S: SecretKeyStore> ThresholdSignatureCspClient for Csp<R, S> {
    /// See the trait for documentation.
    ///
    /// Warning: The secret key store has no transactions, so in the event of
    /// failure it is possible that some but not all keys are written.
    #[cfg(test)]
    fn threshold_keygen(
        &mut self,
        algorithm_id: AlgorithmId,
        threshold: ic_types::NumberOfNodes,
        signatory_eligibilty: &[bool],
    ) -> CryptoResult<(CspPublicCoefficients, Vec<Option<KeyId>>)> {
        match algorithm_id {
            AlgorithmId::ThresBls12_381 => {
                let seed = Randomness::from(self.rng_write_lock().gen::<[u8; 32]>());
                let (public_coefficients, secret_keys) =
                    clib::api::keygen(seed, threshold, signatory_eligibilty)?;
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
            _ => Err(CryptoError::InvalidArgument {
                message: format!("Unsupported algorithm: {:?}", algorithm_id),
            }),
        }
    }

    fn threshold_sign_to_be_removed(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError> {
        match algorithm_id {
            AlgorithmId::ThresBls12_381 => {
                let csp_key = self.sks_read_lock().get(&key_id).ok_or_else(|| {
                    CspThresholdSignError::SecretKeyNotFound {
                        algorithm: AlgorithmId::ThresBls12_381,
                        key_id,
                    }
                })?;
                let clib_key = clib::types::SecretKeyBytes::try_from(csp_key)?;
                let clib_individual_signature = clib::api::sign_message(message, &clib_key)?;
                Ok(CspSignature::ThresBls12_381(
                    ThresBls12_381_Signature::Individual(clib_individual_signature),
                ))
            }
            _ => Err(CspThresholdSignError::UnsupportedAlgorithm {
                algorithm: algorithm_id,
            }),
        }
    }

    fn threshold_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        public_coefficients: CspPublicCoefficients,
    ) -> Result<CspSignature, CspThresholdSignError> {
        let key_id = public_coefficients_key_id(&public_coefficients);
        self.threshold_sign_to_be_removed(algorithm_id, message, key_id)
    }

    fn threshold_combine_signatures(
        &self,
        algorithm_id: AlgorithmId,
        signatures: &[Option<CspSignature>],
        public_coefficients: CspPublicCoefficients,
    ) -> CryptoResult<CspSignature> {
        match algorithm_id {
            AlgorithmId::ThresBls12_381 => {
                let clib_public_coefficients = PublicCoefficientsBytes::from(public_coefficients);
                let clib_individual_signatures: CryptoResult<
                    Vec<Option<clib::types::IndividualSignatureBytes>>,
                > = signatures
                    .iter()
                    .map(|csp_signature_maybe| {
                        csp_signature_maybe
                            .map(clib::types::IndividualSignatureBytes::try_from)
                            .transpose()
                    })
                    .collect();
                let clib_individual_signatures = clib_individual_signatures?;
                let clib_combined_signature = clib::api::combine_signatures(
                    &clib_individual_signatures[..],
                    try_number_of_nodes_from_pub_coeff_bytes(&clib_public_coefficients)?,
                )?;
                Ok(CspSignature::ThresBls12_381(
                    ThresBls12_381_Signature::Combined(clib_combined_signature),
                ))
            }
            _ => Err(CryptoError::InvalidArgument {
                message: format!("Unsupported algorithm: {:?}", algorithm_id),
            }),
        }
    }

    fn threshold_individual_public_key(
        &self,
        algorithm_id: AlgorithmId,
        node_index: NodeIndex,
        public_coefficients: CspPublicCoefficients,
    ) -> CryptoResult<CspThresholdSigPublicKey> {
        match algorithm_id {
            AlgorithmId::ThresBls12_381 => {
                let clib_public_coefficients_bytes =
                    PublicCoefficientsBytes::from(public_coefficients);
                let public_key_bytes =
                    clib::api::individual_public_key(&clib_public_coefficients_bytes, node_index)?;
                Ok(CspThresholdSigPublicKey::ThresBls12_381(public_key_bytes))
            }
            _ => Err(CryptoError::InvalidArgument {
                message: format!("Unsupported algorithm: {:?}", algorithm_id),
            }),
        }
    }

    fn threshold_verify_individual_signature(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        signature: CspSignature,
        public_key: CspThresholdSigPublicKey,
    ) -> CryptoResult<()> {
        match algorithm_id {
            AlgorithmId::ThresBls12_381 => {
                let clib_signature = clib::types::IndividualSignatureBytes::try_from(signature)?;
                let clib_public_key = PublicKeyBytes::from(public_key);
                clib::api::verify_individual_signature(message, clib_signature, clib_public_key)
            }
            _ => Err(CryptoError::InvalidArgument {
                message: format!("Unsupported algorithm: {:?}", algorithm_id),
            }),
        }
    }

    fn threshold_verify_combined_signature(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        signature: CspSignature,
        public_coefficients: CspPublicCoefficients,
    ) -> CryptoResult<()> {
        match algorithm_id {
            AlgorithmId::ThresBls12_381 => {
                let clib_signature = clib::types::CombinedSignatureBytes::try_from(signature)?;
                let clib_public_coefficients = PublicCoefficientsBytes::from(public_coefficients);
                let clib_public_key = clib::api::combined_public_key(&clib_public_coefficients)?;
                clib::api::verify_combined_signature(message, clib_signature, clib_public_key)
            }
            _ => Err(CryptoError::InvalidArgument {
                message: format!("Unsupported algorithm: {:?}", algorithm_id),
            }),
        }
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> CspSecretKeyInjector for Csp<R, S> {
    fn insert_secret_key(&mut self, key_id: KeyId, sk: CspSecretKey) {
        let _ignore_result = self.sks_write_lock().insert(key_id, sk, None);
    }
}
