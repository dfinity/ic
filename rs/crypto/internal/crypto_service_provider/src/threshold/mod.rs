//! Threshold signature implementation for the CSP
use crate::Csp;
use crate::api::{CspThresholdSignError, ThresholdSignatureCspClient};
use crate::key_id::{KeyId, KeyIdInstantiationError};
use crate::types::{CspPublicCoefficients, CspSignature, ThresBls12_381_Signature};
use ic_crypto_internal_threshold_sig_bls12381 as clib;
use ic_crypto_internal_threshold_sig_bls12381::types::public_coefficients::try_number_of_nodes_from_pub_coeff_bytes;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::NodeIndex;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};

use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult};
use std::convert::TryFrom;

pub mod ni_dkg;

#[cfg(test)]
mod tests;

impl ThresholdSignatureCspClient for Csp {
    fn threshold_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
        public_coefficients: CspPublicCoefficients,
    ) -> Result<CspSignature, CspThresholdSignError> {
        let key_id =
            KeyId::try_from(&public_coefficients).map_err(|key_id_instantiation_error| {
                match key_id_instantiation_error {
                    KeyIdInstantiationError::InvalidArguments(internal_error) => {
                        CspThresholdSignError::KeyIdInstantiationError(internal_error)
                    }
                }
            })?;
        let message_len = message.len();
        let result = self.csp_vault.threshold_sign(algorithm_id, message, key_id);
        self.metrics.observe_parameter_size(
            MetricsDomain::ThresholdSignature,
            "threshold_sign",
            "message",
            message_len,
            MetricsResult::from(&result),
        );
        result
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
                            .clone()
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
                message: format!("Unsupported algorithm: {algorithm_id:?}"),
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
                let public_key_bytes = clib::api::individual_public_key_from_trusted_bytes(
                    &clib_public_coefficients_bytes,
                    node_index,
                )?;
                Ok(CspThresholdSigPublicKey::ThresBls12_381(public_key_bytes))
            }
            _ => Err(CryptoError::InvalidArgument {
                message: format!("Unsupported algorithm: {algorithm_id:?}"),
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
                message: format!("Unsupported algorithm: {algorithm_id:?}"),
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
                message: format!("Unsupported algorithm: {algorithm_id:?}"),
            }),
        }
    }
}
