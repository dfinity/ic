//! Canister threshold signatures.
//!
//! The code in this file mediates between the external API, the CSP state
//! including the secret key store and random number generator, and the
//! stateless crypto lib.

#[cfg(test)]
mod tests;

use crate::api::{
    CspCreateMEGaKeyError, CspIDkgProtocol, CspThresholdEcdsaSigVerifier, CspThresholdEcdsaSigner,
};
use crate::vault::api::IDkgTranscriptInternalBytes;
use crate::Csp;
use ic_crypto_internal_threshold_sig_ecdsa::{
    combine_ecdsa_signature_shares, verify_ecdsa_signature_share, verify_ecdsa_threshold_signature,
    DerivationPath, IDkgTranscriptInternal, MEGaPublicKey, ThresholdEcdsaCombinedSigInternal,
    ThresholdEcdsaSigShareInternal, ThresholdEcdsaVerifySigShareInternalError,
    ThresholdEcdsaVerifySignatureInternalError,
};
use ic_crypto_internal_types::scope::{ConstScope, Scope};
use ic_logger::debug;
use ic_types::crypto::canister_threshold_sig::error::{
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
    ThresholdEcdsaVerifyCombinedSignatureError, ThresholdEcdsaVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::{ExtendedDerivationPath, ThresholdEcdsaSigInputs};
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeIndex, NumberOfNodes, Randomness};

use std::collections::BTreeMap;

pub const IDKG_MEGA_SCOPE: Scope = Scope::Const(ConstScope::IDkgMEGaEncryptionKeys);
pub const IDKG_THRESHOLD_KEYS_SCOPE: Scope = Scope::Const(ConstScope::IDkgThresholdKeys);

/// Interactive distributed key generation client
///
/// Please see the trait definition for full documentation.
impl CspIDkgProtocol for Csp {
    fn idkg_gen_dealing_encryption_key_pair(&self) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        debug!(self.logger; crypto.method_name => "idkg_gen_dealing_encryption_key_pair");

        self.csp_vault.idkg_gen_dealing_encryption_key_pair()
    }
}

/// Threshold-ECDSA signature share generation client.
///
/// Please see the trait definition for full documentation.
impl CspThresholdEcdsaSigner for Csp {
    fn ecdsa_sign_share(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
    ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaSignShareError> {
        debug!(self.logger; crypto.method_name => "ecdsa_sign_share");

        let key = inputs.key_transcript().transcript_to_bytes();

        let q = inputs.presig_quadruple();
        let kappa_unmasked = q.kappa_unmasked().transcript_to_bytes();
        let lambda_masked = q.lambda_masked().transcript_to_bytes();
        let kappa_times_lambda = q.kappa_times_lambda().transcript_to_bytes();
        let key_times_lambda = q.key_times_lambda().transcript_to_bytes();

        self.csp_vault.ecdsa_sign_share(
            inputs.derivation_path().clone(),
            inputs.hashed_message().to_vec(),
            *inputs.nonce(),
            IDkgTranscriptInternalBytes::from(key),
            IDkgTranscriptInternalBytes::from(kappa_unmasked),
            IDkgTranscriptInternalBytes::from(lambda_masked),
            IDkgTranscriptInternalBytes::from(kappa_times_lambda),
            IDkgTranscriptInternalBytes::from(key_times_lambda),
            inputs.algorithm_id(),
        )
    }
}

/// Threshold-ECDSA signature verification client.
///
/// Please see the trait definition for full documentation.
impl CspThresholdEcdsaSigVerifier for Csp {
    fn ecdsa_combine_sig_shares(
        &self,
        derivation_path: &ExtendedDerivationPath,
        hashed_message: &[u8],
        nonce: &Randomness,
        key_transcript: &IDkgTranscriptInternal,
        kappa_unmasked: &IDkgTranscriptInternal,
        reconstruction_threshold: NumberOfNodes,
        sig_shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdEcdsaCombinedSigInternal, ThresholdEcdsaCombineSigSharesError> {
        debug!(self.logger; crypto.method_name => "ecdsa_combine_sig_shares");

        combine_ecdsa_signature_shares(
            &DerivationPath::from(derivation_path),
            hashed_message,
            *nonce,
            key_transcript,
            kappa_unmasked,
            reconstruction_threshold,
            sig_shares,
            algorithm_id,
        )
        .map_err(|e| ThresholdEcdsaCombineSigSharesError::InternalError {
            internal_error: format!("{:?}", e),
        })
    }

    fn ecdsa_verify_sig_share(
        &self,
        share: &ThresholdEcdsaSigShareInternal,
        signer_index: NodeIndex,
        derivation_path: &ExtendedDerivationPath,
        hashed_message: &[u8],
        nonce: &Randomness,
        key: &IDkgTranscriptInternal,
        kappa_unmasked: &IDkgTranscriptInternal,
        lambda_masked: &IDkgTranscriptInternal,
        kappa_times_lambda: &IDkgTranscriptInternal,
        key_times_lambda: &IDkgTranscriptInternal,
        algorithm_id: AlgorithmId,
    ) -> Result<(), ThresholdEcdsaVerifySigShareError> {
        debug!(self.logger; crypto.method_name => "ecdsa_verify_sig_share");

        verify_ecdsa_signature_share(
            share,
            &DerivationPath::from(derivation_path),
            hashed_message,
            *nonce,
            signer_index,
            key,
            kappa_unmasked,
            lambda_masked,
            kappa_times_lambda,
            key_times_lambda,
            algorithm_id,
        )
        .map_err(|e| match e {
            ThresholdEcdsaVerifySigShareInternalError::InvalidArguments(s) => {
                ThresholdEcdsaVerifySigShareError::InvalidArguments(s)
            }
            ThresholdEcdsaVerifySigShareInternalError::InternalError(s) => {
                ThresholdEcdsaVerifySigShareError::InternalError { internal_error: s }
            }
            ThresholdEcdsaVerifySigShareInternalError::InconsistentCommitments => {
                ThresholdEcdsaVerifySigShareError::InvalidSignatureShare
            }
            ThresholdEcdsaVerifySigShareInternalError::InvalidSignatureShare => {
                ThresholdEcdsaVerifySigShareError::InvalidSignatureShare
            }
        })
    }

    fn ecdsa_verify_combined_signature(
        &self,
        signature: &ThresholdEcdsaCombinedSigInternal,
        derivation_path: &ExtendedDerivationPath,
        hashed_message: &[u8],
        nonce: &Randomness,
        key: &IDkgTranscriptInternal,
        kappa_unmasked: &IDkgTranscriptInternal,
        algorithm_id: AlgorithmId,
    ) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError> {
        debug!(self.logger; crypto.method_name => "ecdsa_verify_combined_signature");

        verify_ecdsa_threshold_signature(
            signature,
            &DerivationPath::from(derivation_path),
            hashed_message,
            *nonce,
            kappa_unmasked,
            key,
            algorithm_id,
        )
        .map_err(|e| match e {
            ThresholdEcdsaVerifySignatureInternalError::InvalidSignature => {
                ThresholdEcdsaVerifyCombinedSignatureError::InvalidSignature
            }
            ThresholdEcdsaVerifySignatureInternalError::InvalidArguments(s) => {
                ThresholdEcdsaVerifyCombinedSignatureError::InvalidArguments(s)
            }
            ThresholdEcdsaVerifySignatureInternalError::InternalError(s) => {
                ThresholdEcdsaVerifyCombinedSignatureError::InternalError { internal_error: s }
            }
            ThresholdEcdsaVerifySignatureInternalError::InconsistentCommitments => {
                ThresholdEcdsaVerifyCombinedSignatureError::InternalError {
                    internal_error: "Wrong commitment types".to_string(),
                }
            }
        })
    }
}
