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
use crate::keygen::mega_key_id;
use crate::secret_key_store::SecretKeyStore;
use crate::Csp;
use ic_crypto_internal_threshold_sig_ecdsa::{
    combine_sig_shares as tecdsa_combine_sig_shares, create_transcript as tecdsa_create_transcript,
    publicly_verify_dealing as tecdsa_verify_dealing_public,
    verify_complaint as tecdsa_verify_complaint,
    verify_signature_share as tecdsa_verify_signature_share,
    verify_threshold_signature as tecdsa_verify_combined_signature,
    verify_transcript as tecdsa_verify_transcript, CommitmentOpening, DerivationPath,
    IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptOperationInternal, MEGaPublicKey, ThresholdEcdsaCombinedSigInternal,
    ThresholdEcdsaSigShareInternal, ThresholdEcdsaVerifySigShareInternalError,
    ThresholdEcdsaVerifySignatureInternalError,
};
use ic_crypto_internal_types::scope::{ConstScope, Scope};
use ic_logger::debug;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    IDkgOpenTranscriptError, IDkgVerifyComplaintError, IDkgVerifyDealingPrivateError,
    IDkgVerifyDealingPublicError, IDkgVerifyTranscriptError, ThresholdEcdsaCombineSigSharesError,
    ThresholdEcdsaSignShareError, ThresholdEcdsaVerifyCombinedSignatureError,
    ThresholdEcdsaVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use rand::{CryptoRng, Rng};
use std::collections::BTreeMap;

pub const IDKG_MEGA_SCOPE: Scope = Scope::Const(ConstScope::IDkgMEGaEncryptionKeys);

/// Interactive distributed key generation client
///
/// Please see the trait definition for full documentation.
impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> CspIDkgProtocol
    for Csp<R, S, C>
{
    fn idkg_create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        context_data: &[u8],
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: &[MEGaPublicKey],
        transcript_operation: &IDkgTranscriptOperationInternal,
    ) -> Result<IDkgDealingInternal, IDkgCreateDealingError> {
        debug!(self.logger; crypto.method_name => "idkg_create_dealing");

        self.csp_vault.idkg_create_dealing(
            algorithm_id,
            context_data,
            dealer_index,
            reconstruction_threshold,
            receiver_keys,
            transcript_operation,
        )
    }

    fn idkg_verify_dealing_private(
        &self,
        algorithm_id: AlgorithmId,
        dealing: &IDkgDealingInternal,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_public_key: &MEGaPublicKey,
        context_data: &[u8],
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        debug!(self.logger; crypto.method_name => "idkg_verify_dealing_private");

        let receiver_key_id = mega_key_id(receiver_public_key);

        self.csp_vault.idkg_verify_dealing_private(
            algorithm_id,
            dealing,
            dealer_index,
            receiver_index,
            receiver_key_id,
            context_data,
        )
    }

    fn idkg_verify_dealing_public(
        &self,
        algorithm_id: AlgorithmId,
        dealing: &IDkgDealingInternal,
        operation_mode: &IDkgTranscriptOperationInternal,
        reconstruction_threshold: NumberOfNodes,
        dealer_index: NodeIndex,
        number_of_receivers: NumberOfNodes,
        context_data: &[u8],
    ) -> Result<(), IDkgVerifyDealingPublicError> {
        debug!(self.logger; crypto.method_name => "idkg_verify_dealing_public");

        tecdsa_verify_dealing_public(
            algorithm_id,
            dealing,
            operation_mode,
            reconstruction_threshold,
            dealer_index,
            number_of_receivers,
            context_data,
        )
        .map_err(|e| IDkgVerifyDealingPublicError::InvalidDealing {
            reason: format!("{:?}", e),
        })
    }

    fn idkg_create_transcript(
        &self,
        algorithm_id: AlgorithmId,
        reconstruction_threshold: NumberOfNodes,
        verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        operation_mode: &IDkgTranscriptOperationInternal,
    ) -> Result<IDkgTranscriptInternal, IDkgCreateTranscriptError> {
        debug!(self.logger; crypto.method_name => "idkg_create_transcript");

        tecdsa_create_transcript(
            algorithm_id,
            reconstruction_threshold,
            verified_dealings,
            operation_mode,
        )
        .map_err(|e| IDkgCreateTranscriptError::InternalError {
            internal_error: format!("{:?}", e),
        })
    }

    fn idkg_verify_transcript(
        &self,
        transcript: &IDkgTranscriptInternal,
        algorithm_id: AlgorithmId,
        reconstruction_threshold: NumberOfNodes,
        verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        operation_mode: &IDkgTranscriptOperationInternal,
    ) -> Result<(), IDkgVerifyTranscriptError> {
        debug!(self.logger; crypto.method_name => "idkg_verify_transcript");

        Ok(tecdsa_verify_transcript(
            transcript,
            algorithm_id,
            reconstruction_threshold,
            verified_dealings,
            operation_mode,
        )?)
    }

    fn idkg_load_transcript(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        public_key: &MEGaPublicKey,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        debug!(self.logger; crypto.method_name => "idkg_load_transcript");

        let key_id = mega_key_id(public_key);

        self.csp_vault.idkg_load_transcript(
            dealings,
            context_data,
            receiver_index,
            &key_id,
            transcript,
        )
    }

    fn idkg_load_transcript_with_openings(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        public_key: &MEGaPublicKey,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<(), IDkgLoadTranscriptError> {
        debug!(self.logger; crypto.method_name => "idkg_load_transcript_with_openings");

        let key_id = mega_key_id(public_key);

        self.csp_vault.idkg_load_transcript_with_openings(
            dealings,
            openings,
            context_data,
            receiver_index,
            &key_id,
            transcript,
        )
    }

    fn idkg_create_mega_key_pair(
        &mut self,
        algorithm_id: AlgorithmId,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        debug!(self.logger; crypto.method_name => "idkg_create_mega_key_pair");

        self.csp_vault.idkg_gen_mega_key_pair(algorithm_id)
    }

    fn idkg_verify_complaint(
        &self,
        complaint: &IDkgComplaintInternal,
        complainer_index: NodeIndex,
        complainer_key: &MEGaPublicKey,
        dealing: &IDkgDealingInternal,
        dealer_index: NodeIndex,
        context_data: &[u8],
    ) -> Result<(), IDkgVerifyComplaintError> {
        debug!(self.logger; crypto.method_name => "idkg_verify_complaint");

        Ok(tecdsa_verify_complaint(
            complaint,
            complainer_index,
            complainer_key,
            dealing,
            dealer_index,
            context_data,
        )?)
    }

    fn idkg_open_dealing(
        &self,
        dealing: IDkgDealingInternal,
        dealer_index: NodeIndex,
        context_data: &[u8],
        opener_index: NodeIndex,
        opener_public_key: &MEGaPublicKey,
    ) -> Result<CommitmentOpening, IDkgOpenTranscriptError> {
        let opener_key_id = mega_key_id(opener_public_key);
        self.csp_vault.idkg_open_dealing(
            dealing,
            dealer_index,
            context_data,
            opener_index,
            &opener_key_id,
        )
    }
}

/// Threshold-ECDSA signature share generation client.
///
/// Please see the trait definition for full documentation.
impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> CspThresholdEcdsaSigner
    for Csp<R, S, C>
{
    fn ecdsa_sign_share(
        &self,
        derivation_path: &ExtendedDerivationPath,
        hashed_message: &[u8],
        nonce: &Randomness,
        key: &IDkgTranscriptInternal,
        kappa_unmasked: &IDkgTranscriptInternal,
        lambda_masked: &IDkgTranscriptInternal,
        kappa_times_lambda: &IDkgTranscriptInternal,
        key_times_lambda: &IDkgTranscriptInternal,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaSignShareError> {
        debug!(self.logger; crypto.method_name => "ecdsa_sign_share");

        self.csp_vault.ecdsa_sign_share(
            derivation_path,
            hashed_message,
            nonce,
            key,
            kappa_unmasked,
            lambda_masked,
            kappa_times_lambda,
            key_times_lambda,
            algorithm_id,
        )
    }
}

/// Threshold-ECDSA signature verification client.
///
/// Please see the trait definition for full documentation.
impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore>
    CspThresholdEcdsaSigVerifier for Csp<R, S, C>
{
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

        tecdsa_combine_sig_shares(
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

        tecdsa_verify_signature_share(
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
            ThresholdEcdsaVerifySigShareInternalError::UnsupportedAlgorithm => {
                ThresholdEcdsaVerifySigShareError::InternalError {
                    internal_error: "Algorithm not supported".to_string(),
                }
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

        tecdsa_verify_combined_signature(
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
            ThresholdEcdsaVerifySignatureInternalError::UnsupportedAlgorithm => {
                ThresholdEcdsaVerifyCombinedSignatureError::InternalError {
                    internal_error: "Algorithm not supported".to_string(),
                }
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
