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
use crate::{Csp, KeyId};
use ic_crypto_internal_threshold_sig_ecdsa::{
    combine_sig_shares as tecdsa_combine_sig_shares, create_transcript as tecdsa_create_transcript,
    publicly_verify_dealing as tecdsa_verify_dealing_public,
    verify_complaint as tecdsa_verify_complaint,
    verify_dealing_opening as tecdsa_verify_dealing_opening,
    verify_signature_share as tecdsa_verify_signature_share,
    verify_threshold_signature as tecdsa_verify_combined_signature,
    verify_transcript as tecdsa_verify_transcript, CommitmentOpening, DerivationPath,
    IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptInternalBytes, IDkgTranscriptOperationInternal, MEGaPublicKey,
    ThresholdEcdsaCombinedSigInternal, ThresholdEcdsaSigShareInternal,
    ThresholdEcdsaVerifySigShareInternalError, ThresholdEcdsaVerifySignatureInternalError,
};
use ic_crypto_internal_types::scope::{ConstScope, Scope};
use ic_logger::debug;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    IDkgOpenTranscriptError, IDkgRetainKeysError, IDkgVerifyComplaintError,
    IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError, IDkgVerifyOpeningError,
    IDkgVerifyTranscriptError, ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
    ThresholdEcdsaVerifyCombinedSignatureError, ThresholdEcdsaVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::{
    idkg::{BatchSignedIDkgDealing, IDkgDealingBytes},
    ExtendedDerivationPath, ThresholdEcdsaSigInputs,
};
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeIndex, NumberOfNodes, Randomness, RegistryVersion};

use std::collections::{BTreeMap, BTreeSet};

pub const IDKG_MEGA_SCOPE: Scope = Scope::Const(ConstScope::IDkgMEGaEncryptionKeys);
pub const IDKG_THRESHOLD_KEYS_SCOPE: Scope = Scope::Const(ConstScope::IDkgThresholdKeys);

/// Interactive distributed key generation client
///
/// Please see the trait definition for full documentation.
impl CspIDkgProtocol for Csp {
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
        dealing: IDkgDealingBytes,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_public_key: &MEGaPublicKey,
        context_data: &[u8],
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        debug!(self.logger; crypto.method_name => "idkg_verify_dealing_private");

        let receiver_key_id = key_id_from_mega_public_key_or_panic(receiver_public_key);

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
        dealings: &BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        public_key: &MEGaPublicKey,
        transcript: IDkgTranscriptInternalBytes,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        debug!(self.logger; crypto.method_name => "idkg_load_transcript");

        let key_id = key_id_from_mega_public_key_or_panic(public_key);

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
        dealings: &BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
        openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        public_key: &MEGaPublicKey,
        transcript: IDkgTranscriptInternalBytes,
    ) -> Result<(), IDkgLoadTranscriptError> {
        debug!(self.logger; crypto.method_name => "idkg_load_transcript_with_openings");

        let key_id = key_id_from_mega_public_key_or_panic(public_key);

        self.csp_vault.idkg_load_transcript_with_openings(
            dealings,
            openings,
            context_data,
            receiver_index,
            &key_id,
            transcript,
        )
    }

    fn idkg_gen_dealing_encryption_key_pair(&self) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        debug!(self.logger; crypto.method_name => "idkg_gen_dealing_encryption_key_pair");

        self.csp_vault.idkg_gen_dealing_encryption_key_pair()
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
        debug!(self.logger; crypto.method_name => "idkg_open_dealing");

        let opener_key_id = key_id_from_mega_public_key_or_panic(opener_public_key);

        self.csp_vault.idkg_open_dealing(
            dealing,
            dealer_index,
            context_data,
            opener_index,
            &opener_key_id,
        )
    }

    fn idkg_verify_dealing_opening(
        &self,
        dealing: IDkgDealingInternal,
        opener_index: NodeIndex,
        opening: CommitmentOpening,
    ) -> Result<(), IDkgVerifyOpeningError> {
        debug!(self.logger; crypto.method_name => "idkg_verify_dealing_opening");

        tecdsa_verify_dealing_opening(&dealing, opener_index, &opening).map_err(|e| {
            IDkgVerifyOpeningError::InternalError {
                internal_error: format!("{:?}", e),
            }
        })
    }

    fn idkg_retain_active_keys(
        &self,
        active_transcripts: &BTreeSet<IDkgTranscriptInternal>,
        oldest_public_key: MEGaPublicKey,
    ) -> Result<(), IDkgRetainKeysError> {
        debug!(self.logger; crypto.method_name => "idkg_retain_active_keys");

        let active_key_ids = active_transcripts
            .iter()
            .map(|active_transcript| {
                KeyId::from(active_transcript.combined_commitment.commitment())
            })
            .collect();

        self.csp_vault
            .idkg_retain_active_keys(active_key_ids, oldest_public_key)
    }

    fn idkg_observe_minimum_registry_version_in_active_idkg_transcripts(
        &self,
        registry_version: RegistryVersion,
    ) {
        self.metrics
            .observe_minimum_registry_version_in_active_idkg_transcripts(registry_version.get());
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

        let key = inputs.key_transcript().transcript_as_bytebuf();

        let q = inputs.presig_quadruple();
        let kappa_unmasked = q.kappa_unmasked().transcript_as_bytebuf();
        let lambda_masked = q.lambda_masked().transcript_as_bytebuf();
        let kappa_times_lambda = q.kappa_times_lambda().transcript_as_bytebuf();
        let key_times_lambda = q.key_times_lambda().transcript_as_bytebuf();

        self.csp_vault.ecdsa_sign_share(
            inputs.derivation_path(),
            inputs.hashed_message(),
            inputs.nonce(),
            key,
            kappa_unmasked,
            lambda_masked,
            kappa_times_lambda,
            key_times_lambda,
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

fn key_id_from_mega_public_key_or_panic(public_key: &MEGaPublicKey) -> KeyId {
    KeyId::try_from(public_key).unwrap_or_else(|err| panic!("{}", err))
}
