//! CSP canister threshold signature traits

use ic_crypto_internal_threshold_sig_ecdsa::{
    CommitmentOpening, IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptOperationInternal, MEGaPublicKey, ThresholdEcdsaCombinedSigInternal,
    ThresholdEcdsaSigShareInternal,
};
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    IDkgOpenTranscriptError, IDkgVerifyComplaintError, IDkgVerifyDealingPrivateError,
    IDkgVerifyTranscriptError, ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use std::collections::BTreeMap;

pub mod errors;
pub use errors::*;

/// Crypto service provider (CSP) client for interactive distributed key
/// generation (IDkg) for canister threshold signatures.
pub trait CspIDkgProtocol {
    /// Generates a share of a dealing for a single receiver.
    fn idkg_create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        context_data: &[u8],
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: &[MEGaPublicKey],
        transcript_operation: &IDkgTranscriptOperationInternal,
    ) -> Result<IDkgDealingInternal, IDkgCreateDealingError>;

    /// Performs private verification of a dealing.
    fn idkg_verify_dealing_private(
        &self,
        algorithm_id: AlgorithmId,
        dealing: &IDkgDealingInternal,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_public_key: &MEGaPublicKey,
        context_data: &[u8],
    ) -> Result<(), IDkgVerifyDealingPrivateError>;

    /// Generates an IDkg transcript from verified IDkg dealings
    fn idkg_create_transcript(
        &self,
        algorithm_id: AlgorithmId,
        reconstruction_threshold: NumberOfNodes,
        verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        operation_mode: &IDkgTranscriptOperationInternal,
    ) -> Result<IDkgTranscriptInternal, IDkgCreateTranscriptError>;

    fn idkg_verify_transcript(
        &self,
        transcript: &IDkgTranscriptInternal,
        algorithm_id: AlgorithmId,
        reconstruction_threshold: NumberOfNodes,
        verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        operation_mode: &IDkgTranscriptOperationInternal,
    ) -> Result<(), IDkgVerifyTranscriptError>;

    /// Compute secret from transcript and store in SKS, generating complaints
    /// if necessary.
    fn idkg_load_transcript(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        public_key: &MEGaPublicKey,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError>;

    /// Computes a secret share from a transcript and openings, and stores it
    /// in the canister secret key store.
    fn idkg_load_transcript_with_openings(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        public_key: &MEGaPublicKey,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<(), IDkgLoadTranscriptError>;

    /// Generate a MEGa key pair for encrypting threshold key shares in transmission
    /// from dealers to receivers.
    fn idkg_create_mega_key_pair(
        &mut self,
        algorithm_id: AlgorithmId,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;

    /// Verifies that the given `complaint` about `dealing` is correct/justified.
    /// A complaint is created, e.g., when loading of a transcript fails.
    fn idkg_verify_complaint(
        &self,
        complaint: &IDkgComplaintInternal,
        complainer_index: NodeIndex,
        complainer_key: &MEGaPublicKey,
        dealing: &IDkgDealingInternal,
        dealer_index: NodeIndex,
        context_data: &[u8],
    ) -> Result<(), IDkgVerifyComplaintError>;

    /// Opens
    fn idkg_open_dealing(
        &self,
        dealing: IDkgDealingInternal,
        dealer_index: NodeIndex,
        context_data: &[u8],
        opener_index: NodeIndex,
        opener_public_key: &MEGaPublicKey,
    ) -> Result<CommitmentOpening, IDkgOpenTranscriptError>;
}

/// Crypto service provider (CSP) client for threshold ECDSA signature share
/// generation.
pub trait CspThresholdEcdsaSigner {
    /// Generate a signature share.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaSignShareError>;
}

/// Crypto service provider (CSP) client for threshold ECDSA signature
/// verification.
pub trait CspThresholdEcdsaSigVerifier {
    /// Combine signature shares.
    #[allow(clippy::too_many_arguments)]
    fn ecdsa_combine_sig_shares(
        &self,
        derivation_path: &ExtendedDerivationPath,
        hashed_message: &[u8],
        nonce: &Randomness,
        key: &IDkgTranscriptInternal,
        kappa_unmasked: &IDkgTranscriptInternal,
        reconstruction_threshold: NumberOfNodes,
        sig_shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdEcdsaCombinedSigInternal, ThresholdEcdsaCombineSigSharesError>;
}
