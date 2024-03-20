//! CSP canister threshold signature traits

use ic_crypto_internal_threshold_sig_ecdsa::{
    IDkgTranscriptInternal, MEGaPublicKey, ThresholdEcdsaCombinedSigInternal,
    ThresholdEcdsaSigShareInternal,
};
use ic_types::crypto::canister_threshold_sig::error::{
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
    ThresholdEcdsaVerifyCombinedSignatureError, ThresholdEcdsaVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::{ExtendedDerivationPath, ThresholdEcdsaSigInputs};
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use std::collections::BTreeMap;

pub mod errors;
pub use errors::*;

/// Crypto service provider (CSP) client for interactive distributed key
/// generation (IDkg) for canister threshold signatures.
pub trait CspIDkgProtocol {
    /// Generate a MEGa public/private key pair for encrypting threshold key shares in transmission
    /// from dealers to receivers. The generated public key will be stored in the node's public key store
    /// while the private key will be stored in the node's secret key store.
    ///
    /// # Returns
    /// Generated public key.
    ///
    /// # Errors
    /// * [`CspCreateMEGaKeyError::SerializationError`] if serialization of public or private key
    ///   before storing it in their respective key store failed.
    /// * [`CspCreateMEGaKeyError::TransientInternalError`] if there is a
    ///   transient internal error, e.g,. an IO error when writing a key to
    ///   disk, or an RPC error when calling a remote CSP vault.
    /// * [`CspCreateMEGaKeyError::DuplicateKeyId`] if there already
    ///   exists a secret key in the store for the secret key ID derived from
    ///   the public part of the randomly generated key pair. This error
    ///   most likely indicates a bad randomness source.
    /// * [`CspCreateMEGaKeyError::InternalError`]: if the key ID for the secret key cannot be
    ///   derived from the generated public key.
    fn idkg_gen_dealing_encryption_key_pair(&self) -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;
}

/// Crypto service provider (CSP) client for threshold ECDSA signature share
/// generation.
pub trait CspThresholdEcdsaSigner {
    /// Generate a signature share.
    fn ecdsa_sign_share(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
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

    /// Verify a signature share
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
    ) -> Result<(), ThresholdEcdsaVerifySigShareError>;

    /// Verify a combined ECDSA signature with respect to a particular kappa transcript
    fn ecdsa_verify_combined_signature(
        &self,
        signature: &ThresholdEcdsaCombinedSigInternal,
        derivation_path: &ExtendedDerivationPath,
        hashed_message: &[u8],
        nonce: &Randomness,
        key: &IDkgTranscriptInternal,
        kappa_unmasked: &IDkgTranscriptInternal,
        algorithm_id: AlgorithmId,
    ) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError>;
}
