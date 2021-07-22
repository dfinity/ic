use crate::crypto::Signable;
use ic_base_types::{NodeId, SubnetId};
use ic_types::crypto::threshold_sig::ni_dkg::DkgId;
use ic_types::crypto::{CombinedThresholdSigOf, CryptoResult, ThresholdSigShareOf};
use ic_types::RegistryVersion;
use std::collections::BTreeMap;

pub mod ni_dkg;

/// A Crypto Component interface to create threshold signature shares.
pub trait ThresholdSigner<T: Signable> {
    /// Creates a threshold signature share.
    ///
    /// This method depends on key material for the respective DKG ID to be
    /// present in the secret key store (SKS) of the crypto component. To
    /// initialize this key material, the DKG transcript for the respective
    /// DKG ID must be loaded by using the `load_transcript` method of the
    /// `DkgAlgorithm` trait, which is implemented by the crypto component.
    ///
    /// # Errors
    /// * `CryptoError::ThresholdSigDataNotFound` if the threshold signature
    ///   data store does not contain public coefficients for the `dkg_id`. This
    ///   error indicates that `NiDkgAlgorithm::load_transcript` (or
    ///   `DkgAlgorithm::load_transcript`, respectively) must be called prior to
    ///   calling this method.
    /// * `CryptoError::SecretKeyNotFound` if the secret key is not present in
    ///   the secret key store.
    // TODO (CRP-479): switch to Result<ThresholdSigShareOf<T>,
    // ThresholdSigDataNotFoundError>
    fn sign_threshold(&self, message: &T, dkg_id: DkgId) -> CryptoResult<ThresholdSigShareOf<T>>;
}

/// A Crypto Component interface to verify threshold signatures.
///
/// The methods in this trait depend on key material for the respective DKG ID
/// to be present in the cache of the crypto component. To initialize this key
/// material, the DKG transcript for the respective DKG ID must be loaded by
/// using the `load_transcript` method of the `DkgAlgorithm` trait (which is
/// implemented by the crypto component).
pub trait ThresholdSigVerifier<T: Signable> {
    /// Verifies a threshold signature share.
    ///
    /// See the trait's doc comment for applicable preconditions.
    ///
    /// # Errors
    /// * `CryptoError::SignatureVerification` if the signature is not valid
    /// * `CryptoError::ThresholdSigDataNotFound` if the threshold signature
    ///   data store does not contain the necessary information for the `dkg_id`
    ///   to calculate the individual public key required for verifying the
    ///   `signature`. This error indicates that `DkgAlgorithm::load_transcript`
    ///   must be called prior to calling this method.
    /// * `CryptoError::MalformedSignature` if the given `signature` is not a
    ///   valid threshold signature (e.g., because of invalid length).
    /// * `CryptoError::InvalidArgument` if the transcript data in the threshold
    ///   signature data store does not contain a node index for the given
    ///   `signer`. This indicates that the `signer` is not a valid receiver for
    ///   the DKG round with ID `dkg_id`.
    ///
    /// # Panics
    /// * This method panics if calculating the individual public key fails,
    ///   which would happen if the implementations of DKG and threshold
    ///   signatures are not aligned.
    /// * This method panics if verifying the signature fails because the
    ///   implementations of DKG and threshold signatures are not aligned.
    fn verify_threshold_sig_share(
        &self,
        signature: &ThresholdSigShareOf<T>,
        message: &T,
        dkg_id: DkgId,
        signer: NodeId,
    ) -> CryptoResult<()>;

    /// Combines the given threshold signature `shares`.
    ///
    /// See the trait's doc comment for applicable preconditions.
    ///
    /// # Errors
    /// * `CryptoError::InvalidArgument` if the shares are empty, the threshold
    ///   is too high, no index is present in the store for a node id in shares,
    ///   the algorithm is unknown, or the public coefficients cannot be parsed.
    /// * `CryptoError::ThresholdSigDataNotFound` if the threshold signature
    ///   data store does not contain the public coefficients and node indices
    ///   for the `dkg_id`. This error indicates that
    ///   `DkgAlgorithm::load_transcript` must be called prior to calling this
    ///   method.
    /// * `CryptoError::MalformedSignature` if a sig share is malformed.
    // TODO (DFN-1505): Fix doc once the error handling is improved and some
    // InvalidArguments lead to panic. (see map_csp_combine_sigs_error_or_panic)
    fn combine_threshold_sig_shares(
        &self,
        shares: BTreeMap<NodeId, ThresholdSigShareOf<T>>,
        dkg_id: DkgId,
    ) -> CryptoResult<CombinedThresholdSigOf<T>>;

    /// Verifies a combined threshold signature.
    ///
    /// See the trait's doc comment for applicable preconditions.
    ///
    /// # Errors
    /// * `CryptoError::SignatureVerification` if the signature is not valid
    /// * `CryptoError::ThresholdSigDataNotFound` if the threshold signature
    ///   data store does not contain the necessary information for the
    ///   `dkg_id`. This error indicates that `DkgAlgorithm::load_transcript`
    ///   must be called prior to calling this method.
    /// * `CryptoError::MalformedSignature` if the given `signature` is not a
    ///   valid combined threshold signature (e.g., because of invalid length)
    fn verify_threshold_sig_combined(
        &self,
        signature: &CombinedThresholdSigOf<T>,
        message: &T,
        dkg_id: DkgId,
    ) -> CryptoResult<()>;
}

/// A Crypto Component interface to verify threshold signatures by a subnet's
/// public key.
pub trait ThresholdSigVerifierByPublicKey<T: Signable> {
    /// Verifies a combined threshold signature using a subnet's public key.
    ///
    /// The public key is derived from the subnet's initial DKG transcript
    /// stored in the registry.
    ///
    /// # Errors
    /// * `CryptoError::SignatureVerification` if the signature is not valid
    /// * `CryptoError::DkgTranscriptNotFound` if the registry does not contain
    ///   an initial DKG transcript for the given `subnet_id` at the given
    ///   `registry_version`.
    /// * `CryptoError::MalformedSignature` if the given `signature` is not a
    ///   valid combined threshold signature (e.g., because of invalid length)
    fn verify_combined_threshold_sig_by_public_key(
        &self,
        signature: &CombinedThresholdSigOf<T>,
        message: &T,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()>;
}
