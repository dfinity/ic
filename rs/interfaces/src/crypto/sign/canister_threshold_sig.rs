//! Traits for canister-requested threshold ECDSA signatures
//! and the associated interactive distributed key generation protocol (IDKG).
//!
//! Canisters must be able to create ECDSA signatures (e.g., to create bitcoin and thereum
//! transactions) but they cannot securely store a private key in memory (because the state of a
//! canister is known to all replicas in the subnet hosting the canister and one or more replicas
//! may be malicious). The secret key is therefore shared among the replicas of the subnet and they
//! must be able to collaboratively create ECDSA signatures.
//!
//! Since each ECDSA signature requires 4 transcripts, which are created by the distributed key
//! generation protocol, computing these transcripts must be
//! efficient and that's the reason why the protocol is interactive.

use ic_base_types::NodeId;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    IDkgOpenTranscriptError, IDkgRetainThresholdKeysError, IDkgVerifyComplaintError,
    IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError, IDkgVerifyInitialDealingsError,
    IDkgVerifyOpeningError, IDkgVerifyTranscriptError, ThresholdEcdsaCombineSigSharesError,
    ThresholdEcdsaSignShareError, ThresholdEcdsaVerifyCombinedSignatureError,
    ThresholdEcdsaVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealing, IDkgComplaint, IDkgOpening, IDkgTranscript, IDkgTranscriptParams,
    InitialIDkgDealings, SignedIDkgDealing,
};
use ic_types::crypto::canister_threshold_sig::{
    ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
};
use std::collections::{BTreeMap, HashSet};

/// A Crypto Component interface to run interactive distributed key generation (IDKG)
/// protocol for canister-requested threshold ECDSA signatures.
///
/// The IDKG protocol produces a *transcript* that gives all replicas inside a subnet shares of an
/// ECDSA secret key. Each canister-requested threshold signature requires 4 pre-computed
/// transcripts (they are independent of the message to be signed),
/// see [`PreSignatureQuadruple`].
///
/// # Use-Cases
///
/// ## Initial Key Generation
///
/// Dealers and receivers are all members of the same subnet.
/// When consensus realizes a key needs to be generated:
/// 1. Run IDKG protocol with [`Random`] operation to generate transcript `alpha`.
/// 1. Run IDKG protocol with [`ReshareOfUnmasked`] with transcript `alpha` to open public key.
///
/// ## Key Resharing
///
/// When the topology of a subnet changes or a key rotation of the nodes is triggered, the key
/// transcript `alpha` is reshared to the new subnet.
/// * Dealers: receivers of the previous transcript `alpha`
/// * Receivers: all nodes in the subnet with the new topology (which may include new nodes but
/// does not contain nodes that were removed).
///
/// Consensus orchestrates resharing by:
/// 1. Run IDKG protocol with [`ReshareOfUnmasked`] with transcript `alpha` to reshare.
///
/// ## Key Resharing Accross Subnets
///
/// Triggered by the governance canister to backup the key in another subnet. Half of the protocol
/// runs in a source subnet, while the other half runs in a target subnet. Note that the target
/// subnet may yet to be created.
/// * Dealers: all nodes in the source subnet
/// * Receivers: all nodes in the target subnet
///
/// 1. Run IDKG with [`ReshareOfUnmasked`] with transcript `alpha`.
///     * Source subnet calls [Self::create_dealing()] and [Self::verify_dealing_public()].
///     * Source subnet collects a set of [`InitialIDkgDealings`], which are included in the registry.
///     * Target subnet fetches the [`InitialIDkgDealings`] from the registry, terminates the protocol
///     by calling all other IDKG APIs [Self::verify_dealing_private()], [Self::create_transcript()], ...
///
/// No back communication from target to source: this is possible by including enough (>=2f+1, only
/// f+1 are needed) honest dealings in the InitialDealings (assuming at most f corruptions in the
/// sources subnet)
///
/// [`InitialIDkgDealings`]: ic_types::crypto::canister_threshold_sig::idkg::InitialIDkgDealings
/// [`PreSignatureQuadruple`]: ic_types::crypto::canister_threshold_sig::PreSignatureQuadruple
/// [`Random`]: ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptOperation::Random
/// [`ReshareOfUnmasked`]: ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptOperation::ReshareOfUnmasked
///
/// # Preconditions
///
/// * For a fixed `IDkgTranscriptId`, the `IDkgTranscriptParams` must never
///   change throughout a round of execution. That is, if two calls to methods
///   of `IDkgProtocol` are made with `IDkgTranscriptParams` values `params1`
///   and `params2` respectively, then if `params1.transcript_id == params2.dkg_id`,
///   we must have `params1 == params2`.
pub trait IDkgProtocol {
    /// Create a signed dealing of a prescribed type..
    ///
    /// A dealing contains a polynomial commitment and encryption of the secret
    /// shares of the receivers.
    /// In addition, for some transcript types, this contains a contextual proof
    /// for the secret value being shared.
    /// The dealing is signed by the secret key of the node issuing the dealing (a.k.a the dealer).
    ///
    /// The type of dealing created is determined by the
    /// `IDkgTranscriptOperation` specified in the `params`.
    ///
    /// For resharing or multiplication, the relevant previous dealings
    /// must have been loaded via prior calls to `load_transcript`.
    fn create_dealing(
        &self,
        params: &IDkgTranscriptParams,
    ) -> Result<SignedIDkgDealing, IDkgCreateDealingError>;

    /// Perform public verification of a dealing.
    ///
    /// This checks the consistency of the dealing with the params, the signature on the dealing,
    /// and it verifies the optional contextual proof.
    ///
    /// # Errors
    /// * `IDkgVerifyDealingPublicError::TranscriptIdMismatch` if the transcript ID in the `params`
    ///    is different from the one included in the dealing.
    /// * `IDkgVerifyDealingPublicError::InvalidDealing` if the internal dealing is invalid.
    /// * `IDkgVerifyDealingPublicError::InvalidSignature` if the signature on the dealing is invalid.
    fn verify_dealing_public(
        &self,
        params: &IDkgTranscriptParams,
        signed_dealing: &SignedIDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPublicError>;

    /// Perform private verification of a dealing.
    ///
    /// If called by a receiver of the dealing, this verifies:
    /// * Decryptability of the receiver's ciphertext
    /// * The consistency of the decrypted share with the polynomial
    ///   commitment.
    ///
    /// # Preconditions
    /// * Public verification of the given dealing was successful: call first
    ///   [Self::verify_dealing_public] and ensure that no error occurred *before* calling this method.
    ///   Otherwise, calling this method may result in a security vulnerability!
    ///
    /// # Errors
    /// * `IDkgVerifyDealingPrivateError::NotAReceiver` if the caller isn't in the
    ///   dealing's receivers. Only receivers can perform private verification of dealings.
    /// * `IDkgVerifyDealingPrivateError::InvalidDealing` if the decrypted shares are not consistent
    ///    with polynomial commitment.
    /// * `IDkgVerifyDealingPrivateError::InvalidArgument` if some argument cannot be parsed correctly.
    /// * `IDkgVerifyDealingPrivateError::PrivateKeyNotFound` if the secret key store of the node
    ///    does not contain the secret key necessary to decrypt the ciphertext.
    /// * `IDkgVerifyDealingPrivateError::RegistryError` if the registry client returned an error.
    /// * `IDkgVerifyDealingPrivateError::PublicKeyNotInRegistry` if the encryption key of the
    ///    receiver is not in the registry.
    /// * `IDkgVerifyDealingPrivateError::MalformedPublicKey` if the public key of one of the receivers
    ///    is not well formed.
    /// * `IDkgVerifyDealingPrivateError::UnsupportedAlgorithm` if the `params.algorithm_id` is not supported
    /// * `IDkgVerifyDealingPrivateError::InternalError` if the an internal error occurs.
    /// * `IDkgVerifyDealingPrivateError::CspVaultRpcError` if there is an RPC error reported when
    ///    connecting with the vault.
    fn verify_dealing_private(
        &self,
        params: &IDkgTranscriptParams,
        signed_dealing: &SignedIDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPrivateError>;

    /// Verifies initial dealings for XNet resharing.
    ///
    /// Verification ensures that
    /// * the `params` are equal to the params of `initial_dealings`
    /// *  public dealing verification is successful for all dealings in `initial_dealings`
    ///
    /// # Errors
    /// * `IDkgVerifyInitialDealingsError::MismatchingTranscriptParams` if the
    ///   `params` are equal to the params of `initial_dealings`.
    /// * `IDkgVerifyInitialDealingsError::PublicVerificationFailure` if public
    ///   dealing verification fails for some dealing in `initial_dealings`.
    fn verify_initial_dealings(
        &self,
        params: &IDkgTranscriptParams,
        initial_dealings: &InitialIDkgDealings,
    ) -> Result<(), IDkgVerifyInitialDealingsError>;

    /// Combine the given dealings into a transcript.
    ///
    /// Performs the following on each dealing:
    /// * Checks consistency with the params
    /// * Checks that the multisignature was computed by at least
    /// `IDkgTranscriptParams::verification_threshold` receivers
    /// * Verifies the (combined) multisignature
    fn create_transcript(
        &self,
        params: &IDkgTranscriptParams,
        dealings: &BTreeMap<NodeId, BatchSignedIDkgDealing>,
    ) -> Result<IDkgTranscript, IDkgCreateTranscriptError>;

    /// Verify the multisignature on each dealing in the transcript.
    ///
    /// Also checks that each multisignature was computed by at least
    /// `IDkgTranscriptParams::verification_threshold` receivers.
    fn verify_transcript(
        &self,
        params: &IDkgTranscriptParams,
        transcript: &IDkgTranscript,
    ) -> Result<(), IDkgVerifyTranscriptError>;

    /// Load the transcript.
    ///
    /// This:
    /// * Decrypts this receiver's ciphertext in each dealing
    /// * Checks the consistency of the decrypted shares with the polynomial
    ///   commitment
    /// * Recombines the secret share from all dealers' contributions
    /// * Combines the polynomial commitments to get any needed public data
    /// * Stores the recombined secret in the local canister secret key store
    ///
    /// # Returns
    /// * `Ok([])` if decryption succeeded
    /// * `Ok(Vec<IDkgComplaints>)` if some dealings require Openings
    /// * `Err` if a fatal error occurred
    fn load_transcript(
        &self,
        transcript: &IDkgTranscript,
    ) -> Result<Vec<IDkgComplaint>, IDkgLoadTranscriptError>;

    /// Verifies the validity of a complaint against some dealings.
    ///
    /// This:
    /// * Checks the decryption verification proof
    /// * Attempts decryption-from-proof of the complainer's ciphertext and
    ///   either:
    ///   * Confirms that the ciphertext can't be decrypted
    ///   * Checks that the decrypted share is not consistent with the
    ///     polynomial commitment.
    ///
    /// # Errors
    /// * `IDkgVerifyComplaintError::InvalidComplaint` if the complaint is invalid.
    /// * `IDkgVerifyComplaintError::InvalidArguments` if one or more arguments
    ///   are invalid.
    /// * `IDkgVerifyComplaintError::InvalidArgumentsMismatchingTranscriptIDs` if
    ///   the transcript IDs in the transcript and the complaint do not match (i.e.,
    ///   are not equal).
    /// * `IDkgVerifyComplaintError::InvalidArgumentsMissingDealingInTranscript`
    ///   if the (verified) dealings in the transcript do not contain a dealing
    ///   whose dealer ID matches the complaint's dealer ID.
    /// * `IDkgVerifyComplaintError::InvalidArgumentsMissingComplainerInTranscript`
    ///   if the transcript's receivers do not contain a receiver whose ID matches
    ///   the complaint's complainer ID.
    /// * `IDkgVerifyComplaintError::ComplainerPublicKeyNotInRegistry` if the
    ///   complainer's (MEGa) public key cannot be found in the registry.
    /// * `IDkgVerifyComplaintError::MalformedComplainerPublicKey` if the
    ///   complainer's (MEGa) public key fetched from the registry is malformed.
    /// * `IDkgVerifyComplaintError::UnsupportedComplainerPublicKeyAlgorithm` if
    ///   the algorithm of the complainer's (MEGa) public key in the registry is
    ///   not supported.
    /// * `IDkgVerifyComplaintError::SerializationError` if the (internal raw)
    ///   complaint cannot be deserialized, or if the dealing corresponding to the
    ///   complaint's dealer ID cannot be deserialized from the transcript.
    /// * `IDkgVerifyComplaintError::Registry` if the registry client returns an
    ///   error, e.g., because the transcript's `registry_version` is not available.
    /// * `IDkgVerifyComplaintError::InternalError` if an internal error occurred
    ///   during the verification.
    fn verify_complaint(
        &self,
        transcript: &IDkgTranscript,
        complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyComplaintError>;

    /// Generate an opening for the dealing given in `complaint`,
    /// reported by `complainer_id`.
    fn open_transcript(
        &self,
        transcript: &IDkgTranscript,
        complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<IDkgOpening, IDkgOpenTranscriptError>;

    /// Verify that an opening corresponds to the complaint,
    /// and matches the commitment in the transcript.
    fn verify_opening(
        &self,
        transcript: &IDkgTranscript,
        opener: NodeId,
        opening: &IDkgOpening,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyOpeningError>;

    /// Load the transcript (cf. `load_transcript`),
    /// with the help of `openings`.
    ///
    /// # Preconditions
    /// * For each (complaint, (opener, opening)) tuple, it holds that
    ///   `verify_opening(transcript, opener, opening, complaint).is_ok()`
    fn load_transcript_with_openings(
        &self,
        transcript: &IDkgTranscript,
        openings: &BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    ) -> Result<(), IDkgLoadTranscriptError>;

    /// Retains only the IDKG key material needed for the given transcripts.
    /// If no transcript is given, no key material will be removed.
    ///
    /// All other IDKG key material will be removed as follows:
    /// * rotated IDKG public keys in the public key store which are no longer used.
    ///   The oldest used IDKG public key is identified by the smallest registry version
    ///   in the given transcripts. Older IDKG public key will be removed while the others
    ///   will be kept.
    /// * corresponding IDKG secret keys in the node secret key store
    /// * IDKG threshold keys in the canister secret key store which are no longer used.
    ///   Each given transcript uniquely identifies an IDKG threshold key.
    ///   IDKG threshold keys not identified by a transcript will be removed.
    ///
    /// # Errors
    /// * `IDkgRetainThresholdKeysError::InternalError` if an internal error such as
    ///   an RPC error communicating with a remote CSP vault occurs
    /// * `IDkgRetainThresholdKeysError::SerializationError` if a transcript cannot
    ///   be serialized into a key id to identify the IDKG threshold secret key
    fn retain_active_transcripts(
        &self,
        active_transcripts: &HashSet<IDkgTranscript>,
    ) -> Result<(), IDkgRetainThresholdKeysError>;
}

/// A Crypto Component interface to generate ECDSA threshold signature shares.
pub trait ThresholdEcdsaSigner {
    /// Generate a signature share.
    fn sign_share(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
    ) -> Result<ThresholdEcdsaSigShare, ThresholdEcdsaSignShareError>;
}

/// A Crypto Component interface to perform public operations in the ECDSA
/// threshold signature scheme.
pub trait ThresholdEcdsaSigVerifier {
    /// Verify that the given signature share was correctly created from
    /// `inputs`.
    fn verify_sig_share(
        &self,
        signer: NodeId,
        inputs: &ThresholdEcdsaSigInputs,
        share: &ThresholdEcdsaSigShare,
    ) -> Result<(), ThresholdEcdsaVerifySigShareError>;

    /// Combine the given signature shares into a convential ECDSA signature.
    ///
    /// The signature is returned as raw bytes.
    fn combine_sig_shares(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
        shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
    ) -> Result<ThresholdEcdsaCombinedSignature, ThresholdEcdsaCombineSigSharesError>;

    /// Verify that a combined signature was properly created from the inputs.
    fn verify_combined_sig(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
        signature: &ThresholdEcdsaCombinedSignature,
    ) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError>;
}
