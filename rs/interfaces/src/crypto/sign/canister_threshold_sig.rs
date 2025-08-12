//! Traits providing the crypto component interfaces for a threshold ECDSA protocol.
//!
//! A set of nodes can use a threshold ECDSA protocol to establish a decentralized ECDSA signing service.
//! The protocol is secure as long as the number of corrupted nodes is less than the threshold (typically
//! less than 1/3). The main building block used in the protocol is an interactive distributed key generation
//! protocol (IDKG), which is used for the following:
//! * Generate an ECDSA signing key, which is secret-shared between the participants.
//! * Re-share an existing ECDSA signing key to a new set of nodes, e.g. if nodes leave or join a subnet, or
//!   to back up the key on a another subnet.
//! * Secret-share random values (also known as Beaver triplets) used in the computation of threshold ECDSA
//!   signatures.
//!
//! A signing service supporting multiple users needs to manage many public keys, often several per users.
//! Since generating and managing these is expensive, it would not scale to generate different keys per user.
//! Instead, the threshold ECDSA protocol implemented by the IC uses key derivation to derive individual
//! users public keys from a master ECDSA signing key. The key derivation is a generalization of BIP32, and
//! users can further derive any number of subkeys from their main public key. This allows the signing service
//! to easily scale with the number of users.
//!
//! At an high-level, the ECDSA signing protocol can be divided into an offline and online phase:
//! * Offline phase: this is a pre-computation step that can be performed ahead of time, before the message and
//!   the identity of the signer are known to the nodes. Most of the interaction takes place in this phase of the
//!   protocol. This phase consists of running 5 instances of the IDKG protocol to construct a *quadruple* of
//!   secret-shared values that are used in the online phase of the protocol (the value generated in one of the
//!   instances is used as an intermediary value and it is not used in the signing protocol). Each quadruple can
//!   only be used in the construction of a single ECDSA signature.
//! * Online phase: this phase is executed to answer an incoming signature request, i.e. once the message and
//!   the identity of the signer are known. This part of the protocol is non-interactive, i.e all nodes use their
//!   shares of a precomputed quadruple to compute locally a signature share. Enough shares can then be publicly
//!   combined into a full ECDSA signature.

use ic_base_types::NodeId;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    IDkgOpenTranscriptError, IDkgRetainKeysError, IDkgVerifyComplaintError,
    IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError, IDkgVerifyInitialDealingsError,
    IDkgVerifyOpeningError, IDkgVerifyTranscriptError, ThresholdEcdsaCombineSigSharesError,
    ThresholdEcdsaCreateSigShareError, ThresholdEcdsaVerifyCombinedSignatureError,
    ThresholdEcdsaVerifySigShareError, ThresholdSchnorrCombineSigSharesError,
    ThresholdSchnorrCreateSigShareError, ThresholdSchnorrVerifyCombinedSigError,
    ThresholdSchnorrVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealings, IDkgComplaint, IDkgOpening, IDkgTranscript, IDkgTranscriptParams,
    InitialIDkgDealings, SignedIDkgDealing,
};
use ic_types::crypto::canister_threshold_sig::{
    ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
    ThresholdSchnorrCombinedSignature, ThresholdSchnorrSigInputs, ThresholdSchnorrSigShare,
};
use std::collections::{BTreeMap, HashSet};

/// A Crypto Component interface to run interactive distributed key generation (IDKG) protocol as part of the
/// threshold ECDSA protocol. Nodes can engage in an instance of the IDKG protocol to secret-share some values.
/// A successful execution of the protocol terminates with a *transcript* which summarizes the messages exchanged
/// during the protocol.
///
/// # Protocol Overview:
/// The IDKG protocol involves two sets of participants interacting in the protocol: *dealers* and *receivers*.
/// The set of dealers jointly constructs a common secret, which is secret-shared to the set of the receivers.
/// I.e. each receiver obtains a piece of the common secret, such that a threshold number of receivers has to
/// contribute with their shares in order to reconstruct the full secret.
///
/// Before starting the protocol, the node in a subnet agree on some global parameters [`IDkgTranscriptParams`],
/// including, for example, the set of participants, which elliptic curve should be used, and an identifier for the
/// protocol instance. The params used in a protocol instance must remain the same for the entire duration of the
/// protocol.
///
/// ## Dealings:
/// Dealers contribute to the protocol with a *dealing*, which consists of encrypted shares of a secret value known
/// by the dealer, one encrypted share for each receiver, as well as a commitment to the shares. The protocol uses
/// different types of commitments schemes:
/// * Perfectly hiding commitments, as used in Pedersen's  verifiable secret sharing scheme (VSS). Here we refer to
///   values committed with such commitment as `Masked`.
/// * Perfectly binding commitments, as used in Feldman's VSS. Here we refer to values committed with such commitment
///   as `Unmasked`.
///
/// Dealers can construct dealings for different kind of secrets and use different types of commitment schemes:
/// * [`Random`]: at the end of the protocol the receivers have a share of a new random value that is masked.
/// * [`ReshareOfMasked`]: given an existing masked secret shared between the dealers, at the end the receivers obtain
///   a new sharing for the same secret, but unmasked.
/// * [`ReshareOfUnmasked`]: given an existing unmasked secret shared between the dealers, at the end the receivers
///   obtain a new sharing for the same secret, that is still unmasked.
/// * [`UnmaskedTimesMasked`]: given two existing secrets, one masked and one unmasked, shared between the dealers,
///   at the end the receivers obtain a sharing of the product of the initial secret that is masked.
///
/// Since this is an *interactive* distributed key generation protocol, the verification of encrypted shares in a dealing
/// is done privately by the receivers, which decrypt their shares and check the validity against some public commitment.
/// This is in contrast with non-interactive DKG protocols, where the verification of dealings can be performed publicly.
/// In case the verification is successful, receivers sign the dealings to show their support.
///
/// ## Transcripts:
/// Multiple dealings contributions from different dealers are required to establish a common secret. The minimum
/// number of contributions depends both on the reconstruction threshold and on the kind of secret value being shared.
/// Once enough dealings with sufficient receivers' support are collected, they are then combined into a transcript
/// [`IDkgTranscript`] which summarizes all the information the receivers need to reconstruct their share of the
/// common secret.
///
/// ## Complaints:
/// After a transcript is successfully created, it could happen that a receiver cannot successfully decrypt all its
/// shares from the dealers. If this happens the receiver can compute a [`IDkgComplaint`] against specific dealings
/// and send this to all the other receivers. The receivers can verify the complaint and, if valid, return an
/// [`IDkgOpening`] to the issuer of the complaint. Given enough valid openings, the issuer can reconstruct the missing
/// share.
///
/// # Use-Cases
///
/// ## Key Generation
///
/// * Dealers: all the nodes in a subnet.
/// * Receivers: same nodes as the set of dealers.
///   The nodes run two instances of the IDKG protocol in sequence:
/// 1. Run IDKG protocol to generate a [`Random`] secret key. Since the commitment used here is masking, the nodes do
///    not yet know the corresponding public key, but only a share of it.
/// 2. Run IDKG protocol to do a [`ReshareOfMasked`] secret key generated in the previous protocol instance. Since the
///    commitment used here is unmasked, the nodes will then learn the public key corresponding to the secret key
///    generated in the first instance.
///
/// ## Key Re-sharing
///
/// When the membership of subnet changes or in case shares associated with the key needs to be refreshed (e.g. for proactive
/// security), the nodes of the subnet run one instance of the IDKG protocol.
/// * Dealers: nodes that were receivers in the IDKG instance that generated the key to be re-shared.
/// * Receivers: all nodes in the subnet with the new topology (which may include new nodes and exclude nodes that were
///   removed).
///   The nodes re-share a key by running a single IDKG protocol instance:
/// 1. Run IDKG protocol to do a [`ReshareOfUnmasked`] key that was previously generated.
///
/// ## XNet Key Re-sharing
///
/// Subnets can share an existing key with another subnet, e.g. to back it up or to scale the threshold ECDSA protocol.
/// Half of the IDKG protocol runs in the source subnet that knows the key, while the other half runs in a target subnet
/// receiving a copy of the key.
/// * Dealers: all nodes in the source subnet
/// * Receivers: all nodes in the target subnet. Note that this subnet does not need to exist yet, it could be under
///   construction
///
/// The nodes run a single IDKG protocol instance:
/// * The source subnet initiate a protocol to [`ReshareOfUnmasked`] key that was previously generated.
/// * The source subnet collects enough dealings into [`InitialIDkgDealings`] that are then included in the registry.
/// * The target subnet fetches the [`InitialIDkgDealings`] from the registry and completes the execution of the protocol.
///
/// No communication between the source and target subnets is required apart from the registry. This is possible by
/// making sure that the initial dealings include enough honest dealings, so that the receivers can terminate the protocol.
/// I.e. with at most f corruptions, a set of >=2f+1 dealings from distinct dealers is guaranteed to have at least f+1
/// honest dealings.
///
/// [`InitialIDkgDealings`]: ic_types::crypto::canister_threshold_sig::idkg::InitialIDkgDealings
/// [`EcdsaPreSignatureQuadruple`]: ic_types::crypto::canister_threshold_sig::EcdsaPreSignatureQuadruple
/// [`Random`]: ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptOperation::Random
/// [`ReshareOfMasked`]: ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptOperation::ReshareOfMasked
/// [`ReshareOfUnmasked`]: ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptOperation::ReshareOfUnmasked
/// [`UnmaskedTimesMasked`]: ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptOperation::UnmaskedTimesMasked
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
    ///
    /// # Errors
    /// * [`IDkgCreateDealingError::NotADealer`] if the current node is not specified as a dealer
    ///   in `params`.
    /// * [`IDkgCreateDealingError::MalformedPublicKey`] if the public key in the registry of any
    ///   of the receivers specified in `params` is malformed.
    /// * [`IDkgCreateDealingError::PublicKeyNotFound`] if the public key of any of the receivers
    ///   specified in `params` is not found in the registry.
    /// * [`IDkgCreateDealingError::UnsupportedAlgorithm`] if the public key in the registry of any
    ///   of the receivers specified in `params` has an unsupported algorithm.
    /// * [`IDkgCreateDealingError::RegistryError`] if there was an error retrieving the public key
    ///   of any of the receivers specified in `params` from the registry.
    /// * [`IDkgCreateDealingError::SerializationError`] if there was an error deserializing the
    ///   internal iDKG transcript in `params.operation_type`, or an error serializing the created
    ///   dealing.
    /// * [`IDkgCreateDealingError::SignatureError`] if there was an error signing the created
    ///   dealing.
    /// * [`IDkgCreateDealingError::InternalError`] if there was an internal error creating the
    ///   dealing, likely due to invalid input.
    /// * [`IDkgCreateDealingError::SecretSharesNotFound`] if the secret shares necessary for
    ///   creating the dealing could not be found in the canister secret key store. Calling
    ///   [`IDkgProtocol::load_transcript`] may be necessary.
    /// * [`IDkgCreateDealingError::TransientInternalError`] if there was a transient internal
    ///   error, e.g., when communicating with the remote CSP vault.
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
    /// * [`IDkgVerifyDealingPublicError::TranscriptIdMismatch`] if the transcript ID in the `params`
    ///   is different from the one included in the dealing.
    /// * [`IDkgVerifyDealingPublicError::InvalidDealing`] if the internal dealing is invalid.
    /// * [`IDkgVerifyDealingPublicError::InvalidSignature`] if the signature on the dealing is invalid.
    #[allow(clippy::result_large_err)]
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
    /// * [`IDkgVerifyDealingPrivateError::NotAReceiver`] if the caller isn't in the
    ///   dealing's receivers. Only receivers can perform private verification of dealings.
    /// * [`IDkgVerifyDealingPrivateError::InvalidDealing`] if the decrypted shares are not consistent
    ///   with polynomial commitment.
    /// * [`IDkgVerifyDealingPrivateError::InvalidArgument`] if some argument cannot be parsed correctly.
    /// * [`IDkgVerifyDealingPrivateError::PrivateKeyNotFound`] if the secret key store of the node
    ///   does not contain the secret key necessary to decrypt the ciphertext.
    /// * [`IDkgVerifyDealingPrivateError::RegistryError`] if the registry client returned an error.
    /// * [`IDkgVerifyDealingPrivateError::PublicKeyNotInRegistry`] if the encryption key of the
    ///   receiver is not in the registry.
    /// * [`IDkgVerifyDealingPrivateError::MalformedPublicKey`] if the public key of one of the receivers
    ///   is not well formed.
    /// * [`IDkgVerifyDealingPrivateError::UnsupportedAlgorithm`] if the `params.algorithm_id` is not supported
    /// * [`IDkgVerifyDealingPrivateError::InternalError`] if the an internal error occurs.
    /// * [`IDkgVerifyDealingPrivateError::TransientInternalError`] if there was a transient internal
    ///   error, e.g., when communicating with the remote CSP vault.
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
    /// * [`IDkgVerifyInitialDealingsError::MismatchingTranscriptParams`] if the
    ///   `params` are equal to the params of `initial_dealings`.
    /// * [`IDkgVerifyInitialDealingsError::PublicVerificationFailure`] if public
    ///   dealing verification fails for some dealing in `initial_dealings`.
    #[allow(clippy::result_large_err)]
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
    ///   `IDkgTranscriptParams::verification_threshold` receivers
    /// * Verifies the (combined) multisignature
    ///
    /// # Errors
    /// * [`IDkgCreateTranscriptError::SerializationError`] if there was an error deserializing the
    ///   internal iDKG transcript in `params.operation_type`; if there was an error deserializing
    ///   the internal dealings from the signed `dealings`; or if there was an error serializing
    ///   the created transcript.
    /// * [`IDkgCreateTranscriptError::InternalError`] if there was an internal error creating the
    ///   transcript, likely due to invalid input.
    /// * [`IDkgCreateTranscriptError::DealerNotAllowed`] if a `NodeId` of a dealer in `dealings`
    ///   is not included in the list of allowed dealers in `params`.
    /// * [`IDkgCreateTranscriptError::SignerNotAllowed`] if a `NodeId` of a signer in `dealings`
    ///   is not included in the list of allowed receivers in `params`.
    /// * [`IDkgCreateTranscriptError::UnsatisfiedCollectionThreshold`] if the number of `dealings`
    ///   is less than the collection threshold specified in `params`.
    /// * [`IDkgCreateTranscriptError::UnsatisfiedVerificationThreshold`] if the number of signers
    ///   in any dealing in `dealings` is less than the verification threshold specified in
    ///   `params`.
    /// * [`IDkgCreateTranscriptError::InvalidSignatureBatch`] if there was an error verifying any
    ///   of the signatures in any of the dealings in `dealings`.
    fn create_transcript(
        &self,
        params: &IDkgTranscriptParams,
        dealings: &BatchSignedIDkgDealings,
    ) -> Result<IDkgTranscript, IDkgCreateTranscriptError>;

    /// Verify the multisignature on each dealing in the transcript.
    ///
    /// Also checks that each multisignature was computed by at least
    /// `IDkgTranscriptParams::verification_threshold` receivers.
    ///
    /// # Errors
    /// * [`IDkgVerifyTranscriptError::InvalidArgument`] if there was an error verifying the
    ///   transcript due to invalid arguments, e.g., an invalid algorithm, insufficient number of
    ///   dealings, an unexpected commitment type wrt. the dealing type, etc.
    /// * [`IDkgVerifyTranscriptError::InvalidDealingSignatureBatch`] if there was an error
    ///   verifying any of the signatures in any of the dealings in `dealings`.
    /// * [`IDkgVerifyTranscriptError::SerializationError`] if there was an error deserializing the
    ///   internal transcript in `transcript`, or if there was an error deserializing any of the
    ///   internal dealings in the verified dealings in `transcript`.
    /// * [`IDkgVerifyTranscriptError::InvalidTranscript`] if the re-creation of an internal
    ///   transcript does not match the internal transcript in `transcript`.
    #[allow(clippy::result_large_err)]
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
    /// * `Ok([])` if decryption succeeded, if the secret share had already been stored in the
    ///   canister secret keystore, or if this node is not a receiver of the `transcript`.
    /// * `Ok(Vec<IDkgComplaints>)` if some dealings require Openings
    ///
    /// # Errors
    /// * [`IDkgLoadTranscriptError::InvalidArguments`] if there was an error decrypting
    ///   ciphertexts, or an error combining openings.
    /// * [`IDkgLoadTranscriptError::PublicKeyNotFound`] if the public key of this receiver was not
    ///   found in the registry.
    /// * [`IDkgLoadTranscriptError::SerializationError`] if there was an error deserializing a
    ///   dealing from the signed and verified dealings in `transcript`; if there was an error
    ///   deserializing the internal transcript in `transcript`; if there was an error
    ///   serializing any of the generated internal complaints; if there was an error deserializing
    ///   the `MEGaPublicKeySet` from the secret keystore, or if the key with the computed `KeyId`
    ///   was not of the expected type.
    /// * [`IDkgLoadTranscriptError::PrivateKeyNotFound`] if the private key corresponding to this
    ///   receiver's public key was not found in the canister secret keystore.
    /// * [`IDkgLoadTranscriptError::InternalError`] if there was an internal error while loading
    ///   the transcript, e.g., an error writing to the canister secret keystore.
    /// * [`IDkgLoadTranscriptError::MalformedPublicKey`] if this receiver's public key in the
    ///   registry is malformed.
    /// * [`IDkgLoadTranscriptError::UnsupportedAlgorithm`] if this receiver's public key in the
    ///   registry has an unsupported algorithm.
    /// * [`IDkgLoadTranscriptError::RegistryError`] if there was an error retrieving this
    ///   receiver's public key from the registry.
    /// * [`IDkgLoadTranscriptError::TransientInternalError`] if there was a transient internal
    ///   error, e.g., when communicating with the remote CSP vault.
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
    /// * [`IDkgVerifyComplaintError::InvalidComplaint`] if the complaint is invalid.
    /// * [`IDkgVerifyComplaintError::InvalidArguments`] if one or more arguments
    ///   are invalid.
    /// * [`IDkgVerifyComplaintError::InvalidArgumentsMismatchingTranscriptIDs`] if
    ///   the transcript IDs in the transcript and the complaint do not match (i.e.,
    ///   are not equal).
    /// * [`IDkgVerifyComplaintError::InvalidArgumentsMissingDealingInTranscript`]
    ///   if the (verified) dealings in the transcript do not contain a dealing
    ///   whose dealer ID matches the complaint's dealer ID.
    /// * [`IDkgVerifyComplaintError::InvalidArgumentsMissingComplainerInTranscript`]
    ///   if the transcript's receivers do not contain a receiver whose ID matches
    ///   the complaint's complainer ID.
    /// * [`IDkgVerifyComplaintError::ComplainerPublicKeyNotInRegistry`] if the
    ///   complainer's (MEGa) public key cannot be found in the registry.
    /// * [`IDkgVerifyComplaintError::MalformedComplainerPublicKey`] if the
    ///   complainer's (MEGa) public key fetched from the registry is malformed.
    /// * [`IDkgVerifyComplaintError::UnsupportedComplainerPublicKeyAlgorithm`] if
    ///   the algorithm of the complainer's (MEGa) public key in the registry is
    ///   not supported.
    /// * [`IDkgVerifyComplaintError::SerializationError`] if the (internal raw)
    ///   complaint cannot be deserialized, or if the dealing corresponding to the
    ///   complaint's dealer ID cannot be deserialized from the transcript.
    /// * [`IDkgVerifyComplaintError::Registry`] if the registry client returns an
    ///   error, e.g., because the transcript's `registry_version` is not available.
    /// * [`IDkgVerifyComplaintError::InternalError`] if an internal error occurred
    ///   during the verification.
    fn verify_complaint(
        &self,
        transcript: &IDkgTranscript,
        complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyComplaintError>;

    /// Generate an opening for the dealing given in `complaint`,
    /// reported by `complainer_id`.
    ///
    /// # Errors
    /// * [`IDkgOpenTranscriptError::PrivateKeyNotFound`] if the private key corresponding to this
    ///   receiver's public key was not found in the canister secret keystore.
    /// * [`IDkgOpenTranscriptError::PublicKeyNotFound`] if the public key of this receiver was not
    ///   found in the registry.
    /// * [`IDkgOpenTranscriptError::MissingDealingInTranscript`] if the `transcript` does not
    ///   contain a dealing with the `NodeId` of the dealer accused in the `complaint`.
    /// * [`IDkgOpenTranscriptError::RegistryError`] if there was an error retrieving this
    ///   receiver's public key from the registry.
    /// * [`IDkgOpenTranscriptError::InternalError`] if there was an internal error while verifying
    ///   the complaint; if there was an error serializing the internal opening; if this node is
    ///   not a receiver in the `transcript`; if there was an error deserializing a signed dealing;
    ///   or if this receiver's public key in the registry is malformed, or has an unsupported
    ///   algorithm.
    /// * [`IDkgOpenTranscriptError::TransientInternalError`] if there was a transient internal
    ///   error, e.g., when communicating with the remote CSP vault.
    fn open_transcript(
        &self,
        transcript: &IDkgTranscript,
        complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<IDkgOpening, IDkgOpenTranscriptError>;

    /// Verify that an opening corresponds to the complaint,
    /// and matches the commitment in the transcript.
    ///
    /// # Errors
    /// * [`IDkgVerifyOpeningError::TranscriptIdMismatch`] if the transcript ID in the `transcript`
    ///   does not match the one in the `opening` and/or the `complaint`.
    /// * [`IDkgVerifyOpeningError::DealerIdMismatch`] if the dealer ID in the `opening` does not
    ///   match the one in the `complaint`.
    /// * [`IDkgVerifyOpeningError::MissingDealingInTranscript`] if the `transcript` does not
    ///   contain a dealing with the `NodeId` of the dealer accused in the `complaint`.
    /// * [`IDkgVerifyOpeningError::MissingOpenerInReceivers`] if the ID of the `opener` does not
    ///   exist as a receiver in the `transcript`.
    /// * [`IDkgVerifyOpeningError::InternalError`] if there was an internal error verifying the
    ///   `opening`; if there was an error deserializing the internal `opening`; or if there was an
    ///   error deserializing a signed dealing.
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
    ///
    /// # Errors
    /// * [`IDkgLoadTranscriptError::InsufficientOpenings`] if, in any of the complaints, there are
    ///   less openings than the reconstruction threshold specified in the `transcript`.
    /// * [`IDkgLoadTranscriptError::InvalidArguments`] if there was an error decrypting
    ///   ciphertexts, or an error combining openings.
    /// * [`IDkgLoadTranscriptError::PublicKeyNotFound`] if the public key of this receiver was not
    ///   found in the registry.
    /// * [`IDkgLoadTranscriptError::SerializationError`] if there was an error deserializing a
    ///   dealing from the signed and verified dealings in `transcript`; if there was an error
    ///   deserializing the internal transcript in `transcript`; or if there was an error
    ///   serializing any of the generated internal complaints.
    /// * [`IDkgLoadTranscriptError::PrivateKeyNotFound`] if the private key corresponding to this
    ///   receiver's public key was not found in the canister secret keystore.
    /// * [`IDkgLoadTranscriptError::InternalError`] if there was an internal error while loading
    ///   the transcript, e.g., an error writing to the canister secret keystore.
    /// * [`IDkgLoadTranscriptError::MalformedPublicKey`] if this receiver's public key in the
    ///   registry is malformed.
    /// * [`IDkgLoadTranscriptError::UnsupportedAlgorithm`] if this receiver's public key in the
    ///   registry has an unsupported algorithm.
    /// * [`IDkgLoadTranscriptError::RegistryError`] if there was an error retrieving this
    ///   receiver's public key from the registry.
    /// * [`IDkgLoadTranscriptError::TransientInternalError`] if there was a transient internal
    ///   error, e.g., when communicating with the remote CSP vault.
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
    /// * [`IDkgRetainThresholdKeysError::InternalError`] if an internal error such as
    ///   an RPC error communicating with a remote CSP vault occurs
    /// * [`IDkgRetainThresholdKeysError::SerializationError`] if a transcript cannot
    ///   be serialized into a key id to identify the IDKG threshold secret key
    /// * [`IDkgRetainKeysError::TransientInternalError`] if there is a transient error
    ///   retaining the active transcripts
    fn retain_active_transcripts(
        &self,
        active_transcripts: &HashSet<IDkgTranscript>,
    ) -> Result<(), IDkgRetainKeysError>;
}

/// A Crypto Component interface to generate threshold ECDSA signature shares during the
/// online phase of the threshold ECDSA protocol. During the offline phase, nodes precompute
/// quadruples of IDKG transcripts. Each of these quadruples is then used by the nodes to
/// reply to a single signing request, and then it is discarded.
///
/// # Protocol Overview:
/// The threshold signing protocol is non-interactive, which means that the nodes participating
/// to the protocol only need to compute a signature share and publish it. Shares can then be
/// publicly verified by anybody and combined into a single ECDSA signature.
pub trait ThresholdEcdsaSigner {
    /// Create a threshold ECDSA signature share.
    ///
    /// # Prerequisites
    /// This method depends on the key material for the IDKG transcripts specified in
    /// `ThresholdEcdsaSigInputs` to be present in the canister secret key store of the
    /// crypto component. To initialize this key material the transcripts must be loaded
    /// using the method [`IDkgProtocol::load_transcript`].
    ///
    /// # Errors
    /// * [`ThresholdEcdsaSignShareError::InternalError`] if there was an internal error creating the
    ///   signature share, likely due to invalid input.
    /// * [`ThresholdEcdsaSignShareError::NotAReceiver`] if the caller isn't in the
    ///   transcripts' receivers. Only receivers can create signature shares.
    /// * [`ThresholdEcdsaSignShareError::SerializationError`] if there was an error deserializing the
    ///   transcripts or serializing the signature share.
    /// * [`ThresholdEcdsaSignShareError::SecretSharesNotFound`] if the secret shares necessary
    ///   for creating the dealing could not be found in the canister secret key store. Calling
    ///   [`IDkgProtocol::load_transcript`] may be necessary.
    /// * [`ThresholdEcdsaSignShareError::TransientInternalError`] if there was a transient internal
    ///   error, e.g., when communicating with the remote CSP vault.
    fn create_sig_share(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
    ) -> Result<ThresholdEcdsaSigShare, ThresholdEcdsaCreateSigShareError>;
}

/// A Crypto Component interface to perform public operations during the online phase of the
/// threshold ECDSA protocol. During the online phase, nodes compute and advertise shares of
/// the signatures. These interfaces can be used to verify the shares, combine them into a
/// single ECDSA signature, and verify the combined signature. All these operations can be
/// performed publicly and do not require private information.
pub trait ThresholdEcdsaSigVerifier {
    /// Verify a threshold ECDSA signature share.
    ///
    /// # Errors
    /// * [`ThresholdEcdsaVerifySigShareError::InternalError`] if there was an internal error while
    ///   verifying the signature share, likely due to invalid input.
    /// * [`ThresholdEcdsaVerifySigShareError::SerializationError`] if there was an error deserializing the
    ///   transcripts or the signature share.
    /// * [`ThresholdEcdsaVerifySigShareError::InvalidSignatureShare`] if the signature share is not
    ///   valid.
    /// * [`ThresholdEcdsaVerifySigShareError::InvalidArgumentMissingSignerInTranscript`] if the signer
    ///   was not eligible according to the key transcript.
    /// * [`ThresholdEcdsaVerifySigShareError::InvalidArguments`] if some arguments are invalid, e.g.,
    ///   wrong algorithm id.
    fn verify_sig_share(
        &self,
        signer: NodeId,
        inputs: &ThresholdEcdsaSigInputs,
        share: &ThresholdEcdsaSigShare,
    ) -> Result<(), ThresholdEcdsaVerifySigShareError>;

    /// Combine the given threshold ECDSA signature shares into a conventional ECDSA signature.
    ///
    /// All of the signature shares must have been generated with respect to the same ThresholdEcdsaSigInputs
    ///
    /// The signature is returned as raw bytes.
    ///
    /// # Errors
    /// * [`ThresholdEcdsaCombineSigSharesError::InternalError`] if there was an internal error while
    ///   combining the signature shares, likely due to invalid input.
    /// * [`ThresholdEcdsaCombineSigSharesError::UnsatisfiedReconstructionThreshold`] if the number
    ///   of signature shares was not sufficient to reconstruct an ECDSA signature.
    /// * [`ThresholdEcdsaCombineSigSharesError::SerializationError`] if there was an error deserializing the
    ///   transcripts or the signature shares.
    /// * [`ThresholdEcdsaCombineSigSharesError::SignerNotAllowed`] if one or more of the singers were
    ///   not eligible according to the key transcript.
    fn combine_sig_shares(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
        shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
    ) -> Result<ThresholdEcdsaCombinedSignature, ThresholdEcdsaCombineSigSharesError>;

    /// Verify a combined ECDSA signature and its consistency with the input. In particular it verifies that
    /// the signature is computed from the `kappa` transcript, which is the presignature computed in the offline phase
    /// of the protocol. This helps ensuring each instance of the signing protocol computes fresh signatures.
    ///
    /// # Errors
    /// * [`ThresholdEcdsaVerifyCombinedSignatureError::InternalError`] if there was an internal error while
    ///   verifying the combined signature, likely due to invalid input.
    /// * [`ThresholdEcdsaVerifyCombinedSignatureError::InvalidSignature`] if the signature is not valid.
    /// * [`ThresholdEcdsaVerifyCombinedSignatureError::SerializationError`] if there was an error deserializing the
    ///   transcripts or the signature.
    /// * [`ThresholdEcdsaVerifyCombinedSignatureError::InvalidArguments`] if some arguments are invalid, e.g.,
    ///   wrong algorithm id.
    fn verify_combined_sig(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
        signature: &ThresholdEcdsaCombinedSignature,
    ) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError>;
}

/// A Crypto Component interface to generate threshold Schnorr signature shares during the
/// online phase of the threshold Schnorr protocol. During the offline phase, nodes precompute
/// presignature IDKG transcripts. Each of these presignatures is then used by the nodes to
/// reply to a single signing request, and then the presignature is discarded.
///
/// # Protocol Overview:
/// The threshold signing protocol is non-interactive, which means that the nodes participating
/// to the protocol only need to compute a signature share and publish it. Shares can then be
/// publicly verified by anybody and combined into a single Schnorr signature.
pub trait ThresholdSchnorrSigner {
    /// Create a threshold Schnorr signature share.
    ///
    /// # Prerequisites
    /// This method depends on the key material for the IDKG transcripts specified in
    /// `ThresholdSchnorrSigInputs` to be present in the canister secret key store of the
    /// crypto component. To initialize this key material the transcripts must be loaded
    /// using the method [`IDkgProtocol::load_transcript`].
    ///
    /// # Errors
    /// * [`ThresholdSchnorrCreateSigShareError::InternalError`] if there was an internal error creating the
    ///   signature share, likely due to invalid input.
    /// * [`ThresholdSchnorrCreateSigShareError::NotAReceiver`] if the caller isn't in the
    ///   transcripts' receivers. Only receivers can create signature shares.
    /// * [`ThresholdSchnorrCreateSigShareError::SerializationError`] if there was an error deserializing the
    ///   transcripts or serializing the signature share.
    /// * [`ThresholdSchnorrCreateSigShareError::SecretSharesNotFound`] if the secret shares necessary
    ///   for creating the dealing could not be found in the canister secret key store. Calling
    ///   [`IDkgProtocol::load_transcript`] may be necessary.
    /// * [`ThresholdSchnorrCreateSigShareError::TransientInternalError`] if there was a transient internal
    ///   error, e.g., when communicating with the remote vault.
    fn create_sig_share(
        &self,
        inputs: &ThresholdSchnorrSigInputs,
    ) -> Result<ThresholdSchnorrSigShare, ThresholdSchnorrCreateSigShareError>;
}

/// A Crypto Component interface to perform public operations during the online phase of the
/// threshold Schnorr protocol. During the online phase, nodes compute and advertise shares of
/// the signatures. These interfaces can be used to verify the shares, combine them into a
/// single Schnorr signature, and verify the combined signature. All these operations can be
/// performed publicly and do not require private information.
pub trait ThresholdSchnorrSigVerifier {
    /// Verify a threshold Schnorr signature share.
    ///
    /// # Errors
    /// * [`ThresholdSchnorrVerifySigShareError::InternalError`] if there was an internal error while
    ///   verifying the signature share, likely due to invalid input.
    /// * [`ThresholdSchnorrVerifySigShareError::SerializationError`] if there was an error deserializing the
    ///   transcripts or the signature share.
    /// * [`ThresholdSchnorrVerifySigShareError::InvalidSignatureShare`] if the signature share is not
    ///   valid.
    /// * [`ThresholdSchnorrVerifySigShareError::InvalidArgumentMissingSignerInTranscript`] if the signer
    ///   was not eligible according to the key transcript.
    /// * [`ThresholdSchnorrVerifySigShareError::InvalidArguments`] if some arguments are invalid, e.g.,
    ///   wrong algorithm id.
    fn verify_sig_share(
        &self,
        signer: NodeId,
        inputs: &ThresholdSchnorrSigInputs,
        share: &ThresholdSchnorrSigShare,
    ) -> Result<(), ThresholdSchnorrVerifySigShareError>;

    /// Combine the given threshold Schnorr signature shares into a conventional Schnorr signature.
    ///
    /// All of the signature shares must have been generated with respect to the same ThresholdSchnorrSigInputs
    ///
    /// The signature is returned as raw bytes.
    ///
    /// # Errors
    /// * [`ThresholdSchnorrCombineSigSharesError::InternalError`] if there was an internal error while
    ///   combining the signature shares, likely due to invalid input.
    /// * [`ThresholdSchnorrCombineSigSharesError::UnsatisfiedReconstructionThreshold`] if the number
    ///   of signature shares was not sufficient to reconstruct a Schnorr signature.
    /// * [`ThresholdSchnorrCombineSigSharesError::SerializationError`] if there was an error deserializing the
    ///   transcripts or the signature shares.
    /// * [`ThresholdSchnorrCombineSigSharesError::SignerNotAllowed`] if one or more of the singers were
    ///   not eligible according to the key transcript.
    fn combine_sig_shares(
        &self,
        inputs: &ThresholdSchnorrSigInputs,
        shares: &BTreeMap<NodeId, ThresholdSchnorrSigShare>,
    ) -> Result<ThresholdSchnorrCombinedSignature, ThresholdSchnorrCombineSigSharesError>;

    /// Verify a combined Schnorr signature and its consistency with the input.
    /// In particular, it verifies that the signature is computed from the
    /// presignature transcript, which is computed in the offline phase of the
    /// protocol. This helps ensuring each instance of the signing protocol
    /// computes fresh signatures.
    ///
    /// # Errors
    /// * [`ThresholdSchnorrVerifyCombinedSigError::InternalError`] if
    ///   there was an internal error while verifying the combined signature,
    ///   likely due to invalid input.
    /// * [`ThresholdSchnorrVerifyCombinedSigError::InvalidSignature`] if
    ///   the signature is not valid.
    /// * [`ThresholdSchnorrVerifyCombinedSigError::SerializationError`]
    ///   if there was an error deserializing the transcripts or the signature.
    /// * [`ThresholdSchnorrVerifyCombinedSigError::InvalidArguments`] if
    ///   some arguments were invalid, e.g., wrong algorithm ID.
    fn verify_combined_sig(
        &self,
        inputs: &ThresholdSchnorrSigInputs,
        signature: &ThresholdSchnorrCombinedSignature,
    ) -> Result<(), ThresholdSchnorrVerifyCombinedSigError>;
}
