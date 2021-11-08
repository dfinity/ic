//! CSP threshold signature traits

use crate::api::CspThresholdSignError;
use crate::types::{
    CspDealing, CspDkgTranscript, CspPop, CspPublicCoefficients, CspResponse,
    CspSecretKeyConversionError, CspSignature,
};
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::CspEncryptionPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey, CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use ic_types::crypto::{AlgorithmId, CryptoResult, KeyId};
use ic_types::{IDkgId, NodeId, NodeIndex, NumberOfNodes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

pub mod threshold_sign_error;

/// Crypto service provider (CSP) client for threshold signatures.
///
/// A CSP client categorizes the offered methods in two categories:
/// * methods that are served non-statically by calling out to a CSP (server)
///   which includes RPC calls (incl. serialization of parameters and
///   deserialization of return values)
/// * methods that are served statically by computing the output locally, that
///   is, without having to make RPC calls, which are comparatively expensive.
///
/// When implementing this client,
/// * the methods for key generation and signing are computed non-statically
/// * all other methods (that is, combining and verifying signatures, and
///   computing public keys) are computed statically
///
/// The methods in this trait that are meant to be served statically are
/// intentionally made non-static (i.e., they take a `&self` parameter) so that
/// mocking of this trait (for testing purposes) is possible.
pub trait ThresholdSignatureCspClient {
    /// Generates threshold keys.
    ///
    /// This interface is primarily of interest for testing and demos.
    ///
    /// # Arguments
    /// * `algorithm_id` indicates the algorithms to be used in the key
    ///   generation.
    /// * `threshold` is the minimum number of signatures that can be combined
    ///   to make a valid threshold signature.
    /// * `signatory_eligibility` is a boolean indicating, for each signatory,
    ///   whether they should receive a key.  The `i`th signatory should receive
    ///   a key if and only if `signatory_eligibility[i]==true`.
    /// # Returns
    /// * `CspPublicCoefficients` can be used by the caller to verify
    ///   signatures.
    /// * `Vec<Option<KeyId>>` contains key identifiers.  The vector has the
    ///   same length as the input `signatory_eligibility` and the i'th entry
    ///   contains a secret key if and only if `signatory_eligibility[i]` is
    ///   `true`.
    /// # Panics
    /// * An implementation MAY panic if it is unable to access the secret key
    ///   store to save keys or if it cannot access a suitable random number
    ///   generator.
    /// # Errors
    /// * If `threshold > signatory_eligibility.len()` then it is impossible for
    ///   the signatories to create a valid combined signature, so
    ///   implementations MUST return an error.
    /// * An implementation MAY return an error if it is temporarily unable to
    ///   generate and store keys.
    #[cfg(test)]
    fn threshold_keygen(
        &mut self,
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        signatory_eligibility: &[bool],
    ) -> CryptoResult<(CspPublicCoefficients, Vec<Option<KeyId>>)>;

    /// Signs with a threshold key
    fn threshold_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        public_coefficients: CspPublicCoefficients,
    ) -> Result<CspSignature, CspThresholdSignError>;

    /// Combine multiple individual signatures.
    ///
    /// Note: This will not check whether the individual signatures are valid,
    /// however if all the input signatures are valid and sufficient in number
    /// the result will be a valid combined signature.
    ///
    /// Note: Signatures must be given in the correct order.  A signature by the
    /// i'th node must be in the i'th place of the vector of signatures.  The
    /// vector of signatures may have holes where signatories have not
    /// contributed; that is to be expected.
    fn threshold_combine_signatures(
        &self,
        algorithm_id: AlgorithmId,
        signatures: &[Option<CspSignature>],
        public_coefficients: CspPublicCoefficients,
    ) -> CryptoResult<CspSignature>;

    /// Gets an individual signatory's public key.
    ///
    /// Note: This is an expensive operation.  It is worth keeping the result if
    /// it is likely to be reused.
    fn threshold_individual_public_key(
        &self,
        algorithm_id: AlgorithmId,
        node_index: NodeIndex,
        public_coefficients: CspPublicCoefficients,
    ) -> CryptoResult<CspThresholdSigPublicKey>;

    /// Checks whether an individual node's signature is valid.
    fn threshold_verify_individual_signature(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        signature: CspSignature,
        public_key: CspThresholdSigPublicKey,
    ) -> CryptoResult<()>;

    /// Checks whether a combined signature is valid.
    /// If sufficient valid signatures are combined, the result will pass this
    /// test and this is the ultimate goal of the threshold signature scheme.
    fn threshold_verify_combined_signature(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        signature: CspSignature,
        public_coefficients: CspPublicCoefficients,
    ) -> CryptoResult<()>;
}

/// Crypto service provider (CSP) client for distributed key generation
///
/// # Distributed Key Generation
/// ## Motivation
/// With a standard threshold signature scheme, one entity generates all the
/// signatories' keys and so is in a position to abuse that power.  In
/// distributed key generation, multiple actors, called dealers, collaborate to
/// generate the signatories secret key material in a way that no strict subset
/// of dealers has sufficient information to abuse their position.
///
/// ## Usage
/// * The participants are divided into dealers, who contribute to key
///   generation, and receivers, who will be threshold signatories.
/// * Ephemeral key phase:
///   * All participants generate an ephemeral DiffieHellman key and share their
///     ephemeral public keys with the other participants.  This key should be
///     used for one DKG and then discarded.
///   * All participants should verify that the ephemeral public keys are
///     plausibly correct and evict any participants whose public keys are
///     invalid.
/// * Dealing phase:
///   * The dealers each individually generate a threshold polynomial and
///     publish it as a 'dealing'.  The secret keys for the receivers are
///     encrypted with DiffieHellman and published with the polynomial; only the
///     corresponding receivers can decrypt the secret keys.
///   * All participants verify that the dealings look plausibly correct and
///     reject any dealings that are invalid.
/// * Complaint phase:
///   * Each receiver individually decrypts their secret key in each dealing and
///     verifies that it is correct; if not they generate a complaint against
///     that dealer.
///   * Each participant verifies that the complaints are superficially valid,
///     rejecting any that are not.
/// * Transcript phase
///   * Each participant examines the complaints and verifies the zero knowledge
///     proof that should be included in a complaint.  If a complaint is
///     invalid, all complaints by that receiver are disregarded.  Of the
///     remaining complaints, any dealings that have been proven to be invalid
///     are rejected.  The remaining valid dealings are combined to generate the
///     threshold key.  The valid dealings, together with the threshold public
///     key, are published as the transcript.
///   * Individual signatories compute their threshold secret key from the
///     transcript, decrypting their shares using their ephemeral DiffieHellman
///     key.  The ephemeral key is then deleted to protect the threshold key
///     from compromise.
///
/// # Resharing
/// ## Motivation
/// Signatories may cease to exist or be forced to retire.  Under these
/// circumstances it may be desirable to find a new set of signatories to
/// replace the old.  However it is desirable for such a change to be invisible
/// from the perspective of a user wishing to verify threshold signatures.  That
/// is, it is desirable for the public threshold coefficient at zero to remain
/// the same when there is a change of signatories.  The resharing scheme
/// achieves this.
///
/// ## Usage
/// The resharing protocol is the same as the distributed key generation
/// protocol with these modifications:
/// * A threshold key must preexist.
/// * Signatories of the previous threshold key are the dealers during the
///   resharing DKG.
/// * The arguments and calculation differ slightly at some of the steps in the
///   protocol.
///
/// # On the inclusion of self in otherwise static methods
///
/// A CSP client categorizes the offered methods in two categories:
/// * methods that are served non-statically by calling out to a CSP (server)
///   which includes RPC calls (incl. serialization of parameters and
///   deserialization of return values)
/// * methods that are served statically by computing the output locally, that
///   is, without having to make RPC calls, which are comparatively expensive.
///
/// When implementing this scheme,
/// * the methods dkg_create_ephemeral, dkg_create_dealing and
///   dkg_load_private_key are computed non-statically
/// * all other methods are computed statically
///
/// The methods in this trait that are meant to be served statically are
/// intentionally made non-static (i.e., they take a `&self` parameter) so that
/// mocking of this trait (for testing purposes) is possible.
pub trait DistributedKeyGenerationCspClient {
    /// Generates an ephemeral key used for distributed key generation of
    /// threshold keys. Note: Ephemeral keys are NOT threshold keys
    ///
    /// # Arguments
    /// * `dkg_id` is the identifier for the distributed key being generated.
    /// * `node_id` is a unique identifier for this DKG participant.
    /// # Panics
    /// This method MUST panic if it is unable to store the secret key.
    /// # Errors
    /// This method SHALL return an error if:
    /// * there is an incompatible preexisting key for this entity and DKG.
    ///   (`MalformedSecretKey`)
    fn dkg_create_ephemeral(
        &self,
        dkg_id: IDkgId,
        node_id: &[u8],
    ) -> Result<(CspEncryptionPublicKey, CspPop), dkg_errors::DkgCreateEphemeralError>;

    /// Verifies that an ephemeral public key and PoP is valid.
    ///
    /// # Arguments
    /// * `dkg_id` is the identifier for the distributed key being generated.
    /// * `node_id` is a unique identifier for this DKG participant.
    /// * `(public_key, pop)` is a public key and the corresponding proof of
    ///   possession.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * the public key is not well formed. (`MalformedPublicKeyWithPopError`)
    /// * the CspPop is not consistent with all other arguments.
    ///   (`InvalidPopError`)
    fn dkg_verify_ephemeral(
        &self,
        dkg_id: IDkgId,
        node_id: &[u8],
        key: (CspEncryptionPublicKey, CspPop),
    ) -> Result<(), dkg_errors::DkgVerifyEphemeralError>;

    /// Generates keys for each eligible receiver.
    ///
    /// # Preconditions
    /// * The caller MUST verify that the PoPs are valid before calling this
    ///   method.  This method will not return an error if a PoP is invalid but
    ///   such use is dangerous.
    /// # Arguments
    /// * `dkg_id` is the identifier for the distributed key being generated.
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature.
    /// * `receiver_keys` is a vector with one entry for each receiver, in
    ///   order. Eligible receivers have their public key in their slot.
    ///   Ineligible receivers have none.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * any of the public keys is malformed. (`MalformedPublicKeyError`)
    /// * the ephemeral key for the DKG cannot be found. (`KeyNotFoundError`)
    /// * the threshold or number of receiver keys is out of bounds.
    ///   (`SizeError`)
    fn dkg_create_dealing(
        &self,
        dkg_id: IDkgId,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
    ) -> Result<CspDealing, dkg_errors::DkgCreateDealingError>;

    /// Verifies the syntactic correctness of the dealing
    ///
    /// This checks that the dealing parses and that the public elements are
    /// plausible (degree and group size)
    ///
    /// # Arguments
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature.
    /// * `receiver_keys` is a vector with one entry for each receiver, in
    ///   order. Eligible receivers have their public key in their slot.
    ///   Ineligible receivers have none.
    /// * `csp_dealing` is the dealing to be verified.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * the `csp_dealing` is malformed. (`MalformedDealingError`)
    /// * the `csp_dealing` is incompatible with `threshold`.
    ///   (`InvalidDealingError`)
    /// * `dealing.receiver_data` has a different length from `receiver_keys`.
    ///   (`InvalidDealingError`)
    /// * `csp_dealing` SHOULD contain an encrypted secret key share for the
    ///   i'th receiver if and only if a key for the i'th receiver is present in
    ///   `receiver_keys` (i.e. not None); if this is not the case this method
    ///   SHALL return an error. (`InvalidDealingError`)
    /// * the number of receiver keys is out of bounds. (`SizeError`)
    fn dkg_verify_dealing(
        &self,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        csp_dealing: CspDealing,
    ) -> Result<(), dkg_errors::DkgVerifyDealingError>;

    /// Verifies that an encrypted key for this node is valid.
    ///
    /// This is called by a receiver to check that the key they have received
    /// from a dealer is valid.
    ///
    /// # Arguments
    /// * `dkg_id` is the identifier for the distributed key being generated.
    /// * `verified_csp_dealings` - for each dealer who has dealt and not been
    ///   disqualified, their dealing.
    /// * `my_index` is the receiver index for the current node.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * any of the arguments is malformed.  Note, however, that the caller
    ///   MUST verify dealings before creating a response so this SHOULD never
    ///   happen. (`MalformedPublicKeyWithPopError` or `MalformedDealingError`)
    /// * any of the dealings does not contain a share for the current node.
    ///   (`MissingShareError`)
    /// * there is no ephemeral key for this DKG ID. (`KeyNotFoundError`)
    /// * the number of dealings is out of bounds. (`SizeError`)
    fn dkg_create_response(
        &self,
        dkg_id: IDkgId,
        verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        my_index: NodeIndex,
    ) -> Result<CspResponse, dkg_errors::DkgCreateResponseError>;

    /// Verifies the complaints and other relevant fields in a response.
    ///
    /// If all the complaints in the response are upheld, the response is
    /// considered valid and any dealers the response makes complaints against
    /// SHOULD be disqualified.  On the other hand if any of the complaints are
    /// invalid, the entire response SHALL be rejected and complaints SHOULD be
    /// discarded, even if some of the complaints are valid.
    ///
    /// # Arguments
    /// * `dkg_id` is the identifier for the distributed key being generated.
    /// * `verified_csp_dealings` is verified syntactically correct dealings.
    /// * `receiver_index` is the index of the receiver who generated the
    ///   response.
    /// * `receiver_key` is the public key of the receiver who generated the
    ///   response.
    /// * `response` is the response being verified.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * any of the fields is malformed. (`MalformedPublicKeyWithPopError`,
    ///   `MalformedDealingError` or `MalformedResponseError`)
    /// * one or more complaints in the response is invalid.
    ///   (`InvalidResponseError`)
    /// * the number of dealings is out of bounds. (`SizeError`)
    fn dkg_verify_response(
        &self,
        dkg_id: IDkgId,
        verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        receiver_index: NodeIndex,
        receiver_key: (CspEncryptionPublicKey, CspPop),
        response: CspResponse,
    ) -> Result<(), dkg_errors::DkgVerifyResponseError>;

    /// Filters out bad dealings.
    ///
    /// # Arguments
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature.
    /// * `verified_keys` is the ephemeral public keys of all eligible
    ///   receivers.
    /// * `verified_csp_dealings` is syntactically correct dealings.
    /// * `verified_responses` are, primarily, verified complaints about
    ///   dealings.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * any of the fields is malformed. (`MalformedPublicKeyWithPopError`,
    ///   `MalformedDealingError`, `MalformedResponseError`)
    /// * all dealings are disqualified by verified responses.
    ///   (`InsufficientValidDealingsError`)
    /// * there are insufficient valid responses.
    ///   (`InsufficientValidResponsesError`)
    /// * the threshold, number of keys or dealings is out of bounds.
    ///   (`SizeError`)
    fn dkg_create_transcript(
        &self,
        threshold: NumberOfNodes,
        verified_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        verified_responses: &[Option<CspResponse>],
    ) -> Result<CspDkgTranscript, dkg_errors::DkgCreateTranscriptError>;

    /// Creates a threshold key in the secret key store.
    ///
    /// This allows a recipient to proceed as with any threshold key:
    /// * The key ID is derived from the dkg_id with: `KeyId::from(dkg_id)`
    /// * The PublicCoefficients are available from the transcript.
    /// See the threshold API for how to proceed further.
    ///
    /// Note: This causes the ephemeral key to be deleted, if it is still in the
    /// secret key store.
    ///
    /// # Arguments
    /// * `dkg_id` is the identifier for the distributed key being generated.
    /// * `csp_transcript` is a summary of the key generation.
    /// # Panics
    /// * This MAY panic if the secret key store is unavailable.
    /// # Errors
    /// This method SHALL return an error if:
    /// * the transcript is malformed. (`MalformedTranscriptError`)
    /// * it is unable to compute the secret key. (`InvalidTranscriptError`)
    /// * it fails to write the secret key to the key store.
    ///   (`SecretKeyStoreWriteError`)
    fn dkg_load_private_key(
        &self,
        dkg_id: IDkgId,
        csp_transcript: CspDkgTranscript,
    ) -> Result<(), dkg_errors::DkgLoadPrivateKeyError>;

    /// Generates a fresh set of threshold keys from a threshold secret
    /// key held by this node.
    ///
    /// # Preconditions
    /// * The dealers in the current DKG must be signatories for the preceding
    ///   threshold key.
    /// * A new set of ephemeral keys should be used for each DKG; the previous
    ///   ephemeral keys are likely to have been deleted before this method is
    ///   called.
    /// * The caller MUST verify that the PoPs are valid before calling this
    ///   method.  This method will not return an error if a PoP is invalid but
    ///   such use is dangerous.
    /// # Arguments
    /// * `dkg_id` is the new DKG identifier.
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature using the new keys; this may differ from the
    ///   preceding threshold.
    /// * `receiver_keys` is the ephemeral public keys of all eligible
    ///   receivers.
    /// * `resharing_public_coefficients` are the public coefficients of the
    ///   previous DKG that is being reshared.
    /// * `receiver_keys` is a vector with one entry for each receiver, in
    ///   order. Eligible receivers have their public key in their slot.
    ///   Ineligible receivers have none.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * any of the public keys is malformed. (`MalformedPublicKeyError`)
    /// * the ephemeral key for the DKG cannot be found. (`KeyNotFoundError`)
    /// * the number of public coefficients or receiver keys is out of bounds.
    ///   (`SizeError`)
    fn dkg_create_resharing_dealing(
        &self,
        dkg_id: IDkgId,
        threshold: NumberOfNodes,
        resharing_public_coefficients: CspPublicCoefficients,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
    ) -> Result<CspDealing, dkg_errors::DkgCreateReshareDealingError>;

    /// Verifies the syntactic correctness of a reshared dealing.
    ///
    /// This checks that the dealing parses and that the public elements have
    /// the correct degree and group size.
    ///
    /// # Arguments
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature using the new keys; this may differ from the
    ///   preceding threshold.
    /// * `receiver_keys` is a vector with one entry for each receiver, in
    ///   order. Eligible receivers have their public key in their slot.
    ///   Ineligible receivers have none.
    /// * `csp_dealing` is the dealing to be verified.
    /// * `dealer_index` is is the current dealer's index in the preceding
    ///   threshold key.
    /// * `resharing_public_coefficients` are the public coefficients of the
    ///   previous threshold key.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * the `csp_dealing` is malformed. (`MalformedDealingError`)
    /// * the `csp_dealing` has a different threshold from the preceding
    ///   dealing. (`InvalidDealingError`)
    /// * `dealing.receiver_data` has a different length from `receiver_keys`.
    ///   (`InvalidDealingError`)
    /// * `csp_dealing` SHOULD contain an encrypted secret key share for the
    ///   i'th receiver if and only if a key for the i'th receiver is present in
    ///   `receiver_keys` (i.e. not None); if this is not the case this method
    ///   SHALL return an error. (`InvalidDealingError`)
    /// * the number of receiver keys is out of bounds. (`SizeError`)
    fn dkg_verify_resharing_dealing(
        &self,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        csp_dealing: CspDealing,
        dealer_index: NodeIndex,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<(), dkg_errors::DkgVerifyReshareDealingError>;

    /// Filters out bad resharing dealings.
    ///
    /// # Arguments
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature using the new keys; this may differ from the
    ///   preceding threshold.
    /// * `receiver_keys` is the ephemeral public keys of all eligible
    ///   receivers. Note that the order of the keys matters and must be
    ///   preserved for use with the new threshold key.
    /// * `verified_dealings` are syntactically correct dealings.
    /// * `verified_responses` are, primarily, verified complaints about
    ///   dealings.
    /// * `dealer_keys` is the ephemeral public keys of dealers.  Note that the
    ///   order of the keys matters; the ith entry in this vector should
    ///   correspond to the ith receiver of the preceding threshold key.
    /// * `resharing_public_coefficients` are the public coefficients of the
    ///   previous threshold key. They are used to determine the threshold of
    ///   the previous threshold key being reshared.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * any of the fields is malformed. (`MalformedPublicKeyWithPopError`,
    ///   `MalformedDealingError`, `MalformedResponseError`)
    /// * all dealings are disqualified by verified responses.
    ///   (`InsufficientValidDealingsError`)
    /// * there are insufficient valid responses; the minimum is
    ///   `2*threshold-1`. (`InsufficientValidResponsesError`)
    /// * the threshold, number of keys or dealings is out of bounds.
    ///   (`SizeError`)
    fn dkg_create_resharing_transcript(
        &self,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        verified_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        verified_responses: &[Option<CspResponse>],
        dealer_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<CspDkgTranscript, dkg_errors::DkgCreateReshareTranscriptError>;
}

/// Crypto service provider (CSP) client for non-interactive distributed key
/// generation (NiDKG).
///
/// # Distributed Key Generation
/// ## Motivation
/// With a standard threshold signature scheme, one entity generates all the
/// signatories' keys and so is in a position to abuse that power.  In
/// distributed key generation, multiple actors, called dealers, collaborate to
/// generate the signatories secret key material in a way that no strict subset
/// of dealers has sufficient information to abuse their position.
///
/// Non-interactive DKG is a design that is easy to use because there is
/// effectively only a single step:  Dealers deal shares and can then cease to
/// exist, as far as the protocol is concerned.  Receivers likewise do not need
/// to communicate with each other; they can read the dealings written by the
/// dealers and proceed without further ado.  Not only is this design
/// convenient, it also enables use cases in which it is hard for participants
/// to coordinate with each other.
///
/// ## Usage
/// Participants may be dealers, who contribute to key generation, or receivers,
/// who will be threshold signatories, or both.
///
/// ### Dealing
///   * The dealers each individually generate a threshold polynomial and
///     publish it as a 'dealing'.  The secret keys for the receivers are
///     encrypted with a forward secure encryption scheme and published with the
///     polynomial; only the corresponding receivers can decrypt the secret
///     keys.
///   * Each dealing should be verified and accepted only if sound.
/// ### Receiving
///   * The receivers each read the dealings and compile them into a transcript.
///   * Each receiver can compute their secret threshold key from the transcript
///     and so contribute to threshold signatures.
///
/// ## Resharing
/// ### Motivation
/// Signatories may cease to exist or be forced to retire.  Under these
/// circumstances it may be desirable to find a new set of signatories to
/// replace the old.  However it is desirable for such a change to be invisible
/// from the perspective of a user wishing to verify threshold signatures.  That
/// is, it is desirable for the public threshold coefficient at zero to remain
/// the same when there is a change of signatories.  The resharing scheme
/// achieves this.
///
/// ### Usage
/// The resharing protocol is the same as the distributed key generation
/// protocol with these modifications:
/// * A threshold key must preexist.
/// * Signatories of the previous threshold key are the dealers during the
///   resharing DKG.
/// * The arguments and calculation differ slightly at some of the steps in the
///   protocol.
///
/// TODO(CRP-563): Prefix the NiDkg methods with nidkg_.
///
/// TODO(CRP-564): Remove the csp_ prefix from argument names.
pub trait NiDkgCspClient {
    /// Generates a forward secure key pair used to encrypt threshold key shares
    /// in transmission.
    ///
    /// Note: FS keys are NOT threshold keys.
    ///
    /// The secret key is stored in the secret key store.  It is not returned by
    /// the method as that would violate the principle that secret keys never
    /// leave the CSP.  The public key and the proof of possession are returned.
    /// The public key can be used to verify signatures, it also needs to be
    /// provided when signing as it is used to retrieve the secret key from the
    /// key store.
    ///
    /// # Arguments
    /// * `node_id` is the identity of the node generating the public key.
    /// # Panics
    /// This method MUST panic if it is unable to store the secret key.
    /// # Errors
    /// This method is infallible.  An error structure is included in the
    /// signature only for future use.
    fn create_forward_secure_key_pair(
        &mut self,
        algorithm_id: AlgorithmId,
        node_id: NodeId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), ni_dkg_errors::CspDkgCreateFsKeyError>;

    /// Updates the epoch of the (forward-secure) DKG dealing decryption key
    /// (i.e., the secret part of the DKG dealing encryption key) so that it
    /// cannot be used at epochs that are smaller than the given epoch.
    ///
    /// # Arguments
    /// * `algorithm_id` selects the algorithm suite to use for the scheme.
    /// * `epoch` is the epoch to be deleted, together with all smaller epochs.
    /// # Panics
    /// This method MUST panic if it is unable to store the updated secret key.
    /// # Errors
    /// This method SHALL return an error if:
    /// * the public key is not well formed. (`MalformedPublicKeyError`)
    /// This method SHALL NOT return an error if:
    /// * the forward secure epoch is already higher than the epoch provided in
    ///   the method argument.  In this case the secret key is unchanged.
    fn update_forward_secure_epoch(
        &self,
        algorithm_id: AlgorithmId,
        epoch: Epoch,
    ) -> Result<(), ni_dkg_errors::CspDkgUpdateFsEpochError>;

    /// Generates keys for each eligible receiver.
    ///
    /// # Arguments
    /// * `algorithm_id` selects the algorithm suite to use for the scheme.
    /// * `dkg_id` is the identifier for the distributed key being generated.
    /// * `dealer_index` the index associated with the dealer.
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature.
    /// * `epoch` is a monotonic increasing counter used to select forward
    ///   secure keys.
    /// * `receiver_keys` is a map storing one public key for each receiver,
    ///   indexed by their corresponding NodeIndex.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * the `algorithm_id` is not an NiDkg variant. (`UnsupportedAlgorithmId`)
    /// * the threshold is less than 1 or greater than the number of receivers.
    ///   (`InvalidThresholdError`)
    /// * the receiver indices are not 0..num_receivers-1 inclusive.
    ///   (`MisnumberedReceiverError`)
    /// * one of the receivers' public keys is malformed.
    ///   (`MalformedFsPublicKeyError`)
    /// * the number of receiver keys is unsupported by this machine.
    ///   (`SizeError`)
    fn create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dkg_id: NiDkgId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
    ) -> Result<CspNiDkgDealing, ni_dkg_errors::CspDkgCreateDealingError>;

    /// Generates a fresh set of threshold keys from a threshold secret
    /// key held by this node.
    ///
    /// # Preconditions
    /// * The dealers in the current DKG must be signatories for the preceding
    ///   threshold key.
    /// # Arguments
    /// * `algorithm_id` selects the algorithm suite to use for the scheme.
    /// * `dkg_id` is the new DKG identifier.
    /// * `dealer_resharing_index` the index associated with the dealer in the
    ///   resharing committee.
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature using the new keys; this may differ from the
    ///   preceding threshold.
    /// * `epoch` is a monotonic increasing counter used to select forward
    ///   secure keys.
    /// * `receiver_keys` is a map storing one public key for each receiver,
    ///   indexed by their corresponding NodeIndex.
    /// * `resharing_public_coefficients` are the public coefficients of the
    ///   previous DKG that is being reshared.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * the `algorithm_id` is not an NiDkg variant. (`UnsupportedAlgorithmId`)
    /// * the threshold is less than 1 or greater than the number of receivers.
    ///   (`InvalidThresholdError`)
    /// * the receiver indices are not 0..num_receivers-1 inclusive.
    ///   (`MisnumberedReceiverError`)
    /// * one of the receiver keys is invalid. (`MalformedFsPublicKeyError`)
    /// * the key to be reshared is not present or malformed.
    ///   (`ReshareKeyNotFoundError`, `MalformedReshareSecretKeyError`)
    /// * the number of public coefficients or receiver keys is unsupported by
    ///   this machine. (`SizeError`)
    #[allow(clippy::too_many_arguments)]
    fn create_resharing_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dkg_id: NiDkgId,
        dealer_resharing_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<CspNiDkgDealing, ni_dkg_errors::CspDkgCreateReshareDealingError>;

    /// Verifies the correctness of the dealing
    ///
    /// This checks that the dealing parses and uses zero knowledge proofs to
    /// verify that the shares are correct.
    ///
    /// # Arguments
    /// * `algorithm_id` selects the algorithm suite to use for the scheme.
    /// * `dkg_id` is a unique identifier for the DKG.
    /// * `dealer_index` the index associated with the dealer.
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature.
    /// * `epoch` is a monotonic increasing counter used to select forward
    ///   secure keys.
    /// * `receiver_keys` is a map storing one public key for each receiver,
    ///   indexed by their corresponding NodeIndex.
    /// * `dealing` is the dealing to be verified.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * the `algorithm_id` is not an NiDkg variant. (`UnsupportedAlgorithmId`)
    /// * the threshold is less than 1 or greater than the number of receivers.
    ///   (`InvalidThresholdError`)
    /// * the receiver indices are not 0..num_receivers-1 inclusive.
    ///   (`MisnumberedReceiverError`)
    /// * one of the receiver keys is invalid. (`MalformedFsPublicKeyError`)
    /// * the `dealing` is malformed. (`MalformedDealingError`)
    /// * the `dealing` is incompatible with `threshold`.
    ///   (`InvalidDealingError`)
    /// * `dealing` SHOULD contain an encrypted secret key share for the i'th
    ///   receiver if and only if a key for the i'th receiver is present in
    ///   `receiver_keys`; if this is not the case this method SHALL return an
    ///   error. (`InvalidDealingError`)
    /// * the number of receiver keys is unsupported by this machine.
    ///   (`SizeError`)
    #[allow(clippy::too_many_arguments)]
    fn verify_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dkg_id: NiDkgId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        dealing: CspNiDkgDealing,
    ) -> Result<(), ni_dkg_errors::CspDkgVerifyDealingError>;

    /// Verifies the correctness of a reshared dealing.
    ///
    /// This checks that the public key is unchanged by resharing as well as all
    /// the checks performed by `verify_dealing` to ensure that the shares are
    /// correct.
    ///
    /// # Arguments
    /// * `algorithm_id` selects the algorithm suite to use for the scheme.
    /// * `dkg_id` is the new DKG identifier.
    /// * `dealer_resharing_index` the index associated with the dealer in the
    ///   resharing committee.
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature using the new keys; this may differ from the
    ///   preceding threshold.
    /// * `epoch` is a monotonic increasing counter used to select forward
    ///   secure keys.
    /// * `receiver_keys` is a map storing one public key for each receiver,
    ///   indexed by their corresponding NodeIndex.
    /// * `dealing` is the dealing to be verified.
    /// * `resharing_public_coefficients` are the public coefficients of the
    ///   previous threshold key.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * the `algorithm_id` is not an NiDkg variant. (`UnsupportedAlgorithmId`)
    /// * the threshold is less than 1 or greater than the number of receivers.
    ///   (`InvalidThresholdError`)
    /// * the receiver indices are not 0..num_receivers-1 inclusive.
    ///   (`MisnumberedReceiverError`)
    /// * one of the receiver keys is invalid. (`MalformedFsPublicKeyError`)
    /// * the reshare public coefficients are malformed.
    ///   (`MalformedResharePublicCoefficientsError`)
    /// * the `dealing` is malformed. (`MalformedDealingError`)
    /// * the `dealing` does not match the threshold. (`InvalidDealingError`)
    /// * `dealing` SHOULD contain an encrypted secret key share for the i'th
    ///   receiver if and only if a key for the i'th receiver is present in
    ///   `receiver_keys`; if this is not the case this method SHALL return an
    ///   error. (`InvalidDealingError`)
    /// * the `dealing` does not reshare the preexisting dealer's public key.
    ///   (`InvalidDealingError`)
    /// * the number of receiver keys is unsupported by this machine.
    ///   (`SizeError`)
    #[allow(clippy::too_many_arguments)] // The arguments are per the spec.
    fn verify_resharing_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dkg_id: NiDkgId,
        dealer_resharing_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        dealing: CspNiDkgDealing,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<(), ni_dkg_errors::CspDkgVerifyReshareDealingError>;

    /// Assembles all valid dealings into a single record.
    ///
    /// # Preconditions
    /// * The dealings MUST be verified before inclusion.
    /// # Arguments
    /// * `algorithm_id` selects the algorithm suite to use for the scheme.
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature.
    /// * `number_of_receivers` is the number of receivers that should have
    ///   shares in each dealing.
    /// * `csp_dealings` are correct dealings.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * the `algorithm_id` is not an NiDkg variant. (`UnsupportedAlgorithmId`)
    /// * the threshold is less than 1 or greater than the number of receivers.
    ///   (`InvalidThresholdError`)
    /// * any of the dealings is invalid. (`InvalidDealingError`)
    /// * any `dealing` in `csp_dealings` does not match `number_of_receivers`.
    ///   (`InvalidDealingError`)
    /// * there are insufficient dealings to proceed safely.
    ///   (`InsufficientDataError`)
    /// * the threshold, number of keys or dealings is unsupported by this
    ///   machine. (`SizeError`)
    fn create_transcript(
        &self,
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        number_of_receivers: NumberOfNodes,
        csp_dealings: BTreeMap<NodeIndex, CspNiDkgDealing>,
    ) -> Result<CspNiDkgTranscript, ni_dkg_errors::CspDkgCreateTranscriptError>;

    /// Assembles all valid resharing dealings into a single record.
    ///
    /// # Preconditions
    /// * The dealings MUST be verified before inclusion.
    /// # Arguments
    /// * `algorithm_id` selects the algorithm suite to use for the scheme.
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature using the new keys; this may differ from the
    ///   preceding threshold.
    /// * `number_of_receivers` is the number of receivers that should have
    ///   shares in each dealing.
    /// * `csp_dealings` are correct dealings.
    /// * `resharing_public_coefficients` are the public coefficients of the
    ///   previous threshold key. They are used to determine the threshold and
    ///   public key of the previous threshold key being reshared.
    /// # Panics
    /// This method is not expected to panic.
    /// # Errors
    /// This method SHALL return an error if:
    /// * the `algorithm_id` is not an NiDkg variant. (`UnsupportedAlgorithmId`)
    /// * the threshold is less than 1 or greater than the number of receivers.
    ///   (`InvalidThresholdError`)
    /// * the public key to be reshared is invalid.
    ///   (`MalformedResharePublicCoefficientsError`)
    /// * any `dealing` in `csp_dealings` does not match `number_of_receivers`.
    ///   (`InvalidDealingError`)
    /// * there are insufficient dealings to proceed safely.
    ///   (`InsufficientDataError`)
    /// * the reshared public key changes.  This will not happen if all dealings
    ///   are verified correctly. (`ResharingFailed`)
    /// * the threshold, number of keys or dealings is unsupported by this
    ///   machine. (`SizeError`)
    fn create_resharing_transcript(
        &self,
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        number_of_receivers: NumberOfNodes,
        csp_dealings: BTreeMap<NodeIndex, CspNiDkgDealing>,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<CspNiDkgTranscript, ni_dkg_errors::CspDkgCreateReshareTranscriptError>;

    /// Computes a threshold signing key and stores it in the secret key store.
    ///
    /// After calling this method to store the key in the secret key store, the
    /// threshold signature API can be used to generate signature shares.
    ///
    /// Notes:
    /// * The key ID is derived from the public coefficients with:
    ///   `KeyId::from(&public_coefficients)`
    /// * See the threshold API for how to proceed further.
    /// # Arguments
    /// * `algorithm_id` selects the algorithm suite to use for the scheme.
    /// * `dkg_id` is the identifier for the distributed key being generated.
    /// * `epoch` is a monotonic increasing counter used to select forward
    ///   secure keys.
    /// * `csp_transcript` is a summary of the key generation.
    /// * `receiver_index` is the index of the current node in the list of
    ///   receivers.
    /// # Panics
    /// * This MAY panic if the secret key store is unavailable.
    /// # Errors
    /// This method SHALL return an error if:
    /// * the `algorithm_id` is not an NiDkg variant. (`UnsupportedAlgorithmId`)
    /// * the forward secure decryption key was not found. (`KeyNotFoundError`)
    /// * the forward secure decryption key is malformed.
    ///   (`MalformedSecretKeyError`)
    /// * the transcript is malformed. (`MalformedTranscriptError`)
    /// * it is unable to compute the secret key. (`InvalidTranscriptError`)
    fn load_threshold_signing_key(
        &self,
        algorithm_id: AlgorithmId,
        dkg_id: NiDkgId,
        epoch: Epoch,
        csp_transcript: CspNiDkgTranscript,
        receiver_index: NodeIndex,
    ) -> Result<(), ni_dkg_errors::CspDkgLoadPrivateKeyError>;

    /// Keeps the specified NiDKG threshold keys.
    ///
    /// A threshold key in the secret key store with public coefficients
    /// matching an entry in the list will be kept; other threshold keys will be
    /// deleted.
    ///
    /// There is no guarantee that there are secret keys matching all the listed
    /// public coefficients.  If this method is requested to retain a key that
    /// is not in the secret key store, that key will be ignored.
    fn retain_threshold_keys_if_present(&self, active_keys: BTreeSet<CspPublicCoefficients>);
}
