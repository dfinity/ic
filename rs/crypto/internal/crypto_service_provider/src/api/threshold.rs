//! CSP threshold signature traits

use crate::api::CspThresholdSignError;
use crate::types::{CspPublicCoefficients, CspSecretKeyConversionError, CspSignature};
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspFsEncryptionPublicKey, CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use ic_types::crypto::{AlgorithmId, CryptoResult};
use ic_types::{NodeIndex, NumberOfNodes};
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
    /// Signs with a threshold key
    fn threshold_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
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
    ///
    /// # Security Notice
    /// The `public_coefficients` are assumed to be trusted
    /// (e.g. obtained from the ThresholdSigDataStore)
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
    ///   This method SHALL NOT return an error if:
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
    /// * the key ID of the secret key to be reshared could not be computed.
    ///   (`ReshareKeyIdComputationError`)
    /// * the key to be reshared is not present or malformed.
    ///   (`ReshareKeyNotInSecretKeyStoreError`, `MalformedReshareSecretKeyError`)
    /// * the number of public coefficients or receiver keys is unsupported by
    ///   this machine. (`SizeError`)
    /// * a transient error occurred while computing the resharing dealing (e.g., there was a
    ///   problem communicating with the remote CSP vault). (`TransientInternalError`)
    #[allow(clippy::too_many_arguments)]
    fn create_resharing_dealing(
        &self,
        algorithm_id: AlgorithmId,
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
    /// * `collection_threshold` is the number of dealings to be included in
    ///   the transcript.
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
    ///   (`InsufficientDealingsError`)
    /// * the threshold, number of keys or dealings is unsupported by this
    ///   machine. (`SizeError`)
    fn create_transcript(
        &self,
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        number_of_receivers: NumberOfNodes,
        csp_dealings: BTreeMap<NodeIndex, CspNiDkgDealing>,
        collection_threshold: NumberOfNodes,
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
    /// * the public key is malformed. (`MalformedPublicKeyError`)
    /// * there is an internal error, e.g., a serialization error while inserting the threshold
    ///   secret key into the key store. (`InternalError`)
    /// * there is a transient internal error, e.g., an RPC error communicating with the remote CSP
    ///   vault. (`TransientInternalError`)
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
    ///
    /// # Arguments
    /// * `active_keys` contains the public coefficients of the active keys that need to be kept.
    ///
    /// # Errors
    /// This method SHALL return an error if:
    /// * a key ID could not be computed from the public coefficients. (`KeyIdInstantiationError`)
    /// * a transient internal error occurred while retaining the threshold keys, e.g., while
    ///   communicating with the remote CSP vault. (`TransientInternalError`)
    fn retain_threshold_keys_if_present(
        &self,
        active_keys: BTreeSet<CspPublicCoefficients>,
    ) -> Result<(), ni_dkg_errors::CspDkgRetainThresholdKeysError>;

    /// Make a metrics observation of the minimum epoch in active transcripts.
    fn observe_minimum_epoch_in_active_transcripts(&self, epoch: Epoch);

    /// Make a metrics observation of the epoch in loaded transcript.
    fn observe_epoch_in_loaded_transcript(&self, epoch: Epoch);
}
