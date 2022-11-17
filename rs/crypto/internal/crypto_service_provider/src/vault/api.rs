use crate::api::{CspCreateMEGaKeyError, CspThresholdSignError};
use crate::key_id::KeyId;
use crate::types::CspPublicCoefficients;
use crate::types::{CspPop, CspPublicKey, CspSignature};
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_threshold_sig_ecdsa::{
    CommitmentOpening, IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptOperationInternal, MEGaPublicKey, ThresholdEcdsaSigShareInternal,
};
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgLoadTranscriptError, IDkgOpenTranscriptError,
    IDkgRetainThresholdKeysError, IDkgVerifyDealingPrivateError, ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::{AlgorithmId, CurrentNodePublicKeys};
use ic_types::{NodeId, NodeIndex, NumberOfNodes, Randomness};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspBasicSignatureError {
    SecretKeyNotFound {
        algorithm: AlgorithmId,
        key_id: KeyId,
    },
    UnsupportedAlgorithm {
        algorithm: AlgorithmId,
    },
    WrongSecretKeyType {
        algorithm: AlgorithmId,
        secret_key_variant: String,
    },
    MalformedSecretKey {
        algorithm: AlgorithmId,
    },
    InternalError {
        internal_error: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspBasicSignatureKeygenError {
    InternalError { internal_error: String },
    DuplicateKeyId { key_id: KeyId },
    TransientInternalError { internal_error: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspMultiSignatureError {
    SecretKeyNotFound {
        algorithm: AlgorithmId,
        key_id: KeyId,
    },
    UnsupportedAlgorithm {
        algorithm: AlgorithmId,
    },
    WrongSecretKeyType {
        algorithm: AlgorithmId,
        secret_key_variant: String,
    },
    InternalError {
        internal_error: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspMultiSignatureKeygenError {
    MalformedPublicKey {
        algorithm: AlgorithmId,
        key_bytes: Option<Vec<u8>>,
        internal_error: String,
    },
    InternalError {
        internal_error: String,
    },
    DuplicateKeyId {
        key_id: KeyId,
    },
    TransientInternalError {
        internal_error: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspThresholdSignatureKeygenError {
    UnsupportedAlgorithm { algorithm: AlgorithmId },
    InvalidArgument { message: String },
    InternalError { internal_error: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspSecretKeyStoreContainsError {
    InternalError { internal_error: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspPublicKeyStoreError {
    // TODO: CRP-1719 add more error variants if necessary
    TransientInternalError(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspTlsKeygenError {
    InvalidNotAfterDate { message: String, not_after: String },
    InternalError { internal_error: String },
    DuplicateKeyId { key_id: KeyId },
    TransientInternalError { internal_error: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspTlsSignError {
    SecretKeyNotFound {
        key_id: KeyId,
    },
    WrongSecretKeyType {
        algorithm: AlgorithmId,
        secret_key_variant: String,
    },
    MalformedSecretKey {
        error: String,
    },
    SigningFailed {
        error: String,
    },
    InternalError {
        internal_error: String,
    },
}

/// `CspVault` offers a selection of operations that involve
/// secret keys managed by the vault.
pub trait CspVault:
    BasicSignatureCspVault
    + MultiSignatureCspVault
    + ThresholdSignatureCspVault
    + NiDkgCspVault
    + IDkgProtocolCspVault
    + ThresholdEcdsaSignerCspVault
    + SecretKeyStoreCspVault
    + TlsHandshakeCspVault
    + PublicRandomSeedGenerator
    + PublicKeyStoreCspVault
{
}

// Blanket implementation of `CspVault` for all types that fulfill the
// requirements.
impl<T> CspVault for T where
    T: BasicSignatureCspVault
        + MultiSignatureCspVault
        + ThresholdSignatureCspVault
        + NiDkgCspVault
        + IDkgProtocolCspVault
        + ThresholdEcdsaSignerCspVault
        + SecretKeyStoreCspVault
        + TlsHandshakeCspVault
        + PublicRandomSeedGenerator
        + PublicKeyStoreCspVault
{
}

/// Operations of `CspVault` related to basic signatures
/// (cf. `CspSigner` and `CspKeyGenerator`).
pub trait BasicSignatureCspVault {
    /// Signs the given message using the specified algorithm and key ID.
    ///
    /// # Arguments
    /// * `algorithm_id` specifies the signature algorithm
    /// * `message` is the message to be signed
    /// * `key_id` determines the private key to sign with
    /// # Returns
    /// The computed signature.
    /// # Note
    /// `sign`-method of basic signatures takes the full message as an argument
    /// (rather than just message digest).
    /// The reason for this "inefficiency" is the fact that in
    /// Ed25519-signatures (that this trait has to support) the computation
    /// of the message digest uses secret key data as an input, and so
    /// cannot be computed outside of the CspVault (cf. PureEdDSA in
    /// [RFC 8032](https://tools.ietf.org/html/rfc8032#section-5.1.6))
    fn sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError>;

    /// Generates a node signing public/private key pair.
    ///
    /// # Returns
    /// Generated public key.
    ///
    /// # Errors
    /// * `CspBasicSignatureKeygenError::InternalError` if there is an internal
    ///   error (e.g., the public key in the public key store is already set).
    /// * `CspBasicSignatureKeygenError::DuplicateKeyId` if there already
    ///   exists a secret key in the store for the secret key ID derived from
    ///   the public part of the randomly generated key pair. This error
    ///   most likely indicates a bad randomness source.
    /// * `CspBasicSignatureKeygenError::TransientInternalError` if there is a
    ///   transient internal error, e.g., an IO error when writing a key to
    ///   disk, or an RPC error when calling a remote CSP vault.
    fn gen_node_signing_key_pair(&self) -> Result<CspPublicKey, CspBasicSignatureKeygenError>;
}

/// Operations of `CspVault` related to multi-signatures
/// (cf. `CspSigner` and `CspKeyGenerator`).
pub trait MultiSignatureCspVault {
    /// Signs the given message using the specified algorithm and key ID.
    ///
    /// # Arguments
    /// * `algorithm_id` specifies the signature algorithm
    /// * `message` is the message to be signed
    /// * `key_id` determines the private key to sign with
    /// # Returns
    /// The computed signature.
    ///
    /// # Note
    /// `multi_sign`-method takes the full message as an argument (rather than
    /// just message digest) to be consistent with
    /// `BasicSignatureCspVault::sign()`-method.
    fn multi_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspMultiSignatureError>;

    /// Generates a public/private key pair, with a proof of possession.
    ///
    /// # Returns
    /// The public key of the keypair and the proof of possession.
    ///
    /// # Errors
    /// * `CspMultiignatureKeygenError::InternalError` if there is an internal
    ///   error (e.g., the public key in the public key store is already set).
    /// * `CspMultiSignatureKeygenError::DuplicateKeyId` if there already
    ///   exists a secret key in the store for the secret key ID derived from
    ///   the public part of the randomly generated key pair. This error
    ///   most likely indicates a bad randomness source.
    /// * `CspMultiSignatureKeygenError::TransientInternalError` if there is a
    ///   transient internal error, e.g,. an IO error when writing a key to
    ///   disk, or an RPC error when calling a remote CSP vault.
    fn gen_committee_signing_key_pair(
        &self,
    ) -> Result<(CspPublicKey, CspPop), CspMultiSignatureKeygenError>;
}

/// Operations of `CspVault` related to threshold signatures
/// (cf. `ThresholdSignatureCspClient`).
pub trait ThresholdSignatureCspVault {
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
    fn threshold_keygen_for_test(
        &self,
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        signatory_eligibility: &[bool],
    ) -> Result<(CspPublicCoefficients, Vec<Option<KeyId>>), CspThresholdSignatureKeygenError>;

    /// Signs the given message using the specified algorithm and key ID.
    ///
    /// # Arguments
    /// * `algorithm_id` specifies the signature algorithm
    /// * `message` is the message to be signed
    /// * `key_id` determines the private key to sign with
    /// # Returns
    /// The computed threshold signature.
    ///
    /// # Note
    /// `threshold_sign`-method takes the full message as an argument (rather
    /// than just message digest) to be consistent with
    /// `BasicSignatureCspVault::sign()`-method.
    fn threshold_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError>;
}

/// Operations of `CspVault` related to NI-DKG (cf. `NiDkgCspClient`).
pub trait NiDkgCspVault {
    /// Generates a forward-secure dealing encryption key pair used to encrypt threshold key shares
    /// in transmission.
    ///
    /// # Returns
    /// The public key and the corresponding proof-of-possession.
    /// # Errors
    /// * `ni_dkg_errors::CspDkgCreateFsKeyError::InternalError` if there is an internal
    ///   error (e.g., the public key in the public key store is already set).
    /// * `ni_dkg_errors::CspDkgCreateFsKeyError::TransientInternalError` if there is a transient
    ///   internal error, e.g., an IO error when writing a key to disk, or an
    ///   RPC error when calling a remote CSP vault.
    fn gen_dealing_encryption_key_pair(
        &self,
        node_id: NodeId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), ni_dkg_errors::CspDkgCreateFsKeyError>;

    /// Updates the forward-secure secret key determined by the key id,
    /// so that it cannot be used to decrypt data at epochs that are smaller
    /// (older) than the given epoch.
    ///
    /// # Arguments
    /// * `key_id` identifies the forward-secure secret key.
    /// * `epoch` is the epoch to be deleted, together with all smaller epochs.
    fn update_forward_secure_epoch(
        &self,
        algorithm_id: AlgorithmId,
        key_id: KeyId,
        epoch: Epoch,
    ) -> Result<(), ni_dkg_errors::CspDkgUpdateFsEpochError>;

    /// Generates a dealing which contains a share for each eligible receiver.
    /// If `reshared_secret` is `None`, then the dealing is a sharing of a
    /// fresh random value, otherwise it is a re-sharing of the secret
    /// identified by `reshared_secret`.
    ///
    /// # Arguments
    /// * `algorithm_id` selects the algorithm suite to use for the scheme.
    /// * `dealer_index` the index associated with the dealer.
    /// * `threshold` is the minimum number of nodes required to generate a
    ///   valid threshold signature.
    /// * `epoch` is a monotonic increasing counter used to select forward
    ///   secure keys.
    /// * `receiver_keys` is a map storing a forward-secure public key for each
    ///   receiver, indexed by their corresponding NodeIndex.
    /// * 'maybe_resharing_secret' if `Some`, identifies the secret to be
    ///   reshared.
    /// # Returns
    /// A new dealing.
    fn create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: &BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        maybe_resharing_secret: Option<KeyId>,
    ) -> Result<CspNiDkgDealing, ni_dkg_errors::CspDkgCreateReshareDealingError>;

    /// Computes a threshold signing key and stores it in the secret key store.
    ///
    /// After calling this method the threshold signature API can be used
    /// to generate signature shares.
    /// # Arguments
    /// * `algorithm_id` selects the algorithm suite to use for the scheme.
    /// * `dkg_id` is the identifier for the distributed key being generated.
    /// * `epoch` is a monotonic increasing counter used to select forward
    ///   secure keys.
    /// * `csp_transcript_for_node` is a summary of the key generation,
    ///   containing the transcript parts relevant for the current node.
    /// * `fs_key_id` identifies the forward-secure key that is used to decrypt
    ///   shares.
    /// * `receiver_index` is the index of the current node in the list of
    ///   receivers.
    fn load_threshold_signing_key(
        &self,
        algorithm_id: AlgorithmId,
        epoch: Epoch,
        csp_transcript: CspNiDkgTranscript,
        fs_key_id: KeyId,
        receiver_index: NodeIndex,
    ) -> Result<(), ni_dkg_errors::CspDkgLoadPrivateKeyError>;

    /// Keeps the specified NiDKG threshold keys.
    ///
    /// A threshold key in the secret key store with an id specified in
    /// `active_key_ids` will be kept; other threshold keys will be deleted.
    ///
    /// There is no guarantee that there are secret keys matching all the key
    /// ids. If this method is requested to retain a key that is not in the
    /// secret key store, that key will be ignored.
    /// # Arguments
    /// * `active_key_ids` identifies threshold keys that should be retained
    fn retain_threshold_keys_if_present(
        &self,
        active_key_ids: BTreeSet<KeyId>,
    ) -> Result<(), ni_dkg_errors::CspDkgRetainThresholdKeysError>;
}

/// Operations of `CspVault` related to querying the secret key store (cf.
/// `CspSecretKeyStoreChecker`).
pub trait SecretKeyStoreCspVault {
    /// Checks whether the secret key store contains a key with the given
    /// `key_id`.
    ///
    /// # Arguments
    /// * `key_id` identifies the key whose presence should be checked.
    fn sks_contains(&self, key_id: &KeyId) -> Result<bool, CspSecretKeyStoreContainsError>;
}

/// Operations of `CspVault` related to querying the public key store.
pub trait PublicKeyStoreCspVault {
    /// Checks whether the local public key store contains the provided public keys.
    ///
    /// # Returns
    /// `true` if all the provided public keys exist in the local public key store,
    /// `false` if one or more of the provided public keys do not exist in the local
    /// public key store
    ///
    /// # Errors
    /// * `CspPublicKeyStoreError::TransientInternalError` if there is a transient
    ///   internal error, e.g., an RPC error when calling a remote CSP vault.
    fn pks_contains(
        &self,
        public_keys: CurrentNodePublicKeys,
    ) -> Result<bool, CspPublicKeyStoreError>;
    /// Returns the node's current public keys.
    ///
    /// For keys that are periodically rotated (such as the iDKG dealing encryption key pair) only
    /// the latest public key locally available will be returned. This public key may in particular
    /// not yet be in the registry.
    ///
    /// # Errors
    /// * if a transient error (e.g., RPC timeout) occurs when accessing the public key store
    fn current_node_public_keys(&self) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;
}

/// Operations of `CspVault` related to TLS handshakes.
pub trait TlsHandshakeCspVault: Send + Sync {
    /// Generates TLS key material for node with ID `node_id`.
    ///
    /// The secret key is stored in the key store and used to create a
    /// self-signed X.509 public key certificate with
    /// * a random serial,
    /// * the common name (CN) of both subject and issuer being the `ToString`
    ///   form of the given `node_id`,
    /// * validity starting at the time of calling this method, and
    /// * validity ending at `not_after`, which must be specified according to
    ///   section 4.1.2.5 in RFC 5280.
    ///
    /// Returns the key ID of the secret key, and the public key certificate.
    ///
    /// # Errors
    /// * if `not_after` is not specified according to RFC 5280 or if
    /// `not_after` is in the past
    /// * if a malformed X509 certificate is generated
    fn gen_tls_key_pair(
        &self,
        node: NodeId,
        not_after: &str,
    ) -> Result<TlsPublicKeyCert, CspTlsKeygenError>;

    /// Signs the given message using the specified algorithm and key ID.
    ///
    /// # Arguments
    /// * `message` is the message to be signed
    /// * `key_id` determines the private key to sign with
    /// # Returns
    /// The computed signature to be used during a TLS handshake.
    ///
    /// # Note
    /// The method takes the full message as an argument (rather than
    /// just message digest) to be consistent with
    /// `BasicSignatureCspVault::sign()`-method.
    fn tls_sign(&self, message: &[u8], key_id: &KeyId) -> Result<CspSignature, CspTlsSignError>;
}

/// Operations of `CspVault` related to I-DKG (cf. `CspIDkgProtocol`).
pub trait IDkgProtocolCspVault {
    /// Generate an IDkg dealing.
    fn idkg_create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        context_data: &[u8],
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: &[MEGaPublicKey],
        transcript_operation: &IDkgTranscriptOperationInternal,
    ) -> Result<IDkgDealingInternal, IDkgCreateDealingError>;

    /// See [`CspIDkgProtocol::idkg_verify_dealing_private`].
    fn idkg_verify_dealing_private(
        &self,
        algorithm_id: AlgorithmId,
        dealing: &IDkgDealingInternal,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_key_id: KeyId,
        context_data: &[u8],
    ) -> Result<(), IDkgVerifyDealingPrivateError>;

    /// Compute secret from transcript and store in SKS, generating complaints
    /// if necessary.
    fn idkg_load_transcript(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        key_id: &KeyId,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError>;

    /// See [`crate::api::CspIDkgProtocol::idkg_load_transcript_with_openings`].
    fn idkg_load_transcript_with_openings(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        key_id: &KeyId,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<(), IDkgLoadTranscriptError>;

    /// Generate a MEGa keypair, for encrypting/decrypting IDkg dealing shares.
    ///
    /// See [`crate::api::CspIDkgProtocol::idkg_gen_dealing_encryption_key_pair`].
    fn idkg_gen_dealing_encryption_key_pair(&self) -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;

    /// Opens the dealing from dealer specified by `dealer_index`.
    fn idkg_open_dealing(
        &self,
        dealing: IDkgDealingInternal,
        dealer_index: NodeIndex,
        context_data: &[u8],
        opener_index: NodeIndex,
        opener_key_id: &KeyId,
    ) -> Result<CommitmentOpening, IDkgOpenTranscriptError>;

    /// Retains canister threshold keys identified by `active_key_ids`, and removes other
    /// canister threshold keys within the same IDKG threshold keys scope from the
    /// canister SKS.
    fn idkg_retain_threshold_keys_if_present(
        &self,
        active_key_ids: BTreeSet<KeyId>,
    ) -> Result<(), IDkgRetainThresholdKeysError>;
}

/// Operations of `CspVault` related to threshold-ECDSA (cf.
/// `CspThresholdEcdsaSigner`).
pub trait ThresholdEcdsaSignerCspVault {
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

/// An error returned by failing to generate a public seed from [`CspVault`].
#[derive(Serialize, Deserialize, Debug)]
pub enum PublicRandomSeedGeneratorError {
    /// Internal error, e.g., an RPC error.
    InternalError { internal_error: String },
}

/// Operations of [`CspVault`] for generating public random seed.
pub trait PublicRandomSeedGenerator {
    /// Returns a public random [`Seed`].
    /// Public in this context means that the produced randomness MUST NOT be used in
    /// any use cases where the security relies on keeping the randomness secret, e.g.,
    /// generation of cryptographic keys.
    fn new_public_seed(&self) -> Result<Seed, PublicRandomSeedGeneratorError>;
}
