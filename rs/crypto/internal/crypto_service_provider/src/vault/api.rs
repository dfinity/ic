use crate::api::{CspCreateMEGaKeyError, CspThresholdSignError};
use crate::secret_key_store::{Scope, SecretKeyStoreError};
use crate::types::{CspPop, CspPublicKey, CspSignature};
use crate::types::{CspPublicCoefficients, CspSecretKey};
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgLoadTranscriptError, ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{NodeId, NodeIndex, NumberOfNodes, Randomness};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use tecdsa::{
    IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptOperationInternal, MEGaPublicKey, ThresholdEcdsaSigShareInternal,
};

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
    UnsupportedAlgorithm { algorithm: AlgorithmId },
    InternalError { internal_error: String },
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
    },
    InternalError {
        internal_error: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspMultiSignatureKeygenError {
    UnsupportedAlgorithm {
        algorithm: AlgorithmId,
    },
    MalformedPublicKey {
        algorithm: AlgorithmId,
        key_bytes: Option<Vec<u8>>,
        internal_error: String,
    },
    InternalError {
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
pub enum CspTlsKeygenError {
    InternalError { internal_error: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspTlsSignError {
    SecretKeyNotFound { key_id: KeyId },
    WrongSecretKeyType { algorithm: AlgorithmId },
    MalformedSecretKey { error: String },
    SigningFailed { error: String },
    InternalError { internal_error: String },
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

    /// Generates a public/private key pair.
    ///
    /// # Arguments
    /// * `algorithm_id` specifies the signature algorithm
    /// # Returns
    /// The key ID and the public key of the keypair
    fn gen_key_pair(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey), CspBasicSignatureKeygenError>;
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

    /// Generates a public/private key pair, with a proof-of-possession.
    ///
    /// # Arguments
    /// * `algorithm_id` specifies the signature algorithm
    /// # Returns
    /// The key ID, the public key of the keypair, and the proof-of-possession.
    fn gen_key_pair_with_pop(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey, CspPop), CspMultiSignatureKeygenError>;
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
    /// Generates a forward-secure key pair used to encrypt threshold key shares
    /// in transmission.
    ///
    /// # Arguments
    /// * `algorithm_id` specifies the forward-secure encryption algorithm
    /// # Returns
    /// The public key and the corresponding proof-of-possession.
    fn gen_forward_secure_key_pair(
        &self,
        node_id: NodeId,
        algorithm_id: AlgorithmId,
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
    fn retain_threshold_keys_if_present(&self, active_key_ids: BTreeSet<KeyId>);
}

/// Operations of `CspVault` related to querying the secret key store (cf.
/// `CspSecretKeyStoreChecker`).
pub trait SecretKeyStoreCspVault {
    /// Checks whether the secret key store contains a key with the given
    /// `key_id`. # Arguments
    /// * `key_id` identifies the key whose presence should be checked.
    fn sks_contains(&self, key_id: &KeyId) -> bool;

    // TODO(CRP-1326): remove this method.
    fn insert_secret_key(
        &self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreError>;

    // TODO(CRP-1326): remove this method.
    fn get_secret_key(&self, id: &KeyId) -> Option<CspSecretKey>;
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
    /// # Panics
    /// * if `not_after` is not specified according to RFC 5280 or if
    /// `not_after` is in the past
    /// * if a malformed X509 certificate is generated
    fn gen_tls_key_pair(
        &self,
        node: NodeId,
        not_after: &str,
    ) -> Result<(KeyId, TlsPublicKeyCert), CspTlsKeygenError>;

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

    /// Compute secret from transcript and store in SKS, generating complaints
    /// if necessary.
    fn idkg_load_transcript(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        key_id: &KeyId,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<Vec<IDkgComplaintInternal>, IDkgLoadTranscriptError>;

    /// Generate a MEGa keypair, for encrypting/decrypting IDkg dealing shares.
    fn idkg_gen_mega_key_pair(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;
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
