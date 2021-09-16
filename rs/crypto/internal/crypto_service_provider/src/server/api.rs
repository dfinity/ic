use crate::api::CspThresholdSignError;
#[cfg(test)]
use crate::types::CspPublicCoefficients;
use crate::types::{CspPop, CspPublicKey, CspSignature};
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_types::encrypt::forward_secure::groth20_bls12_381::FsEncryptionPublicKey;
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{NodeId, NodeIndex, NumberOfNodes};
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
        algorithm_id: AlgorithmId,
    },
    MalformedSecretKey {
        algorithm: AlgorithmId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspSignatureKeygenError {
    UnsupportedAlgorithm { algorithm: AlgorithmId },
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
    WrongSecretKeyType {},
    MalformedMessageDigest {},
    MalformedSecretKey {
        algorithm: AlgorithmId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspMultiSignatureKegenError {
    UnsupportedAlgorithm { algorithm: AlgorithmId },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CspThresholdSignatureKeygenError {
    UnsupportedAlgorithm { algorithm: AlgorithmId },
    InvalidArgument { message: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CspNiDkgTranscriptForNode {
    node_id: NodeId,
    transcript: CspNiDkgTranscript,
}

/// `CspServer` offers a selection of operations that involve
/// secret keys managed by the server.
pub trait CspServer:
    BasicSignatureCspServer
    + MultiSignatureCspServer
    + ThresholdSignatureCspServer
    + NiDkgCspServer
    + SecretKeyStoreCspServer
{
}

/// Operations of `CspServer` related to basic signatures
/// (cf. `CspSigner` and `CspKeyGenerator`).
pub trait BasicSignatureCspServer {
    /// Signs the given message using the specified algorithm and key IDs
    ///
    /// # Arguments
    /// * `algorithm_id` specifies the signature algorithm
    /// * `message` is the message to be signed
    /// * `key_id` determines the private key to sign with
    /// # Returns
    /// The computed signature.
    /// # Note
    /// Unlike for multi- and threshold-signatures below, `sign`-method
    /// of basic signatures takes the full message as an argument
    /// (rather than just message digest).
    /// The reason for this discrepancy is the fact that in Ed25519-signatures
    /// (that this trait has to support) the computation of the message digest
    /// uses secret key data as an input, and so cannot be computed outside
    /// of the CspServer (cf. PureEdDSA in
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
    ) -> Result<(KeyId, CspPublicKey), CspSignatureKeygenError>;
}

/// Operations of `CspServer` related to multi-signatures
/// (cf. `CspSigner` and `CspKeyGenerator`).
pub trait MultiSignatureCspServer {
    /// Signs the given message digest using the specified algorithm and key
    /// IDs.
    ///
    /// # Arguments
    /// * `algorithm_id` specifies the signature algorithm
    /// * `msg_digest` is the digest of the message to be signed
    /// * `key_id` determines the private key to sign with
    /// # Returns
    /// The computed signature.
    fn multi_sign(
        &self,
        algorithm_id: AlgorithmId,
        msg_digest: &[u8],
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
    ) -> Result<(KeyId, CspPublicKey, CspPop), CspMultiSignatureKegenError>;
}

/// Operations of `CspServer` related to threshold signatures
/// (cf. `ThresholdSignatureCspClient`).
pub trait ThresholdSignatureCspServer {
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
    fn threshold_keygen_for_test(
        &mut self,
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        signatory_eligibility: &[bool],
    ) -> Result<(CspPublicCoefficients, Vec<Option<KeyId>>), CspThresholdSignatureKeygenError>;

    /// Signs the given message digest using the specified algorithm and key
    /// IDs.
    ///
    /// # Arguments
    /// * `algorithm_id` specifies the signature algorithm
    /// * `message` is the message to be signed
    /// * `key_id` determines the private key to sign with
    /// # Returns
    /// The computed threshold signature.
    fn threshold_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError>;
}

/// Operations of `CspServer` related to NI-DKG (cf. `NiDkgCspClient`).
pub trait NiDkgCspServer {
    /// Generates a forward-secure key pair used to encrypt threshold key shares
    /// in transmission.
    ///
    /// # Arguments
    /// * `algorithm_id` specifies the forward-secure encryption algorithm
    /// # Returns
    /// The public key and the corresponding proof-of-possession.
    fn gen_forward_secure_key_pair(
        &mut self,
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
        &mut self,
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
    /// * 'reshared_secret' if `Some`, identifies the secret to be reshared.
    /// # Returns
    /// A new dealing.
    fn create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
        reshared_secret: Option<KeyId>,
    ) -> Result<CspNiDkgDealing, ni_dkg_errors::CspDkgCreateDealingError>;

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
        &mut self,
        algorithm_id: AlgorithmId,
        epoch: Epoch,
        csp_transcript_for_node: CspNiDkgTranscriptForNode,
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
    fn retain_threshold_keys_if_present(&mut self, active_key_ids: BTreeSet<KeyId>);
}

/// Operations of `CspServer` related querying SKS (cf.
/// `CspSecretKeyStoreChecker`).
pub trait SecretKeyStoreCspServer {
    /// Checks whether the secret key store contains a key with the given
    /// `key_id`. # Arguments
    /// * `key_id` identifies the key whose presence should be checked.
    fn sks_contains(&self, key_id: &KeyId) -> bool;
}
