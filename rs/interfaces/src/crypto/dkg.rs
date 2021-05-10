use ic_types::crypto::dkg::{Config, Dealing, EncryptionPublicKeyWithPop, Response, Transcript};
use ic_types::crypto::CryptoResult;
use ic_types::NodeId;
use std::collections::BTreeMap;

/// The building blocks to perform distributed key generation (DKG).
///
/// There are two variants of DKG that are supported:
///
/// # (Non-Resharing) DKG
/// In the standard DKG, the group public key changes in every DKG phase.
///
/// To run this variant of DKG, always use a `dkg::Config` that has
/// `resharing_transcript = None`.
///
/// # Resharing DKG
/// In resharing DKG, the group public key remains the same, as opposed to
/// changing in every DKG phase.
///
/// To run non-resharing DKG, proceed as follows:
/// * In the first phase, run (non-resharing) DKG using a `dkg::Config` that has
///   `resharing_transcript = None`.
/// * With the resulting `Transcript`, re-sharing DKG can be run repeatedly by
///   using a `dkg::Config` that has `resharing_transcript = Some(transcript)`,
///   where transcript is the `Transcript` from the previous DKG phase.
pub trait DkgAlgorithm {
    /// Generate an (ephemeral) encryption key pair, store the secret key in the
    /// local store, and return the public key.
    fn generate_encryption_keys(
        &self,
        config: &Config,
        node_id: NodeId,
    ) -> CryptoResult<EncryptionPublicKeyWithPop>;

    /// Verify an (ephemeral) public encryption key and its proof of possession.
    fn verify_encryption_public_key(
        &self,
        config: &Config,
        sender: NodeId,
        key: &EncryptionPublicKeyWithPop,
    ) -> CryptoResult<()>;

    /// Create a dealing.
    ///
    /// # Preconditions
    /// * for each `(node_id, pk)` in `verified_keys`, it holds that
    ///   `verify_encryption_public_key(config, node_id, pk).is_ok()`
    fn create_dealing(
        &self,
        config: &Config,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        node_id: NodeId,
    ) -> CryptoResult<Dealing>;

    /// Verify a dealing.
    ///
    /// # Preconditions
    /// * for each `(node_id, pk)` in `verified_keys`, it holds that
    ///   `verify_encryption_public_key(config, node_id, pk).is_ok()`
    fn verify_dealing(
        &self,
        config: &Config,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        dealer: NodeId,
        dealing: &Dealing,
    ) -> CryptoResult<()>;

    /// Create a response.
    ///
    /// # Preconditions
    /// * for each `(node_id, pk)` in `verified_keys`, it holds that
    ///   `verify_encryption_public_key(config, node_id, pk).is_ok()`
    /// * for each `(dealer, dealing)` in `verified_dealings`, it holds that
    ///   `verify_dealing(config, verified_keys, dealer, dealing).is_ok()`
    fn create_response(
        &self,
        config: &Config,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        verified_dealings: &BTreeMap<NodeId, Dealing>,
        node_id: NodeId,
    ) -> CryptoResult<Response>;

    /// Verify a response.
    ///
    /// # Preconditions
    /// * for each `(node_id, pk)` in `verified_keys`, it holds that
    ///   `verify_encryption_public_key(config, node_id, pk).is_ok()`
    /// * for each `(dealer, dealing)` in `verified_dealings`, it holds that
    ///   `verify_dealing(config, verified_keys, dealer, dealing).is_ok()`
    fn verify_response(
        &self,
        config: &Config,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        verified_dealings: &BTreeMap<NodeId, Dealing>,
        receiver: NodeId,
        response: &Response,
    ) -> CryptoResult<()>;

    /// Combine the given dealings into a transcript.
    ///
    /// # Preconditions
    /// * for each `(node_id, pk)` in `verified_keys`, it holds that
    ///   `verify_encryption_public_key(config, node_id, pk).is_ok()`
    /// * for each `(dealer, dealing)` in `verified_dealings`, it holds that
    ///   `verify_dealing(config, verified_keys, dealer, dealing).is_ok()`
    /// * for each `(receiver, response)` in `verified_responses`, it holds that
    ///   `verify_response(config, verified_keys, verified_dealings, receiver,
    ///   response).is_ok()`
    fn create_transcript(
        &self,
        config: &Config,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        verified_dealings: &BTreeMap<NodeId, Dealing>,
        verified_responses: &BTreeMap<NodeId, Response>,
    ) -> CryptoResult<Transcript>;

    /// Load the given transcript. This ensures that
    /// * the (group's) public threshold signing key is available for the
    ///   methods of the `ThresholdSigVerifier` trait, and
    /// * the individual nodes' public threshold signing keys are available for
    ///   the methods of the `ThresholdSigVerifier` trait, and
    /// * if the node is a receiver, the node's secret threshold signing key is
    ///   available for the methods of the `ThresholdSigner` trait
    /// for the DKG instance identified by the DKG ID contained in the
    /// transcript.
    fn load_transcript(&self, transcript: &Transcript, node_id: NodeId) -> CryptoResult<()>;
}
