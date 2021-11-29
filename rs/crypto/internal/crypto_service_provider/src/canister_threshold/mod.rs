//! Canister threshold signatures.
//!
//! The code in this file mediates between the external API, the CSP state
//! including the secret key store and random number generator, and the
//! stateless crypto lib.

use crate::api::{CspCreateMEGaKeyError, IDkgProtocolCspClient};
use crate::keygen::mega_key_id;
use crate::secret_key_store::SecretKeyStore;
use crate::server::api::IDkgProtocolCspVault;
use crate::Csp;
use ic_crypto_internal_types::scope::{ConstScope, Scope};
use ic_logger::debug;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
};
use ic_types::crypto::AlgorithmId;
use ic_types::NodeIndex;
use ic_types::NumberOfNodes;
use rand::{CryptoRng, Rng};
use std::collections::BTreeMap;
use tecdsa::{
    create_transcript as tecdsa_create_transcript, IDkgComplaintInternal, IDkgDealingInternal,
    IDkgTranscriptInternal, IDkgTranscriptOperationInternal, MEGaPublicKey,
};

pub const IDKG_MEGA_SCOPE: Scope = Scope::Const(ConstScope::IDkgMEGaEncryptionKeys);

/// Interactive distributed key generation client
///
/// Please see the trait definition for full documentation.
impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore> IDkgProtocolCspClient
    for Csp<R, S, C>
{
    /// Generate a share of a dealing for a single receiver.
    fn idkg_create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        context_data: &[u8],
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: &[MEGaPublicKey],
        transcript_operation: &IDkgTranscriptOperationInternal,
    ) -> Result<IDkgDealingInternal, IDkgCreateDealingError> {
        debug!(self.logger; crypto.method_name => "idkg_create_dealing");

        self.csp_vault.idkg_create_dealing(
            algorithm_id,
            context_data,
            dealer_index,
            reconstruction_threshold,
            receiver_keys,
            transcript_operation,
        )
    }

    /// Generate an IDkg transcript from verified IDkg dealings
    fn idkg_create_transcript(
        &self,
        algorithm_id: AlgorithmId,
        reconstruction_threshold: NumberOfNodes,
        verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        operation_mode: &IDkgTranscriptOperationInternal,
    ) -> Result<IDkgTranscriptInternal, IDkgCreateTranscriptError> {
        debug!(self.logger; crypto.method_name => "idkg_create_transcript");

        tecdsa_create_transcript(
            algorithm_id,
            reconstruction_threshold,
            verified_dealings,
            operation_mode,
        )
        .map_err(|e| IDkgCreateTranscriptError::InternalError {
            internal_error: format!("{:?}", e),
        })
    }

    /// Compute secret from transcript and store in SKS, generating complaints
    /// if necessary.
    fn idkg_load_transcript(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        public_key: &MEGaPublicKey,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<Vec<IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        debug!(self.logger; crypto.method_name => "idkg_load_transcript");

        let key_id = mega_key_id(public_key);

        self.csp_vault.idkg_load_transcript(
            dealings,
            context_data,
            receiver_index,
            &key_id,
            transcript,
        )
    }

    /// Creates a key pair for encrypting threshold key shares in transmission
    /// from dealers to receivers.
    fn idkg_create_mega_key_pair(
        &mut self,
        algorithm_id: AlgorithmId,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        debug!(self.logger; crypto.method_name => "idkg_create_mega_key_pair");

        self.csp_vault.idkg_gen_mega_key_pair(algorithm_id)
    }
}
