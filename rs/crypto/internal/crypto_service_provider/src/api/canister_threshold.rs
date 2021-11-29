//! CSP canister threshold signature traits

use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
};
use ic_types::crypto::AlgorithmId;
use ic_types::NodeIndex;
use ic_types::NumberOfNodes;
use std::collections::BTreeMap;
use tecdsa::{
    IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptOperationInternal, MEGaPublicKey,
};

pub mod errors;
pub use errors::*;

/// Crypto service provider (CSP) client for interactive distributed key
/// generation (IDkg) for canister threshold signatures.
pub trait IDkgProtocolCspClient {
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

    /// Generate an IDkg transcript from verified IDkg dealings
    fn idkg_create_transcript(
        &self,
        algorithm_id: AlgorithmId,
        reconstruction_threshold: NumberOfNodes,
        verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        operation_mode: &IDkgTranscriptOperationInternal,
    ) -> Result<IDkgTranscriptInternal, IDkgCreateTranscriptError>;

    /// Compute secret from transcript and store in SKS, generating complaints
    /// if necessary.
    fn idkg_load_transcript(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        public_key: &MEGaPublicKey,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<Vec<IDkgComplaintInternal>, IDkgLoadTranscriptError>;

    /// Generate a MEGa encryption key pair used to encrypt threshold key shares
    /// in transmission.
    fn idkg_create_mega_key_pair(
        &mut self,
        algorithm_id: AlgorithmId,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;
}
