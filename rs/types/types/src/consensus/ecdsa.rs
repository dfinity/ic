//! Defines types used for threshold ECDSA key generation.

// TODO: Remove once we have implemented the functionality
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use self::ecdsa_crypto_mock::{
    BeaverTriple, EcdsaSignature, MultiplicationTranscript, MultiplicationTranscriptParams,
    OngoingSigningRequests, RandomTranscript, RandomTranscriptParams, RequestId,
    ResharingTranscript, TranscriptId,
};

/// The payload information necessary for ECDSA threshold signatures, that is
/// published on every consensus round.
pub struct EcdsaBatchPayload {
    /// Signatures that we agreed upon in this round.
    signature_agreements: BTreeMap<RequestId, EcdsaSignature>,

    /// `RandomTranscripts` that we agreed upon in this round.
    random_transcript_agreements: BTreeMap<TranscriptId, RandomTranscript>,

    /// `MultiplicationTranscripts` that we agreed upon in this round.
    multiplication_transcript_agreements: BTreeMap<TranscriptId, MultiplicationTranscript>,

    /// The `RequestIds` for which we are currently generating signatures.
    ongoing_signatures: OngoingSigningRequests,
}

/// The payload information necessary for ECDSA threshold signatures, that is
/// published on summary blocks.
pub struct EcdsaSummaryPayload {
    /// Configs to generate random transcripts from. These are taken from
    /// random_transcripts.
    random_configs: Vec<RandomTranscriptParams>,

    /// Configs to generate multiplication transcripts from. These are taken
    /// from random_transcripts.
    multiplication_configs: Vec<MultiplicationTranscriptParams>,

    /// The `RequestIds` for which we are currently generating signatures.
    ongoing_signatures: OngoingSigningRequests,

    /// The ECDSA transcript that we're currently using (if we have one).
    current_ecdsa_transcript: Option<ResharingTranscript>,

    /// The ECDSA transcript that would become the current transcript on the
    /// next summary (if we have one).
    next_ecdsa_transcript: Option<ResharingTranscript>,

    /// Beaver triples that we can use to create ECDSA signatures.
    available_beaver_triples: Vec<BeaverTriple>,

    /// Available transcripts of random numbers. We use these to build beaver
    /// triples.
    random_transcripts: Vec<RandomTranscript>,
}

/// The ECDSA message that goes into the artifact pool and gossiped with peers
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EcdsaMessage;

#[allow(missing_docs)]
/// Mock module of the crypto types that are needed by consensus for threshold
/// ECDSA generation. These types should be replaced by the real Types once they
/// are available.
mod ecdsa_crypto_mock {
    use std::collections::BTreeMap;

    pub struct RequestId;
    pub struct EcdsaSignature;

    pub struct RandomTranscript;
    pub struct ResharingTranscript;
    pub struct MultiplicationTranscript;

    pub struct RandomTranscriptParams;
    pub struct ResharingTranscriptParams;
    pub struct MultiplicationTranscriptParams;

    pub struct TranscriptId;
    pub struct BeaverTripleId;
    pub type BeaverTriple = (RandomTranscript, RandomTranscript, MultiplicationTranscript);
    pub type OngoingSigningRequests = BTreeMap<RequestId, (BeaverTripleId, BeaverTripleId)>;
}
