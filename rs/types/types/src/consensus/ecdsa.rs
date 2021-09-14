//! Defines types used for threshold ECDSA key generation.

// TODO: Remove once we have implemented the functionality
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use self::ecdsa_crypto_mock::{
    EcdsaQuadruple, EcdsaSignature, MultiplicationTranscript, MultiplicationTranscriptParams,
    OngoingSigningRequests, RandomFatTranscript, RandomFatTranscriptParams, RandomSkinnyTranscript,
    RandomSkinnyTranscriptParams, RequestId, ResharingTranscript, TranscriptId,
};

/// Refers to any EcdsaPayload type
pub enum EcdsaPayload {
    Batch(EcdsaBatchPayload),
    Summary(EcdsaSummaryPayload),
}

struct RandomTranscriptPair {
    skinny: RandomSkinnyTranscript,
    fat: RandomFatTranscript,
}

struct RandomTranscriptParamsPair {
    skinny: RandomSkinnyTranscriptParams,
    fat: RandomFatTranscriptParams,
}

/// The payload information necessary for ECDSA threshold signatures, that is
/// published on every consensus round.
pub struct EcdsaBatchPayload {
    /// Signatures that we agreed upon in this round.
    signature_agreements: BTreeMap<RequestId, EcdsaSignature>,

    /// `RandomTranscripts` that we agreed upon in this round.
    random_transcript_agreements: BTreeMap<TranscriptId, RandomTranscriptPair>,

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
    random_configs: Vec<RandomTranscriptParamsPair>,

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

    /// ECDSA transcript quadruples that we can use to create ECDSA signatures.
    available_ecdsa_quadruples: Vec<EcdsaQuadruple>,

    /// Available transcripts of random numbers. We use these to build
    /// quadruples
    random_transcripts: Vec<RandomTranscriptPair>,
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

    pub struct RandomSkinnyTranscript;
    pub struct RandomFatTranscript;
    pub struct ResharingTranscript;
    pub struct MultiplicationTranscript;

    pub struct RandomSkinnyTranscriptParams;
    pub struct RandomFatTranscriptParams;
    pub struct ResharingTranscriptParams;
    pub struct MultiplicationTranscriptParams;

    pub struct TranscriptId;
    pub struct QuadrupleId;
    pub type EcdsaQuadruple = (
        RandomSkinnyTranscript,
        MultiplicationTranscript,
        RandomFatTranscript,
        MultiplicationTranscript,
    );
    pub type OngoingSigningRequests = BTreeMap<RequestId, (QuadrupleId, QuadrupleId)>;
}
