//! Defines types used for threshold ECDSA key generation.

// TODO: Remove once we have implemented the functionality
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

use self::ecdsa_crypto_mock::{EcdsaComplaint, EcdsaDealing, EcdsaOpening, RequestId};
use crate::crypto::{
    canister_threshold_sig::idkg::{
        IDkgDealing, IDkgTranscript, IDkgTranscriptId, IDkgTranscriptParams, IDkgTranscriptType,
    },
    CombinedMultiSigOf,
};

type EcdsaSignature = CombinedMultiSigOf<IDkgDealing>;

pub type EcdsaQuadruple = (
    RandomSkinnyTranscript,
    MultiplicationTranscript,
    RandomFatTranscript,
    MultiplicationTranscript,
);

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
    random_transcript_agreements: BTreeMap<IDkgTranscriptId, RandomTranscriptPair>,

    /// `MultiplicationTranscripts` that we agreed upon in this round.
    multiplication_transcript_agreements: BTreeMap<IDkgTranscriptId, MultiplicationTranscript>,

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

pub struct QuadrupleId;
pub type OngoingSigningRequests = BTreeMap<RequestId, QuadrupleId>;

/// The ECDSA message that goes into the artifact pool and gossiped with peers
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum EcdsaMessage {
    EcdsaDealing(EcdsaDealing),
    EcdsaComplaint(EcdsaComplaint),
    EcdsaOpening(EcdsaOpening),
    EcdsaSignature(EcdsaSignature),
}

/// This is a helper trait that indicates, that somethings has a transcript
/// type. This type can of course be queried.
pub trait HasTranscriptType {
    fn get_type(&self) -> &IDkgTranscriptType;
}

impl HasTranscriptType for IDkgTranscript {
    fn get_type(&self) -> &IDkgTranscriptType {
        todo!()
    }
}

impl HasTranscriptType for IDkgTranscriptParams {
    fn get_type(&self) -> &IDkgTranscriptType {
        todo!()
    }
}

pub struct RandomSkinny<T>(T);
pub type RandomSkinnyTranscript = RandomSkinny<IDkgTranscript>;
pub type RandomSkinnyTranscriptParams = RandomSkinny<IDkgTranscriptParams>;

impl<T> RandomSkinny<T>
where
    T: HasTranscriptType,
{
    pub fn try_convert(value: T) -> Option<Self> {
        match value.get_type() {
            IDkgTranscriptType::RandomSkinny => Some(RandomSkinny(value)),
            _ => None,
        }
    }

    pub fn into_base_type(self) -> T {
        self.0
    }
}

impl<T> Deref for RandomSkinny<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for RandomSkinny<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

pub struct RandomFat<T>(T);
pub type RandomFatTranscript = RandomFat<IDkgTranscript>;
pub type RandomFatTranscriptParams = RandomFat<IDkgTranscriptParams>;

impl<T> RandomFat<T>
where
    T: HasTranscriptType,
{
    pub fn try_convert(value: T) -> Option<Self> {
        match value.get_type() {
            IDkgTranscriptType::RandomFat => Some(RandomFat(value)),
            _ => None,
        }
    }

    pub fn into_base_type(self) -> T {
        self.0
    }
}

impl<T> Deref for RandomFat<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for RandomFat<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

pub struct Resharing<T>(T);
pub type ResharingTranscript = Resharing<IDkgTranscript>;
pub type ResharingTranscriptParams = Resharing<IDkgTranscriptParams>;

impl<T> Resharing<T>
where
    T: HasTranscriptType,
{
    pub fn try_convert(value: T) -> Option<Self> {
        match value.get_type() {
            IDkgTranscriptType::Resharing(_) => Some(Resharing(value)),
            _ => None,
        }
    }

    pub fn into_base_type(self) -> T {
        self.0
    }
}

impl<T> Deref for Resharing<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Resharing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
pub struct Multiplication<T>(T);
pub type MultiplicationTranscript = Multiplication<IDkgTranscript>;
pub type MultiplicationTranscriptParams = Multiplication<IDkgTranscriptParams>;

impl<T> Multiplication<T>
where
    T: HasTranscriptType,
{
    pub fn try_convert(value: T) -> Option<Self> {
        match value.get_type() {
            IDkgTranscriptType::Multiplication(_, _) => Some(Multiplication(value)),
            _ => None,
        }
    }

    pub fn into_base_type(self) -> T {
        self.0
    }
}

impl<T> Deref for Multiplication<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Multiplication<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

#[allow(missing_docs)]
/// Mock module of the crypto types that are needed by consensus for threshold
/// ECDSA generation. These types should be replaced by the real Types once they
/// are available.
mod ecdsa_crypto_mock {
    use serde::{Deserialize, Serialize};

    // TODO: Where to define this type?
    pub struct RequestId;

    // TODO: Find typedefs for these types.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
    pub struct EcdsaDealing;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
    pub struct EcdsaComplaint;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
    pub struct EcdsaOpening;
}
