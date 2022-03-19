//! Defines types used for threshold ECDSA key generation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use strum_macros::EnumIter;

pub use crate::consensus::ecdsa_refs::{
    EcdsaBlockReader, IDkgTranscriptOperationRef, IDkgTranscriptParamsRef, MaskedTranscript,
    PreSignatureQuadrupleRef, QuadrupleInCreation, RandomTranscriptParams, RequestId, RequestIdTag,
    ReshareOfMaskedParams, ReshareOfUnmaskedParams, ThresholdEcdsaSigInputsRef,
    TranscriptCastError, TranscriptLookupError, TranscriptRef, UnmaskedTimesMaskedParams,
    UnmaskedTranscript,
};
use crate::consensus::{BasicSignature, MultiSignature, MultiSignatureShare};
use crate::crypto::{
    canister_threshold_sig::idkg::{
        IDkgComplaint, IDkgDealing, IDkgOpening, IDkgTranscript, IDkgTranscriptId,
    },
    canister_threshold_sig::{ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigShare},
    CryptoHashOf, Signed, SignedBytesWithoutDomainSeparator,
};
use crate::{Height, NodeId, RegistryVersion};

/// For completed signature requests, we differentiate between those
/// that have already been reported and those that have not. This is
/// to prevent signatures from being reported more than once.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompletedSignature {
    ReportedToExecution,
    Unreported(ThresholdEcdsaCombinedSignature),
}

/// Common data that is carried in both `EcdsaSummaryPayload` and `EcdsaDataPayload`.
/// published on every consensus round. It represents the current state of the
/// protocol since the summary block.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EcdsaPayload {
    /// Collection of completed signatures.
    pub signature_agreements: BTreeMap<RequestId, CompletedSignature>,

    /// The `RequestIds` for which we are currently generating signatures.
    pub ongoing_signatures: BTreeMap<RequestId, ThresholdEcdsaSigInputsRef>,

    /// ECDSA transcript quadruples that we can use to create ECDSA signatures.
    pub available_quadruples: BTreeMap<QuadrupleId, PreSignatureQuadrupleRef>,

    /// Ecdsa Quadruple in creation.
    pub quadruples_in_creation: BTreeMap<QuadrupleId, QuadrupleInCreation>,

    /// Next TranscriptId that is incremented after creating a new transcript.
    pub next_unused_transcript_id: IDkgTranscriptId,

    /// Transcripts created at this height.
    pub idkg_transcripts: BTreeMap<IDkgTranscriptId, IDkgTranscript>,

    /// Resharing requests in progress.
    pub ongoing_xnet_reshares: BTreeMap<EcdsaReshareRequest, ReshareOfUnmaskedParams>,

    /// Completed resharing requests.
    pub xnet_reshare_agreements: BTreeMap<EcdsaReshareRequest, CompletedReshareRequest>,
}

/// The payload information necessary for ECDSA threshold signatures, that is
/// published on every consensus round. It represents the current state of
/// the protocol since the summary block.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EcdsaDataPayload {
    /// Ecdsa Payload data
    pub ecdsa_payload: EcdsaPayload,
    /// Progress of creating the next ECDSA key transcript.
    pub next_key_transcript_creation: KeyTranscriptCreation,
}

/// The creation of an ecdsa key transcript goes through one of the two paths below:
/// 1. RandomTranscript -> ReshareOfMasked -> Created
/// 2. ReshareOfUnmasked -> Created
///
/// The initial bootstrap will start with an empty 'EcdsaSummaryPayload', and then
/// we'll go through the first path to create the key transcript.
///
/// After the initial key transcript is created, we will be able to create the first
/// 'EcdsaSummaryPayload' by carrying over the key transcript, which will be carried
/// over to the next DKG interval if there is no node membership change.
///
/// If in the future there is a membership change, we will create a new key transcript
/// by going through the second path above. Then the switch-over will happen at
/// the next 'EcdsaSummaryPayload'.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyTranscriptCreation {
    Begin,
    // Configuration to create initial random transcript.
    RandomTranscriptParams(RandomTranscriptParams),
    // Configuration to create initial key transcript by resharing the random transcript.
    ReshareOfMaskedParams(ReshareOfMaskedParams),
    // Configuration to create next key transcript by resharing the current key transcript.
    ReshareOfUnmaskedParams(ReshareOfUnmaskedParams),
    // Created
    Created(UnmaskedTranscript),
}

impl KeyTranscriptCreation {
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        match self {
            Self::Begin => vec![],
            Self::RandomTranscriptParams(params) => params.as_ref().get_refs(),
            Self::ReshareOfMaskedParams(params) => params.as_ref().get_refs(),
            Self::ReshareOfUnmaskedParams(params) => params.as_ref().get_refs(),
            Self::Created(unmasked) => vec![*unmasked.as_ref()],
        }
    }
}

impl EcdsaPayload {
    /// Return an iterator of all transcript configs that have no matching
    /// results yet.
    pub fn iter_transcript_configs_in_creation(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        let iter = self
            .ongoing_xnet_reshares
            .values()
            .map(|reshare_param| reshare_param.as_ref());
        Box::new(
            self.quadruples_in_creation
                .iter()
                .map(|(_, quadruple)| quadruple.iter_transcript_configs_in_creation())
                .flatten()
                .chain(iter),
        )
    }
}

impl EcdsaDataPayload {
    /// Return an iterator of all transcript configs that have no matching
    /// results yet.
    pub fn iter_transcript_configs_in_creation(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        let iter = match &self.next_key_transcript_creation {
            KeyTranscriptCreation::RandomTranscriptParams(x) => Some(x.as_ref()),
            KeyTranscriptCreation::ReshareOfMaskedParams(x) => Some(x.as_ref()),
            KeyTranscriptCreation::ReshareOfUnmaskedParams(x) => Some(x.as_ref()),
            KeyTranscriptCreation::Begin => None,
            KeyTranscriptCreation::Created(_) => None,
        }
        .into_iter();
        Box::new(
            self.ecdsa_payload
                .iter_transcript_configs_in_creation()
                .chain(iter),
        )
    }

    /// Return active transcript references in the data payload.
    pub fn active_transcripts(&self) -> Vec<TranscriptRef> {
        let ecdsa_payload = &self.ecdsa_payload;
        let mut active_refs = Vec::new();
        for obj in ecdsa_payload.ongoing_signatures.values() {
            active_refs.append(&mut obj.get_refs());
        }
        for obj in ecdsa_payload.available_quadruples.values() {
            active_refs.append(&mut obj.get_refs());
        }
        for obj in ecdsa_payload.quadruples_in_creation.values() {
            active_refs.append(&mut obj.get_refs());
        }
        for obj in ecdsa_payload.ongoing_xnet_reshares.values() {
            active_refs.append(&mut obj.as_ref().get_refs());
        }
        for obj in ecdsa_payload.xnet_reshare_agreements.values() {
            if let CompletedReshareRequest::Unreported(response) = obj {
                active_refs.append(&mut response.reshare_param.as_ref().get_refs());
            }
        }
        active_refs.append(&mut self.next_key_transcript_creation.get_refs());

        active_refs
    }
}

/// The payload information necessary for ECDSA threshold signatures, that is
/// published on summary blocks.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EcdsaSummaryPayload {
    /// Ecdsa payload data.
    pub ecdsa_payload: EcdsaPayload,
    /// The ECDSA key transcript used for the corresponding interval.
    pub current_key_transcript: UnmaskedTranscript,
}

impl EcdsaSummaryPayload {
    /// Return the oldest registry version required to keep nodes in the subnet
    /// in order to finish signature signing. It is important for security purpose
    /// to require ongoing signature requests to finish before we can let nodes
    /// move off a subnet.
    ///
    /// Note that we do not consider available quadruples here because it would
    /// prevent nodes from leaving when the quadruples are not consumed.
    pub(crate) fn get_oldest_registry_version_in_use(&self) -> Option<RegistryVersion> {
        let idkg_transcripts = &self.ecdsa_payload.idkg_transcripts;
        let key_transcript_id = self.current_key_transcript.as_ref().transcript_id;
        let registry_version = idkg_transcripts
            .get(&key_transcript_id)
            .map(|transcript| transcript.registry_version);
        self.ecdsa_payload.ongoing_signatures.iter().fold(
            registry_version,
            |mut registry_version, (_, sig_input_ref)| {
                for r in sig_input_ref.get_refs() {
                    let transcript_version = idkg_transcripts
                        .get(&r.transcript_id)
                        .map(|transcript| transcript.registry_version);
                    if registry_version.is_none() {
                        registry_version = transcript_version;
                    } else {
                        registry_version = registry_version.min(transcript_version)
                    }
                }
                registry_version
            },
        )
    }
}

#[derive(
    Copy, Clone, Default, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize, Hash,
)]
pub struct QuadrupleId(pub usize);

impl QuadrupleId {
    pub fn increment(self) -> QuadrupleId {
        QuadrupleId(self.0 + 1)
    }
}

/// Internal format of the resharing request from execution.
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EcdsaReshareRequest {
    pub key_id: Vec<u8>,
    pub receiving_node_ids: Vec<NodeId>,
    pub registry_version: RegistryVersion,
}

/// Internal format of the completed response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EcdsaReshareResponse {
    /// The transcript param ref used to create the transcript/dealings.
    /// The references will be resolved to build the IDkgTranscriptParams
    /// before returning to execution.
    pub reshare_param: ReshareOfUnmaskedParams,

    /// The verified dealings in the created transcript.
    pub dealings: Vec<(NodeId, IDkgDealing)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompletedReshareRequest {
    ReportedToExecution,
    Unreported(Box<EcdsaReshareResponse>),
}

/// The ECDSA artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum EcdsaMessage {
    EcdsaSignedDealing(EcdsaSignedDealing),
    EcdsaDealingSupport(EcdsaDealingSupport),
    EcdsaSigShare(EcdsaSigShare),
    EcdsaComplaint(EcdsaComplaint),
    EcdsaOpening(EcdsaOpening),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum EcdsaMessageHash {
    EcdsaSignedDealing(CryptoHashOf<EcdsaSignedDealing>),
    EcdsaDealingSupport(CryptoHashOf<EcdsaDealingSupport>),
    EcdsaSigShare(CryptoHashOf<EcdsaSigShare>),
    EcdsaComplaint(CryptoHashOf<EcdsaComplaint>),
    EcdsaOpening(CryptoHashOf<EcdsaOpening>),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash, EnumIter)]
pub enum EcdsaMessageType {
    Dealing,
    DealingSupport,
    SigShare,
    Complaint,
    Opening,
}

impl From<&EcdsaMessage> for EcdsaMessageType {
    fn from(msg: &EcdsaMessage) -> EcdsaMessageType {
        match msg {
            EcdsaMessage::EcdsaSignedDealing(_) => EcdsaMessageType::Dealing,
            EcdsaMessage::EcdsaDealingSupport(_) => EcdsaMessageType::DealingSupport,
            EcdsaMessage::EcdsaSigShare(_) => EcdsaMessageType::SigShare,
            EcdsaMessage::EcdsaComplaint(_) => EcdsaMessageType::Complaint,
            EcdsaMessage::EcdsaOpening(_) => EcdsaMessageType::Opening,
        }
    }
}

impl From<&EcdsaMessageHash> for EcdsaMessageType {
    fn from(hash: &EcdsaMessageHash) -> EcdsaMessageType {
        match hash {
            EcdsaMessageHash::EcdsaSignedDealing(_) => EcdsaMessageType::Dealing,
            EcdsaMessageHash::EcdsaDealingSupport(_) => EcdsaMessageType::DealingSupport,
            EcdsaMessageHash::EcdsaSigShare(_) => EcdsaMessageType::SigShare,
            EcdsaMessageHash::EcdsaComplaint(_) => EcdsaMessageType::Complaint,
            EcdsaMessageHash::EcdsaOpening(_) => EcdsaMessageType::Opening,
        }
    }
}

/// The dealing content generated by a dealer
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EcdsaDealing {
    /// Height of the finalized block that requested the transcript
    pub requested_height: Height,

    /// The crypto dealing
    /// TODO: dealers should send the BasicSigned<> dealing
    pub idkg_dealing: IDkgDealing,
}

impl Display for EcdsaDealing {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Dealing[transcript_id = {:?}, requested_height = {:?}, dealer_id = {:?}]",
            self.idkg_dealing.transcript_id, self.requested_height, self.idkg_dealing.dealer_id,
        )
    }
}

impl SignedBytesWithoutDomainSeparator for EcdsaDealing {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// The signed dealing sent by dealers
/// TODO: rename without the `Signed` suffix (to EcdsaDealingContent, EcdsaDealing)
pub type EcdsaSignedDealing = Signed<EcdsaDealing, BasicSignature<EcdsaDealing>>;

impl EcdsaSignedDealing {
    pub fn get(&self) -> &EcdsaDealing {
        &self.content
    }
}

impl Display for EcdsaSignedDealing {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, basic_signer_id = {:?}",
            self.content, self.signature.signer,
        )
    }
}

impl SignedBytesWithoutDomainSeparator for EcdsaSignedDealing {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// TODO: EcdsaDealing can be big, consider sending only the signature
/// as part of the shares
/// The individual signature share in support of a dealing
pub type EcdsaDealingSupport = Signed<EcdsaDealing, MultiSignatureShare<EcdsaDealing>>;

/// The multi-signature verified dealing
pub type EcdsaVerifiedDealing = Signed<EcdsaDealing, MultiSignature<EcdsaDealing>>;

impl Display for EcdsaDealingSupport {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, multi_signer_id = {:?}",
            self.content, self.signature.signer,
        )
    }
}

/// The ECDSA signature share
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EcdsaSigShare {
    /// Height of the finalized block that requested the signature
    pub requested_height: Height,

    /// The node that signed the share
    pub signer_id: NodeId,

    /// The request this signature share belongs to
    pub request_id: RequestId,

    /// The signature share
    pub share: ThresholdEcdsaSigShare,
}

impl Display for EcdsaSigShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SigShare[request_id = {:?}, requested_height = {:?}, signer_id = {:?}]",
            self.request_id, self.requested_height, self.signer_id,
        )
    }
}

/// Complaint related defines
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EcdsaComplaintContent {
    /// Finalized height of the complainer
    pub complainer_height: Height,

    /// The complaint
    pub idkg_complaint: IDkgComplaint,
}
pub type EcdsaComplaint = Signed<EcdsaComplaintContent, BasicSignature<EcdsaComplaintContent>>;

impl EcdsaComplaint {
    pub fn get(&self) -> &EcdsaComplaintContent {
        &self.content
    }
}

impl Display for EcdsaComplaint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Complaint[transcript = {:?}, dealer = {:?}, complainer = {:?}]",
            self.content.idkg_complaint.transcript_id,
            self.content.idkg_complaint.dealer_id,
            self.signature.signer
        )
    }
}

impl SignedBytesWithoutDomainSeparator for EcdsaComplaintContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

impl SignedBytesWithoutDomainSeparator for EcdsaComplaint {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// Opening related defines
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EcdsaOpeningContent {
    /// Complainer Id. This is the signer Id in the complaint message
    pub complainer_id: NodeId,

    /// Finalized height of the complainer
    pub complainer_height: Height,

    /// The opening
    pub idkg_opening: IDkgOpening,
}
pub type EcdsaOpening = Signed<EcdsaOpeningContent, BasicSignature<EcdsaOpeningContent>>;

impl EcdsaOpening {
    pub fn get(&self) -> &EcdsaOpeningContent {
        &self.content
    }
}

impl Display for EcdsaOpening {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Opening[transcript = {:?}, dealer = {:?}, complainer = {:?}, opener = {:?}]",
            self.content.idkg_opening.transcript_id,
            self.content.idkg_opening.dealer_id,
            self.content.complainer_id,
            self.signature.signer
        )
    }
}

impl SignedBytesWithoutDomainSeparator for EcdsaOpeningContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

impl SignedBytesWithoutDomainSeparator for EcdsaOpening {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// The final output of the transcript creation sequence
pub type EcdsaTranscript = IDkgTranscript;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EcdsaMessageAttribute {
    EcdsaSignedDealing(Height),
    EcdsaDealingSupport(Height),
    EcdsaSigShare(Height),
    EcdsaComplaint(Height),
    EcdsaOpening(Height),
}

impl From<&EcdsaMessage> for EcdsaMessageAttribute {
    fn from(msg: &EcdsaMessage) -> EcdsaMessageAttribute {
        match msg {
            EcdsaMessage::EcdsaSignedDealing(dealing) => {
                EcdsaMessageAttribute::EcdsaSignedDealing(dealing.content.requested_height)
            }
            EcdsaMessage::EcdsaDealingSupport(support) => {
                EcdsaMessageAttribute::EcdsaDealingSupport(support.content.requested_height)
            }
            EcdsaMessage::EcdsaSigShare(share) => {
                EcdsaMessageAttribute::EcdsaSigShare(share.requested_height)
            }
            EcdsaMessage::EcdsaComplaint(complaint) => {
                EcdsaMessageAttribute::EcdsaComplaint(complaint.content.complainer_height)
            }
            EcdsaMessage::EcdsaOpening(opening) => {
                EcdsaMessageAttribute::EcdsaOpening(opening.content.complainer_height)
            }
        }
    }
}

impl TryFrom<EcdsaMessage> for EcdsaSignedDealing {
    type Error = EcdsaMessage;
    fn try_from(msg: EcdsaMessage) -> Result<Self, Self::Error> {
        match msg {
            EcdsaMessage::EcdsaSignedDealing(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<EcdsaMessage> for EcdsaDealingSupport {
    type Error = EcdsaMessage;
    fn try_from(msg: EcdsaMessage) -> Result<Self, Self::Error> {
        match msg {
            EcdsaMessage::EcdsaDealingSupport(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<EcdsaMessage> for EcdsaSigShare {
    type Error = EcdsaMessage;
    fn try_from(msg: EcdsaMessage) -> Result<Self, Self::Error> {
        match msg {
            EcdsaMessage::EcdsaSigShare(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<EcdsaMessage> for EcdsaComplaint {
    type Error = EcdsaMessage;
    fn try_from(msg: EcdsaMessage) -> Result<Self, Self::Error> {
        match msg {
            EcdsaMessage::EcdsaComplaint(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<EcdsaMessage> for EcdsaOpening {
    type Error = EcdsaMessage;
    fn try_from(msg: EcdsaMessage) -> Result<Self, Self::Error> {
        match msg {
            EcdsaMessage::EcdsaOpening(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

// The ECDSA summary.
pub type Summary = Option<EcdsaSummaryPayload>;

pub type Payload = Option<EcdsaDataPayload>;
