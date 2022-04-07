//! Defines types used for threshold ECDSA key generation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
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
    CryptoHash, CryptoHashOf, Signed, SignedBytesWithoutDomainSeparator,
};
use crate::{node_id_into_protobuf, node_id_try_from_protobuf};
use crate::{Height, NodeId, RegistryVersion};
use ic_protobuf::registry::subnet::v1 as subnet_pb;
use ic_protobuf::types::v1 as pb;

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

    fn update(&mut self, height: Height) {
        match self {
            Self::Begin => (),
            Self::RandomTranscriptParams(params) => params.as_mut().update(height),
            Self::ReshareOfMaskedParams(params) => params.as_mut().update(height),
            Self::ReshareOfUnmaskedParams(params) => params.as_mut().update(height),
            Self::Created(unmasked) => unmasked.as_mut().update(height),
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

    /// Return active transcript references in the  payload.
    pub fn active_transcripts(&self) -> Vec<TranscriptRef> {
        let mut active_refs = Vec::new();
        for obj in self.ongoing_signatures.values() {
            active_refs.append(&mut obj.get_refs());
        }
        for obj in self.available_quadruples.values() {
            active_refs.append(&mut obj.get_refs());
        }
        for obj in self.quadruples_in_creation.values() {
            active_refs.append(&mut obj.get_refs());
        }
        for obj in self.ongoing_xnet_reshares.values() {
            active_refs.append(&mut obj.as_ref().get_refs());
        }
        for obj in self.xnet_reshare_agreements.values() {
            if let CompletedReshareRequest::Unreported(response) = obj {
                active_refs.append(&mut response.reshare_param.as_ref().get_refs());
            }
        }

        active_refs
    }

    /// Updates the height of all the transcript refs to the given height.
    pub fn update_refs(&mut self, height: Height) {
        for obj in self.ongoing_signatures.values_mut() {
            obj.update(height);
        }
        for obj in self.available_quadruples.values_mut() {
            obj.update(height);
        }
        for obj in self.quadruples_in_creation.values_mut() {
            obj.update(height);
        }
        for obj in self.ongoing_xnet_reshares.values_mut() {
            obj.as_mut().update(height);
        }
        for obj in self.xnet_reshare_agreements.values_mut() {
            if let CompletedReshareRequest::Unreported(response) = obj {
                response.reshare_param.as_mut().update(height);
            }
        }
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
        let mut active_refs = self.ecdsa_payload.active_transcripts();
        active_refs.append(&mut self.next_key_transcript_creation.get_refs());

        active_refs
    }

    /// Updates the height of all the transcript refs to the given height.
    pub fn update_refs(&mut self, height: Height) {
        self.ecdsa_payload.update_refs(height);
        self.next_key_transcript_creation.update(height);
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

    /// Return active transcript references in the summary payload.
    pub fn active_transcripts(&self) -> Vec<TranscriptRef> {
        let mut active_refs = self.ecdsa_payload.active_transcripts();
        active_refs.push(*self.current_key_transcript.as_ref());

        active_refs
    }

    /// Updates the height of all the transcript refs to the given height.
    pub fn update_refs(&mut self, height: Height) {
        self.ecdsa_payload.update_refs(height);
        self.current_key_transcript.as_mut().update(height);
    }
}

#[derive(
    Copy, Clone, Default, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize, Hash,
)]
pub struct QuadrupleId(pub u64);

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

impl From<&EcdsaReshareRequest> for pb::EcdsaReshareRequest {
    fn from(request: &EcdsaReshareRequest) -> Self {
        let mut receiving_node_ids = Vec::new();
        for node in &request.receiving_node_ids {
            receiving_node_ids.push(node_id_into_protobuf(*node));
        }
        Self {
            key_id: request.key_id.clone(),
            receiving_node_ids,
            registry_version: request.registry_version.get(),
        }
    }
}

impl TryFrom<&pb::EcdsaReshareRequest> for EcdsaReshareRequest {
    type Error = String;
    fn try_from(request: &pb::EcdsaReshareRequest) -> Result<Self, Self::Error> {
        let mut receiving_node_ids = Vec::new();
        for node in &request.receiving_node_ids {
            let node_id = node_id_try_from_protobuf(node.clone()).map_err(|err| {
                format!(
                    "pb::EcdsaReshareRequest:: Failed to convert node_id: {:?}",
                    err
                )
            })?;
            receiving_node_ids.push(node_id);
        }

        Ok(Self {
            key_id: request.key_id.clone(),
            receiving_node_ids,
            registry_version: RegistryVersion::new(request.registry_version),
        })
    }
}

/// Internal format of the completed response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EcdsaReshareResponse {
    /// The transcript param ref used to create the transcript/dealings.
    /// The references will be resolved to build the IDkgTranscriptParams
    /// before returning to execution.
    pub reshare_param: ReshareOfUnmaskedParams,

    /// The verified dealings in the created transcript.
    pub dealings: Vec<IDkgDealing>,
}

impl From<&EcdsaReshareResponse> for pb::EcdsaReshareResponse {
    fn from(response: &EcdsaReshareResponse) -> Self {
        let mut tuples = Vec::new();
        for dealing in &response.dealings {
            tuples.push(dealing.into());
        }

        Self {
            transcript: Some((&response.reshare_param).into()),
            tuples,
        }
    }
}

impl TryFrom<&pb::EcdsaReshareResponse> for EcdsaReshareResponse {
    type Error = String;
    fn try_from(response: &pb::EcdsaReshareResponse) -> Result<Self, Self::Error> {
        let proto = response
            .transcript
            .as_ref()
            .ok_or("pb::EcdsaReshareResponse:: Missing reshare transcript")?;
        let reshare_param: ReshareOfUnmaskedParams = proto.try_into()?;

        let mut dealings = Vec::new();
        for tuple in &response.tuples {
            let dealing = tuple.try_into().map_err(|err| {
                format!(
                    "pb::EcdsaReshareResponse:: Failed to convert tuple: {:?}",
                    err
                )
            })?;
            dealings.push(dealing);
        }

        Ok(Self {
            reshare_param,
            dealings,
        })
    }
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

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash, EnumIter,
)]
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

impl From<(EcdsaMessageType, Vec<u8>)> for EcdsaMessageHash {
    fn from((message_type, bytes): (EcdsaMessageType, Vec<u8>)) -> EcdsaMessageHash {
        let crypto_hash = CryptoHash(bytes);
        match message_type {
            EcdsaMessageType::Dealing => {
                EcdsaMessageHash::EcdsaSignedDealing(CryptoHashOf::from(crypto_hash))
            }
            EcdsaMessageType::DealingSupport => {
                EcdsaMessageHash::EcdsaDealingSupport(CryptoHashOf::from(crypto_hash))
            }
            EcdsaMessageType::SigShare => {
                EcdsaMessageHash::EcdsaSigShare(CryptoHashOf::from(crypto_hash))
            }
            EcdsaMessageType::Complaint => {
                EcdsaMessageHash::EcdsaComplaint(CryptoHashOf::from(crypto_hash))
            }
            EcdsaMessageType::Opening => {
                EcdsaMessageHash::EcdsaOpening(CryptoHashOf::from(crypto_hash))
            }
        }
    }
}

/// The dealing content generated by a dealer
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EcdsaDealing {
    /// Height of the finalized block that requested the transcript
    pub requested_height: Height,

    /// The crypto dealing
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

impl From<&EcdsaSummaryPayload> for pb::EcdsaSummaryPayload {
    fn from(summary: &EcdsaSummaryPayload) -> Self {
        // signature_agreements
        let mut signature_agreements = Vec::new();
        for (request_id, completed) in &summary.ecdsa_payload.signature_agreements {
            let unreported = match completed {
                CompletedSignature::Unreported(signature) => signature.signature.clone(),
                CompletedSignature::ReportedToExecution => vec![],
            };
            signature_agreements.push(pb::CompletedSignature {
                request_id: Some(pb::RequestId {
                    request_id: request_id.as_ref().clone(),
                }),
                unreported,
            });
        }

        // ongoing_signatures
        let mut ongoing_signatures = Vec::new();
        for (request_id, ongoing) in &summary.ecdsa_payload.ongoing_signatures {
            ongoing_signatures.push(pb::OngoingSignature {
                request_id: Some(pb::RequestId {
                    request_id: request_id.as_ref().clone(),
                }),
                sig_inputs: Some(ongoing.into()),
            })
        }

        // available_quadruples
        let mut available_quadruples = Vec::new();
        for (quadruple_id, quadruple) in &summary.ecdsa_payload.available_quadruples {
            available_quadruples.push(pb::AvailableQuadruple {
                quadrupled_id: quadruple_id.0,
                quadruple: Some(quadruple.into()),
            });
        }

        // quadruples_in_creation
        let mut quadruples_in_creation = Vec::new();
        for (quadruple_id, quadruple) in &summary.ecdsa_payload.quadruples_in_creation {
            quadruples_in_creation.push(pb::QuadrupleInProgress {
                quadrupled_id: quadruple_id.0,
                quadruple: Some(quadruple.into()),
            });
        }

        let next_unused_transcript_id: Option<subnet_pb::IDkgTranscriptId> =
            Some((&summary.ecdsa_payload.next_unused_transcript_id).into());

        // idkg_transcripts
        let mut idkg_transcripts = Vec::new();
        for transcript in summary.ecdsa_payload.idkg_transcripts.values() {
            idkg_transcripts.push(transcript.into());
        }

        // ongoing_xnet_reshares
        let mut ongoing_xnet_reshares = Vec::new();
        for (request, transcript) in &summary.ecdsa_payload.ongoing_xnet_reshares {
            ongoing_xnet_reshares.push(pb::OngoingXnetReshare {
                request: Some(request.into()),
                transcript: Some(transcript.into()),
            });
        }

        // xnet_reshare_agreements
        let mut xnet_reshare_agreements = Vec::new();
        for (request, completed) in &summary.ecdsa_payload.xnet_reshare_agreements {
            let response = match completed {
                CompletedReshareRequest::Unreported(response) => Some(response.as_ref().into()),
                CompletedReshareRequest::ReportedToExecution => None,
            };

            xnet_reshare_agreements.push(pb::XnetReshareAgreement {
                request: Some(request.into()),
                response,
            });
        }

        let current_key_transcript = Some((&summary.current_key_transcript).into());

        Self {
            signature_agreements,
            ongoing_signatures,
            available_quadruples,
            quadruples_in_creation,
            next_unused_transcript_id,
            idkg_transcripts,
            ongoing_xnet_reshares,
            xnet_reshare_agreements,
            current_key_transcript,
        }
    }
}

impl TryFrom<(&pb::EcdsaSummaryPayload, Height)> for EcdsaSummaryPayload {
    type Error = String;
    fn try_from(
        (summary, height): (&pb::EcdsaSummaryPayload, Height),
    ) -> Result<Self, Self::Error> {
        // signature_agreements
        let mut signature_agreements = BTreeMap::new();
        for completed_signature in &summary.signature_agreements {
            let request_id = completed_signature
                .request_id
                .as_ref()
                .ok_or("pb::EcdsaSummaryPayload:: Missing completed_signature request Id")
                .map(|id| RequestId::new(id.request_id.clone()))?;

            let signature = if !completed_signature.unreported.is_empty() {
                CompletedSignature::Unreported(ThresholdEcdsaCombinedSignature {
                    signature: completed_signature.unreported.clone(),
                })
            } else {
                CompletedSignature::ReportedToExecution
            };
            signature_agreements.insert(request_id, signature);
        }

        // ongoing_signatures
        let mut ongoing_signatures = BTreeMap::new();
        for ongoing_signature in &summary.ongoing_signatures {
            let request_id = ongoing_signature
                .request_id
                .as_ref()
                .ok_or("pb::EcdsaSummaryPayload:: Missing ongoing_signature request Id")
                .map(|id| RequestId::new(id.request_id.clone()))?;
            let proto = ongoing_signature
                .sig_inputs
                .as_ref()
                .ok_or("pb::EcdsaSummaryPayload:: Missing sig inputs")?;
            let sig_inputs: ThresholdEcdsaSigInputsRef = proto.try_into()?;
            ongoing_signatures.insert(request_id, sig_inputs);
        }

        // available_quadruples
        let mut available_quadruples = BTreeMap::new();
        for available_quadruple in &summary.available_quadruples {
            let quadruple_id = QuadrupleId(available_quadruple.quadrupled_id);
            let proto = available_quadruple
                .quadruple
                .as_ref()
                .ok_or("pb::EcdsaSummaryPayload:: Missing available_quadruple")?;
            let quadruple: PreSignatureQuadrupleRef = proto.try_into()?;
            available_quadruples.insert(quadruple_id, quadruple);
        }

        // quadruples_in_creation
        let mut quadruples_in_creation = BTreeMap::new();
        for quadruple_in_creation in &summary.quadruples_in_creation {
            let quadruple_id = QuadrupleId(quadruple_in_creation.quadrupled_id);
            let proto = quadruple_in_creation
                .quadruple
                .as_ref()
                .ok_or("pb::EcdsaSummaryPayload:: Missing quadruple_in_creation Id")?;
            let quadruple: QuadrupleInCreation = proto.try_into()?;
            quadruples_in_creation.insert(quadruple_id, quadruple);
        }

        let next_unused_transcript_id: IDkgTranscriptId = (&summary.next_unused_transcript_id)
            .try_into()
            .map_err(|err| {
                format!(
                    "pb::EcdsaSummaryPayload:: Failed to convert next_unused_transcript_id: {:?}",
                    err
                )
            })?;

        // idkg_transcripts
        let mut idkg_transcripts = BTreeMap::new();
        for proto in &summary.idkg_transcripts {
            let transcript: IDkgTranscript = proto.try_into().map_err(|err| {
                format!(
                    "pb::EcdsaSummaryPayload:: Failed to convert transcript: {:?}",
                    err
                )
            })?;
            let transcript_id = transcript.transcript_id;
            idkg_transcripts.insert(transcript_id, transcript);
        }

        // ongoing_xnet_reshares
        let mut ongoing_xnet_reshares = BTreeMap::new();
        for reshare in &summary.ongoing_xnet_reshares {
            let proto = reshare
                .request
                .as_ref()
                .ok_or("pb::EcdsaSummaryPayload:: Missing reshare request")?;
            let request: EcdsaReshareRequest = proto.try_into()?;

            let proto = reshare
                .transcript
                .as_ref()
                .ok_or("pb::EcdsaSummaryPayload:: Missing reshare transcript")?;
            let transcript: ReshareOfUnmaskedParams = proto.try_into()?;
            ongoing_xnet_reshares.insert(request, transcript);
        }

        // xnet_reshare_agreements
        let mut xnet_reshare_agreements = BTreeMap::new();
        for agreement in &summary.xnet_reshare_agreements {
            let proto = agreement
                .request
                .as_ref()
                .ok_or("pb::EcdsaSummaryPayload:: Missing agreement reshare request")?;
            let request: EcdsaReshareRequest = proto.try_into()?;

            let completed = match &agreement.response {
                Some(rsp) => {
                    let unreported = rsp.try_into()?;
                    CompletedReshareRequest::Unreported(Box::new(unreported))
                }
                None => CompletedReshareRequest::ReportedToExecution,
            };
            xnet_reshare_agreements.insert(request, completed);
        }

        let proto = summary
            .current_key_transcript
            .as_ref()
            .ok_or("pb::EcdsaSummaryPayload:: Missing current_key_transcript")?;
        let current_key_transcript: UnmaskedTranscript = proto.try_into()?;

        let mut ret = Self {
            ecdsa_payload: EcdsaPayload {
                signature_agreements,
                ongoing_signatures,
                available_quadruples,
                quadruples_in_creation,
                next_unused_transcript_id,
                idkg_transcripts,
                ongoing_xnet_reshares,
                xnet_reshare_agreements,
            },
            current_key_transcript,
        };
        ret.update_refs(height);
        Ok(ret)
    }
}
