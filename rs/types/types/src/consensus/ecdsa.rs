//! Defines types used for threshold ECDSA key generation.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Display, Formatter};
use strum_macros::EnumIter;

pub use crate::consensus::ecdsa_refs::{
    unpack_reshare_of_unmasked_params, EcdsaBlockReader, IDkgTranscriptOperationRef,
    IDkgTranscriptParamsRef, MaskedTranscript, PreSignatureQuadrupleRef, QuadrupleId,
    QuadrupleInCreation, RandomTranscriptParams, RequestId, ReshareOfMaskedParams,
    ReshareOfUnmaskedParams, ThresholdEcdsaSigInputsError, ThresholdEcdsaSigInputsRef,
    TranscriptCastError, TranscriptLookupError, TranscriptParamsError, TranscriptRef,
    UnmaskedTimesMaskedParams, UnmaskedTranscript,
};
use crate::consensus::{BasicSignature, MultiSignature, MultiSignatureShare};
use crate::crypto::canister_threshold_sig::error::IDkgTranscriptIdError;
use crate::crypto::{
    canister_threshold_sig::idkg::{
        IDkgComplaint, IDkgDealing, IDkgOpening, IDkgTranscript, IDkgTranscriptId,
        InitialIDkgDealings,
    },
    canister_threshold_sig::{ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigShare},
    CryptoHash, CryptoHashOf, Signed, SignedBytesWithoutDomainSeparator,
};
use crate::{node_id_into_protobuf, node_id_try_from_protobuf};
use crate::{Height, NodeId, RegistryVersion, SubnetId};
use ic_ic00_types::EcdsaKeyId;
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

    /// Generator of unique ids.
    pub uid_generator: EcdsaUIDGenerator,

    /// Transcripts created at this height.
    pub idkg_transcripts: BTreeMap<IDkgTranscriptId, IDkgTranscript>,

    /// Resharing requests in progress.
    pub ongoing_xnet_reshares: BTreeMap<EcdsaReshareRequest, ReshareOfUnmaskedParams>,

    /// Completed resharing requests.
    pub xnet_reshare_agreements: BTreeMap<EcdsaReshareRequest, CompletedReshareRequest>,

    /// State of the key transcripts.
    pub key_transcript: EcdsaKeyTranscript,
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
        let iter = self
            .key_transcript
            .transcript_config_in_creation()
            .into_iter()
            .chain(iter);
        Box::new(
            self.quadruples_in_creation
                .iter()
                .flat_map(|(_, quadruple)| quadruple.iter_transcript_configs_in_creation())
                .chain(iter),
        )
    }

    /// Return an iterator of the ongoing xnet reshare transcripts.
    pub fn iter_xnet_reshare_transcript_configs(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        Box::new(
            self.ongoing_xnet_reshares
                .values()
                .map(|reshare_param| reshare_param.as_ref()),
        )
    }

    /// Return an iterator of all request ids that is used in the payload.
    /// Note that it doesn't guarantee any ordering.
    pub fn iter_request_ids(&self) -> Box<dyn Iterator<Item = &RequestId> + '_> {
        Box::new(
            self.signature_agreements
                .keys()
                .chain(self.ongoing_signatures.keys()),
        )
    }

    /// Return an iterator of all ids of quadruples in the payload.
    pub fn iter_quadruple_ids(&self) -> Box<dyn Iterator<Item = QuadrupleId> + '_> {
        Box::new(
            self.available_quadruples
                .keys()
                .chain(self.quadruples_in_creation.keys())
                .cloned(),
        )
    }
    /// Return an iterator of all unassigned quadruple ids that is used in the payload.
    /// A quadruple id is assigned if it already paired with a signature request (i.e.
    /// there exists a request id that contains this quadruple id).
    pub fn unassigned_quadruple_ids(&self) -> Box<dyn Iterator<Item = QuadrupleId> + '_> {
        let assigned = self
            .iter_request_ids()
            .map(|id| id.quadruple_id)
            .collect::<BTreeSet<_>>();
        Box::new(
            self.iter_quadruple_ids()
                .filter(move |id| !assigned.contains(id)),
        )
    }

    /// Return active transcript references in the  payload.
    pub fn active_transcripts(&self) -> BTreeSet<TranscriptRef> {
        let mut active_refs = BTreeSet::new();
        let mut insert = |refs: Vec<TranscriptRef>| {
            refs.into_iter().for_each(|r| {
                active_refs.insert(r);
            })
        };
        for obj in self.ongoing_signatures.values() {
            insert(obj.get_refs())
        }
        for obj in self.available_quadruples.values() {
            insert(obj.get_refs())
        }
        for obj in self.quadruples_in_creation.values() {
            insert(obj.get_refs())
        }
        for obj in self.ongoing_xnet_reshares.values() {
            insert(obj.as_ref().get_refs())
        }
        insert(self.key_transcript.get_refs());
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
        self.key_transcript.update_refs(height)
    }

    /// Return the oldest registry version required to keep nodes in the subnet
    /// in order to finish signature signing. It is important for security purpose
    /// to require ongoing signature requests to finish before we can let nodes
    /// move off a subnet.
    ///
    /// Note that we do not consider available quadruples here because it would
    /// prevent nodes from leaving when the quadruples are not consumed.
    pub(crate) fn get_oldest_registry_version_in_use(&self) -> Option<RegistryVersion> {
        // TODO: need to consider next_in_creation?
        let idkg_transcripts = &self.idkg_transcripts;
        let registry_version = match self.key_transcript.current {
            Some(unmasked) => {
                let key_transcript_id = unmasked.as_ref().transcript_id;
                idkg_transcripts
                    .get(&key_transcript_id)
                    .map(|transcript| transcript.registry_version)
            }
            _ => None,
        };
        self.ongoing_signatures.iter().fold(
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

    /// Returns the initial DKG dealings being used to bootstrap the target subnet,
    /// if we are in the process of initial key creation.
    pub fn initial_dkg_dealings(&self) -> Option<InitialIDkgDealings> {
        match &self.key_transcript.next_in_creation {
            KeyTranscriptCreation::XnetReshareOfUnmaskedParams((initial_dealings, _)) => {
                Some(initial_dealings.as_ref().clone())
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EcdsaKeyTranscript {
    /// The ECDSA key transcript used for the current interval.
    pub current: Option<UnmaskedTranscript>,
    /// Progress of creating the next ECDSA key transcript.
    pub next_in_creation: KeyTranscriptCreation,
}

impl EcdsaKeyTranscript {
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        let mut active_refs = match &self.next_in_creation {
            KeyTranscriptCreation::Begin => vec![],
            KeyTranscriptCreation::RandomTranscriptParams(params) => params.as_ref().get_refs(),
            KeyTranscriptCreation::ReshareOfMaskedParams(params) => params.as_ref().get_refs(),
            KeyTranscriptCreation::ReshareOfUnmaskedParams(params) => params.as_ref().get_refs(),
            KeyTranscriptCreation::XnetReshareOfUnmaskedParams((_, params)) => {
                params.as_ref().get_refs()
            }
            KeyTranscriptCreation::Created(unmasked) => vec![*unmasked.as_ref()],
        };
        if let Some(unmasked) = &self.current {
            active_refs.push(*unmasked.as_ref());
        }
        active_refs
    }

    fn update_refs(&mut self, height: Height) {
        match &mut self.next_in_creation {
            KeyTranscriptCreation::Begin => (),
            KeyTranscriptCreation::RandomTranscriptParams(params) => params.as_mut().update(height),
            KeyTranscriptCreation::ReshareOfMaskedParams(params) => params.as_mut().update(height),
            KeyTranscriptCreation::ReshareOfUnmaskedParams(params) => {
                params.as_mut().update(height)
            }
            KeyTranscriptCreation::XnetReshareOfUnmaskedParams((_, params)) => {
                params.as_mut().update(height)
            }
            KeyTranscriptCreation::Created(unmasked) => unmasked.as_mut().update(height),
        }
        if let Some(unmasked) = &mut self.current {
            unmasked.as_mut().update(height);
        }
    }

    pub fn transcript_config_in_creation(&self) -> Option<&IDkgTranscriptParamsRef> {
        match &self.next_in_creation {
            KeyTranscriptCreation::Begin => None,
            KeyTranscriptCreation::RandomTranscriptParams(x) => Some(x.as_ref()),
            KeyTranscriptCreation::ReshareOfMaskedParams(x) => Some(x.as_ref()),
            KeyTranscriptCreation::ReshareOfUnmaskedParams(x) => Some(x.as_ref()),
            KeyTranscriptCreation::XnetReshareOfUnmaskedParams((_, x)) => Some(x.as_ref()),
            KeyTranscriptCreation::Created(_) => None,
        }
    }
}

/// The creation of an ecdsa key transcript goes through one of the three paths below:
/// 1. RandomTranscript -> ReshareOfMasked -> Created
/// 2. ReshareOfUnmasked -> Created
/// 3. XnetReshareOfUnmaskedParams -> Created (xnet bootstrapping from initial dealings)
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
    // Bootstrapping from xnet initial dealings.
    XnetReshareOfUnmaskedParams((Box<InitialIDkgDealings>, ReshareOfUnmaskedParams)),
    // Created
    Created(UnmaskedTranscript),
}

impl From<&KeyTranscriptCreation> for pb::KeyTranscriptCreation {
    fn from(key_transcript_in_creation: &KeyTranscriptCreation) -> Self {
        let mut ret = pb::KeyTranscriptCreation {
            state: pb::KeyTranscriptCreationState::BeginUnspecified as i32,
            random: None,
            reshare_of_masked: None,
            reshare_of_unmasked: None,
            xnet_reshare_of_unmasked: None,
            xnet_reshare_initial_dealings: None,
            created: None,
        };
        match key_transcript_in_creation {
            KeyTranscriptCreation::Begin => {
                ret.state = pb::KeyTranscriptCreationState::BeginUnspecified as i32;
            }
            KeyTranscriptCreation::RandomTranscriptParams(params) => {
                ret.state = pb::KeyTranscriptCreationState::RandomTranscriptParams as i32;
                ret.random = Some(params.into());
            }
            KeyTranscriptCreation::ReshareOfMaskedParams(params) => {
                ret.state = pb::KeyTranscriptCreationState::ReshareOfMaskedParams as i32;
                ret.reshare_of_masked = Some(params.into());
            }
            KeyTranscriptCreation::ReshareOfUnmaskedParams(params) => {
                ret.state = pb::KeyTranscriptCreationState::ReshareOfUnmaskedParams as i32;
                ret.reshare_of_unmasked = Some(params.into());
            }
            KeyTranscriptCreation::XnetReshareOfUnmaskedParams((initial_dealings, params)) => {
                ret.state = pb::KeyTranscriptCreationState::XnetReshareOfUnmaskedParams as i32;
                ret.xnet_reshare_initial_dealings = Some(initial_dealings.as_ref().into());
                ret.xnet_reshare_of_unmasked = Some(params.into());
            }
            KeyTranscriptCreation::Created(params) => {
                ret.state = pb::KeyTranscriptCreationState::Created as i32;
                ret.created = Some(params.into());
            }
        }
        ret
    }
}

impl TryFrom<&pb::KeyTranscriptCreation> for KeyTranscriptCreation {
    type Error = String;
    fn try_from(proto: &pb::KeyTranscriptCreation) -> Result<Self, Self::Error> {
        if proto.state == (pb::KeyTranscriptCreationState::BeginUnspecified as i32) {
            Ok(KeyTranscriptCreation::Begin)
        } else if proto.state == (pb::KeyTranscriptCreationState::RandomTranscriptParams as i32) {
            let param_proto = proto
                .random
                .as_ref()
                .ok_or("pb::KeyTranscriptCreation:: Missing random transcript")?;
            Ok(KeyTranscriptCreation::RandomTranscriptParams(
                param_proto.try_into()?,
            ))
        } else if proto.state == (pb::KeyTranscriptCreationState::ReshareOfMaskedParams as i32) {
            let param_proto = proto
                .reshare_of_masked
                .as_ref()
                .ok_or("pb::KeyTranscriptCreation:: Missing reshare of masked transcript")?;
            Ok(KeyTranscriptCreation::ReshareOfMaskedParams(
                param_proto.try_into()?,
            ))
        } else if proto.state == (pb::KeyTranscriptCreationState::ReshareOfUnmaskedParams as i32) {
            let param_proto = proto
                .reshare_of_unmasked
                .as_ref()
                .ok_or("pb::KeyTranscriptCreation:: Missing reshare of unmasked transcript")?;
            Ok(KeyTranscriptCreation::ReshareOfUnmaskedParams(
                param_proto.try_into()?,
            ))
        } else if proto.state
            == (pb::KeyTranscriptCreationState::XnetReshareOfUnmaskedParams as i32)
        {
            let initial_dealings_proto = proto
                .xnet_reshare_initial_dealings
                .as_ref()
                .ok_or("pb::KeyTranscriptCreation:: Missing xnet initial dealings")?;
            let initial_dealings: InitialIDkgDealings =
                initial_dealings_proto.try_into().map_err(|err| {
                    format!(
                        "pb::KeyTranscriptCreation:: failed to convert initial dealings: {:?}",
                        err
                    )
                })?;
            let param_proto = proto
                .xnet_reshare_of_unmasked
                .as_ref()
                .ok_or("pb::KeyTranscriptCreation:: Missing xnet reshare transcript")?;
            Ok(KeyTranscriptCreation::XnetReshareOfUnmaskedParams((
                Box::new(initial_dealings),
                param_proto.try_into()?,
            )))
        } else if proto.state == (pb::KeyTranscriptCreationState::Created as i32) {
            let param_proto = proto
                .created
                .as_ref()
                .ok_or("pb::KeyTranscriptCreation:: Missing created transcript")?;
            Ok(KeyTranscriptCreation::Created(param_proto.try_into()?))
        } else {
            Err(format!(
                "pb::KeyTranscriptCreation:: invalid state: {}",
                pb::KeyTranscriptCreationState::Created as i32
            ))
        }
    }
}

/// Internal format of the resharing request from execution.
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EcdsaReshareRequest {
    pub key_id: EcdsaKeyId,
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
            key_id: Some((&request.key_id).into()),
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
        let key_id = EcdsaKeyId::try_from(request.key_id.clone().expect("Missing key_id"))
            .map_err(|err| {
                format!(
                    "pb::EcdsaReshareRequest:: Failed to convert key_id: {:?}",
                    err
                )
            })?;
        Ok(Self {
            key_id,
            receiving_node_ids,
            registry_version: RegistryVersion::new(request.registry_version),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompletedReshareRequest {
    ReportedToExecution,
    Unreported(Box<InitialIDkgDealings>),
}

/// To make sure all ids used in ECDSA payload are uniquely generated,
/// we use a generator to keep track of this state.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EcdsaUIDGenerator {
    next_unused_transcript_id: IDkgTranscriptId,
    next_unused_quadruple_id: QuadrupleId,
}

impl EcdsaUIDGenerator {
    pub fn new(subnet_id: SubnetId, height: Height) -> Self {
        Self {
            next_unused_transcript_id: IDkgTranscriptId::new(subnet_id, 0, height),
            next_unused_quadruple_id: QuadrupleId(0),
        }
    }
    pub fn update_height(&mut self, height: Height) -> Result<(), IDkgTranscriptIdError> {
        let updated_id = self.next_unused_transcript_id.update_height(height)?;
        self.next_unused_transcript_id = updated_id;
        Ok(())
    }

    pub fn next_transcript_id(&mut self) -> IDkgTranscriptId {
        let id = self.next_unused_transcript_id;
        self.next_unused_transcript_id = id.increment();
        id
    }

    pub fn next_quadruple_id(&mut self) -> QuadrupleId {
        let id = self.next_unused_quadruple_id;
        self.next_unused_quadruple_id = QuadrupleId(id.0 + 1);
        id
    }
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

pub type Summary = Option<EcdsaPayload>;

pub type Payload = Option<EcdsaPayload>;

impl From<&EcdsaPayload> for pb::EcdsaSummaryPayload {
    fn from(summary: &EcdsaPayload) -> Self {
        // signature_agreements
        let mut signature_agreements = Vec::new();
        for (request_id, completed) in &summary.signature_agreements {
            let unreported = match completed {
                CompletedSignature::Unreported(signature) => signature.signature.clone(),
                CompletedSignature::ReportedToExecution => vec![],
            };
            signature_agreements.push(pb::CompletedSignature {
                request_id: Some((*request_id).into()),
                unreported,
            });
        }

        // ongoing_signatures
        let mut ongoing_signatures = Vec::new();
        for (request_id, ongoing) in &summary.ongoing_signatures {
            ongoing_signatures.push(pb::OngoingSignature {
                request_id: Some((*request_id).into()),
                sig_inputs: Some(ongoing.into()),
            })
        }

        // available_quadruples
        let mut available_quadruples = Vec::new();
        for (quadruple_id, quadruple) in &summary.available_quadruples {
            available_quadruples.push(pb::AvailableQuadruple {
                quadruple_id: quadruple_id.0,
                quadruple: Some(quadruple.into()),
            });
        }

        // quadruples_in_creation
        let mut quadruples_in_creation = Vec::new();
        for (quadruple_id, quadruple) in &summary.quadruples_in_creation {
            quadruples_in_creation.push(pb::QuadrupleInProgress {
                quadruple_id: quadruple_id.0,
                quadruple: Some(quadruple.into()),
            });
        }

        let next_unused_transcript_id: Option<subnet_pb::IDkgTranscriptId> =
            Some((&summary.uid_generator.next_unused_transcript_id).into());

        let next_unused_quadruple_id = summary.uid_generator.next_unused_quadruple_id.0;

        // idkg_transcripts
        let mut idkg_transcripts = Vec::new();
        for transcript in summary.idkg_transcripts.values() {
            idkg_transcripts.push(transcript.into());
        }

        // ongoing_xnet_reshares
        let mut ongoing_xnet_reshares = Vec::new();
        for (request, transcript) in &summary.ongoing_xnet_reshares {
            ongoing_xnet_reshares.push(pb::OngoingXnetReshare {
                request: Some(request.into()),
                transcript: Some(transcript.into()),
            });
        }

        // xnet_reshare_agreements
        let mut xnet_reshare_agreements = Vec::new();
        for (request, completed) in &summary.xnet_reshare_agreements {
            let initial_dealings = match completed {
                CompletedReshareRequest::Unreported(initial_dealings) => {
                    Some(initial_dealings.as_ref().into())
                }
                CompletedReshareRequest::ReportedToExecution => None,
            };

            xnet_reshare_agreements.push(pb::XnetReshareAgreement {
                request: Some(request.into()),
                initial_dealings,
            });
        }

        let current_key_transcript = summary
            .key_transcript
            .current
            .as_ref()
            .map(|transcript| transcript.into());
        let next_key_in_creation = Some((&summary.key_transcript.next_in_creation).into());

        Self {
            signature_agreements,
            ongoing_signatures,
            available_quadruples,
            quadruples_in_creation,
            next_unused_transcript_id,
            next_unused_quadruple_id,
            idkg_transcripts,
            ongoing_xnet_reshares,
            xnet_reshare_agreements,
            current_key_transcript,
            next_key_in_creation,
        }
    }
}

impl TryFrom<(&pb::EcdsaSummaryPayload, Height)> for EcdsaPayload {
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
                .and_then(RequestId::try_from)?;
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
                .and_then(RequestId::try_from)?;
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
            let quadruple_id = QuadrupleId(available_quadruple.quadruple_id);
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
            let quadruple_id = QuadrupleId(quadruple_in_creation.quadruple_id);
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

        let next_unused_quadruple_id: QuadrupleId = QuadrupleId(summary.next_unused_quadruple_id);

        let uid_generator = EcdsaUIDGenerator {
            next_unused_transcript_id,
            next_unused_quadruple_id,
        };

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

            let completed = match &agreement.initial_dealings {
                Some(initial_dealings_proto) => {
                    let unreported = initial_dealings_proto.try_into().map_err(|err| {
                        format!(
                            "pb::EcdsaSummaryPayload:: failed to convert initial dealing: {:?}",
                            err
                        )
                    })?;
                    CompletedReshareRequest::Unreported(Box::new(unreported))
                }
                None => CompletedReshareRequest::ReportedToExecution,
            };
            xnet_reshare_agreements.insert(request, completed);
        }

        // Key transcript state
        let current_key_transcript: Option<UnmaskedTranscript> =
            if let Some(proto) = &summary.current_key_transcript {
                Some(proto.try_into()?)
            } else {
                None
            };
        let proto = summary
            .next_key_in_creation
            .as_ref()
            .ok_or("pb::EcdsaSummaryPayload:: Missing next_key_in_creation")?;
        let next_key_in_creation: KeyTranscriptCreation = proto.try_into()?;

        let mut ret = Self {
            signature_agreements,
            ongoing_signatures,
            available_quadruples,
            quadruples_in_creation,
            idkg_transcripts,
            ongoing_xnet_reshares,
            xnet_reshare_agreements,
            uid_generator,
            key_transcript: EcdsaKeyTranscript {
                current: current_key_transcript,
                next_in_creation: next_key_in_creation,
            },
        };
        ret.update_refs(height);
        Ok(ret)
    }
}
