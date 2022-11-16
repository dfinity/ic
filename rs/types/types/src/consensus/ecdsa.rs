//! Defines types used for threshold ECDSA key generation.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Display, Formatter};
use std::hash::Hash;
use std::time::Duration;
use strum_macros::EnumIter;

pub use crate::consensus::ecdsa_refs::{
    unpack_reshare_of_unmasked_params, EcdsaBlockReader, IDkgTranscriptAttributes,
    IDkgTranscriptOperationRef, IDkgTranscriptParamsRef, MaskedTranscript,
    PreSignatureQuadrupleRef, PseudoRandomId, QuadrupleId, QuadrupleInCreation,
    RandomTranscriptParams, RequestId, ReshareOfMaskedParams, ReshareOfUnmaskedParams,
    ThresholdEcdsaSigInputsError, ThresholdEcdsaSigInputsRef, TranscriptAttributes,
    TranscriptCastError, TranscriptLookupError, TranscriptParamsError, TranscriptRef,
    UnmaskedTimesMaskedParams, UnmaskedTranscript,
};
use crate::consensus::BasicSignature;
use crate::crypto::canister_threshold_sig::error::IDkgTranscriptIdError;
use crate::crypto::{
    canister_threshold_sig::idkg::{
        IDkgComplaint, IDkgDealingSupport, IDkgOpening, IDkgTranscript, IDkgTranscriptId,
        IDkgTranscriptParams, InitialIDkgDealings, SignedIDkgDealing,
    },
    canister_threshold_sig::ThresholdEcdsaSigShare,
    crypto_hash, AlgorithmId, CryptoHash, CryptoHashOf, CryptoHashable, Signed,
    SignedBytesWithoutDomainSeparator,
};
use crate::{node_id_into_protobuf, node_id_try_from_protobuf};
use crate::{Height, NodeId, RegistryVersion, SubnetId};
use ic_crypto_sha::Sha256;
use ic_ic00_types::EcdsaKeyId;
use ic_protobuf::registry::subnet::v1 as subnet_pb;
use ic_protobuf::types::v1 as pb;
use phantom_newtype::Id;

/// For completed signature requests, we differentiate between those
/// that have already been reported and those that have not. This is
/// to prevent signatures from being reported more than once.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompletedSignature {
    ReportedToExecution,
    Unreported(crate::messages::Response),
}

/// Common data that is carried in both `EcdsaSummaryPayload` and `EcdsaDataPayload`.
/// published on every consensus round. It represents the current state of the
/// protocol since the summary block.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EcdsaPayload {
    /// Collection of completed signatures.
    pub signature_agreements: BTreeMap<PseudoRandomId, CompletedSignature>,

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

    /// Return an iterator of the ongoing xnet reshare transcripts on the source side.
    pub fn iter_xnet_transcripts_source_subnet(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        Box::new(
            self.ongoing_xnet_reshares
                .values()
                .map(|reshare_param| reshare_param.as_ref()),
        )
    }

    /// Return an iterator of the ongoing xnet reshare transcripts on the target side.
    pub fn iter_xnet_transcripts_target_subnet(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        match &self.key_transcript.next_in_creation {
            KeyTranscriptCreation::XnetReshareOfUnmaskedParams((_, params)) => {
                Box::new(std::iter::once(params.as_ref()))
            }
            _ => Box::new(std::iter::empty()),
        }
    }

    /// Return an iterator of all request ids that is used in the payload.
    /// Note that it doesn't guarantee any ordering.
    pub fn iter_request_ids(&self) -> Box<dyn Iterator<Item = &RequestId> + '_> {
        Box::new(self.ongoing_signatures.keys())
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
    /// A quadruple id is assigned if it already paired with a signature request i.e.
    /// there exists a request id (in ongoing signatures) that contains this quadruple id.
    ///
    /// Note that under proper payload construction, the quadruples paired with requests
    /// in ongoing_signatures should always be disjoint with the set of available and
    /// ongoing quadruples. This function is offered here as a safer alternative.
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
        // Both current key transcript and next_in_creation are considered.
        use KeyTranscriptCreation::*;
        let idkg_transcripts = &self.idkg_transcripts;
        let min_version = |version_1: Option<RegistryVersion>, version_2| {
            if version_1.is_none() {
                version_2
            } else {
                version_1.min(version_2)
            }
        };
        let key_version = self
            .key_transcript
            .current
            .as_ref()
            .map(|transcript| transcript.registry_version());
        let in_creation_version = match &self.key_transcript.next_in_creation {
            Begin => None,
            RandomTranscriptParams(params) => Some(params.as_ref().registry_version()),
            ReshareOfMaskedParams(params) => Some(params.as_ref().registry_version()),
            ReshareOfUnmaskedParams(params) => Some(params.as_ref().registry_version()),
            XnetReshareOfUnmaskedParams(_) => None,
            Created(transcript) => idkg_transcripts
                .get(&transcript.as_ref().transcript_id)
                .map(|transcript| transcript.registry_version),
        };
        let mut registry_version = min_version(key_version, in_creation_version);
        for (_, sig_input_ref) in self.ongoing_signatures.iter() {
            for r in sig_input_ref.get_refs().iter() {
                registry_version = min_version(
                    registry_version,
                    idkg_transcripts
                        .get(&r.transcript_id)
                        .map(|transcript| transcript.registry_version),
                );
            }
        }
        registry_version
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

/// The unmasked transcript is paired with its attributes, which will be used
/// in creating reshare params.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnmaskedTranscriptWithAttributes(IDkgTranscriptAttributes, UnmaskedTranscript);

impl UnmaskedTranscriptWithAttributes {
    pub fn new(attr: IDkgTranscriptAttributes, transcript: UnmaskedTranscript) -> Self {
        Self(attr, transcript)
    }
    pub fn unmasked_transcript(&self) -> UnmaskedTranscript {
        self.1
    }
    pub fn transcript_id(&self) -> IDkgTranscriptId {
        self.1.as_ref().transcript_id
    }
}

impl TranscriptAttributes for UnmaskedTranscriptWithAttributes {
    fn receivers(&self) -> &BTreeSet<NodeId> {
        self.0.receivers()
    }
    fn algorithm_id(&self) -> AlgorithmId {
        self.0.algorithm_id()
    }
    fn registry_version(&self) -> RegistryVersion {
        self.0.registry_version()
    }
}

impl AsRef<TranscriptRef> for UnmaskedTranscriptWithAttributes {
    fn as_ref(&self) -> &TranscriptRef {
        self.1.as_ref()
    }
}

impl AsMut<TranscriptRef> for UnmaskedTranscriptWithAttributes {
    fn as_mut(&mut self) -> &mut TranscriptRef {
        self.1.as_mut()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EcdsaKeyTranscript {
    /// The ECDSA key transcript used for the current interval.
    pub current: Option<UnmaskedTranscriptWithAttributes>,
    /// Progress of creating the next ECDSA key transcript.
    pub next_in_creation: KeyTranscriptCreation,
    /// Key id.
    pub key_id: EcdsaKeyId,
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

impl Display for EcdsaKeyTranscript {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let current = if let Some(transcript) = &self.current {
            format!("Current = {:?}", transcript.as_ref())
        } else {
            "Current = None".to_string()
        };
        match &self.next_in_creation {
            KeyTranscriptCreation::Begin => write!(f, "{}, Next = Begin", current),
            KeyTranscriptCreation::RandomTranscriptParams(x) => write!(
                f,
                "{}, Next = RandomTranscriptParams({:?}",
                current,
                x.as_ref().transcript_id
            ),
            KeyTranscriptCreation::ReshareOfMaskedParams(x) => write!(
                f,
                "{}, Next = ReshareOfMaskedParams({:?})",
                current,
                x.as_ref().transcript_id
            ),
            KeyTranscriptCreation::ReshareOfUnmaskedParams(x) => write!(
                f,
                "{}, Next = ReshareOfUnmaskedParams({:?})",
                current,
                x.as_ref().transcript_id
            ),
            KeyTranscriptCreation::XnetReshareOfUnmaskedParams((_, x)) => write!(
                f,
                "{}, Next = XnetReshareOfUnmaskedParams({:?})",
                current,
                x.as_ref().transcript_id
            ),
            KeyTranscriptCreation::Created(x) => write!(f, "{}, Next = Created({:?})", current, x),
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
    Unreported(crate::messages::Response),
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
    EcdsaSignedDealing(SignedIDkgDealing),
    EcdsaDealingSupport(IDkgDealingSupport),
    EcdsaSigShare(EcdsaSigShare),
    EcdsaComplaint(EcdsaComplaint),
    EcdsaOpening(EcdsaOpening),
}

/// EcdsaArtifactId is the unique identifier for the artifacts. It is made of a prefix + crypto
/// hash of the message itself:
/// EcdsaArtifactId = <EcdsaPrefix, CryptoHash<Message>>
/// EcdsaPrefix     = <8 byte group tag, 8 byte meta info hash>
///
/// Two kinds of look up are possible with this:
/// 1. Look up by full key of <prefix + crypto hash>, which would return the matching
/// artifact if present.
/// 2. Look up by prefix match. This can return 0 or more entries, as several artifacts may share
/// the same prefix. The caller is expected to filter the returned entries as needed. The look up
/// by prefix makes some frequent queries more efficient (e.g) to know if a node has already
/// issued a support for a <transcript Id, dealer Id>, we could iterate through all the
/// entries in the support pool looking for a matching artifact. Instead, we could issue a
/// single prefix query for prefix = <transcript Id, dealer Id, support signer Id>.
///
/// - The group tag creates an ordering of the messages
/// We previously identified the messages only by CryptoHash. This loses any ordering
/// info (e.g) if we want to iterate/process the messages related to older transcripts ahead of
/// the newer ones, this is not possible with CryptoHash. The group tag automatically
/// creates an ordering/grouping (e.g) this is set to transcript Id for dealings and support
/// shares.
///
/// - The meta info hash maps variable length meta info fields into a fixed length
/// hash, which simplifies the design and easy to work with LMDB keys. Ideally, we would like to
/// look up by a list of relevant fields (e.g) dealings by <transcript Id, dealer Id>,
/// support shares by <transcript Id, dealer Id, support signer Id>, complaints by
/// <transcript Id, dealer Id, complainer Id>, etc. But this requires different way of
/// indexing for the different sub pools. Instead, mapping these fields to the hash creates an
/// uniform indexing mechanism for all the sub pools.
///
/// On the down side, more than one artifact may map to the same hash value. So the caller
/// would need to do an exact match to filter as needed. But the collisions are expected to
/// be rare, and the prefix lookup should usually return a single entry.
///
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct EcdsaPrefix {
    group_tag: u64,
    meta_hash: u64,
}

impl EcdsaPrefix {
    pub fn new(group_tag: u64, hash: [u8; 32]) -> Self {
        let w1 = u64::from_be_bytes((&hash[0..8]).try_into().unwrap());
        let w2 = u64::from_be_bytes((&hash[8..16]).try_into().unwrap());
        let w3 = u64::from_be_bytes((&hash[16..24]).try_into().unwrap());
        let w4 = u64::from_be_bytes((&hash[24..]).try_into().unwrap());
        Self::new_with_meta_hash(group_tag, w1 ^ w2 ^ w3 ^ w4)
    }

    pub fn new_with_meta_hash(group_tag: u64, meta_hash: u64) -> Self {
        Self {
            group_tag,
            meta_hash,
        }
    }

    pub fn group_tag(&self) -> u64 {
        self.group_tag
    }

    pub fn meta_hash(&self) -> u64 {
        self.meta_hash
    }
}

pub type EcdsaPrefixOf<T> = Id<T, EcdsaPrefix>;

pub fn dealing_prefix(
    transcript_id: &IDkgTranscriptId,
    dealer_id: &NodeId,
) -> EcdsaPrefixOf<SignedIDkgDealing> {
    // Group_tag: transcript Id, Meta info: <dealer_id>
    let mut hasher = Sha256::new();
    dealer_id.hash(&mut hasher);

    EcdsaPrefixOf::new(EcdsaPrefix::new(transcript_id.id(), hasher.finish()))
}

pub fn dealing_support_prefix(
    transcript_id: &IDkgTranscriptId,
    dealer_id: &NodeId,
    support_node_id: &NodeId,
) -> EcdsaPrefixOf<IDkgDealingSupport> {
    // Group_tag: transcript Id, Meta info: <dealer_id + support sender>
    let mut hasher = Sha256::new();
    dealer_id.hash(&mut hasher);
    support_node_id.hash(&mut hasher);

    EcdsaPrefixOf::new(EcdsaPrefix::new(transcript_id.id(), hasher.finish()))
}

pub fn sig_share_prefix(
    request_id: &RequestId,
    sig_share_node_id: &NodeId,
) -> EcdsaPrefixOf<EcdsaSigShare> {
    // Group_tag: quadruple Id, Meta info: <sig share sender>
    let mut hasher = Sha256::new();
    sig_share_node_id.hash(&mut hasher);

    EcdsaPrefixOf::new(EcdsaPrefix::new(request_id.quadruple_id.0, hasher.finish()))
}

pub fn complaint_prefix(
    transcript_id: &IDkgTranscriptId,
    dealer_id: &NodeId,
    complainer_id: &NodeId,
) -> EcdsaPrefixOf<EcdsaComplaint> {
    // Group_tag: transcript Id, Meta info: <dealer_id + complainer_id>
    let mut hasher = Sha256::new();
    dealer_id.hash(&mut hasher);
    complainer_id.hash(&mut hasher);

    EcdsaPrefixOf::new(EcdsaPrefix::new(transcript_id.id(), hasher.finish()))
}

pub fn opening_prefix(
    transcript_id: &IDkgTranscriptId,
    dealer_id: &NodeId,
    opener_id: &NodeId,
) -> EcdsaPrefixOf<EcdsaOpening> {
    // Group_tag: transcript Id, Meta info: <dealer_id + opener_id>
    let mut hasher = Sha256::new();
    dealer_id.hash(&mut hasher);
    opener_id.hash(&mut hasher);

    EcdsaPrefixOf::new(EcdsaPrefix::new(transcript_id.id(), hasher.finish()))
}

/// The identifier for artifacts/messages.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum EcdsaArtifactId {
    Dealing(
        EcdsaPrefixOf<SignedIDkgDealing>,
        CryptoHashOf<SignedIDkgDealing>,
    ),
    DealingSupport(
        EcdsaPrefixOf<IDkgDealingSupport>,
        CryptoHashOf<IDkgDealingSupport>,
    ),
    SigShare(EcdsaPrefixOf<EcdsaSigShare>, CryptoHashOf<EcdsaSigShare>),
    Complaint(EcdsaPrefixOf<EcdsaComplaint>, CryptoHashOf<EcdsaComplaint>),
    Opening(EcdsaPrefixOf<EcdsaOpening>, CryptoHashOf<EcdsaOpening>),
}

impl EcdsaArtifactId {
    pub fn prefix(&self) -> EcdsaPrefix {
        match self {
            EcdsaArtifactId::Dealing(prefix, _) => prefix.as_ref().clone(),
            EcdsaArtifactId::DealingSupport(prefix, _) => prefix.as_ref().clone(),
            EcdsaArtifactId::SigShare(prefix, _) => prefix.as_ref().clone(),
            EcdsaArtifactId::Complaint(prefix, _) => prefix.as_ref().clone(),
            EcdsaArtifactId::Opening(prefix, _) => prefix.as_ref().clone(),
        }
    }

    pub fn hash(&self) -> CryptoHash {
        match self {
            EcdsaArtifactId::Dealing(_, hash) => hash.as_ref().clone(),
            EcdsaArtifactId::DealingSupport(_, hash) => hash.as_ref().clone(),
            EcdsaArtifactId::SigShare(_, hash) => hash.as_ref().clone(),
            EcdsaArtifactId::Complaint(_, hash) => hash.as_ref().clone(),
            EcdsaArtifactId::Opening(_, hash) => hash.as_ref().clone(),
        }
    }

    pub fn dealing_hash(&self) -> Option<CryptoHashOf<SignedIDkgDealing>> {
        match self {
            Self::Dealing(_, hash) => Some(hash.clone()),
            _ => None,
        }
    }
}

impl From<(EcdsaMessageType, EcdsaPrefix, CryptoHash)> for EcdsaArtifactId {
    fn from(
        (message_type, prefix, crypto_hash): (EcdsaMessageType, EcdsaPrefix, CryptoHash),
    ) -> EcdsaArtifactId {
        match message_type {
            EcdsaMessageType::Dealing => {
                EcdsaArtifactId::Dealing(EcdsaPrefixOf::new(prefix), CryptoHashOf::new(crypto_hash))
            }
            EcdsaMessageType::DealingSupport => EcdsaArtifactId::DealingSupport(
                EcdsaPrefixOf::new(prefix),
                CryptoHashOf::new(crypto_hash),
            ),
            EcdsaMessageType::SigShare => EcdsaArtifactId::SigShare(
                EcdsaPrefixOf::new(prefix),
                CryptoHashOf::new(crypto_hash),
            ),
            EcdsaMessageType::Complaint => EcdsaArtifactId::Complaint(
                EcdsaPrefixOf::new(prefix),
                CryptoHashOf::new(crypto_hash),
            ),
            EcdsaMessageType::Opening => {
                EcdsaArtifactId::Opening(EcdsaPrefixOf::new(prefix), CryptoHashOf::new(crypto_hash))
            }
        }
    }
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

impl From<&EcdsaArtifactId> for EcdsaMessageType {
    fn from(id: &EcdsaArtifactId) -> EcdsaMessageType {
        match id {
            EcdsaArtifactId::Dealing(..) => EcdsaMessageType::Dealing,
            EcdsaArtifactId::DealingSupport(..) => EcdsaMessageType::DealingSupport,
            EcdsaArtifactId::SigShare(..) => EcdsaMessageType::SigShare,
            EcdsaArtifactId::Complaint(..) => EcdsaMessageType::Complaint,
            EcdsaArtifactId::Opening(..) => EcdsaMessageType::Opening,
        }
    }
}

impl EcdsaMessageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dealing => "signed_dealing",
            Self::DealingSupport => "dealing_support",
            Self::SigShare => "sig_share",
            Self::Complaint => "complaint",
            Self::Opening => "opening",
        }
    }
}

/// The ECDSA signature share
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EcdsaSigShare {
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
            "SigShare[request_id = {:?}, signer_id = {:?}]",
            self.request_id, self.signer_id,
        )
    }
}

/// Complaint related defines
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EcdsaComplaintContent {
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
            "Opening[transcript = {:?}, dealer = {:?}, opener = {:?}]",
            self.content.idkg_opening.transcript_id,
            self.content.idkg_opening.dealer_id,
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
    EcdsaSignedDealing(IDkgTranscriptId),
    EcdsaDealingSupport(IDkgTranscriptId),
    EcdsaSigShare(RequestId),
    EcdsaComplaint(IDkgTranscriptId),
    EcdsaOpening(IDkgTranscriptId),
}

impl From<&EcdsaMessage> for EcdsaMessageAttribute {
    fn from(msg: &EcdsaMessage) -> EcdsaMessageAttribute {
        match msg {
            EcdsaMessage::EcdsaSignedDealing(dealing) => {
                EcdsaMessageAttribute::EcdsaSignedDealing(dealing.content.transcript_id)
            }
            EcdsaMessage::EcdsaDealingSupport(support) => {
                EcdsaMessageAttribute::EcdsaDealingSupport(support.transcript_id)
            }
            EcdsaMessage::EcdsaSigShare(share) => {
                EcdsaMessageAttribute::EcdsaSigShare(share.request_id)
            }
            EcdsaMessage::EcdsaComplaint(complaint) => EcdsaMessageAttribute::EcdsaComplaint(
                complaint.content.idkg_complaint.transcript_id,
            ),
            EcdsaMessage::EcdsaOpening(opening) => {
                EcdsaMessageAttribute::EcdsaOpening(opening.content.idkg_opening.transcript_id)
            }
        }
    }
}

impl EcdsaMessageAttribute {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EcdsaSignedDealing(_) => "signed_dealing",
            Self::EcdsaDealingSupport(_) => "dealing_support",
            Self::EcdsaSigShare(_) => "sig_share",
            Self::EcdsaComplaint(_) => "complaint",
            Self::EcdsaOpening(_) => "opening",
        }
    }
}

impl TryFrom<EcdsaMessage> for SignedIDkgDealing {
    type Error = EcdsaMessage;
    fn try_from(msg: EcdsaMessage) -> Result<Self, Self::Error> {
        match msg {
            EcdsaMessage::EcdsaSignedDealing(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<EcdsaMessage> for IDkgDealingSupport {
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
        for (pseudo_random_id, completed) in &summary.signature_agreements {
            let unreported = match completed {
                CompletedSignature::Unreported(response) => Some(response.into()),
                CompletedSignature::ReportedToExecution => None,
            };
            signature_agreements.push(pb::CompletedSignature {
                request_id: None, // To be removed after upgrade
                pseudo_random_id: pseudo_random_id.to_vec(),
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
                    Some(initial_dealings.into())
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
            .map(|transcript| (&transcript.1).into());
        let next_key_in_creation = Some((&summary.key_transcript.next_in_creation).into());
        let key_id = Some((&summary.key_transcript.key_id).into());

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
            key_id,
        }
    }
}

impl TryFrom<(&pb::EcdsaSummaryPayload, Height)> for EcdsaPayload {
    type Error = String;
    fn try_from(
        (summary, height): (&pb::EcdsaSummaryPayload, Height),
    ) -> Result<Self, Self::Error> {
        // Key Id must exist
        let key_id = summary
            .key_id
            .clone()
            .expect("pb::EcdsaSummaryPayload:: Missing key id");
        let key_id = EcdsaKeyId::try_from(key_id).map_err(|err| format!("{:?}", err))?;
        // signature_agreements
        let mut signature_agreements = BTreeMap::new();
        for completed_signature in &summary.signature_agreements {
            // NOTE: We still look at the request_id for compatibility reasons,
            // which should be removed from protobuf after upgrading deployment.
            let request_id = completed_signature
                .request_id
                .as_ref()
                .ok_or("pb::EcdsaSummaryPayload:: Missing completed_signature request Id")
                .and_then(RequestId::try_from);
            let pseudo_random_id = request_id.map(|x| x.pseudo_random_id).or_else(|_| {
                if completed_signature.pseudo_random_id.len() != 32 {
                    return Err("Expects 32 bytes of pseudo_random_id".to_string());
                }
                let mut x = [0; 32];
                x.copy_from_slice(&completed_signature.pseudo_random_id);
                Ok(x)
            })?;
            let signature = if let Some(unreported) = &completed_signature.unreported {
                let response = crate::messages::Response::try_from(unreported.clone())
                    .map_err(|err| format!("{:?}", err))?;
                CompletedSignature::Unreported(response)
            } else {
                CompletedSignature::ReportedToExecution
            };
            signature_agreements.insert(pseudo_random_id, signature);
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
                Some(response) => {
                    let unreported = response.clone().try_into().map_err(|err| {
                        format!(
                            "pb::EcdsaSummaryPayload:: failed to convert initial dealing: {:?}",
                            err
                        )
                    })?;
                    CompletedReshareRequest::Unreported(unreported)
                }
                None => CompletedReshareRequest::ReportedToExecution,
            };
            xnet_reshare_agreements.insert(request, completed);
        }

        // Key transcript state
        let current_key_transcript: Option<UnmaskedTranscriptWithAttributes> =
            if let Some(proto) = &summary.current_key_transcript {
                let unmasked = UnmaskedTranscript::try_from(proto)?;
                let transcript_id = unmasked.as_ref().transcript_id;
                let transcript = idkg_transcripts.get(&transcript_id).ok_or_else(|| {
                    format!(
                        "Key transcript {:?} does not exist in summary",
                        transcript_id
                    )
                })?;
                Some(UnmaskedTranscriptWithAttributes(
                    transcript.to_attributes(),
                    unmasked,
                ))
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
                key_id,
            },
        };
        ret.update_refs(height);
        Ok(ret)
    }
}

///
/// Processing/updates for a particular entity like TranscriptId is scattered across
/// several paths, called from different contexts (e.g)
///     - EcdsaPreSigner builds the dealings/support shares (ECDSA component context),
///       across several calls to on_state_change()
///     - EcdsaTranscriptBuilder builds the verified dealings/transcripts (payload builder context),
///       across possibly several calls to get_completed_transcript()
///
/// The ECDSA stats unifies the relevant metrics for an entity, so that these can be accessed
/// from the different paths. This helps answer higher level queries
/// (e.g) total time spent in stages like support share validation/ aggregation, per transcript.
///
pub trait EcdsaStats: Send + Sync {
    /// Updates the set of transcripts being tracked currently.
    fn update_active_transcripts(&self, block_reader: &dyn EcdsaBlockReader);

    /// Records the time taken to verify the support share received for a dealing.
    fn record_support_validation(&self, support: &IDkgDealingSupport, duration: Duration);

    /// Records the time taken to aggregate the support shares for a dealing.
    fn record_support_aggregation(
        &self,
        transcript_params: &IDkgTranscriptParams,
        support_shares: &[IDkgDealingSupport],
        duration: Duration,
    );

    /// Records the time taken to create the transcript.
    fn record_transcript_creation(
        &self,
        transcript_params: &IDkgTranscriptParams,
        duration: Duration,
    );

    /// Updates the set of signature requests being tracked currently.
    fn update_active_signature_requests(&self, block_reader: &dyn EcdsaBlockReader);

    /// Records the time taken to verify the signature share received for a request.
    fn record_sig_share_validation(&self, request_id: &RequestId, duration: Duration);

    /// Records the time taken to aggregate the signature shares for a request.
    fn record_sig_share_aggregation(&self, request_id: &RequestId, duration: Duration);
}

/// For testing
pub struct EcdsaStatsNoOp {}
impl EcdsaStats for EcdsaStatsNoOp {
    fn update_active_transcripts(&self, _block_reader: &dyn EcdsaBlockReader) {}
    fn record_support_validation(&self, _support: &IDkgDealingSupport, _duration: Duration) {}
    fn record_support_aggregation(
        &self,
        _transcript_params: &IDkgTranscriptParams,
        _support_shares: &[IDkgDealingSupport],
        _duration: Duration,
    ) {
    }
    fn record_transcript_creation(
        &self,
        _transcript_params: &IDkgTranscriptParams,
        _duration: Duration,
    ) {
    }
    fn update_active_signature_requests(&self, _block_reader: &dyn EcdsaBlockReader) {}
    fn record_sig_share_validation(&self, _request_id: &RequestId, _duration: Duration) {}
    fn record_sig_share_aggregation(&self, _request_id: &RequestId, _duration: Duration) {}
}

/// EcdsaObject should be implemented by the ECDSA message types
/// (e.g) EcdsaSignedDealing, EcdsaDealingSupport, etc
pub trait EcdsaObject: CryptoHashable + Clone + Sized {
    /// Returns the artifact prefix.
    fn message_prefix(&self) -> EcdsaPrefixOf<Self>;

    /// Returns the artifact Id.
    fn message_id(&self) -> EcdsaArtifactId;
}

impl EcdsaObject for SignedIDkgDealing {
    fn message_prefix(&self) -> EcdsaPrefixOf<Self> {
        dealing_prefix(&self.idkg_dealing().transcript_id, &self.dealer_id())
    }

    fn message_id(&self) -> EcdsaArtifactId {
        EcdsaArtifactId::Dealing(self.message_prefix(), crypto_hash(self))
    }
}

impl EcdsaObject for IDkgDealingSupport {
    fn message_prefix(&self) -> EcdsaPrefixOf<Self> {
        dealing_support_prefix(&self.transcript_id, &self.dealer_id, &self.sig_share.signer)
    }

    fn message_id(&self) -> EcdsaArtifactId {
        EcdsaArtifactId::DealingSupport(self.message_prefix(), crypto_hash(self))
    }
}

impl EcdsaObject for EcdsaSigShare {
    fn message_prefix(&self) -> EcdsaPrefixOf<Self> {
        sig_share_prefix(&self.request_id, &self.signer_id)
    }

    fn message_id(&self) -> EcdsaArtifactId {
        EcdsaArtifactId::SigShare(self.message_prefix(), crypto_hash(self))
    }
}

impl EcdsaObject for EcdsaComplaint {
    fn message_prefix(&self) -> EcdsaPrefixOf<Self> {
        complaint_prefix(
            &self.content.idkg_complaint.transcript_id,
            &self.content.idkg_complaint.dealer_id,
            &self.signature.signer,
        )
    }

    fn message_id(&self) -> EcdsaArtifactId {
        EcdsaArtifactId::Complaint(self.message_prefix(), crypto_hash(self))
    }
}

impl EcdsaObject for EcdsaOpening {
    fn message_prefix(&self) -> EcdsaPrefixOf<Self> {
        opening_prefix(
            &self.content.idkg_opening.transcript_id,
            &self.content.idkg_opening.dealer_id,
            &self.signature.signer,
        )
    }

    fn message_id(&self) -> EcdsaArtifactId {
        EcdsaArtifactId::Opening(self.message_prefix(), crypto_hash(self))
    }
}

pub fn ecdsa_msg_id(msg: &EcdsaMessage) -> EcdsaArtifactId {
    match msg {
        EcdsaMessage::EcdsaSignedDealing(object) => object.message_id(),
        EcdsaMessage::EcdsaDealingSupport(object) => object.message_id(),
        EcdsaMessage::EcdsaSigShare(object) => object.message_id(),
        EcdsaMessage::EcdsaComplaint(object) => object.message_id(),
        EcdsaMessage::EcdsaOpening(object) => object.message_id(),
    }
}
