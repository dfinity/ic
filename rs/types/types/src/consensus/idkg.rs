//! Defines types used for threshold ECDSA key generation.

pub use crate::consensus::idkg::common::{
    unpack_reshare_of_unmasked_params, EcdsaBlockReader, IDkgTranscriptAttributes,
    IDkgTranscriptOperationRef, IDkgTranscriptParamsRef, MaskedTranscript, PreSigId,
    PseudoRandomId, RandomTranscriptParams, RandomUnmaskedTranscriptParams, RequestId,
    ReshareOfMaskedParams, ReshareOfUnmaskedParams, TranscriptAttributes, TranscriptCastError,
    TranscriptLookupError, TranscriptParamsError, TranscriptRef, UnmaskedTimesMaskedParams,
    UnmaskedTranscript,
};
use crate::consensus::idkg::ecdsa::{PreSignatureQuadrupleRef, QuadrupleInCreation};
use crate::{
    consensus::BasicSignature,
    crypto::{
        canister_threshold_sig::{
            error::*,
            idkg::{
                IDkgComplaint, IDkgDealingSupport, IDkgOpening, IDkgTranscript, IDkgTranscriptId,
                IDkgTranscriptParams, InitialIDkgDealings, SignedIDkgDealing,
            },
            ThresholdEcdsaSigShare, ThresholdSchnorrSigShare,
        },
        crypto_hash, AlgorithmId, CryptoHash, CryptoHashOf, CryptoHashable, Signed,
        SignedBytesWithoutDomainSeparator,
    },
    node_id_into_protobuf, node_id_try_from_option, Height, NodeId, RegistryVersion, SubnetId,
};
use common::SignatureScheme;
use ic_crypto_sha2::Sha256;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types::{EcdsaKeyId, MasterPublicKeyId};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    registry::{crypto::v1 as crypto_pb, subnet::v1 as subnet_pb},
    types::v1 as pb,
};
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::{TryFrom, TryInto},
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    time::Duration,
};
use strum_macros::EnumIter;

use self::common::{PreSignatureInCreation, PreSignatureRef};

pub mod common;
pub mod ecdsa;
pub mod schnorr;

/// For completed signature requests, we differentiate between those
/// that have already been reported and those that have not. This is
/// to prevent signatures from being reported more than once.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum CompletedSignature {
    ReportedToExecution,
    Unreported(crate::batch::ConsensusResponse),
}

/// Common data that is carried in both `EcdsaSummaryPayload` and `EcdsaDataPayload`.
/// published on every consensus round. It represents the current state of the
/// protocol since the summary block.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EcdsaPayload {
    /// Collection of completed signatures.
    pub signature_agreements: BTreeMap<PseudoRandomId, CompletedSignature>,

    /// IDKG transcript Pre-Signatures that we can use to create threshold signatures.
    pub available_pre_signatures: BTreeMap<PreSigId, PreSignatureRef>,

    /// Pre-Signature in creation.
    pub pre_signatures_in_creation: BTreeMap<PreSigId, PreSignatureInCreation>,

    /// Generator of unique ids.
    pub uid_generator: EcdsaUIDGenerator,

    /// Transcripts created at this height.
    pub idkg_transcripts: BTreeMap<IDkgTranscriptId, IDkgTranscript>,

    /// Resharing requests in progress.
    pub ongoing_xnet_reshares: BTreeMap<IDkgReshareRequest, ReshareOfUnmaskedParams>,

    /// Completed resharing requests.
    pub xnet_reshare_agreements: BTreeMap<IDkgReshareRequest, CompletedReshareRequest>,

    /// State of the key transcripts.
    pub key_transcripts: BTreeMap<MasterPublicKeyId, MasterKeyTranscript>,
}

impl EcdsaPayload {
    /// Creates an empty ECDSA payload.
    pub fn empty(
        height: Height,
        subnet_id: SubnetId,
        key_transcripts: Vec<MasterKeyTranscript>,
    ) -> Self {
        Self {
            key_transcripts: key_transcripts
                .into_iter()
                .map(|key_transcript| (key_transcript.key_id(), key_transcript))
                .collect(),
            uid_generator: EcdsaUIDGenerator::new(subnet_id, height),
            signature_agreements: BTreeMap::new(),
            available_pre_signatures: BTreeMap::new(),
            pre_signatures_in_creation: BTreeMap::new(),
            idkg_transcripts: BTreeMap::new(),
            ongoing_xnet_reshares: BTreeMap::new(),
            xnet_reshare_agreements: BTreeMap::new(),
        }
    }

    /// Returns the reference to the current key transcript of the given [`MasterPublicKeyId`].
    pub fn current_key_transcript(
        &self,
        key_id: &MasterPublicKeyId,
    ) -> Option<&UnmaskedTranscriptWithAttributes> {
        self.key_transcripts
            .get(key_id)
            .and_then(|key_transcript| key_transcript.current.as_ref())
    }

    /// Return an iterator of all transcript configs that have no matching
    /// results yet.
    pub fn iter_transcript_configs_in_creation(
        &self,
    ) -> impl Iterator<Item = &IDkgTranscriptParamsRef> + '_ {
        let xnet_reshares_transcripts = self.ongoing_xnet_reshares.values().map(AsRef::as_ref);
        let key_transcripts = self
            .key_transcripts
            .values()
            .flat_map(MasterKeyTranscript::transcript_config_in_creation);

        self.pre_signatures_in_creation
            .iter()
            .flat_map(|(_, pre_sig)| pre_sig.iter_transcript_configs_in_creation())
            .chain(key_transcripts)
            .chain(xnet_reshares_transcripts)
    }

    /// Return an iterator of the ongoing xnet reshare transcripts on the source side.
    pub fn iter_xnet_transcripts_source_subnet(
        &self,
    ) -> impl Iterator<Item = &IDkgTranscriptParamsRef> + '_ {
        self.ongoing_xnet_reshares.values().map(AsRef::as_ref)
    }

    /// Return an iterator of the ongoing xnet reshare transcripts on the target side.
    pub fn iter_xnet_transcripts_target_subnet(
        &self,
    ) -> impl Iterator<Item = &IDkgTranscriptParamsRef> + '_ {
        self.key_transcripts.values().filter_map(|key_transcript| {
            if let KeyTranscriptCreation::XnetReshareOfUnmaskedParams((_, params)) =
                &key_transcript.next_in_creation
            {
                Some(params.as_ref())
            } else {
                None
            }
        })
    }

    /// Return an iterator of all ids of pre-signatures for the given key in the payload.
    pub fn iter_pre_signature_ids<'a>(
        &'a self,
        key_id: &'a MasterPublicKeyId,
    ) -> impl Iterator<Item = PreSigId> + '_ {
        let available_pre_signature_ids = self
            .available_pre_signatures
            .iter()
            .filter(|(_, pre_sig)| pre_sig.key_id() == *key_id)
            .map(|(key, _)| key);

        let in_creation_pre_signature_ids = self
            .pre_signatures_in_creation
            .iter()
            .filter(|(_, pre_sig)| pre_sig.key_id() == *key_id)
            .map(|(key, _)| key);

        available_pre_signature_ids
            .chain(in_creation_pre_signature_ids)
            .cloned()
    }

    /// Return active transcript references in the  payload.
    pub fn active_transcripts(&self) -> BTreeSet<TranscriptRef> {
        let mut active_refs = BTreeSet::new();
        for obj in self.available_pre_signatures.values() {
            active_refs.extend(obj.get_refs());
        }
        for obj in self.pre_signatures_in_creation.values() {
            active_refs.extend(obj.get_refs());
        }
        for obj in self.ongoing_xnet_reshares.values() {
            active_refs.extend(obj.as_ref().get_refs());
        }
        for obj in self.key_transcripts.values() {
            active_refs.extend(obj.get_refs());
        }

        active_refs
    }

    /// Updates the height of all the transcript refs to the given height.
    pub fn update_refs(&mut self, height: Height) {
        for obj in self.available_pre_signatures.values_mut() {
            obj.update(height);
        }
        for obj in self.pre_signatures_in_creation.values_mut() {
            obj.update(height);
        }
        for obj in self.ongoing_xnet_reshares.values_mut() {
            obj.as_mut().update(height);
        }
        for obj in self.key_transcripts.values_mut() {
            obj.update_refs(height)
        }
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
        let idkg_transcripts = &self.idkg_transcripts;
        let min_version = |version_1: Option<RegistryVersion>, version_2| {
            if version_1.is_none() {
                version_2
            } else {
                version_1.min(version_2)
            }
        };

        let min_current_key_version = self
            .key_transcripts
            .values()
            .filter_map(|key_transcript| key_transcript.current.as_ref())
            .map(TranscriptAttributes::registry_version)
            .min();

        let min_in_creation_key_version = self
            .key_transcripts
            .values()
            .filter_map(|key_transcript| match &key_transcript.next_in_creation {
                KeyTranscriptCreation::Begin => None,
                KeyTranscriptCreation::RandomTranscriptParams(params) => {
                    Some(params.as_ref().registry_version())
                }
                KeyTranscriptCreation::ReshareOfMaskedParams(params) => {
                    Some(params.as_ref().registry_version())
                }
                KeyTranscriptCreation::ReshareOfUnmaskedParams(params) => {
                    Some(params.as_ref().registry_version())
                }
                KeyTranscriptCreation::XnetReshareOfUnmaskedParams((_, params)) => {
                    Some(params.as_ref().registry_version())
                }
                KeyTranscriptCreation::Created(transcript) => idkg_transcripts
                    .get(&transcript.as_ref().transcript_id)
                    .map(|transcript| transcript.registry_version),
            })
            .min();

        min_version(min_current_key_version, min_in_creation_key_version)
    }

    /// Returns the initial DKG dealings being used to bootstrap the target subnet,
    /// if we are in the process of initial key creation.
    pub fn initial_dkg_dealings(&self) -> impl Iterator<Item = &InitialIDkgDealings> + '_ {
        self.key_transcripts.values().filter_map(|key_transcript| {
            if let KeyTranscriptCreation::XnetReshareOfUnmaskedParams((initial_dealings, _)) =
                &key_transcript.next_in_creation
            {
                Some(initial_dealings.as_ref())
            } else {
                None
            }
        })
    }
}

/// The unmasked transcript is paired with its attributes, which will be used
/// in creating reshare params.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct UnmaskedTranscriptWithAttributes(IDkgTranscriptAttributes, UnmaskedTranscript);

impl From<&UnmaskedTranscriptWithAttributes> for pb::UnmaskedTranscriptWithAttributes {
    fn from(transcript_with_attrs: &UnmaskedTranscriptWithAttributes) -> Self {
        pb::UnmaskedTranscriptWithAttributes {
            transcript_ref: Some(transcript_with_attrs.1.as_ref().into()),
            attributes: Some((&transcript_with_attrs.0).into()),
        }
    }
}

impl TryFrom<&pb::UnmaskedTranscriptWithAttributes> for UnmaskedTranscriptWithAttributes {
    type Error = ProxyDecodeError;
    fn try_from(
        transcript_with_attrs: &pb::UnmaskedTranscriptWithAttributes,
    ) -> Result<Self, Self::Error> {
        let attributes = try_from_option_field(
            transcript_with_attrs.attributes.as_ref(),
            "UnmaskedTranscriptWithAttributes::attributes",
        )?;
        let unmasked = pb::UnmaskedTranscript {
            transcript_ref: transcript_with_attrs.transcript_ref.clone(),
        };
        Ok(UnmaskedTranscriptWithAttributes::new(
            attributes,
            (&unmasked).try_into()?,
        ))
    }
}

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterKeyTranscript {
    /// The ECDSA key transcript used for the current interval.
    pub current: Option<UnmaskedTranscriptWithAttributes>,
    /// Progress of creating the next ECDSA key transcript.
    pub next_in_creation: KeyTranscriptCreation,
    /// DEPRECATED: ECDSA Key id.
    pub deprecated_key_id: Option<EcdsaKeyId>,
    /// Master key Id allowing different signature schemes.
    pub master_key_id: MasterPublicKeyId,
}

impl Hash for MasterKeyTranscript {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let MasterKeyTranscript {
            current,
            next_in_creation,
            deprecated_key_id,
            master_key_id,
        } = self;
        current.hash(state);
        next_in_creation.hash(state);
        if let Some(key_id) = deprecated_key_id {
            key_id.hash(state);
        }
        master_key_id.hash(state);
    }
}

impl MasterKeyTranscript {
    pub fn new(key_id: MasterPublicKeyId, next_in_creation: KeyTranscriptCreation) -> Self {
        Self {
            current: None,
            next_in_creation,
            deprecated_key_id: None,
            master_key_id: key_id,
        }
    }

    pub fn update(
        &self,
        current: Option<UnmaskedTranscriptWithAttributes>,
        next_in_creation: KeyTranscriptCreation,
    ) -> Self {
        Self {
            current: current.or_else(|| self.current.clone()),
            next_in_creation,
            deprecated_key_id: None,
            master_key_id: self.master_key_id.clone(),
        }
    }

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

impl Display for MasterKeyTranscript {
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

impl From<MasterKeyTranscript> for pb::MasterKeyTranscript {
    fn from(transcript: MasterKeyTranscript) -> Self {
        Self {
            current: transcript
                .current
                .as_ref()
                .map(pb::UnmaskedTranscriptWithAttributes::from),
            next_in_creation: Some(pb::KeyTranscriptCreation::from(
                &transcript.next_in_creation,
            )),
            deprecated_key_id: transcript
                .deprecated_key_id
                .as_ref()
                .map(|key_id| key_id.into()),
            master_key_id: Some(crypto_pb::MasterPublicKeyId::from(
                &transcript.master_key_id,
            )),
        }
    }
}

impl From<&MasterKeyTranscript> for pb::MasterKeyTranscript {
    fn from(transcript: &MasterKeyTranscript) -> Self {
        Self::from(transcript.clone())
    }
}

impl TryFrom<pb::MasterKeyTranscript> for MasterKeyTranscript {
    type Error = ProxyDecodeError;

    fn try_from(proto: pb::MasterKeyTranscript) -> Result<Self, Self::Error> {
        let deprecated_key_id = proto
            .deprecated_key_id
            .clone()
            .map(|key_id| key_id.try_into())
            .transpose()?;

        let current = proto
            .current
            .as_ref()
            .map(UnmaskedTranscriptWithAttributes::try_from)
            .transpose()?;

        let next_in_creation = try_from_option_field(
            proto.next_in_creation.as_ref(),
            "KeyTranscript::next_in_creation",
        )?;

        let master_key_id =
            try_from_option_field(proto.master_key_id, "KeyTranscript::master_key_id")?;

        Ok(Self {
            deprecated_key_id,
            current,
            next_in_creation,
            master_key_id,
        })
    }
}

impl TryFrom<&pb::MasterKeyTranscript> for MasterKeyTranscript {
    type Error = ProxyDecodeError;

    fn try_from(transcript: &pb::MasterKeyTranscript) -> Result<Self, Self::Error> {
        Self::try_from(transcript.clone())
    }
}

/// The creation of an ecdsa key transcript goes through one of the three paths below:
/// 1. Begin -> RandomTranscript -> ReshareOfMasked -> Created
/// 2. Begin -> ReshareOfUnmasked -> Created
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
#[cfg_attr(test, derive(ExhaustiveSet))]
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
    type Error = ProxyDecodeError;
    fn try_from(proto: &pb::KeyTranscriptCreation) -> Result<Self, Self::Error> {
        if proto.state == (pb::KeyTranscriptCreationState::BeginUnspecified as i32) {
            Ok(KeyTranscriptCreation::Begin)
        } else if proto.state == (pb::KeyTranscriptCreationState::RandomTranscriptParams as i32) {
            Ok(KeyTranscriptCreation::RandomTranscriptParams(
                try_from_option_field(proto.random.as_ref(), "KeyTranscriptCreation::random")?,
            ))
        } else if proto.state == (pb::KeyTranscriptCreationState::ReshareOfMaskedParams as i32) {
            Ok(KeyTranscriptCreation::ReshareOfMaskedParams(
                try_from_option_field(
                    proto.reshare_of_masked.as_ref(),
                    "KeyTranscriptCreation::reshare_of_masked",
                )?,
            ))
        } else if proto.state == (pb::KeyTranscriptCreationState::ReshareOfUnmaskedParams as i32) {
            Ok(KeyTranscriptCreation::ReshareOfUnmaskedParams(
                try_from_option_field(
                    proto.reshare_of_unmasked.as_ref(),
                    "KeyTranscriptCreation::reshare_of_unmasked",
                )?,
            ))
        } else if proto.state
            == (pb::KeyTranscriptCreationState::XnetReshareOfUnmaskedParams as i32)
        {
            let initial_dealings: InitialIDkgDealings = try_from_option_field(
                proto.xnet_reshare_initial_dealings.as_ref(),
                "KeyTranscriptCreation::xnet_reshare_initial_dealings",
            )?;
            let xnet_param_unmasked = try_from_option_field(
                proto.xnet_reshare_of_unmasked.as_ref(),
                "KeyTranscriptCreation::xnet_reshare_of_unmasked",
            )?;
            Ok(KeyTranscriptCreation::XnetReshareOfUnmaskedParams((
                Box::new(initial_dealings),
                xnet_param_unmasked,
            )))
        } else if proto.state == (pb::KeyTranscriptCreationState::Created as i32) {
            Ok(KeyTranscriptCreation::Created(try_from_option_field(
                proto.created.as_ref(),
                "KeyTranscriptCreation::created",
            )?))
        } else {
            Err(ProxyDecodeError::Other(format!(
                "KeyTranscriptCreation:: invalid state: {}",
                pb::KeyTranscriptCreationState::Created as i32
            )))
        }
    }
}

/// Internal format of the resharing request from execution.
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub struct IDkgReshareRequest {
    pub key_id: Option<EcdsaKeyId>,
    pub master_key_id: MasterPublicKeyId,
    pub receiving_node_ids: Vec<NodeId>,
    pub registry_version: RegistryVersion,
}

impl Hash for IDkgReshareRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let IDkgReshareRequest {
            key_id,
            master_key_id,
            receiving_node_ids,
            registry_version,
        } = self;
        if let Some(key_id) = key_id {
            key_id.hash(state);
        }
        master_key_id.hash(state);
        receiving_node_ids.hash(state);
        registry_version.hash(state);
    }
}

impl From<&IDkgReshareRequest> for pb::IDkgReshareRequest {
    fn from(request: &IDkgReshareRequest) -> Self {
        let mut receiving_node_ids = Vec::new();
        for node in &request.receiving_node_ids {
            receiving_node_ids.push(node_id_into_protobuf(*node));
        }
        Self {
            key_id: request.key_id.as_ref().map(|key_id| key_id.into()),
            master_key_id: Some((&request.master_key_id).into()),
            receiving_node_ids,
            registry_version: request.registry_version.get(),
        }
    }
}

impl TryFrom<&pb::IDkgReshareRequest> for IDkgReshareRequest {
    type Error = ProxyDecodeError;
    fn try_from(request: &pb::IDkgReshareRequest) -> Result<Self, Self::Error> {
        let receiving_node_ids = request
            .receiving_node_ids
            .iter()
            .map(|node| node_id_try_from_option(Some(node.clone())))
            .collect::<Result<Vec<_>, ProxyDecodeError>>()?;

        let key_id = request
            .key_id
            .clone()
            .map(|key_id| key_id.try_into())
            .transpose()?;

        let master_key_id = try_from_option_field(
            request.master_key_id.clone(),
            "IDkgReshareRequest::master_key_id",
        )?;

        Ok(Self {
            key_id,
            master_key_id,
            receiving_node_ids,
            registry_version: RegistryVersion::new(request.registry_version),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum CompletedReshareRequest {
    ReportedToExecution,
    Unreported(crate::batch::ConsensusResponse),
}

/// To make sure all ids used in ECDSA payload are uniquely generated,
/// we use a generator to keep track of this state.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct EcdsaUIDGenerator {
    next_unused_transcript_id: IDkgTranscriptId,
    next_unused_pre_signature_id: u64,
}

impl EcdsaUIDGenerator {
    pub fn new(subnet_id: SubnetId, height: Height) -> Self {
        Self {
            next_unused_transcript_id: IDkgTranscriptId::new(subnet_id, 0, height),
            next_unused_pre_signature_id: 0,
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

    pub fn next_pre_signature_id(&mut self) -> PreSigId {
        let id = self.next_unused_pre_signature_id;
        self.next_unused_pre_signature_id += 1;

        PreSigId(id)
    }
}

/// The ECDSA artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum IDkgMessage {
    Dealing(SignedIDkgDealing),
    DealingSupport(IDkgDealingSupport),
    EcdsaSigShare(EcdsaSigShare),
    SchnorrSigShare(SchnorrSigShare),
    Complaint(SignedIDkgComplaint),
    Opening(SignedIDkgOpening),
}

impl IDkgMessage {
    pub fn message_id(&self) -> IDkgArtifactId {
        match self {
            IDkgMessage::Dealing(x) => x.message_id(),
            IDkgMessage::DealingSupport(x) => x.message_id(),
            IDkgMessage::EcdsaSigShare(x) => x.message_id(),
            IDkgMessage::SchnorrSigShare(x) => x.message_id(),
            IDkgMessage::Complaint(x) => x.message_id(),
            IDkgMessage::Opening(x) => x.message_id(),
        }
    }
}

impl From<IDkgMessage> for pb::IDkgMessage {
    fn from(value: IDkgMessage) -> Self {
        use pb::i_dkg_message::Msg;
        let msg = match &value {
            IDkgMessage::Dealing(x) => Msg::SignedDealing(x.into()),
            IDkgMessage::DealingSupport(x) => Msg::DealingSupport(x.into()),
            IDkgMessage::EcdsaSigShare(x) => Msg::EcdsaSigShare(x.into()),
            IDkgMessage::SchnorrSigShare(x) => Msg::SchnorrSigShare(x.into()),
            IDkgMessage::Complaint(x) => Msg::Complaint(x.into()),
            IDkgMessage::Opening(x) => Msg::Opening(x.into()),
        };
        Self { msg: Some(msg) }
    }
}

impl TryFrom<pb::IDkgMessage> for IDkgMessage {
    type Error = ProxyDecodeError;

    fn try_from(proto: pb::IDkgMessage) -> Result<Self, Self::Error> {
        use pb::i_dkg_message::Msg;
        let Some(msg) = &proto.msg else {
            return Err(ProxyDecodeError::MissingField("IDkgMessage::msg"));
        };
        Ok(match &msg {
            Msg::SignedDealing(x) => IDkgMessage::Dealing(x.try_into()?),
            Msg::DealingSupport(x) => IDkgMessage::DealingSupport(x.try_into()?),
            Msg::EcdsaSigShare(x) => IDkgMessage::EcdsaSigShare(x.try_into()?),
            Msg::SchnorrSigShare(x) => IDkgMessage::SchnorrSigShare(x.try_into()?),
            Msg::Complaint(x) => IDkgMessage::Complaint(x.try_into()?),
            Msg::Opening(x) => IDkgMessage::Opening(x.try_into()?),
        })
    }
}

/// IDkgArtifactId is the unique identifier for the artifacts. It is made of a prefix + crypto
/// hash of the message itself:
/// IDkgArtifactId = `<IDkgPrefix, CryptoHash<Message>>`
/// IDkgPrefix     = <8 byte group tag, 8 byte meta info hash>
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
pub struct IDkgPrefix {
    group_tag: u64,
    meta_hash: u64,
    height: Height,
}

impl IDkgPrefix {
    pub fn new(group_tag: u64, hash: [u8; 32], height: Height) -> Self {
        let w1 = u64::from_be_bytes((&hash[0..8]).try_into().unwrap());
        let w2 = u64::from_be_bytes((&hash[8..16]).try_into().unwrap());
        let w3 = u64::from_be_bytes((&hash[16..24]).try_into().unwrap());
        let w4 = u64::from_be_bytes((&hash[24..]).try_into().unwrap());
        Self::new_with_meta_hash(group_tag, w1 ^ w2 ^ w3 ^ w4, height)
    }

    pub fn new_with_meta_hash(group_tag: u64, meta_hash: u64, height: Height) -> Self {
        Self {
            group_tag,
            meta_hash,
            height,
        }
    }

    pub fn group_tag(&self) -> u64 {
        self.group_tag
    }

    pub fn meta_hash(&self) -> u64 {
        self.meta_hash
    }

    pub fn height(&self) -> Height {
        self.height
    }
}

impl From<&IDkgPrefix> for pb::IDkgPrefix {
    fn from(value: &IDkgPrefix) -> Self {
        Self {
            group_tag: value.group_tag,
            meta_hash: value.meta_hash,
            height: value.height.get(),
        }
    }
}

impl From<&pb::IDkgPrefix> for IDkgPrefix {
    fn from(value: &pb::IDkgPrefix) -> Self {
        Self {
            group_tag: value.group_tag,
            meta_hash: value.meta_hash,
            height: Height::from(value.height),
        }
    }
}

pub type IDkgPrefixOf<T> = Id<T, IDkgPrefix>;

pub fn dealing_prefix(
    transcript_id: &IDkgTranscriptId,
    dealer_id: &NodeId,
) -> IDkgPrefixOf<SignedIDkgDealing> {
    // Group_tag: transcript Id, Meta info: <dealer_id>
    let mut hasher = Sha256::new();
    dealer_id.hash(&mut hasher);

    IDkgPrefixOf::new(IDkgPrefix::new(
        transcript_id.id(),
        hasher.finish(),
        transcript_id.source_height(),
    ))
}

pub fn dealing_support_prefix(
    transcript_id: &IDkgTranscriptId,
    dealer_id: &NodeId,
    support_node_id: &NodeId,
) -> IDkgPrefixOf<IDkgDealingSupport> {
    // Group_tag: transcript Id, Meta info: <dealer_id + support sender>
    let mut hasher = Sha256::new();
    dealer_id.hash(&mut hasher);
    support_node_id.hash(&mut hasher);

    IDkgPrefixOf::new(IDkgPrefix::new(
        transcript_id.id(),
        hasher.finish(),
        transcript_id.source_height(),
    ))
}

pub fn ecdsa_sig_share_prefix(
    request_id: &RequestId,
    sig_share_node_id: &NodeId,
) -> IDkgPrefixOf<EcdsaSigShare> {
    // Group_tag: quadruple Id, Meta info: <sig share sender>
    let mut hasher = Sha256::new();
    sig_share_node_id.hash(&mut hasher);

    IDkgPrefixOf::new(IDkgPrefix::new(
        request_id.pre_signature_id.id(),
        hasher.finish(),
        request_id.height,
    ))
}

pub fn schnorr_sig_share_prefix(
    request_id: &RequestId,
    sig_share_node_id: &NodeId,
) -> IDkgPrefixOf<SchnorrSigShare> {
    // Group_tag: pre-signature Id, Meta info: <sig share sender>
    let mut hasher = Sha256::new();
    sig_share_node_id.hash(&mut hasher);

    IDkgPrefixOf::new(IDkgPrefix::new(
        request_id.pre_signature_id.id(),
        hasher.finish(),
        request_id.height,
    ))
}

pub fn complaint_prefix(
    transcript_id: &IDkgTranscriptId,
    dealer_id: &NodeId,
    complainer_id: &NodeId,
) -> IDkgPrefixOf<SignedIDkgComplaint> {
    // Group_tag: transcript Id, Meta info: <dealer_id + complainer_id>
    let mut hasher = Sha256::new();
    dealer_id.hash(&mut hasher);
    complainer_id.hash(&mut hasher);

    IDkgPrefixOf::new(IDkgPrefix::new(
        transcript_id.id(),
        hasher.finish(),
        transcript_id.source_height(),
    ))
}

pub fn opening_prefix(
    transcript_id: &IDkgTranscriptId,
    dealer_id: &NodeId,
    opener_id: &NodeId,
) -> IDkgPrefixOf<SignedIDkgOpening> {
    // Group_tag: transcript Id, Meta info: <dealer_id + opener_id>
    let mut hasher = Sha256::new();
    dealer_id.hash(&mut hasher);
    opener_id.hash(&mut hasher);

    IDkgPrefixOf::new(IDkgPrefix::new(
        transcript_id.id(),
        hasher.finish(),
        transcript_id.source_height(),
    ))
}

/// The identifier for artifacts/messages.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum IDkgArtifactId {
    Dealing(
        IDkgPrefixOf<SignedIDkgDealing>,
        CryptoHashOf<SignedIDkgDealing>,
    ),
    DealingSupport(
        IDkgPrefixOf<IDkgDealingSupport>,
        CryptoHashOf<IDkgDealingSupport>,
    ),
    EcdsaSigShare(IDkgPrefixOf<EcdsaSigShare>, CryptoHashOf<EcdsaSigShare>),
    SchnorrSigShare(IDkgPrefixOf<SchnorrSigShare>, CryptoHashOf<SchnorrSigShare>),
    Complaint(
        IDkgPrefixOf<SignedIDkgComplaint>,
        CryptoHashOf<SignedIDkgComplaint>,
    ),
    Opening(
        IDkgPrefixOf<SignedIDkgOpening>,
        CryptoHashOf<SignedIDkgOpening>,
    ),
}

impl IDkgArtifactId {
    pub fn prefix(&self) -> IDkgPrefix {
        match self {
            IDkgArtifactId::Dealing(prefix, _) => prefix.as_ref().clone(),
            IDkgArtifactId::DealingSupport(prefix, _) => prefix.as_ref().clone(),
            IDkgArtifactId::EcdsaSigShare(prefix, _) => prefix.as_ref().clone(),
            IDkgArtifactId::SchnorrSigShare(prefix, _) => prefix.as_ref().clone(),
            IDkgArtifactId::Complaint(prefix, _) => prefix.as_ref().clone(),
            IDkgArtifactId::Opening(prefix, _) => prefix.as_ref().clone(),
        }
    }

    pub fn hash(&self) -> CryptoHash {
        match self {
            IDkgArtifactId::Dealing(_, hash) => hash.as_ref().clone(),
            IDkgArtifactId::DealingSupport(_, hash) => hash.as_ref().clone(),
            IDkgArtifactId::EcdsaSigShare(_, hash) => hash.as_ref().clone(),
            IDkgArtifactId::SchnorrSigShare(_, hash) => hash.as_ref().clone(),
            IDkgArtifactId::Complaint(_, hash) => hash.as_ref().clone(),
            IDkgArtifactId::Opening(_, hash) => hash.as_ref().clone(),
        }
    }

    pub fn height(&self) -> Height {
        self.prefix().height()
    }

    pub fn dealing_hash(&self) -> Option<CryptoHashOf<SignedIDkgDealing>> {
        match self {
            Self::Dealing(_, hash) => Some(hash.clone()),
            _ => None,
        }
    }
}

impl From<(IDkgMessageType, IDkgPrefix, CryptoHash)> for IDkgArtifactId {
    fn from(
        (message_type, prefix, crypto_hash): (IDkgMessageType, IDkgPrefix, CryptoHash),
    ) -> IDkgArtifactId {
        match message_type {
            IDkgMessageType::Dealing => {
                IDkgArtifactId::Dealing(IDkgPrefixOf::new(prefix), CryptoHashOf::new(crypto_hash))
            }
            IDkgMessageType::DealingSupport => IDkgArtifactId::DealingSupport(
                IDkgPrefixOf::new(prefix),
                CryptoHashOf::new(crypto_hash),
            ),
            IDkgMessageType::EcdsaSigShare => IDkgArtifactId::EcdsaSigShare(
                IDkgPrefixOf::new(prefix),
                CryptoHashOf::new(crypto_hash),
            ),
            IDkgMessageType::SchnorrSigShare => IDkgArtifactId::SchnorrSigShare(
                IDkgPrefixOf::new(prefix),
                CryptoHashOf::new(crypto_hash),
            ),
            IDkgMessageType::Complaint => {
                IDkgArtifactId::Complaint(IDkgPrefixOf::new(prefix), CryptoHashOf::new(crypto_hash))
            }
            IDkgMessageType::Opening => {
                IDkgArtifactId::Opening(IDkgPrefixOf::new(prefix), CryptoHashOf::new(crypto_hash))
            }
        }
    }
}

impl From<IDkgArtifactId> for pb::IDkgArtifactId {
    fn from(value: IDkgArtifactId) -> Self {
        use pb::i_dkg_artifact_id::Kind;
        let kind = match value.clone() {
            IDkgArtifactId::Dealing(p, h) => Kind::Dealing(pb::PrefixHashPair {
                prefix: Some((&p.get()).into()),
                hash: h.get().0,
            }),
            IDkgArtifactId::DealingSupport(p, h) => Kind::DealingSupport(pb::PrefixHashPair {
                prefix: Some((&p.get()).into()),
                hash: h.get().0,
            }),
            IDkgArtifactId::EcdsaSigShare(p, h) => Kind::EcdsaSigShare(pb::PrefixHashPair {
                prefix: Some((&p.get()).into()),
                hash: h.get().0,
            }),
            IDkgArtifactId::SchnorrSigShare(p, h) => Kind::SchnorrSigShare(pb::PrefixHashPair {
                prefix: Some((&p.get()).into()),
                hash: h.get().0,
            }),
            IDkgArtifactId::Complaint(p, h) => Kind::Complaint(pb::PrefixHashPair {
                prefix: Some((&p.get()).into()),
                hash: h.get().0,
            }),
            IDkgArtifactId::Opening(p, h) => Kind::Opening(pb::PrefixHashPair {
                prefix: Some((&p.get()).into()),
                hash: h.get().0,
            }),
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<pb::IDkgArtifactId> for IDkgArtifactId {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::IDkgArtifactId) -> Result<Self, Self::Error> {
        use pb::i_dkg_artifact_id::Kind;
        let kind = value
            .kind
            .clone()
            .ok_or_else(|| ProxyDecodeError::MissingField("IDkgArtifactId::kind"))?;

        Ok(match kind {
            Kind::Dealing(p) => Self::Dealing(
                IDkgPrefixOf::new(try_from_option_field(p.prefix.as_ref(), "Dealing::prefix")?),
                CryptoHashOf::new(CryptoHash(p.hash)),
            ),
            Kind::DealingSupport(p) => Self::DealingSupport(
                IDkgPrefixOf::new(try_from_option_field(
                    p.prefix.as_ref(),
                    "DealingSupport::prefix",
                )?),
                CryptoHashOf::new(CryptoHash(p.hash)),
            ),
            Kind::EcdsaSigShare(p) => Self::EcdsaSigShare(
                IDkgPrefixOf::new(try_from_option_field(
                    p.prefix.as_ref(),
                    "EcdsaSigShare::prefix",
                )?),
                CryptoHashOf::new(CryptoHash(p.hash)),
            ),
            Kind::SchnorrSigShare(p) => Self::SchnorrSigShare(
                IDkgPrefixOf::new(try_from_option_field(
                    p.prefix.as_ref(),
                    "SchnorrSigShare::prefix",
                )?),
                CryptoHashOf::new(CryptoHash(p.hash)),
            ),
            Kind::Complaint(p) => Self::Complaint(
                IDkgPrefixOf::new(try_from_option_field(
                    p.prefix.as_ref(),
                    "Complaint::prefix",
                )?),
                CryptoHashOf::new(CryptoHash(p.hash)),
            ),
            Kind::Opening(p) => Self::Opening(
                IDkgPrefixOf::new(try_from_option_field(p.prefix.as_ref(), "Opening::prefix")?),
                CryptoHashOf::new(CryptoHash(p.hash)),
            ),
        })
    }
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash, EnumIter,
)]
pub enum IDkgMessageType {
    Dealing,
    DealingSupport,
    EcdsaSigShare,
    SchnorrSigShare,
    Complaint,
    Opening,
}

impl From<&IDkgMessage> for IDkgMessageType {
    fn from(msg: &IDkgMessage) -> IDkgMessageType {
        match msg {
            IDkgMessage::Dealing(_) => IDkgMessageType::Dealing,
            IDkgMessage::DealingSupport(_) => IDkgMessageType::DealingSupport,
            IDkgMessage::EcdsaSigShare(_) => IDkgMessageType::EcdsaSigShare,
            IDkgMessage::SchnorrSigShare(_) => IDkgMessageType::SchnorrSigShare,
            IDkgMessage::Complaint(_) => IDkgMessageType::Complaint,
            IDkgMessage::Opening(_) => IDkgMessageType::Opening,
        }
    }
}

impl From<&IDkgArtifactId> for IDkgMessageType {
    fn from(id: &IDkgArtifactId) -> IDkgMessageType {
        match id {
            IDkgArtifactId::Dealing(..) => IDkgMessageType::Dealing,
            IDkgArtifactId::DealingSupport(..) => IDkgMessageType::DealingSupport,
            IDkgArtifactId::EcdsaSigShare(..) => IDkgMessageType::EcdsaSigShare,
            IDkgArtifactId::SchnorrSigShare(..) => IDkgMessageType::SchnorrSigShare,
            IDkgArtifactId::Complaint(..) => IDkgMessageType::Complaint,
            IDkgArtifactId::Opening(..) => IDkgMessageType::Opening,
        }
    }
}

impl IDkgMessageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dealing => "signed_dealing",
            Self::DealingSupport => "dealing_support",
            Self::EcdsaSigShare => "ecdsa_sig_share",
            Self::SchnorrSigShare => "schnorr_sig_share",
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

impl From<&EcdsaSigShare> for pb::EcdsaSigShare {
    fn from(value: &EcdsaSigShare) -> Self {
        Self {
            signer_id: Some(node_id_into_protobuf(value.signer_id)),
            request_id: Some(pb::RequestId::from(value.request_id.clone())),
            sig_share_raw: value.share.sig_share_raw.clone(),
        }
    }
}

impl TryFrom<&pb::EcdsaSigShare> for EcdsaSigShare {
    type Error = ProxyDecodeError;
    fn try_from(value: &pb::EcdsaSigShare) -> Result<Self, Self::Error> {
        Ok(Self {
            signer_id: node_id_try_from_option(value.signer_id.clone())?,
            request_id: try_from_option_field(
                value.request_id.as_ref(),
                "EcdsaSigShare::request_id",
            )?,
            share: ThresholdEcdsaSigShare {
                sig_share_raw: value.sig_share_raw.clone(),
            },
        })
    }
}

impl Display for EcdsaSigShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EcdsaSigShare[request_id = {:?}, signer_id = {:?}]",
            self.request_id, self.signer_id,
        )
    }
}

/// The Schnorr signature share
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct SchnorrSigShare {
    /// The node that signed the share
    pub signer_id: NodeId,

    /// The request this signature share belongs to
    pub request_id: RequestId,

    /// The signature share
    pub share: ThresholdSchnorrSigShare,
}

impl From<&SchnorrSigShare> for pb::SchnorrSigShare {
    fn from(value: &SchnorrSigShare) -> Self {
        Self {
            signer_id: Some(node_id_into_protobuf(value.signer_id)),
            request_id: Some(pb::RequestId::from(value.request_id.clone())),
            sig_share_raw: value.share.sig_share_raw.clone(),
        }
    }
}

impl TryFrom<&pb::SchnorrSigShare> for SchnorrSigShare {
    type Error = ProxyDecodeError;
    fn try_from(value: &pb::SchnorrSigShare) -> Result<Self, Self::Error> {
        Ok(Self {
            signer_id: node_id_try_from_option(value.signer_id.clone())?,
            request_id: try_from_option_field(
                value.request_id.as_ref(),
                "SchnorrSigShare::request_id",
            )?,
            share: ThresholdSchnorrSigShare {
                sig_share_raw: value.sig_share_raw.clone(),
            },
        })
    }
}

impl Display for SchnorrSigShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SchnorrSigShare[request_id = {:?}, signer_id = {:?}]",
            self.request_id, self.signer_id,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SigShare {
    Ecdsa(EcdsaSigShare),
    Schnorr(SchnorrSigShare),
}

impl Display for SigShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SigShare::Ecdsa(share) => write!(f, "{share}"),
            SigShare::Schnorr(share) => write!(f, "{share}"),
        }
    }
}

impl SigShare {
    pub fn signer(&self) -> NodeId {
        match self {
            SigShare::Ecdsa(share) => share.signer_id,
            SigShare::Schnorr(share) => share.signer_id,
        }
    }

    pub fn request_id(&self) -> RequestId {
        match self {
            SigShare::Ecdsa(share) => share.request_id.clone(),
            SigShare::Schnorr(share) => share.request_id.clone(),
        }
    }

    pub fn scheme(&self) -> SignatureScheme {
        match self {
            SigShare::Ecdsa(_) => SignatureScheme::Ecdsa,
            SigShare::Schnorr(_) => SignatureScheme::Schnorr,
        }
    }
}

/// Complaint related defines
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct IDkgComplaintContent {
    pub idkg_complaint: IDkgComplaint,
}

pub type SignedIDkgComplaint = Signed<IDkgComplaintContent, BasicSignature<IDkgComplaintContent>>;

impl SignedIDkgComplaint {
    pub fn get(&self) -> &IDkgComplaintContent {
        &self.content
    }
}

impl From<&SignedIDkgComplaint> for pb::SignedIDkgComplaint {
    fn from(value: &SignedIDkgComplaint) -> Self {
        Self {
            content: Some((&value.content).into()),
            signature: Some(value.signature.clone().into()),
        }
    }
}

impl TryFrom<&pb::SignedIDkgComplaint> for SignedIDkgComplaint {
    type Error = ProxyDecodeError;
    fn try_from(value: &pb::SignedIDkgComplaint) -> Result<Self, Self::Error> {
        Ok(Self {
            content: try_from_option_field(value.content.as_ref(), "SignedIDkgComplaint::content")?,
            signature: try_from_option_field(
                value.signature.clone(),
                "SignedIDkgComplaint::signature",
            )?,
        })
    }
}

impl From<&IDkgComplaintContent> for pb::IDkgComplaintContent {
    fn from(value: &IDkgComplaintContent) -> Self {
        Self {
            idkg_complaint: Some((&value.idkg_complaint).into()),
        }
    }
}

impl TryFrom<&pb::IDkgComplaintContent> for IDkgComplaintContent {
    type Error = ProxyDecodeError;
    fn try_from(value: &pb::IDkgComplaintContent) -> Result<Self, Self::Error> {
        Ok(Self {
            idkg_complaint: try_from_option_field(
                value.idkg_complaint.as_ref(),
                "IDkgComplaintContent::idkg_complaint",
            )?,
        })
    }
}

impl Display for SignedIDkgComplaint {
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

impl SignedBytesWithoutDomainSeparator for IDkgComplaintContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

impl SignedBytesWithoutDomainSeparator for SignedIDkgComplaint {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// Opening related defines
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct IDkgOpeningContent {
    /// The opening
    pub idkg_opening: IDkgOpening,
}
pub type SignedIDkgOpening = Signed<IDkgOpeningContent, BasicSignature<IDkgOpeningContent>>;

impl SignedIDkgOpening {
    pub fn get(&self) -> &IDkgOpeningContent {
        &self.content
    }
}

impl From<&SignedIDkgOpening> for pb::SignedIDkgOpening {
    fn from(value: &SignedIDkgOpening) -> Self {
        Self {
            content: Some((&value.content).into()),
            signature: Some(value.signature.clone().into()),
        }
    }
}

impl TryFrom<&pb::SignedIDkgOpening> for SignedIDkgOpening {
    type Error = ProxyDecodeError;
    fn try_from(value: &pb::SignedIDkgOpening) -> Result<Self, Self::Error> {
        Ok(Self {
            content: try_from_option_field(value.content.as_ref(), "SignedIDkgOpening::content")?,
            signature: try_from_option_field(
                value.signature.clone(),
                "SignedIDkgOpening::signature",
            )?,
        })
    }
}

impl From<&IDkgOpeningContent> for pb::IDkgOpeningContent {
    fn from(value: &IDkgOpeningContent) -> Self {
        Self {
            idkg_opening: Some((&value.idkg_opening).into()),
        }
    }
}

impl TryFrom<&pb::IDkgOpeningContent> for IDkgOpeningContent {
    type Error = ProxyDecodeError;
    fn try_from(value: &pb::IDkgOpeningContent) -> Result<Self, Self::Error> {
        Ok(Self {
            idkg_opening: try_from_option_field(
                value.idkg_opening.as_ref(),
                "IDkgOpeningContent::idkg_opening",
            )?,
        })
    }
}

impl Display for SignedIDkgOpening {
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

impl SignedBytesWithoutDomainSeparator for IDkgOpeningContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

impl SignedBytesWithoutDomainSeparator for SignedIDkgOpening {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// The final output of the transcript creation sequence
pub type EcdsaTranscript = IDkgTranscript;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IDkgMessageAttribute {
    Dealing(IDkgTranscriptId),
    DealingSupport(IDkgTranscriptId),
    EcdsaSigShare(RequestId),
    SchnorrSigShare(RequestId),
    Complaint(IDkgTranscriptId),
    Opening(IDkgTranscriptId),
}

impl From<IDkgMessageAttribute> for pb::IDkgMessageAttribute {
    fn from(value: IDkgMessageAttribute) -> Self {
        use pb::i_dkg_message_attribute::Kind;
        let kind = match value {
            IDkgMessageAttribute::Dealing(id) => Kind::SignedDealing((&id).into()),
            IDkgMessageAttribute::DealingSupport(id) => Kind::DealingSupport((&id).into()),
            IDkgMessageAttribute::EcdsaSigShare(id) => Kind::EcdsaSigShare(id.into()),
            IDkgMessageAttribute::SchnorrSigShare(id) => Kind::SchnorrSigShare(id.into()),
            IDkgMessageAttribute::Complaint(id) => Kind::Complaint((&id).into()),
            IDkgMessageAttribute::Opening(id) => Kind::Opening((&id).into()),
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<pb::IDkgMessageAttribute> for IDkgMessageAttribute {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::IDkgMessageAttribute) -> Result<Self, Self::Error> {
        use pb::i_dkg_message_attribute::Kind;
        let Some(kind) = &value.kind else {
            return Err(ProxyDecodeError::MissingField("IDkgMessageAttribute::kind"));
        };
        Ok(match &kind {
            Kind::SignedDealing(id) => IDkgMessageAttribute::Dealing(id.try_into()?),
            Kind::DealingSupport(id) => IDkgMessageAttribute::DealingSupport(id.try_into()?),
            Kind::EcdsaSigShare(id) => IDkgMessageAttribute::EcdsaSigShare(id.try_into()?),
            Kind::SchnorrSigShare(id) => IDkgMessageAttribute::SchnorrSigShare(id.try_into()?),
            Kind::Complaint(id) => IDkgMessageAttribute::Complaint(id.try_into()?),
            Kind::Opening(id) => IDkgMessageAttribute::Opening(id.try_into()?),
        })
    }
}

impl From<&IDkgMessage> for IDkgMessageAttribute {
    fn from(msg: &IDkgMessage) -> IDkgMessageAttribute {
        match msg {
            IDkgMessage::Dealing(dealing) => {
                IDkgMessageAttribute::Dealing(dealing.content.transcript_id)
            }
            IDkgMessage::DealingSupport(support) => {
                IDkgMessageAttribute::DealingSupport(support.transcript_id)
            }
            IDkgMessage::EcdsaSigShare(share) => {
                IDkgMessageAttribute::EcdsaSigShare(share.request_id.clone())
            }
            IDkgMessage::SchnorrSigShare(share) => {
                IDkgMessageAttribute::SchnorrSigShare(share.request_id.clone())
            }
            IDkgMessage::Complaint(complaint) => {
                IDkgMessageAttribute::Complaint(complaint.content.idkg_complaint.transcript_id)
            }
            IDkgMessage::Opening(opening) => {
                IDkgMessageAttribute::Opening(opening.content.idkg_opening.transcript_id)
            }
        }
    }
}

impl IDkgMessageAttribute {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dealing(_) => "signed_dealing",
            Self::DealingSupport(_) => "dealing_support",
            Self::EcdsaSigShare(_) => "ecdsa_sig_share",
            Self::SchnorrSigShare(_) => "schnorr_sig_share",
            Self::Complaint(_) => "complaint",
            Self::Opening(_) => "opening",
        }
    }
}

impl TryFrom<IDkgMessage> for SignedIDkgDealing {
    type Error = IDkgMessage;
    fn try_from(msg: IDkgMessage) -> Result<Self, Self::Error> {
        match msg {
            IDkgMessage::Dealing(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<IDkgMessage> for IDkgDealingSupport {
    type Error = IDkgMessage;
    fn try_from(msg: IDkgMessage) -> Result<Self, Self::Error> {
        match msg {
            IDkgMessage::DealingSupport(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<IDkgMessage> for EcdsaSigShare {
    type Error = IDkgMessage;
    fn try_from(msg: IDkgMessage) -> Result<Self, Self::Error> {
        match msg {
            IDkgMessage::EcdsaSigShare(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<IDkgMessage> for SchnorrSigShare {
    type Error = IDkgMessage;
    fn try_from(msg: IDkgMessage) -> Result<Self, Self::Error> {
        match msg {
            IDkgMessage::SchnorrSigShare(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<IDkgMessage> for SignedIDkgComplaint {
    type Error = IDkgMessage;
    fn try_from(msg: IDkgMessage) -> Result<Self, Self::Error> {
        match msg {
            IDkgMessage::Complaint(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<IDkgMessage> for SignedIDkgOpening {
    type Error = IDkgMessage;
    fn try_from(msg: IDkgMessage) -> Result<Self, Self::Error> {
        match msg {
            IDkgMessage::Opening(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

pub type Summary = Option<EcdsaPayload>;

pub type Payload = Option<EcdsaPayload>;

impl From<&EcdsaPayload> for pb::EcdsaPayload {
    fn from(payload: &EcdsaPayload) -> Self {
        // signature_agreements
        let mut signature_agreements = Vec::new();
        for (pseudo_random_id, completed) in &payload.signature_agreements {
            let unreported = match completed {
                CompletedSignature::Unreported(response) => Some(response.into()),
                CompletedSignature::ReportedToExecution => None,
            };
            signature_agreements.push(pb::CompletedSignature {
                pseudo_random_id: pseudo_random_id.to_vec(),
                unreported,
            });
        }

        let mut available_pre_signatures = Vec::new();
        for (pre_sig_id, pre_sig) in &payload.available_pre_signatures {
            available_pre_signatures.push(pb::AvailablePreSignature {
                pre_signature_id: pre_sig_id.id(),
                pre_signature: Some(pre_sig.into()),
            });
        }

        let mut pre_signatures_in_creation = Vec::new();
        for (pre_sig_id, pre_sig) in &payload.pre_signatures_in_creation {
            pre_signatures_in_creation.push(pb::PreSignatureInProgress {
                pre_signature_id: pre_sig_id.id(),
                pre_signature: Some(pre_sig.into()),
            });
        }

        let next_unused_transcript_id: Option<subnet_pb::IDkgTranscriptId> =
            Some((&payload.uid_generator.next_unused_transcript_id).into());

        // idkg_transcripts
        let mut idkg_transcripts = Vec::new();
        for transcript in payload.idkg_transcripts.values() {
            idkg_transcripts.push(transcript.into());
        }

        // ongoing_xnet_reshares
        let mut ongoing_xnet_reshares = Vec::new();
        for (request, transcript) in &payload.ongoing_xnet_reshares {
            ongoing_xnet_reshares.push(pb::OngoingXnetReshare {
                request: Some(request.into()),
                transcript: Some(transcript.into()),
            });
        }

        // xnet_reshare_agreements
        let mut xnet_reshare_agreements = Vec::new();
        for (request, completed) in &payload.xnet_reshare_agreements {
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

        let key_transcripts: Vec<_> = payload
            .key_transcripts
            .values()
            .cloned()
            .map(pb::MasterKeyTranscript::from)
            .collect();

        Self {
            signature_agreements,
            available_pre_signatures,
            pre_signatures_in_creation,
            next_unused_transcript_id,
            next_unused_pre_signature_id: payload.uid_generator.next_unused_pre_signature_id,
            idkg_transcripts,
            ongoing_xnet_reshares,
            xnet_reshare_agreements,
            key_transcripts,
            // Kept for backwards compatibility
            generalized_pre_signatures: true,
        }
    }
}

impl TryFrom<(&pb::EcdsaPayload, Height)> for EcdsaPayload {
    type Error = ProxyDecodeError;
    fn try_from((payload, height): (&pb::EcdsaPayload, Height)) -> Result<Self, Self::Error> {
        let mut ret = EcdsaPayload::try_from(payload)?;
        ret.update_refs(height);
        Ok(ret)
    }
}

impl TryFrom<&pb::EcdsaPayload> for EcdsaPayload {
    type Error = ProxyDecodeError;
    fn try_from(payload: &pb::EcdsaPayload) -> Result<Self, Self::Error> {
        let mut key_transcripts = BTreeMap::new();

        for key_transcript_proto in &payload.key_transcripts {
            let key_transcript = MasterKeyTranscript::try_from(key_transcript_proto)?;

            key_transcripts.insert(key_transcript.key_id(), key_transcript);
        }

        let mut signature_agreements = BTreeMap::new();
        for completed_signature in &payload.signature_agreements {
            let pseudo_random_id = {
                if completed_signature.pseudo_random_id.len() != 32 {
                    return Err(ProxyDecodeError::Other(
                        "Expects 32 bytes of pseudo_random_id".to_string(),
                    ));
                }

                let mut x = [0; 32];
                x.copy_from_slice(&completed_signature.pseudo_random_id);
                x
            };

            let signature = if let Some(unreported) = &completed_signature.unreported {
                let response = crate::batch::ConsensusResponse::try_from(unreported.clone())?;
                CompletedSignature::Unreported(response)
            } else {
                CompletedSignature::ReportedToExecution
            };

            signature_agreements.insert(pseudo_random_id, signature);
        }

        // available_pre_signatures
        let mut available_pre_signatures = BTreeMap::new();
        for available_pre_signature in &payload.available_pre_signatures {
            let pre_signature_id = PreSigId(available_pre_signature.pre_signature_id);
            let pre_signature: PreSignatureRef = try_from_option_field(
                available_pre_signature.pre_signature.as_ref(),
                "EcdsaPayload::available_pre_signature::pre_signature",
            )?;
            available_pre_signatures.insert(pre_signature_id, pre_signature);
        }

        // pre_signatures_in_creation
        let mut pre_signatures_in_creation = BTreeMap::new();
        for pre_signature_in_creation in &payload.pre_signatures_in_creation {
            let pre_signature_id = PreSigId(pre_signature_in_creation.pre_signature_id);
            let pre_signature: PreSignatureInCreation = try_from_option_field(
                pre_signature_in_creation.pre_signature.as_ref(),
                "EcdsaPayload::pre_signature_in_creation::pre_signature",
            )?;
            pre_signatures_in_creation.insert(pre_signature_id, pre_signature);
        }

        let next_unused_transcript_id: IDkgTranscriptId = try_from_option_field(
            payload.next_unused_transcript_id.as_ref(),
            "EcdsaPayload::next_unused_transcript_id",
        )?;

        let uid_generator = EcdsaUIDGenerator {
            next_unused_transcript_id,
            next_unused_pre_signature_id: payload.next_unused_pre_signature_id,
        };

        // idkg_transcripts
        let mut idkg_transcripts = BTreeMap::new();
        for proto in &payload.idkg_transcripts {
            let transcript: IDkgTranscript = proto.try_into().map_err(|err| {
                ProxyDecodeError::Other(format!(
                    "EcdsaPayload:: Failed to convert transcript: {:?}",
                    err
                ))
            })?;
            let transcript_id = transcript.transcript_id;
            idkg_transcripts.insert(transcript_id, transcript);
        }

        // ongoing_xnet_reshares
        let mut ongoing_xnet_reshares = BTreeMap::new();
        for reshare in &payload.ongoing_xnet_reshares {
            let request: IDkgReshareRequest =
                try_from_option_field(reshare.request.as_ref(), "EcdsaPayload::reshare::request")?;

            let transcript: ReshareOfUnmaskedParams = try_from_option_field(
                reshare.transcript.as_ref(),
                "EcdsaPayload::reshare::transcript",
            )?;
            ongoing_xnet_reshares.insert(request, transcript);
        }

        // xnet_reshare_agreements
        let mut xnet_reshare_agreements = BTreeMap::new();
        for agreement in &payload.xnet_reshare_agreements {
            let request: IDkgReshareRequest = try_from_option_field(
                agreement.request.as_ref(),
                "EcdsaPayload::agreement::request",
            )?;

            let completed = match &agreement.initial_dealings {
                Some(response) => {
                    let unreported = response.clone().try_into().map_err(|err| {
                        ProxyDecodeError::Other(format!(
                            "EcdsaPayload:: failed to convert initial dealing: {:?}",
                            err
                        ))
                    })?;
                    CompletedReshareRequest::Unreported(unreported)
                }
                None => CompletedReshareRequest::ReportedToExecution,
            };
            xnet_reshare_agreements.insert(request, completed);
        }

        Ok(Self {
            signature_agreements,
            available_pre_signatures,
            pre_signatures_in_creation,
            idkg_transcripts,
            ongoing_xnet_reshares,
            xnet_reshare_agreements,
            uid_generator,
            key_transcripts,
        })
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
pub trait IDkgStats: Send + Sync {
    /// Updates the set of transcripts being tracked currently.
    fn update_active_transcripts(&self, block_reader: &dyn EcdsaBlockReader);

    /// Updates the set of pre-signatures being tracked currently.
    fn update_active_pre_signatures(&self, block_reader: &dyn EcdsaBlockReader);

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
    fn update_active_signature_requests(&self, requests: Vec<RequestId>);

    /// Records the time taken to verify the signature share received for a request.
    fn record_sig_share_validation(&self, request_id: &RequestId, duration: Duration);

    /// Records the time taken to aggregate the signature shares for a request.
    fn record_sig_share_aggregation(&self, request_id: &RequestId, duration: Duration);
}

/// IDkgObject should be implemented by the ECDSA message types
/// (e.g) Dealing, DealingSupport, etc
pub trait IDkgObject: CryptoHashable + Clone + Sized {
    /// Returns the artifact prefix.
    fn message_prefix(&self) -> IDkgPrefixOf<Self>;

    /// Returns the artifact Id.
    fn message_id(&self) -> IDkgArtifactId;
}

impl IDkgObject for SignedIDkgDealing {
    fn message_prefix(&self) -> IDkgPrefixOf<Self> {
        dealing_prefix(&self.idkg_dealing().transcript_id, &self.dealer_id())
    }

    fn message_id(&self) -> IDkgArtifactId {
        IDkgArtifactId::Dealing(self.message_prefix(), crypto_hash(self))
    }
}

impl IDkgObject for IDkgDealingSupport {
    fn message_prefix(&self) -> IDkgPrefixOf<Self> {
        dealing_support_prefix(&self.transcript_id, &self.dealer_id, &self.sig_share.signer)
    }

    fn message_id(&self) -> IDkgArtifactId {
        IDkgArtifactId::DealingSupport(self.message_prefix(), crypto_hash(self))
    }
}

impl IDkgObject for EcdsaSigShare {
    fn message_prefix(&self) -> IDkgPrefixOf<Self> {
        ecdsa_sig_share_prefix(&self.request_id, &self.signer_id)
    }

    fn message_id(&self) -> IDkgArtifactId {
        IDkgArtifactId::EcdsaSigShare(self.message_prefix(), crypto_hash(self))
    }
}

impl IDkgObject for SchnorrSigShare {
    fn message_prefix(&self) -> IDkgPrefixOf<Self> {
        schnorr_sig_share_prefix(&self.request_id, &self.signer_id)
    }

    fn message_id(&self) -> IDkgArtifactId {
        IDkgArtifactId::SchnorrSigShare(self.message_prefix(), crypto_hash(self))
    }
}

impl IDkgObject for SignedIDkgComplaint {
    fn message_prefix(&self) -> IDkgPrefixOf<Self> {
        complaint_prefix(
            &self.content.idkg_complaint.transcript_id,
            &self.content.idkg_complaint.dealer_id,
            &self.signature.signer,
        )
    }

    fn message_id(&self) -> IDkgArtifactId {
        IDkgArtifactId::Complaint(self.message_prefix(), crypto_hash(self))
    }
}

impl IDkgObject for SignedIDkgOpening {
    fn message_prefix(&self) -> IDkgPrefixOf<Self> {
        opening_prefix(
            &self.content.idkg_opening.transcript_id,
            &self.content.idkg_opening.dealer_id,
            &self.signature.signer,
        )
    }

    fn message_id(&self) -> IDkgArtifactId {
        IDkgArtifactId::Opening(self.message_prefix(), crypto_hash(self))
    }
}

impl From<&IDkgMessage> for IDkgArtifactId {
    fn from(msg: &IDkgMessage) -> IDkgArtifactId {
        match msg {
            IDkgMessage::Dealing(object) => object.message_id(),
            IDkgMessage::DealingSupport(object) => object.message_id(),
            IDkgMessage::EcdsaSigShare(object) => object.message_id(),
            IDkgMessage::SchnorrSigShare(object) => object.message_id(),
            IDkgMessage::Complaint(object) => object.message_id(),
            IDkgMessage::Opening(object) => object.message_id(),
        }
    }
}

pub trait HasMasterPublicKeyId {
    /// Returns a reference to the [`MasterPublicKeyId`] associated with the object.
    fn key_id(&self) -> MasterPublicKeyId;
}

impl HasMasterPublicKeyId for QuadrupleInCreation {
    fn key_id(&self) -> MasterPublicKeyId {
        MasterPublicKeyId::Ecdsa(self.key_id.clone())
    }
}

impl HasMasterPublicKeyId for PreSignatureQuadrupleRef {
    fn key_id(&self) -> MasterPublicKeyId {
        MasterPublicKeyId::Ecdsa(self.key_id.clone())
    }
}

impl HasMasterPublicKeyId for PreSignatureInCreation {
    fn key_id(&self) -> MasterPublicKeyId {
        match self {
            PreSignatureInCreation::Ecdsa(quadruple) => {
                MasterPublicKeyId::Ecdsa(quadruple.key_id.clone())
            }
            PreSignatureInCreation::Schnorr(transcript) => {
                MasterPublicKeyId::Schnorr(transcript.key_id.clone())
            }
        }
    }
}

impl HasMasterPublicKeyId for PreSignatureRef {
    fn key_id(&self) -> MasterPublicKeyId {
        match self {
            PreSignatureRef::Ecdsa(quadruple) => MasterPublicKeyId::Ecdsa(quadruple.key_id.clone()),
            PreSignatureRef::Schnorr(transcript) => {
                MasterPublicKeyId::Schnorr(transcript.key_id.clone())
            }
        }
    }
}

impl HasMasterPublicKeyId for IDkgReshareRequest {
    fn key_id(&self) -> MasterPublicKeyId {
        self.master_key_id.clone()
    }
}

impl HasMasterPublicKeyId for MasterKeyTranscript {
    fn key_id(&self) -> MasterPublicKeyId {
        self.master_key_id.clone()
    }
}

impl<T: HasMasterPublicKeyId, U> HasMasterPublicKeyId for (T, U) {
    fn key_id(&self) -> MasterPublicKeyId {
        self.0.key_id()
    }
}

impl<T: HasMasterPublicKeyId> HasMasterPublicKeyId for &T {
    fn key_id(&self) -> MasterPublicKeyId {
        (*self).key_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_generator_pre_signature_ids_are_globally_unique_test() {
        let mut uid_generator =
            EcdsaUIDGenerator::new(ic_types_test_utils::ids::SUBNET_0, Height::new(100));

        let pre_sig_id_0 = uid_generator.next_pre_signature_id();
        let pre_sig_id_1 = uid_generator.next_pre_signature_id();
        let pre_sig_id_2 = uid_generator.next_pre_signature_id();

        assert_eq!(pre_sig_id_0.id(), 0);
        assert_eq!(pre_sig_id_1.id(), 1);
        assert_eq!(pre_sig_id_2.id(), 2);
    }
}
