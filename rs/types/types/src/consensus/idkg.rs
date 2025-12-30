//! Defines types used for threshold master key generation.

use crate::artifact::{IdentifiableArtifact, PbArtifact};
pub use crate::consensus::idkg::common::{
    IDkgBlockReader, IDkgTranscriptAttributes, IDkgTranscriptOperationRef, IDkgTranscriptParamsRef,
    MaskedTranscript, PreSigId, PseudoRandomId, RandomTranscriptParams,
    RandomUnmaskedTranscriptParams, RequestId, ReshareOfMaskedParams, ReshareOfUnmaskedParams,
    TranscriptAttributes, TranscriptCastError, TranscriptLookupError, TranscriptParamsError,
    TranscriptRef, UnmaskedTimesMaskedParams, UnmaskedTranscript,
    unpack_reshare_of_unmasked_params,
};
use crate::consensus::idkg::ecdsa::{PreSignatureQuadrupleRef, QuadrupleInCreation};
use crate::crypto::vetkd::VetKdEncryptedKeyShareContent;
use crate::{
    Height, NodeId, RegistryVersion, SubnetId,
    consensus::BasicSignature,
    crypto::{
        AlgorithmId, CryptoHash, CryptoHashOf, CryptoHashable, Signed,
        SignedBytesWithoutDomainSeparator,
        canister_threshold_sig::{
            ThresholdEcdsaSigShare, ThresholdSchnorrSigShare,
            error::*,
            idkg::{
                IDkgComplaint, IDkgDealingSupport, IDkgOpening, IDkgTranscript, IDkgTranscriptId,
                IDkgTranscriptParams, InitialIDkgDealings, SignedIDkgDealing,
            },
        },
        crypto_hash,
    },
    node_id_into_protobuf, node_id_try_from_option,
};
use common::SignatureScheme;
use ic_base_types::{subnet_id_into_protobuf, subnet_id_try_from_protobuf};
use ic_crypto_sha2::Sha256;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_protobuf::types::v1 as pb_types;
use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    registry::subnet::v1 as subnet_pb,
    types::v1 as pb,
};
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::{TryFrom, TryInto},
    fmt::{self, Display, Formatter},
    hash::Hash,
    time::Duration,
};
use strum_macros::EnumIter;

use self::common::{PreSignatureInCreation, PreSignatureRef};

use super::vetkd::VetKdEncryptedKeyShare;

pub mod common;
pub mod ecdsa;
pub mod schnorr;

/// If enabled, pre-signature artifacts required to serve canister threshold signature requests
/// (tECDSA/tSchnorr) will be stored in the pre-signature stash residing in replicated state.
/// This means they will be immediately purged from the blockchain once delivered.
/// If disabled, pre-signatures remain on the blockchain, until they are consumed by a signature
/// request.
pub const STORE_PRE_SIGNATURES_IN_STATE: bool = false;

/// For completed signature requests, we differentiate between those
/// that have already been reported and those that have not. This is
/// to prevent signatures from being reported more than once.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum CompletedSignature {
    ReportedToExecution,
    Unreported(crate::batch::ConsensusResponse),
}

/// A [`MasterPublicKeyId`], that contains a variant that is compatible with the IDKG protocol.
///
/// The [`MasterPublicKeyId`] can hold a number of different key types.
/// Some of them can be used with the IDKG protocol, while others can not.
/// The [`IDkgMasterPublicKeyId`] type indicates, that this key id can be used with a IDKG protocol.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct IDkgMasterPublicKeyId(MasterPublicKeyId);

impl TryFrom<MasterPublicKeyId> for IDkgMasterPublicKeyId {
    type Error = String;

    fn try_from(val: MasterPublicKeyId) -> Result<Self, Self::Error> {
        if !val.is_idkg_key() {
            Err("This key is not an idkg key".to_string())
        } else {
            Ok(Self(val))
        }
    }
}

impl From<IDkgMasterPublicKeyId> for MasterPublicKeyId {
    fn from(val: IDkgMasterPublicKeyId) -> Self {
        val.0
    }
}

impl IDkgMasterPublicKeyId {
    pub fn inner(&self) -> &MasterPublicKeyId {
        &self.0
    }

    /// Return the transcript capacity required to create a pre-signature for this key ID
    pub fn required_pre_sig_capacity(&self) -> usize {
        match self.inner() {
            // Ecdsa pre-signatures require working on 2 transcripts in parallel
            MasterPublicKeyId::Ecdsa(_) => 2,
            // Schnorr pre-signatures consist of only 1 transcript
            MasterPublicKeyId::Schnorr(_) => 1,
            MasterPublicKeyId::VetKd(_) => unreachable!("not an IDkg Key"),
        }
    }
}

impl std::ops::Deref for IDkgMasterPublicKeyId {
    type Target = MasterPublicKeyId;

    fn deref(&self) -> &<Self as std::ops::Deref>::Target {
        self.inner()
    }
}

impl std::borrow::Borrow<MasterPublicKeyId> for IDkgMasterPublicKeyId {
    fn borrow(&self) -> &MasterPublicKeyId {
        self.inner()
    }
}

impl std::fmt::Display for IDkgMasterPublicKeyId {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(fmt, "{}", &self.0)
    }
}

impl Serialize for IDkgMasterPublicKeyId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for IDkgMasterPublicKeyId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<IDkgMasterPublicKeyId, D::Error> {
        use serde::de::Error;

        let master_public_key_id: MasterPublicKeyId =
            serde::Deserialize::deserialize(deserializer)?;

        if !master_public_key_id.is_idkg_key() {
            Err(D::Error::custom(
                "expected an idkg variant of MasterPublicKeyId",
            ))
        } else {
            Ok(Self(master_public_key_id))
        }
    }
}

/// Common data that is carried in both `IDkgSummaryPayload` and `IDkgDataPayload`.
/// published on every consensus round. It represents the current state of the
/// protocol since the summary block.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct IDkgPayload {
    /// Collection of completed signatures.
    pub signature_agreements: BTreeMap<PseudoRandomId, CompletedSignature>,

    /// IDKG transcript Pre-Signatures that we can use to create threshold signatures.
    pub available_pre_signatures: BTreeMap<PreSigId, PreSignatureRef>,

    /// Pre-Signature in creation.
    pub pre_signatures_in_creation: BTreeMap<PreSigId, PreSignatureInCreation>,

    /// Generator of unique ids.
    pub uid_generator: IDkgUIDGenerator,

    /// Transcripts created at this height.
    pub idkg_transcripts: BTreeMap<IDkgTranscriptId, IDkgTranscript>,

    /// Resharing requests in progress.
    pub ongoing_xnet_reshares: BTreeMap<IDkgReshareRequest, ReshareOfUnmaskedParams>,

    /// Completed resharing requests.
    pub xnet_reshare_agreements: BTreeMap<IDkgReshareRequest, CompletedReshareRequest>,

    /// State of the key transcripts.
    pub key_transcripts: BTreeMap<IDkgMasterPublicKeyId, MasterKeyTranscript>,
}

impl IDkgPayload {
    /// Creates an empty IDkg payload.
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
            uid_generator: IDkgUIDGenerator::new(subnet_id, height),
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

    /// Return an iterator of all transcript configs that have no matching
    /// results yet.
    pub fn iter_pre_sig_transcript_configs_in_creation(
        &self,
    ) -> impl Iterator<Item = &IDkgTranscriptParamsRef> + '_ {
        self.pre_signatures_in_creation
            .iter()
            .flat_map(|(_, pre_sig)| pre_sig.iter_transcript_configs_in_creation())
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
        key_id: &'a IDkgMasterPublicKeyId,
    ) -> impl Iterator<Item = PreSigId> + 'a {
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
    /// Note that we do not consider available pre-signatures here because it would
    /// prevent nodes from leaving when the pre-signatures are not consumed.
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

    /// Return the total transcript capacity consumed by ongoing pre-signatures in this payload
    pub fn consumed_pre_sig_capacity(&self) -> usize {
        self.pre_signatures_in_creation
            .values()
            .map(|pre_sig| pre_sig.key_id().required_pre_sig_capacity())
            .sum()
    }
}

/// The unmasked transcript is paired with its attributes, which will be used
/// in creating reshare params.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct MasterKeyTranscript {
    /// The key transcript used for the current interval.
    pub current: Option<UnmaskedTranscriptWithAttributes>,
    /// Progress of creating the next key transcript.
    pub next_in_creation: KeyTranscriptCreation,
    /// Master key Id allowing different signature schemes.
    pub master_key_id: IDkgMasterPublicKeyId,
}

impl MasterKeyTranscript {
    pub fn new(key_id: IDkgMasterPublicKeyId, next_in_creation: KeyTranscriptCreation) -> Self {
        Self {
            current: None,
            next_in_creation,
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
            KeyTranscriptCreation::Begin => write!(f, "{current}, Next = Begin"),
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
            KeyTranscriptCreation::Created(x) => write!(f, "{current}, Next = Created({x:?})"),
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
            master_key_id: Some(pb_types::MasterPublicKeyId::from(
                transcript.master_key_id.inner(),
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
        let current = proto
            .current
            .as_ref()
            .map(UnmaskedTranscriptWithAttributes::try_from)
            .transpose()?;

        let next_in_creation = try_from_option_field(
            proto.next_in_creation.as_ref(),
            "KeyTranscript::next_in_creation",
        )?;

        let master_key_id: MasterPublicKeyId =
            try_from_option_field(proto.master_key_id, "KeyTranscript::master_key_id")?;
        let master_key_id = master_key_id.try_into().map_err(ProxyDecodeError::Other)?;

        Ok(Self {
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

/// The creation of a master key transcript goes through one of the three paths below:
/// 1. Begin -> RandomTranscript -> ReshareOfMasked -> Created
/// 2. Begin -> ReshareOfUnmasked -> Created
/// 3. XnetReshareOfUnmaskedParams -> Created (xnet bootstrapping from initial dealings)
///
/// The initial bootstrap will start with an empty 'IDkgSummaryPayload', and then
/// we'll go through the first path to create the key transcript.
///
/// After the initial key transcript is created, we will be able to create the first
/// 'IDkgSummaryPayload' by carrying over the key transcript, which will be carried
/// over to the next DKG interval if there is no node membership change.
///
/// If in the future there is a membership change, we will create a new key transcript
/// by going through the second path above. Then the switch-over will happen at
/// the next 'IDkgSummaryPayload'.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
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
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct IDkgReshareRequest {
    pub master_key_id: IDkgMasterPublicKeyId,
    pub receiving_node_ids: Vec<NodeId>,
    pub registry_version: RegistryVersion,
}

impl From<&IDkgReshareRequest> for pb::IDkgReshareRequest {
    fn from(request: &IDkgReshareRequest) -> Self {
        let mut receiving_node_ids = Vec::new();
        for node in &request.receiving_node_ids {
            receiving_node_ids.push(node_id_into_protobuf(*node));
        }

        let master_key_id: &MasterPublicKeyId = &request.master_key_id;
        Self {
            master_key_id: Some((master_key_id).into()),
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

        let master_key_id: MasterPublicKeyId = try_from_option_field(
            request.master_key_id.clone(),
            "IDkgReshareRequest::master_key_id",
        )?;
        let master_key_id = master_key_id.try_into().map_err(ProxyDecodeError::Other)?;

        Ok(Self {
            master_key_id,
            receiving_node_ids,
            registry_version: RegistryVersion::new(request.registry_version),
        })
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum CompletedReshareRequest {
    ReportedToExecution,
    Unreported(crate::batch::ConsensusResponse),
}

/// To make sure all ids used in IDkg payload are uniquely generated,
/// we use a generator to keep track of this state.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct IDkgUIDGenerator {
    next_unused_transcript_id: IDkgTranscriptId,
    next_unused_pre_signature_id: u64,
}

impl IDkgUIDGenerator {
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

/// The IDKG artifact.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub enum IDkgMessage {
    Dealing(SignedIDkgDealing),
    DealingSupport(IDkgDealingSupport),
    EcdsaSigShare(EcdsaSigShare),
    SchnorrSigShare(SchnorrSigShare),
    VetKdKeyShare(VetKdKeyShare),
    Complaint(SignedIDkgComplaint),
    Opening(SignedIDkgOpening),
    Transcript(IDkgTranscript),
}

impl IdentifiableArtifact for IDkgMessage {
    const NAME: &'static str = "idkg";
    type Id = IDkgArtifactId;
    fn id(&self) -> Self::Id {
        self.message_id()
    }
}

impl PbArtifact for IDkgMessage {
    type PbId = ic_protobuf::types::v1::IDkgArtifactId;
    type PbIdError = ProxyDecodeError;
    type PbMessage = ic_protobuf::types::v1::IDkgMessage;
    type PbMessageError = ProxyDecodeError;
}

impl IDkgMessage {
    pub fn message_id(&self) -> IDkgArtifactId {
        match self {
            IDkgMessage::Dealing(x) => x.message_id(),
            IDkgMessage::DealingSupport(x) => x.message_id(),
            IDkgMessage::EcdsaSigShare(x) => x.message_id(),
            IDkgMessage::SchnorrSigShare(x) => x.message_id(),
            IDkgMessage::VetKdKeyShare(x) => x.message_id(),
            IDkgMessage::Complaint(x) => x.message_id(),
            IDkgMessage::Opening(x) => x.message_id(),
            IDkgMessage::Transcript(x) => x.message_id(),
        }
    }

    pub fn sig_share_dedup_key(&self) -> Option<(RequestId, NodeId)> {
        match self {
            IDkgMessage::EcdsaSigShare(x) => Some((x.request_id, x.signer_id)),
            IDkgMessage::SchnorrSigShare(x) => Some((x.request_id, x.signer_id)),
            IDkgMessage::VetKdKeyShare(x) => Some((x.request_id, x.signer_id)),
            IDkgMessage::Dealing(_)
            | IDkgMessage::DealingSupport(_)
            | IDkgMessage::Complaint(_)
            | IDkgMessage::Opening(_) => None,
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
            IDkgMessage::VetKdKeyShare(x) => Msg::VetkdKeyShare(x.into()),
            IDkgMessage::Complaint(x) => Msg::Complaint(x.into()),
            IDkgMessage::Opening(x) => Msg::Opening(x.into()),
            IDkgMessage::Transcript(x) => Msg::Transcript(x.into()),
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
            Msg::VetkdKeyShare(x) => IDkgMessage::VetKdKeyShare(x.try_into()?),
            Msg::Complaint(x) => IDkgMessage::Complaint(x.try_into()?),
            Msg::Opening(x) => IDkgMessage::Opening(x.try_into()?),
            Msg::Transcript(x) => IDkgMessage::Transcript(x.try_into()?),
        })
    }
}

/// IDkgArtifactId is the unique identifier for the artifacts. It is made of a prefix + additional
/// data of the message itself:
/// IDkgArtifactId = `<IDkgPrefix, IdData<Message>>`
/// IDkgPrefix     = <8 byte group tag, 8 byte meta info hash>
///
/// Two kinds of look up are possible with this:
/// 1. Look up by full key of <prefix + id data>, which would return the matching
///    artifact if present.
/// 2. Look up by prefix match. This can return 0 or more entries, as several artifacts may share
///    the same prefix. The caller is expected to filter the returned entries as needed. The look up
///    by prefix makes some frequent queries more efficient (e.g) to know if a node has already
///    issued a support for a <transcript Id, dealer Id>, we could iterate through all the
///    entries in the support pool looking for a matching artifact. Instead, we could issue a
///    single prefix query for prefix = <transcript Id, dealer Id, support signer Id>.
///
/// - The group tag creates an ordering of the messages
///   We previously identified the messages only by CryptoHash. This loses any ordering
///   info (e.g) if we want to iterate/process the messages related to older transcripts ahead of
///   the newer ones, this is not possible with CryptoHash. The group tag automatically
///   creates an ordering/grouping (e.g) this is set to transcript Id for dealings and support
///   shares.
///
/// - The meta info hash maps variable length meta info fields into a fixed length
///   hash, which simplifies the design and easy to work with LMDB keys. Ideally, we would like to
///   look up by a list of relevant fields (e.g) dealings by <transcript Id, dealer Id>,
///   support shares by <transcript Id, dealer Id, support signer Id>, complaints by
///   <transcript Id, dealer Id, complainer Id>, etc. But this requires different way of
///   indexing for the different sub pools. Instead, mapping these fields to the hash creates an
///   uniform indexing mechanism for all the sub pools.
///
/// On the down side, more than one artifact may map to the same hash value. So the caller
/// would need to do an exact match to filter as needed. But the collisions are expected to
/// be rare, and the prefix lookup should usually return a single entry.
///
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct IDkgPrefix {
    group_tag: u64,
    meta_hash: u64,
}

impl IDkgPrefix {
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

impl From<&IDkgPrefix> for pb::IDkgPrefix {
    fn from(value: &IDkgPrefix) -> Self {
        Self {
            group_tag: value.group_tag,
            meta_hash: value.meta_hash,
        }
    }
}

impl From<&pb::IDkgPrefix> for IDkgPrefix {
    fn from(value: &pb::IDkgPrefix) -> Self {
        Self {
            group_tag: value.group_tag,
            meta_hash: value.meta_hash,
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

    IDkgPrefixOf::new(IDkgPrefix::new(transcript_id.id(), hasher.finish()))
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

    IDkgPrefixOf::new(IDkgPrefix::new(transcript_id.id(), hasher.finish()))
}

pub fn ecdsa_sig_share_prefix(
    request_id: &RequestId,
    sig_share_node_id: &NodeId,
) -> IDkgPrefixOf<EcdsaSigShare> {
    // Group_tag: callback Id, Meta info: <sig share sender>
    let mut hasher = Sha256::new();
    sig_share_node_id.hash(&mut hasher);

    IDkgPrefixOf::new(IDkgPrefix::new(
        request_id.callback_id.get(),
        hasher.finish(),
    ))
}

pub fn schnorr_sig_share_prefix(
    request_id: &RequestId,
    sig_share_node_id: &NodeId,
) -> IDkgPrefixOf<SchnorrSigShare> {
    // Group_tag: callback Id, Meta info: <sig share sender>
    let mut hasher = Sha256::new();
    sig_share_node_id.hash(&mut hasher);

    IDkgPrefixOf::new(IDkgPrefix::new(
        request_id.callback_id.get(),
        hasher.finish(),
    ))
}

pub fn vetkd_key_share_prefix(
    request_id: &RequestId,
    vetkd_key_share_node_id: &NodeId,
) -> IDkgPrefixOf<VetKdKeyShare> {
    // Group_tag: callback Id, Meta info: <sig share sender>
    let mut hasher = Sha256::new();
    vetkd_key_share_node_id.hash(&mut hasher);

    IDkgPrefixOf::new(IDkgPrefix::new(
        request_id.callback_id.get(),
        hasher.finish(),
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

    IDkgPrefixOf::new(IDkgPrefix::new(transcript_id.id(), hasher.finish()))
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

    IDkgPrefixOf::new(IDkgPrefix::new(transcript_id.id(), hasher.finish()))
}

pub fn transcript_prefix(transcript_id: &IDkgTranscriptId) -> IDkgPrefixOf<IDkgTranscript> {
    // Group_tag: transcript Id, Meta info: none
    IDkgPrefixOf::new(IDkgPrefix::new_with_meta_hash(transcript_id.id(), 0))
}

/// Represent the different ways of iterating through entries that share a same pattern.
///
/// The pattern must be a prefix of the entry key as we leverage the fact that the keys are sorted
/// when iterating.
#[derive(Clone)]
pub enum IterationPattern {
    GroupTag(u64),
    Prefix(IDkgPrefix),
}

pub type IDkgArtifactIdDataOf<T> = Id<T, IDkgArtifactIdData>;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct IDkgArtifactIdData {
    /// The height at which this IDkg instance was requested.
    pub height: Height,
    /// The cryptographic hash of the message.
    pub hash: CryptoHash,
    /// The subnet on which this IDkg instance was requested. This is required to
    /// identify artifacts for key resharings via cross-net.
    pub subnet_id: SubnetId,
}

impl From<IDkgArtifactIdData> for pb::IDkgArtifactIdData {
    fn from(value: IDkgArtifactIdData) -> Self {
        Self {
            height: value.height.get(),
            hash: value.hash.0,
            subnet_id: Some(subnet_id_into_protobuf(value.subnet_id)),
        }
    }
}

impl TryFrom<pb::IDkgArtifactIdData> for IDkgArtifactIdData {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::IDkgArtifactIdData) -> Result<Self, Self::Error> {
        Ok(Self {
            height: Height::from(value.height),
            subnet_id: subnet_id_try_from_protobuf(try_from_option_field(
                value.subnet_id,
                "IDkgArtifactIdData::subnet_id",
            )?)?,
            hash: CryptoHash(value.hash),
        })
    }
}

pub type SigShareIdDataOf<T> = Id<T, SigShareIdData>;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct SigShareIdData {
    /// The height at which the signature request was paired with a pre-signature
    pub height: Height,
    /// The cryptographic hash of the message.
    pub hash: CryptoHash,
}

impl From<SigShareIdData> for pb::SigShareIdData {
    fn from(value: SigShareIdData) -> Self {
        Self {
            height: value.height.get(),
            hash: value.hash.0,
        }
    }
}

impl TryFrom<pb::SigShareIdData> for SigShareIdData {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::SigShareIdData) -> Result<Self, Self::Error> {
        Ok(Self {
            height: Height::from(value.height),
            hash: CryptoHash(value.hash),
        })
    }
}

/// The identifier for artifacts/messages consists of a prefix and additional Id data.
/// The prefix may be used for sorting and range queries in tree-like structures.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub enum IDkgArtifactId {
    Dealing(
        IDkgPrefixOf<SignedIDkgDealing>,
        IDkgArtifactIdDataOf<SignedIDkgDealing>,
    ),
    DealingSupport(
        IDkgPrefixOf<IDkgDealingSupport>,
        IDkgArtifactIdDataOf<IDkgDealingSupport>,
    ),
    EcdsaSigShare(IDkgPrefixOf<EcdsaSigShare>, SigShareIdDataOf<EcdsaSigShare>),
    SchnorrSigShare(
        IDkgPrefixOf<SchnorrSigShare>,
        SigShareIdDataOf<SchnorrSigShare>,
    ),
    VetKdKeyShare(IDkgPrefixOf<VetKdKeyShare>, SigShareIdDataOf<VetKdKeyShare>),
    Complaint(
        IDkgPrefixOf<SignedIDkgComplaint>,
        IDkgArtifactIdDataOf<SignedIDkgComplaint>,
    ),
    Opening(
        IDkgPrefixOf<SignedIDkgOpening>,
        IDkgArtifactIdDataOf<SignedIDkgOpening>,
    ),
    Transcript(
        IDkgPrefixOf<IDkgTranscript>,
        IDkgArtifactIdDataOf<IDkgTranscript>,
    ),
}

impl IDkgArtifactId {
    pub fn prefix(&self) -> IDkgPrefix {
        match self {
            IDkgArtifactId::Dealing(prefix, _) => prefix.as_ref().clone(),
            IDkgArtifactId::DealingSupport(prefix, _) => prefix.as_ref().clone(),
            IDkgArtifactId::EcdsaSigShare(prefix, _) => prefix.as_ref().clone(),
            IDkgArtifactId::SchnorrSigShare(prefix, _) => prefix.as_ref().clone(),
            IDkgArtifactId::VetKdKeyShare(prefix, _) => prefix.as_ref().clone(),
            IDkgArtifactId::Complaint(prefix, _) => prefix.as_ref().clone(),
            IDkgArtifactId::Opening(prefix, _) => prefix.as_ref().clone(),
            IDkgArtifactId::Transcript(prefix, _) => prefix.as_ref().clone(),
        }
    }

    pub fn hash(&self) -> CryptoHash {
        match self {
            IDkgArtifactId::Dealing(_, data) => data.as_ref().hash.clone(),
            IDkgArtifactId::DealingSupport(_, data) => data.as_ref().hash.clone(),
            IDkgArtifactId::EcdsaSigShare(_, data) => data.as_ref().hash.clone(),
            IDkgArtifactId::SchnorrSigShare(_, data) => data.as_ref().hash.clone(),
            IDkgArtifactId::VetKdKeyShare(_, data) => data.as_ref().hash.clone(),
            IDkgArtifactId::Complaint(_, data) => data.as_ref().hash.clone(),
            IDkgArtifactId::Opening(_, data) => data.as_ref().hash.clone(),
            IDkgArtifactId::Transcript(_, data) => data.as_ref().hash.clone(),
        }
    }

    pub fn height(&self) -> Height {
        match self {
            IDkgArtifactId::Dealing(_, data) => data.as_ref().height,
            IDkgArtifactId::DealingSupport(_, data) => data.as_ref().height,
            IDkgArtifactId::EcdsaSigShare(_, data) => data.as_ref().height,
            IDkgArtifactId::SchnorrSigShare(_, data) => data.as_ref().height,
            IDkgArtifactId::VetKdKeyShare(_, data) => data.as_ref().height,
            IDkgArtifactId::Complaint(_, data) => data.as_ref().height,
            IDkgArtifactId::Opening(_, data) => data.as_ref().height,
            IDkgArtifactId::Transcript(_, data) => data.as_ref().height,
        }
    }

    pub fn dealing_hash(&self) -> Option<CryptoHashOf<SignedIDkgDealing>> {
        match self {
            Self::Dealing(_, data) => Some(CryptoHashOf::new(data.as_ref().hash.clone())),
            _ => None,
        }
    }
}

impl From<IDkgArtifactId> for pb::IDkgArtifactId {
    fn from(value: IDkgArtifactId) -> Self {
        use pb::i_dkg_artifact_id::Kind;
        let kind = match value.clone() {
            IDkgArtifactId::Dealing(p, d) => Kind::Dealing(pb::PrefixPairIDkg {
                prefix: Some((&p.get()).into()),
                id_data: Some(pb::IDkgArtifactIdData::from(d.get())),
            }),
            IDkgArtifactId::DealingSupport(p, d) => Kind::DealingSupport(pb::PrefixPairIDkg {
                prefix: Some((&p.get()).into()),
                id_data: Some(pb::IDkgArtifactIdData::from(d.get())),
            }),
            IDkgArtifactId::EcdsaSigShare(p, d) => Kind::EcdsaSigShare(pb::PrefixPairSigShare {
                prefix: Some((&p.get()).into()),
                id_data: Some(pb::SigShareIdData::from(d.get())),
            }),
            IDkgArtifactId::SchnorrSigShare(p, d) => {
                Kind::SchnorrSigShare(pb::PrefixPairSigShare {
                    prefix: Some((&p.get()).into()),
                    id_data: Some(pb::SigShareIdData::from(d.get())),
                })
            }
            IDkgArtifactId::VetKdKeyShare(p, d) => Kind::VetkdKeyShare(pb::PrefixPairSigShare {
                prefix: Some((&p.get()).into()),
                id_data: Some(pb::SigShareIdData::from(d.get())),
            }),
            IDkgArtifactId::Complaint(p, d) => Kind::Complaint(pb::PrefixPairIDkg {
                prefix: Some((&p.get()).into()),
                id_data: Some(pb::IDkgArtifactIdData::from(d.get())),
            }),
            IDkgArtifactId::Opening(p, d) => Kind::Opening(pb::PrefixPairIDkg {
                prefix: Some((&p.get()).into()),
                id_data: Some(pb::IDkgArtifactIdData::from(d.get())),
            }),
            IDkgArtifactId::Transcript(p, d) => Kind::Transcript(pb::PrefixPairIDkg {
                prefix: Some((&p.get()).into()),
                id_data: Some(pb::IDkgArtifactIdData::from(d.get())),
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
                IDkgArtifactIdDataOf::new(try_from_option_field(p.id_data, "Dealing::id_data")?),
            ),
            Kind::DealingSupport(p) => Self::DealingSupport(
                IDkgPrefixOf::new(try_from_option_field(
                    p.prefix.as_ref(),
                    "DealingSupport::prefix",
                )?),
                IDkgArtifactIdDataOf::new(try_from_option_field(
                    p.id_data,
                    "DealingSupport::id_data",
                )?),
            ),
            Kind::EcdsaSigShare(p) => Self::EcdsaSigShare(
                IDkgPrefixOf::new(try_from_option_field(
                    p.prefix.as_ref(),
                    "EcdsaSigShare::prefix",
                )?),
                SigShareIdDataOf::new(try_from_option_field(p.id_data, "EcdsaSigShare::id_data")?),
            ),
            Kind::SchnorrSigShare(p) => Self::SchnorrSigShare(
                IDkgPrefixOf::new(try_from_option_field(
                    p.prefix.as_ref(),
                    "SchnorrSigShare::prefix",
                )?),
                SigShareIdDataOf::new(try_from_option_field(
                    p.id_data,
                    "SchnorrSigShare::id_data",
                )?),
            ),
            Kind::VetkdKeyShare(p) => Self::VetKdKeyShare(
                IDkgPrefixOf::new(try_from_option_field(
                    p.prefix.as_ref(),
                    "VetKdKeyShare::prefix",
                )?),
                SigShareIdDataOf::new(try_from_option_field(p.id_data, "VetKdKeyShare::id_data")?),
            ),
            Kind::Complaint(p) => Self::Complaint(
                IDkgPrefixOf::new(try_from_option_field(
                    p.prefix.as_ref(),
                    "Complaint::prefix",
                )?),
                IDkgArtifactIdDataOf::new(try_from_option_field(p.id_data, "Complaint::id_data")?),
            ),
            Kind::Opening(p) => Self::Opening(
                IDkgPrefixOf::new(try_from_option_field(p.prefix.as_ref(), "Opening::prefix")?),
                IDkgArtifactIdDataOf::new(try_from_option_field(p.id_data, "Opening::id_data")?),
            ),
            Kind::Transcript(p) => Self::Transcript(
                IDkgPrefixOf::new(try_from_option_field(
                    p.prefix.as_ref(),
                    "Transcript::prefix",
                )?),
                IDkgArtifactIdDataOf::new(try_from_option_field(p.id_data, "Transcript::id_data")?),
            ),
        })
    }
}

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, EnumIter, Serialize,
)]
pub enum IDkgMessageType {
    Dealing,
    DealingSupport,
    EcdsaSigShare,
    SchnorrSigShare,
    VetKdKeyShare,
    Complaint,
    Opening,
    Transcript,
}

impl From<&IDkgMessage> for IDkgMessageType {
    fn from(msg: &IDkgMessage) -> IDkgMessageType {
        match msg {
            IDkgMessage::Dealing(_) => IDkgMessageType::Dealing,
            IDkgMessage::DealingSupport(_) => IDkgMessageType::DealingSupport,
            IDkgMessage::EcdsaSigShare(_) => IDkgMessageType::EcdsaSigShare,
            IDkgMessage::SchnorrSigShare(_) => IDkgMessageType::SchnorrSigShare,
            IDkgMessage::VetKdKeyShare(_) => IDkgMessageType::VetKdKeyShare,
            IDkgMessage::Complaint(_) => IDkgMessageType::Complaint,
            IDkgMessage::Opening(_) => IDkgMessageType::Opening,
            IDkgMessage::Transcript(_) => IDkgMessageType::Transcript,
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
            IDkgArtifactId::VetKdKeyShare(..) => IDkgMessageType::VetKdKeyShare,
            IDkgArtifactId::Complaint(..) => IDkgMessageType::Complaint,
            IDkgArtifactId::Opening(..) => IDkgMessageType::Opening,
            IDkgArtifactId::Transcript(..) => IDkgMessageType::Transcript,
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
            Self::VetKdKeyShare => "vetkd_key_share",
            Self::Complaint => "complaint",
            Self::Opening => "opening",
            Self::Transcript => "transcript",
        }
    }
}

/// The ECDSA signature share
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
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
            request_id: Some(pb::RequestId::from(value.request_id)),
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
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
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
            request_id: Some(pb::RequestId::from(value.request_id)),
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

/// The VetKd share
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct VetKdKeyShare {
    /// The node that created the share
    pub signer_id: NodeId,

    /// The request this share belongs to
    pub request_id: RequestId,

    /// The encrypted key share
    pub share: VetKdEncryptedKeyShare,
}

impl From<&VetKdKeyShare> for pb::VetKdKeyShare {
    fn from(value: &VetKdKeyShare) -> Self {
        Self {
            signer_id: Some(node_id_into_protobuf(value.signer_id)),
            request_id: Some(pb::RequestId::from(value.request_id)),
            encrypted_key_share: value.share.encrypted_key_share.0.clone(),
            node_signature: value.share.node_signature.clone(),
        }
    }
}

impl TryFrom<&pb::VetKdKeyShare> for VetKdKeyShare {
    type Error = ProxyDecodeError;
    fn try_from(value: &pb::VetKdKeyShare) -> Result<Self, Self::Error> {
        Ok(Self {
            signer_id: node_id_try_from_option(value.signer_id.clone())?,
            request_id: try_from_option_field(
                value.request_id.as_ref(),
                "VetKdKeyShare::request_id",
            )?,
            share: VetKdEncryptedKeyShare {
                encrypted_key_share: VetKdEncryptedKeyShareContent(
                    value.encrypted_key_share.clone(),
                ),
                node_signature: value.node_signature.clone(),
            },
        })
    }
}

impl Display for VetKdKeyShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VetKdKeyShare[request_id = {:?}, signer_id = {:?}]",
            self.request_id, self.signer_id,
        )
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum SigShare {
    Ecdsa(EcdsaSigShare),
    Schnorr(SchnorrSigShare),
    VetKd(VetKdKeyShare),
}

impl Display for SigShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SigShare::Ecdsa(share) => write!(f, "{share}"),
            SigShare::Schnorr(share) => write!(f, "{share}"),
            SigShare::VetKd(share) => write!(f, "{share}"),
        }
    }
}

impl SigShare {
    pub fn signer(&self) -> NodeId {
        match self {
            SigShare::Ecdsa(share) => share.signer_id,
            SigShare::Schnorr(share) => share.signer_id,
            SigShare::VetKd(share) => share.signer_id,
        }
    }

    pub fn request_id(&self) -> RequestId {
        match self {
            SigShare::Ecdsa(share) => share.request_id,
            SigShare::Schnorr(share) => share.request_id,
            SigShare::VetKd(share) => share.request_id,
        }
    }

    pub fn scheme(&self) -> SignatureScheme {
        match self {
            SigShare::Ecdsa(_) => SignatureScheme::Ecdsa,
            SigShare::Schnorr(_) => SignatureScheme::Schnorr,
            SigShare::VetKd(_) => SignatureScheme::VetKd,
        }
    }
}

/// Complaint related defines
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
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
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
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

impl TryFrom<IDkgMessage> for VetKdKeyShare {
    type Error = IDkgMessage;
    fn try_from(msg: IDkgMessage) -> Result<Self, Self::Error> {
        match msg {
            IDkgMessage::VetKdKeyShare(x) => Ok(x),
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

impl TryFrom<IDkgMessage> for IDkgTranscript {
    type Error = IDkgMessage;
    fn try_from(msg: IDkgMessage) -> Result<Self, Self::Error> {
        match msg {
            IDkgMessage::Transcript(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

pub type Summary = Option<IDkgPayload>;

pub type Payload = Option<IDkgPayload>;

impl From<&IDkgPayload> for pb::IDkgPayload {
    fn from(payload: &IDkgPayload) -> Self {
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
        }
    }
}

impl TryFrom<&pb::IDkgPayload> for IDkgPayload {
    type Error = ProxyDecodeError;
    fn try_from(payload: &pb::IDkgPayload) -> Result<Self, Self::Error> {
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
                "IDkgPayload::available_pre_signature::pre_signature",
            )?;
            available_pre_signatures.insert(pre_signature_id, pre_signature);
        }

        // pre_signatures_in_creation
        let mut pre_signatures_in_creation = BTreeMap::new();
        for pre_signature_in_creation in &payload.pre_signatures_in_creation {
            let pre_signature_id = PreSigId(pre_signature_in_creation.pre_signature_id);
            let pre_signature: PreSignatureInCreation = try_from_option_field(
                pre_signature_in_creation.pre_signature.as_ref(),
                "IDkgPayload::pre_signature_in_creation::pre_signature",
            )?;
            pre_signatures_in_creation.insert(pre_signature_id, pre_signature);
        }

        let next_unused_transcript_id: IDkgTranscriptId = try_from_option_field(
            payload.next_unused_transcript_id.as_ref(),
            "IDkgPayload::next_unused_transcript_id",
        )?;

        let uid_generator = IDkgUIDGenerator {
            next_unused_transcript_id,
            next_unused_pre_signature_id: payload.next_unused_pre_signature_id,
        };

        // idkg_transcripts
        let mut idkg_transcripts = BTreeMap::new();
        for proto in &payload.idkg_transcripts {
            let transcript: IDkgTranscript = proto.try_into().map_err(|err| {
                ProxyDecodeError::Other(format!(
                    "IDkgPayload:: Failed to convert transcript: {err:?}"
                ))
            })?;
            let transcript_id = transcript.transcript_id;
            idkg_transcripts.insert(transcript_id, transcript);
        }

        // ongoing_xnet_reshares
        let mut ongoing_xnet_reshares = BTreeMap::new();
        for reshare in &payload.ongoing_xnet_reshares {
            let request: IDkgReshareRequest =
                try_from_option_field(reshare.request.as_ref(), "IDkgPayload::reshare::request")?;

            let transcript: ReshareOfUnmaskedParams = try_from_option_field(
                reshare.transcript.as_ref(),
                "IDkgPayload::reshare::transcript",
            )?;
            ongoing_xnet_reshares.insert(request, transcript);
        }

        // xnet_reshare_agreements
        let mut xnet_reshare_agreements = BTreeMap::new();
        for agreement in &payload.xnet_reshare_agreements {
            let request: IDkgReshareRequest = try_from_option_field(
                agreement.request.as_ref(),
                "IDkgPayload::agreement::request",
            )?;

            let completed = match &agreement.initial_dealings {
                Some(response) => {
                    let unreported = response.clone().try_into().map_err(|err| {
                        ProxyDecodeError::Other(format!(
                            "IDkgPayload:: failed to convert initial dealing: {err:?}"
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
///     - IDkgPreSigner builds the dealings/support shares (IDKG component context),
///       across several calls to on_state_change()
///     - IDkgTranscriptBuilder builds the verified dealings/transcripts (payload builder context),
///       across possibly several calls to get_completed_transcript()
///
/// The IDkg stats unifies the relevant metrics for an entity, so that these can be accessed
/// from the different paths. This helps answer higher level queries
/// (e.g) total time spent in stages like support share validation/ aggregation, per transcript.
///
pub trait IDkgStats: Send + Sync {
    /// Updates the set of transcripts being tracked currently.
    fn update_active_transcripts(&self, block_reader: &dyn IDkgBlockReader);

    /// Updates the set of pre-signatures being tracked currently.
    fn update_active_pre_signatures(&self, block_reader: &dyn IDkgBlockReader);

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

/// IDkgObject should be implemented by the IDKG message types
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
        let dealing = self.idkg_dealing();
        let id_data = IDkgArtifactIdDataOf::new(IDkgArtifactIdData {
            height: dealing.transcript_id.source_height(),
            hash: crypto_hash(self).get(),
            subnet_id: *dealing.transcript_id.source_subnet(),
        });
        IDkgArtifactId::Dealing(self.message_prefix(), id_data)
    }
}

impl IDkgObject for IDkgDealingSupport {
    fn message_prefix(&self) -> IDkgPrefixOf<Self> {
        dealing_support_prefix(&self.transcript_id, &self.dealer_id, &self.sig_share.signer)
    }

    fn message_id(&self) -> IDkgArtifactId {
        let id_data = IDkgArtifactIdDataOf::new(IDkgArtifactIdData {
            height: self.transcript_id.source_height(),
            hash: crypto_hash(self).get(),
            subnet_id: *self.transcript_id.source_subnet(),
        });
        IDkgArtifactId::DealingSupport(self.message_prefix(), id_data)
    }
}

impl IDkgObject for EcdsaSigShare {
    fn message_prefix(&self) -> IDkgPrefixOf<Self> {
        ecdsa_sig_share_prefix(&self.request_id, &self.signer_id)
    }

    fn message_id(&self) -> IDkgArtifactId {
        let id_data = SigShareIdDataOf::new(SigShareIdData {
            height: self.request_id.height,
            hash: crypto_hash(self).get(),
        });
        IDkgArtifactId::EcdsaSigShare(self.message_prefix(), id_data)
    }
}

impl IDkgObject for SchnorrSigShare {
    fn message_prefix(&self) -> IDkgPrefixOf<Self> {
        schnorr_sig_share_prefix(&self.request_id, &self.signer_id)
    }

    fn message_id(&self) -> IDkgArtifactId {
        let id_data = SigShareIdDataOf::new(SigShareIdData {
            height: self.request_id.height,
            hash: crypto_hash(self).get(),
        });
        IDkgArtifactId::SchnorrSigShare(self.message_prefix(), id_data)
    }
}

impl IDkgObject for VetKdKeyShare {
    fn message_prefix(&self) -> IDkgPrefixOf<Self> {
        vetkd_key_share_prefix(&self.request_id, &self.signer_id)
    }

    fn message_id(&self) -> IDkgArtifactId {
        let id_data = SigShareIdDataOf::new(SigShareIdData {
            height: self.request_id.height,
            hash: crypto_hash(self).get(),
        });
        IDkgArtifactId::VetKdKeyShare(self.message_prefix(), id_data)
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
        let transcript_id = self.content.idkg_complaint.transcript_id;
        let id_data = IDkgArtifactIdDataOf::new(IDkgArtifactIdData {
            height: transcript_id.source_height(),
            hash: crypto_hash(self).get(),
            subnet_id: *transcript_id.source_subnet(),
        });
        IDkgArtifactId::Complaint(self.message_prefix(), id_data)
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
        let transcript_id = self.content.idkg_opening.transcript_id;
        let id_data = IDkgArtifactIdDataOf::new(IDkgArtifactIdData {
            height: transcript_id.source_height(),
            hash: crypto_hash(self).get(),
            subnet_id: *transcript_id.source_subnet(),
        });
        IDkgArtifactId::Opening(self.message_prefix(), id_data)
    }
}

impl IDkgObject for IDkgTranscript {
    fn message_prefix(&self) -> IDkgPrefixOf<Self> {
        transcript_prefix(&self.transcript_id)
    }

    fn message_id(&self) -> IDkgArtifactId {
        let transcript_id = self.transcript_id;
        let id_data = IDkgArtifactIdDataOf::new(IDkgArtifactIdData {
            height: transcript_id.source_height(),
            hash: crypto_hash(self).get(),
            subnet_id: *transcript_id.source_subnet(),
        });
        IDkgArtifactId::Transcript(self.message_prefix(), id_data)
    }
}

impl From<&IDkgMessage> for IDkgArtifactId {
    fn from(msg: &IDkgMessage) -> IDkgArtifactId {
        match msg {
            IDkgMessage::Dealing(object) => object.message_id(),
            IDkgMessage::DealingSupport(object) => object.message_id(),
            IDkgMessage::EcdsaSigShare(object) => object.message_id(),
            IDkgMessage::SchnorrSigShare(object) => object.message_id(),
            IDkgMessage::VetKdKeyShare(object) => object.message_id(),
            IDkgMessage::Complaint(object) => object.message_id(),
            IDkgMessage::Opening(object) => object.message_id(),
            IDkgMessage::Transcript(object) => object.message_id(),
        }
    }
}

pub trait HasIDkgMasterPublicKeyId {
    /// Returns a reference to the [`MasterPublicKeyId`] associated with the object.
    fn key_id(&self) -> IDkgMasterPublicKeyId;
}

impl HasIDkgMasterPublicKeyId for QuadrupleInCreation {
    fn key_id(&self) -> IDkgMasterPublicKeyId {
        IDkgMasterPublicKeyId(MasterPublicKeyId::Ecdsa(self.key_id.clone()))
    }
}

impl HasIDkgMasterPublicKeyId for PreSignatureQuadrupleRef {
    fn key_id(&self) -> IDkgMasterPublicKeyId {
        IDkgMasterPublicKeyId(MasterPublicKeyId::Ecdsa(self.key_id.clone()))
    }
}

impl HasIDkgMasterPublicKeyId for PreSignatureInCreation {
    fn key_id(&self) -> IDkgMasterPublicKeyId {
        let key = match self {
            PreSignatureInCreation::Ecdsa(quadruple) => {
                MasterPublicKeyId::Ecdsa(quadruple.key_id.clone())
            }
            PreSignatureInCreation::Schnorr(transcript) => {
                MasterPublicKeyId::Schnorr(transcript.key_id.clone())
            }
        };
        IDkgMasterPublicKeyId(key)
    }
}

impl HasIDkgMasterPublicKeyId for PreSignatureRef {
    fn key_id(&self) -> IDkgMasterPublicKeyId {
        let key = match self {
            PreSignatureRef::Ecdsa(quadruple) => MasterPublicKeyId::Ecdsa(quadruple.key_id.clone()),
            PreSignatureRef::Schnorr(transcript) => {
                MasterPublicKeyId::Schnorr(transcript.key_id.clone())
            }
        };
        IDkgMasterPublicKeyId(key)
    }
}

impl HasIDkgMasterPublicKeyId for IDkgReshareRequest {
    fn key_id(&self) -> IDkgMasterPublicKeyId {
        self.master_key_id.clone()
    }
}

impl HasIDkgMasterPublicKeyId for MasterKeyTranscript {
    fn key_id(&self) -> IDkgMasterPublicKeyId {
        self.master_key_id.clone()
    }
}

impl<T: HasIDkgMasterPublicKeyId, U> HasIDkgMasterPublicKeyId for (T, U) {
    fn key_id(&self) -> IDkgMasterPublicKeyId {
        self.0.key_id()
    }
}

impl<T: HasIDkgMasterPublicKeyId> HasIDkgMasterPublicKeyId for &T {
    fn key_id(&self) -> IDkgMasterPublicKeyId {
        (*self).key_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_generator_pre_signature_ids_are_globally_unique_test() {
        let mut uid_generator =
            IDkgUIDGenerator::new(ic_types_test_utils::ids::SUBNET_0, Height::new(100));

        let pre_sig_id_0 = uid_generator.next_pre_signature_id();
        let pre_sig_id_1 = uid_generator.next_pre_signature_id();
        let pre_sig_id_2 = uid_generator.next_pre_signature_id();

        assert_eq!(pre_sig_id_0.id(), 0);
        assert_eq!(pre_sig_id_1.id(), 1);
        assert_eq!(pre_sig_id_2.id(), 2);
    }
}
