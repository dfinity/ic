//! Canister threshold transcripts and references related defininitions.
use crate::crypto::{
    canister_threshold_sig::{
        error::IDkgParamsValidationError,
        idkg::{
            IDkgTranscript, IDkgTranscriptId, IDkgTranscriptOperation, IDkgTranscriptParams,
            IDkgTranscriptType,
        },
        ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs,
        ThresholdSchnorrCombinedSignature, ThresholdSchnorrSigInputs,
    },
    AlgorithmId,
};
use crate::{Height, RegistryVersion};
use ic_base_types::{NodeId, PrincipalId};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types::MasterPublicKeyId;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::registry::subnet::v1 as subnet_pb;
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::convert::{AsMut, AsRef, TryFrom};
use std::hash::Hash;
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
};

use super::{
    ecdsa::{
        PreSignatureQuadrupleRef, QuadrupleInCreation, ThresholdEcdsaSigInputsError,
        ThresholdEcdsaSigInputsRef,
    },
    schnorr::{
        PreSignatureTranscriptRef, ThresholdSchnorrSigInputsError, ThresholdSchnorrSigInputsRef,
        TranscriptInCreation,
    },
};

/// PseudoRandomId is defined in execution context as plain 32-byte vector, we give it a synonym here.
pub type PseudoRandomId = [u8; 32];

/// RequestId is used for two purposes:
/// 1. to identify the matching request in signature request contexts.
/// 2. to identify which pre-signature the request is matched to.
///
/// Pre-signatures must be matched with requests in the same order as requests
/// are created.
///
/// The height field represents at which block the RequestId is created.
/// It is used for purging purpose.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct RequestId {
    pub pre_signature_id: PreSigId,
    pub pseudo_random_id: PseudoRandomId,
    pub height: Height,
}

impl From<RequestId> for pb::RequestId {
    fn from(request_id: RequestId) -> Self {
        Self {
            pre_signature_id: request_id.pre_signature_id.id(),
            pseudo_random_id: request_id.pseudo_random_id.to_vec(),
            height: request_id.height.get(),
        }
    }
}

impl TryFrom<&pb::RequestId> for RequestId {
    type Error = ProxyDecodeError;

    fn try_from(request_id: &pb::RequestId) -> Result<Self, Self::Error> {
        if request_id.pseudo_random_id.len() != 32 {
            Err(ProxyDecodeError::Other(String::from(
                "request_id.pseudo_random_id must be 32 bytes long",
            )))
        } else {
            let mut pseudo_random_id = [0; 32];
            pseudo_random_id.copy_from_slice(&request_id.pseudo_random_id);

            Ok(Self {
                pre_signature_id: PreSigId(request_id.pre_signature_id),
                pseudo_random_id,
                height: Height::from(request_id.height),
            })
        }
    }
}

#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct PreSigId(pub u64);

impl PreSigId {
    pub fn id(&self) -> u64 {
        self.0
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct TranscriptRef {
    /// The on chain location of the IDkgTranscript.
    /// The height may refer to a summary or data block.
    pub height: Height,

    /// The transcript ID
    pub transcript_id: IDkgTranscriptId,
}

impl TranscriptRef {
    pub fn new(height: Height, transcript_id: IDkgTranscriptId) -> Self {
        Self {
            height,
            transcript_id,
        }
    }

    /// Updates the height.
    pub fn update(&mut self, height: Height) {
        self.height = height;
    }
}

impl From<&TranscriptRef> for pb::TranscriptRef {
    fn from(trancript_ref: &TranscriptRef) -> Self {
        Self {
            height: trancript_ref.height.get(),
            transcript_id: Some((&trancript_ref.transcript_id).into()),
        }
    }
}

impl TryFrom<&pb::TranscriptRef> for TranscriptRef {
    type Error = ProxyDecodeError;
    fn try_from(trancript_ref: &pb::TranscriptRef) -> Result<Self, Self::Error> {
        let transcript_id = try_from_option_field(
            trancript_ref.transcript_id.as_ref(),
            "TranscriptRef::transcript_id",
        )?;
        Ok(Self {
            height: Height::from(trancript_ref.height),
            transcript_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct TranscriptCastError {
    pub transcript_id: IDkgTranscriptId,
    pub from_type: IDkgTranscriptType,
    pub expected_type: &'static str,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct MaskedTranscript(TranscriptRef);

impl AsRef<TranscriptRef> for MaskedTranscript {
    fn as_ref(&self) -> &TranscriptRef {
        &self.0
    }
}
impl AsMut<TranscriptRef> for MaskedTranscript {
    fn as_mut(&mut self) -> &mut TranscriptRef {
        &mut self.0
    }
}

impl TryFrom<(Height, &IDkgTranscript)> for MaskedTranscript {
    type Error = TranscriptCastError;
    fn try_from((height, transcript): (Height, &IDkgTranscript)) -> Result<Self, Self::Error> {
        match transcript.transcript_type {
            IDkgTranscriptType::Masked(_) => {
                Ok(Self(TranscriptRef::new(height, transcript.transcript_id)))
            }
            _ => Err(TranscriptCastError {
                transcript_id: transcript.transcript_id,
                from_type: transcript.transcript_type.clone(),
                expected_type: "Masked",
            }),
        }
    }
}

impl From<&MaskedTranscript> for pb::MaskedTranscript {
    fn from(transcript: &MaskedTranscript) -> Self {
        Self {
            transcript_ref: Some(transcript.as_ref().into()),
        }
    }
}

impl TryFrom<&pb::MaskedTranscript> for MaskedTranscript {
    type Error = ProxyDecodeError;
    fn try_from(transcript: &pb::MaskedTranscript) -> Result<Self, Self::Error> {
        Ok(Self(try_from_option_field(
            transcript.transcript_ref.as_ref(),
            "MaskedTranscript::transcript_ref",
        )?))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct UnmaskedTranscript(TranscriptRef);

impl AsRef<TranscriptRef> for UnmaskedTranscript {
    fn as_ref(&self) -> &TranscriptRef {
        &self.0
    }
}
impl AsMut<TranscriptRef> for UnmaskedTranscript {
    fn as_mut(&mut self) -> &mut TranscriptRef {
        &mut self.0
    }
}

impl TryFrom<(Height, &IDkgTranscript)> for UnmaskedTranscript {
    type Error = TranscriptCastError;
    fn try_from((height, transcript): (Height, &IDkgTranscript)) -> Result<Self, Self::Error> {
        match transcript.transcript_type {
            IDkgTranscriptType::Unmasked(_) => {
                Ok(Self(TranscriptRef::new(height, transcript.transcript_id)))
            }
            _ => Err(TranscriptCastError {
                transcript_id: transcript.transcript_id,
                from_type: transcript.transcript_type.clone(),
                expected_type: "Unmasked",
            }),
        }
    }
}

impl From<&UnmaskedTranscript> for pb::UnmaskedTranscript {
    fn from(transcript: &UnmaskedTranscript) -> Self {
        Self {
            transcript_ref: Some(transcript.as_ref().into()),
        }
    }
}

impl TryFrom<&pb::UnmaskedTranscript> for UnmaskedTranscript {
    type Error = ProxyDecodeError;
    fn try_from(transcript: &pb::UnmaskedTranscript) -> Result<Self, Self::Error> {
        Ok(Self(try_from_option_field(
            transcript.transcript_ref.as_ref(),
            "UnmaskedTranscript::transcript_ref",
        )?))
    }
}

/// Trait for transcript attributes.
pub trait TranscriptAttributes {
    fn receivers(&self) -> &BTreeSet<NodeId>;
    fn algorithm_id(&self) -> AlgorithmId;
    fn registry_version(&self) -> RegistryVersion;
    fn to_attributes(&self) -> IDkgTranscriptAttributes {
        IDkgTranscriptAttributes {
            receivers: self.receivers().clone(),
            algorithm_id: self.algorithm_id(),
            registry_version: self.registry_version(),
        }
    }
}

impl TranscriptAttributes for IDkgTranscript {
    fn receivers(&self) -> &BTreeSet<NodeId> {
        self.receivers.get()
    }
    fn algorithm_id(&self) -> AlgorithmId {
        self.algorithm_id
    }
    fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }
}

impl TranscriptAttributes for IDkgTranscriptParamsRef {
    fn receivers(&self) -> &BTreeSet<NodeId> {
        &self.receivers
    }
    fn algorithm_id(&self) -> AlgorithmId {
        self.algorithm_id
    }
    fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }
}

/// Attributes of `IDkgTranscript`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct IDkgTranscriptAttributes {
    receivers: BTreeSet<NodeId>,
    algorithm_id: AlgorithmId,
    registry_version: RegistryVersion,
}

impl From<&IDkgTranscriptAttributes> for pb::IDkgTranscriptAttributes {
    fn from(attributes: &IDkgTranscriptAttributes) -> Self {
        pb::IDkgTranscriptAttributes {
            receivers: attributes
                .receivers
                .iter()
                .cloned()
                .map(crate::node_id_into_protobuf)
                .collect(),
            algorithm_id: attributes.algorithm_id as i32,
            registry_version: attributes.registry_version.get(),
        }
    }
}

impl TryFrom<&pb::IDkgTranscriptAttributes> for IDkgTranscriptAttributes {
    type Error = ProxyDecodeError;
    fn try_from(attributes: &pb::IDkgTranscriptAttributes) -> Result<Self, Self::Error> {
        let mut receivers = BTreeSet::new();
        for pb_node_id in &attributes.receivers {
            let node_id = crate::node_id_try_from_option(Some(pb_node_id.clone()))?;
            receivers.insert(node_id);
        }
        Ok(IDkgTranscriptAttributes::new(
            receivers,
            AlgorithmId::from(attributes.algorithm_id),
            RegistryVersion::new(attributes.registry_version),
        ))
    }
}

impl IDkgTranscriptAttributes {
    pub fn new(
        receivers: BTreeSet<NodeId>,
        algorithm_id: AlgorithmId,
        registry_version: RegistryVersion,
    ) -> Self {
        Self {
            receivers,
            algorithm_id,
            registry_version,
        }
    }
}

impl TranscriptAttributes for IDkgTranscriptAttributes {
    fn receivers(&self) -> &BTreeSet<NodeId> {
        &self.receivers
    }
    fn algorithm_id(&self) -> AlgorithmId {
        self.algorithm_id
    }
    fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }
}

/// Wrappers for the common types.

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct RandomTranscriptParams(IDkgTranscriptParamsRef);
impl RandomTranscriptParams {
    pub fn new(
        transcript_id: IDkgTranscriptId,
        dealers: BTreeSet<NodeId>,
        receivers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
        algorithm_id: AlgorithmId,
    ) -> Self {
        Self(IDkgTranscriptParamsRef::new(
            transcript_id,
            dealers,
            receivers,
            registry_version,
            algorithm_id,
            IDkgTranscriptOperationRef::Random,
        ))
    }
}

impl AsRef<IDkgTranscriptParamsRef> for RandomTranscriptParams {
    fn as_ref(&self) -> &IDkgTranscriptParamsRef {
        &self.0
    }
}
impl AsMut<IDkgTranscriptParamsRef> for RandomTranscriptParams {
    fn as_mut(&mut self) -> &mut IDkgTranscriptParamsRef {
        &mut self.0
    }
}
impl From<&RandomTranscriptParams> for pb::RandomTranscriptParams {
    fn from(transcript: &RandomTranscriptParams) -> Self {
        Self {
            transcript_ref: Some(transcript.as_ref().into()),
        }
    }
}
impl TryFrom<&pb::RandomTranscriptParams> for RandomTranscriptParams {
    type Error = ProxyDecodeError;
    fn try_from(transcript: &pb::RandomTranscriptParams) -> Result<Self, Self::Error> {
        Ok(Self(try_from_option_field(
            transcript.transcript_ref.as_ref(),
            "RandomTranscriptParams::transcript_ref",
        )?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct RandomUnmaskedTranscriptParams(IDkgTranscriptParamsRef);
impl RandomUnmaskedTranscriptParams {
    pub fn new(
        transcript_id: IDkgTranscriptId,
        dealers: BTreeSet<NodeId>,
        receivers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
        algorithm_id: AlgorithmId,
    ) -> Self {
        Self(IDkgTranscriptParamsRef::new(
            transcript_id,
            dealers,
            receivers,
            registry_version,
            algorithm_id,
            IDkgTranscriptOperationRef::RandomUnmasked,
        ))
    }
}

impl AsRef<IDkgTranscriptParamsRef> for RandomUnmaskedTranscriptParams {
    fn as_ref(&self) -> &IDkgTranscriptParamsRef {
        &self.0
    }
}
impl AsMut<IDkgTranscriptParamsRef> for RandomUnmaskedTranscriptParams {
    fn as_mut(&mut self) -> &mut IDkgTranscriptParamsRef {
        &mut self.0
    }
}
impl From<&RandomUnmaskedTranscriptParams> for pb::RandomUnmaskedTranscriptParams {
    fn from(transcript: &RandomUnmaskedTranscriptParams) -> Self {
        Self {
            transcript_ref: Some(transcript.as_ref().into()),
        }
    }
}
impl TryFrom<&pb::RandomUnmaskedTranscriptParams> for RandomUnmaskedTranscriptParams {
    type Error = ProxyDecodeError;
    fn try_from(transcript: &pb::RandomUnmaskedTranscriptParams) -> Result<Self, Self::Error> {
        Ok(Self(try_from_option_field(
            transcript.transcript_ref.as_ref(),
            "RandomUnmaskedTranscriptParams::transcript_ref",
        )?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct ReshareOfMaskedParams(IDkgTranscriptParamsRef);
impl ReshareOfMaskedParams {
    pub fn new(
        transcript_id: IDkgTranscriptId,
        receivers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
        masked_attrs: &dyn TranscriptAttributes,
        transcript: MaskedTranscript,
    ) -> Self {
        Self(IDkgTranscriptParamsRef::new(
            transcript_id,
            masked_attrs.receivers().clone(),
            receivers,
            registry_version,
            masked_attrs.algorithm_id(),
            IDkgTranscriptOperationRef::ReshareOfMasked(transcript),
        ))
    }
}

impl AsRef<IDkgTranscriptParamsRef> for ReshareOfMaskedParams {
    fn as_ref(&self) -> &IDkgTranscriptParamsRef {
        &self.0
    }
}
impl AsMut<IDkgTranscriptParamsRef> for ReshareOfMaskedParams {
    fn as_mut(&mut self) -> &mut IDkgTranscriptParamsRef {
        &mut self.0
    }
}
impl From<&ReshareOfMaskedParams> for pb::ReshareOfMaskedParams {
    fn from(transcript: &ReshareOfMaskedParams) -> Self {
        Self {
            transcript_ref: Some(transcript.as_ref().into()),
        }
    }
}
impl TryFrom<&pb::ReshareOfMaskedParams> for ReshareOfMaskedParams {
    type Error = ProxyDecodeError;
    fn try_from(transcript: &pb::ReshareOfMaskedParams) -> Result<Self, Self::Error> {
        Ok(Self(try_from_option_field(
            transcript.transcript_ref.as_ref(),
            "ReshareOfMaskedParams::transcript_ref",
        )?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct ReshareOfUnmaskedParams(IDkgTranscriptParamsRef);
impl ReshareOfUnmaskedParams {
    pub fn new(
        transcript_id: IDkgTranscriptId,
        receivers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
        unmasked_attrs: &dyn TranscriptAttributes,
        transcript: UnmaskedTranscript,
    ) -> Self {
        Self(IDkgTranscriptParamsRef::new(
            transcript_id,
            unmasked_attrs.receivers().clone(),
            receivers,
            registry_version,
            unmasked_attrs.algorithm_id(),
            IDkgTranscriptOperationRef::ReshareOfUnmasked(transcript),
        ))
    }
}

pub fn unpack_reshare_of_unmasked_params(
    height: Height,
    params: &IDkgTranscriptParams,
) -> Option<(ReshareOfUnmaskedParams, IDkgTranscript)> {
    let transcript_id = params.transcript_id();
    let dealers = params.dealers().get().clone();
    let receivers = params.receivers().get().clone();
    let registry_version = params.registry_version();
    let algorithm_id = params.algorithm_id();
    let transcript =
        if let IDkgTranscriptOperation::ReshareOfUnmasked(transcript) = params.operation_type() {
            transcript.clone()
        } else {
            return None;
        };
    let transcript_ref = TranscriptRef::new(height, transcript.transcript_id);
    let operation_type_ref =
        IDkgTranscriptOperationRef::ReshareOfUnmasked(UnmaskedTranscript(transcript_ref));
    Some((
        ReshareOfUnmaskedParams(IDkgTranscriptParamsRef {
            transcript_id,
            dealers,
            receivers,
            registry_version,
            algorithm_id,
            operation_type_ref,
        }),
        transcript,
    ))
}

impl AsRef<IDkgTranscriptParamsRef> for ReshareOfUnmaskedParams {
    fn as_ref(&self) -> &IDkgTranscriptParamsRef {
        &self.0
    }
}
impl AsMut<IDkgTranscriptParamsRef> for ReshareOfUnmaskedParams {
    fn as_mut(&mut self) -> &mut IDkgTranscriptParamsRef {
        &mut self.0
    }
}
impl From<&ReshareOfUnmaskedParams> for pb::ReshareOfUnmaskedParams {
    fn from(transcript: &ReshareOfUnmaskedParams) -> Self {
        Self {
            transcript_ref: Some(transcript.as_ref().into()),
        }
    }
}
impl TryFrom<&pb::ReshareOfUnmaskedParams> for ReshareOfUnmaskedParams {
    type Error = ProxyDecodeError;
    fn try_from(transcript: &pb::ReshareOfUnmaskedParams) -> Result<Self, Self::Error> {
        Ok(Self(try_from_option_field(
            transcript.transcript_ref.as_ref(),
            "ReshareOfUnmaskedParams::transcript_ref",
        )?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct UnmaskedTimesMaskedParams(IDkgTranscriptParamsRef);
impl UnmaskedTimesMaskedParams {
    pub fn new(
        transcript_id: IDkgTranscriptId,
        receivers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
        transcript_1: (&dyn TranscriptAttributes, UnmaskedTranscript),
        transcript_2: (&dyn TranscriptAttributes, MaskedTranscript),
    ) -> Self {
        let receivers_1 = transcript_1.0.receivers();
        let receivers_2 = transcript_2.0.receivers();
        assert_eq!(
            receivers_1, receivers_2,
            "UnmaskedTimesMaskedParams: input transcripts have different set of receivers"
        );
        let dealers = receivers_1.clone();
        Self(IDkgTranscriptParamsRef::new(
            transcript_id,
            dealers,
            receivers,
            registry_version,
            transcript_1.0.algorithm_id(),
            IDkgTranscriptOperationRef::UnmaskedTimesMasked(transcript_1.1, transcript_2.1),
        ))
    }
}

impl AsRef<IDkgTranscriptParamsRef> for UnmaskedTimesMaskedParams {
    fn as_ref(&self) -> &IDkgTranscriptParamsRef {
        &self.0
    }
}
impl AsMut<IDkgTranscriptParamsRef> for UnmaskedTimesMaskedParams {
    fn as_mut(&mut self) -> &mut IDkgTranscriptParamsRef {
        &mut self.0
    }
}
impl From<&UnmaskedTimesMaskedParams> for pb::UnmaskedTimesMaskedParams {
    fn from(transcript: &UnmaskedTimesMaskedParams) -> Self {
        Self {
            transcript_ref: Some(transcript.as_ref().into()),
        }
    }
}
impl TryFrom<&pb::UnmaskedTimesMaskedParams> for UnmaskedTimesMaskedParams {
    type Error = ProxyDecodeError;
    fn try_from(transcript: &pb::UnmaskedTimesMaskedParams) -> Result<Self, Self::Error> {
        Ok(Self(try_from_option_field(
            transcript.transcript_ref.as_ref(),
            "UnmaskedTimesMaskedParams::transcript_ref",
        )?))
    }
}

pub type TranscriptLookupError = String;

/// Wrapper to access the IDKG related info from the blocks.
pub trait IDkgBlockReader: Send + Sync {
    /// Returns the height of the tip
    fn tip_height(&self) -> Height;

    /// Returns the transcripts requested by the tip.
    fn requested_transcripts(&self) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_>;

    /// Returns the IDs of pre-signatures in creation by the tip.
    fn pre_signatures_in_creation(
        &self,
    ) -> Box<dyn Iterator<Item = (PreSigId, MasterPublicKeyId)> + '_>;

    /// For the given pre-signature ID, returns the pre-signature ref if available.
    fn available_pre_signature(&self, id: &PreSigId) -> Option<&PreSignatureRef>;

    /// Returns the set of all the active references.
    fn active_transcripts(&self) -> BTreeSet<TranscriptRef>;

    /// Returns the transcript params for the xnet reshares in progress, on the source subnet side.
    /// One entry is returned per <key_id, target_subnet> in progress.
    fn source_subnet_xnet_transcripts(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_>;

    /// Returns the transcript params for the xnet key creation in progress, on the target
    /// subnet side. One entry is returned per key_id being bootstrapped.
    fn target_subnet_xnet_transcripts(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_>;

    /// Looks up the transcript for the given transcript ref.
    fn transcript(
        &self,
        transcript_ref: &TranscriptRef,
    ) -> Result<IDkgTranscript, TranscriptLookupError>;
}

/// Counterpart of IDkgTranscriptParams that holds transcript references,
/// instead of the transcripts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum IDkgTranscriptOperationRef {
    Random,
    ReshareOfMasked(MaskedTranscript),
    ReshareOfUnmasked(UnmaskedTranscript),
    UnmaskedTimesMasked(UnmaskedTranscript, MaskedTranscript),
    RandomUnmasked,
}

#[derive(Clone, Debug)]
pub enum TranscriptOperationError {
    ReshareOfMasked(TranscriptLookupError),
    ReshareOfUnmasked(TranscriptLookupError),
    UnmaskedTimesMasked1(TranscriptLookupError),
    UnmaskedTimesMasked2(TranscriptLookupError),
}

impl IDkgTranscriptOperationRef {
    /// Resolves the refs to get the IDkgTranscriptOperation.
    pub fn translate(
        &self,
        resolver: &dyn IDkgBlockReader,
    ) -> Result<IDkgTranscriptOperation, TranscriptOperationError> {
        match self {
            Self::Random => Ok(IDkgTranscriptOperation::Random),
            Self::RandomUnmasked => Ok(IDkgTranscriptOperation::RandomUnmasked),
            Self::ReshareOfMasked(r) => Ok(IDkgTranscriptOperation::ReshareOfMasked(
                resolver
                    .transcript(r.as_ref())
                    .map_err(TranscriptOperationError::ReshareOfMasked)?,
            )),
            Self::ReshareOfUnmasked(r) => Ok(IDkgTranscriptOperation::ReshareOfUnmasked(
                resolver
                    .transcript(r.as_ref())
                    .map_err(TranscriptOperationError::ReshareOfUnmasked)?,
            )),
            Self::UnmaskedTimesMasked(r1, r2) => Ok(IDkgTranscriptOperation::UnmaskedTimesMasked(
                resolver
                    .transcript(r1.as_ref())
                    .map_err(TranscriptOperationError::UnmaskedTimesMasked1)?,
                resolver
                    .transcript(r2.as_ref())
                    .map_err(TranscriptOperationError::UnmaskedTimesMasked2)?,
            )),
        }
    }

    /// Returns the refs held
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        match self {
            Self::Random => vec![],
            Self::RandomUnmasked => vec![],
            Self::ReshareOfMasked(r) => vec![*r.as_ref()],
            Self::ReshareOfUnmasked(r) => vec![*r.as_ref()],
            Self::UnmaskedTimesMasked(r1, r2) => vec![*r1.as_ref(), *r2.as_ref()],
        }
    }

    /// Updates the height of the references.
    pub fn update(&mut self, height: Height) {
        match self {
            Self::Random => (),
            Self::RandomUnmasked => (),
            Self::ReshareOfMasked(r) => {
                r.as_mut().update(height);
            }
            Self::ReshareOfUnmasked(r) => {
                r.as_mut().update(height);
            }
            Self::UnmaskedTimesMasked(r1, r2) => {
                r1.as_mut().update(height);
                r2.as_mut().update(height);
            }
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            Self::Random => "Random".to_string(),
            Self::RandomUnmasked => "RandomUnmasked".to_string(),
            Self::ReshareOfMasked(_) => "ReshareOfMasked".to_string(),
            Self::ReshareOfUnmasked(_) => "ReshareOfMasked".to_string(),
            Self::UnmaskedTimesMasked(_, _) => "UnmaskedTimesMasked".to_string(),
        }
    }
}

impl From<&IDkgTranscriptOperationRef> for pb::IDkgTranscriptOperationRef {
    fn from(op_ref: &IDkgTranscriptOperationRef) -> Self {
        match op_ref {
            IDkgTranscriptOperationRef::Random => Self {
                op_type: subnet_pb::IDkgTranscriptOperation::Random as i32,
                masked: None,
                unmasked: None,
            },
            IDkgTranscriptOperationRef::RandomUnmasked => Self {
                op_type: subnet_pb::IDkgTranscriptOperation::RandomUnmasked as i32,
                masked: None,
                unmasked: None,
            },
            IDkgTranscriptOperationRef::ReshareOfMasked(r) => Self {
                op_type: subnet_pb::IDkgTranscriptOperation::ReshareOfMasked as i32,
                masked: Some(r.into()),
                unmasked: None,
            },
            IDkgTranscriptOperationRef::ReshareOfUnmasked(r) => Self {
                op_type: subnet_pb::IDkgTranscriptOperation::ReshareOfUnmasked as i32,
                masked: None,
                unmasked: Some(r.into()),
            },
            IDkgTranscriptOperationRef::UnmaskedTimesMasked(r1, r2) => Self {
                op_type: subnet_pb::IDkgTranscriptOperation::UnmaskedTimesMasked as i32,
                unmasked: Some(r1.into()),
                masked: Some(r2.into()),
            },
        }
    }
}

impl TryFrom<&pb::IDkgTranscriptOperationRef> for IDkgTranscriptOperationRef {
    type Error = ProxyDecodeError;
    fn try_from(op_ref: &pb::IDkgTranscriptOperationRef) -> Result<Self, Self::Error> {
        if op_ref.op_type == (subnet_pb::IDkgTranscriptOperation::Random as i32) {
            Ok(Self::Random)
        } else if op_ref.op_type == (subnet_pb::IDkgTranscriptOperation::RandomUnmasked as i32) {
            Ok(Self::RandomUnmasked)
        } else if op_ref.op_type == (subnet_pb::IDkgTranscriptOperation::ReshareOfMasked as i32) {
            Ok(Self::ReshareOfMasked(try_from_option_field(
                op_ref.masked.as_ref(),
                "IDkgTranscriptOperationRef::masked",
            )?))
        } else if op_ref.op_type == (subnet_pb::IDkgTranscriptOperation::ReshareOfUnmasked as i32) {
            Ok(Self::ReshareOfUnmasked(try_from_option_field(
                op_ref.unmasked.as_ref(),
                "IDkgTranscriptOperationRef::unmasked",
            )?))
        } else if op_ref.op_type == (subnet_pb::IDkgTranscriptOperation::UnmaskedTimesMasked as i32)
        {
            Ok(Self::UnmaskedTimesMasked(
                try_from_option_field(
                    op_ref.unmasked.as_ref(),
                    "IDkgTranscriptOperationRef::unmasked",
                )?,
                try_from_option_field(
                    op_ref.masked.as_ref(),
                    "IDkgTranscriptOperationRef::masked",
                )?,
            ))
        } else {
            Err(ProxyDecodeError::Other(format!(
                "IDkgTranscriptOperationRef:: Unknown operation type: {:?}",
                op_ref.op_type
            )))
        }
    }
}

/// Counterpart of IDkgTranscriptParams that holds transcript references,
/// instead of the transcripts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct IDkgTranscriptParamsRef {
    pub transcript_id: IDkgTranscriptId,
    pub dealers: BTreeSet<NodeId>,
    pub receivers: BTreeSet<NodeId>,
    pub registry_version: RegistryVersion,
    pub algorithm_id: AlgorithmId,
    pub operation_type_ref: IDkgTranscriptOperationRef,
}

impl From<&IDkgTranscriptParamsRef> for pb::IDkgTranscriptParamsRef {
    fn from(params: &IDkgTranscriptParamsRef) -> Self {
        Self {
            transcript_id: Some((&params.transcript_id).into()),
            dealers: params.dealers.iter().fold(Vec::new(), |mut acc, node_id| {
                acc.push(crate::node_id_into_protobuf(*node_id));
                acc
            }),
            receivers: params
                .receivers
                .iter()
                .fold(Vec::new(), |mut acc, node_id| {
                    acc.push(crate::node_id_into_protobuf(*node_id));
                    acc
                }),
            registry_version: params.registry_version.get(),
            algorithm_id: params.algorithm_id as i32,
            operation_type_ref: Some((&params.operation_type_ref).into()),
        }
    }
}

impl TryFrom<&pb::IDkgTranscriptParamsRef> for IDkgTranscriptParamsRef {
    type Error = ProxyDecodeError;
    fn try_from(params: &pb::IDkgTranscriptParamsRef) -> Result<Self, Self::Error> {
        let transcript_id: IDkgTranscriptId = try_from_option_field(
            params.transcript_id.as_ref(),
            "IDkgTranscriptParamsRef::transcript_id",
        )?;

        let mut dealers = BTreeSet::new();
        for pb_node_id in &params.dealers {
            let node_id = crate::node_id_try_from_option(Some(pb_node_id.clone()))?;
            dealers.insert(node_id);
        }

        let mut receivers = BTreeSet::new();
        for pb_node_id in &params.receivers {
            let node_id = crate::node_id_try_from_option(Some(pb_node_id.clone()))?;
            receivers.insert(node_id);
        }

        let operation_ref = try_from_option_field(
            params.operation_type_ref.as_ref(),
            "IDkgTranscriptParamsRef::operation_type_ref",
        )?;

        Ok(Self::new(
            transcript_id,
            dealers,
            receivers,
            RegistryVersion::new(params.registry_version),
            AlgorithmId::from(params.algorithm_id),
            operation_ref,
        ))
    }
}

#[derive(Clone, Debug)]
pub enum TranscriptParamsError {
    OperationRef(TranscriptOperationError),
    ParamsValidation(IDkgParamsValidationError),
}

impl IDkgTranscriptParamsRef {
    pub fn new(
        transcript_id: IDkgTranscriptId,
        dealers: BTreeSet<NodeId>,
        receivers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
        algorithm_id: AlgorithmId,
        operation_type_ref: IDkgTranscriptOperationRef,
    ) -> Self {
        Self {
            transcript_id,
            dealers,
            receivers,
            registry_version,
            algorithm_id,
            operation_type_ref,
        }
    }

    /// Resolves the refs to get the IDkgTranscriptParams.
    pub fn translate(
        &self,
        resolver: &dyn IDkgBlockReader,
    ) -> Result<IDkgTranscriptParams, TranscriptParamsError> {
        let operation_type = self
            .operation_type_ref
            .translate(resolver)
            .map_err(TranscriptParamsError::OperationRef)?;
        IDkgTranscriptParams::new(
            self.transcript_id,
            self.dealers.clone(),
            self.receivers.clone(),
            self.registry_version,
            self.algorithm_id,
            operation_type,
        )
        .map_err(TranscriptParamsError::ParamsValidation)
    }

    /// Returns the refs held
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        self.operation_type_ref.get_refs()
    }

    /// Updates the height of the references.
    pub fn update(&mut self, height: Height) {
        self.operation_type_ref.update(height);
    }
}

#[derive(Hash, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum PreSignatureInCreation {
    Ecdsa(QuadrupleInCreation),
    Schnorr(TranscriptInCreation),
}

impl PreSignatureInCreation {
    /// Return an iterator of all transcript configs that have no matching
    /// results yet.
    pub fn iter_transcript_configs_in_creation(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        match self {
            Self::Schnorr(x) => x.iter_transcript_configs_in_creation(),
            Self::Ecdsa(x) => x.iter_transcript_configs_in_creation(),
        }
    }

    /// Returns the refs held
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        match self {
            Self::Schnorr(x) => x.get_refs(),
            Self::Ecdsa(x) => x.get_refs(),
        }
    }

    /// Updates the height of the references.
    pub fn update(&mut self, height: Height) {
        match self {
            Self::Schnorr(x) => x.update(height),
            Self::Ecdsa(x) => x.update(height),
        }
    }
}

impl From<&PreSignatureInCreation> for pb::PreSignatureInCreation {
    fn from(value: &PreSignatureInCreation) -> Self {
        use pb::pre_signature_in_creation::Msg;
        let msg = match value {
            PreSignatureInCreation::Schnorr(x) => Msg::Schnorr(x.into()),
            PreSignatureInCreation::Ecdsa(x) => Msg::Ecdsa(x.into()),
        };
        Self { msg: Some(msg) }
    }
}

impl TryFrom<&pb::PreSignatureInCreation> for PreSignatureInCreation {
    type Error = ProxyDecodeError;
    fn try_from(pre_signature: &pb::PreSignatureInCreation) -> Result<Self, Self::Error> {
        use pb::pre_signature_in_creation::Msg;
        let Some(msg) = pre_signature.msg.as_ref() else {
            return Err(ProxyDecodeError::MissingField(
                "PreSignatureInCreation::msg",
            ));
        };
        Ok(match msg {
            Msg::Schnorr(x) => PreSignatureInCreation::Schnorr(x.try_into()?),
            Msg::Ecdsa(x) => PreSignatureInCreation::Ecdsa(x.try_into()?),
        })
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum PreSignatureRef {
    Ecdsa(PreSignatureQuadrupleRef),
    Schnorr(PreSignatureTranscriptRef),
}

impl PreSignatureRef {
    /// Returns the refs held
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        match self {
            Self::Schnorr(x) => x.get_refs(),
            Self::Ecdsa(x) => x.get_refs(),
        }
    }

    /// Updates the height of the references.
    pub fn update(&mut self, height: Height) {
        match self {
            Self::Schnorr(x) => x.update(height),
            Self::Ecdsa(x) => x.update(height),
        }
    }

    pub fn key_unmasked(&self) -> UnmaskedTranscript {
        match self {
            Self::Schnorr(x) => x.key_unmasked_ref,
            Self::Ecdsa(x) => x.key_unmasked_ref,
        }
    }
}

impl From<&PreSignatureRef> for pb::PreSignatureRef {
    fn from(value: &PreSignatureRef) -> Self {
        use pb::pre_signature_ref::Msg;
        let msg = match value {
            PreSignatureRef::Schnorr(x) => Msg::Schnorr(x.into()),
            PreSignatureRef::Ecdsa(x) => Msg::Ecdsa(x.into()),
        };
        Self { msg: Some(msg) }
    }
}

impl TryFrom<&pb::PreSignatureRef> for PreSignatureRef {
    type Error = ProxyDecodeError;
    fn try_from(pre_signature: &pb::PreSignatureRef) -> Result<Self, Self::Error> {
        use pb::pre_signature_ref::Msg;
        let Some(msg) = pre_signature.msg.as_ref() else {
            return Err(ProxyDecodeError::MissingField(
                "PreSignatureInCreation::msg",
            ));
        };
        Ok(match msg {
            Msg::Schnorr(x) => PreSignatureRef::Schnorr(x.try_into()?),
            Msg::Ecdsa(x) => PreSignatureRef::Ecdsa(x.try_into()?),
        })
    }
}

#[derive(Clone, Debug)]
pub enum ThresholdSigInputsError {
    Ecdsa(ThresholdEcdsaSigInputsError),
    Schnorr(ThresholdSchnorrSigInputsError),
}

type ThresholdSigInputsResult = Result<ThresholdSigInputs, ThresholdSigInputsError>;

fn ok_ecdsa(inputs: ThresholdEcdsaSigInputs) -> ThresholdSigInputsResult {
    Ok(ThresholdSigInputs::Ecdsa(inputs))
}

fn ok_schnorr(inputs: ThresholdSchnorrSigInputs) -> ThresholdSigInputsResult {
    Ok(ThresholdSigInputs::Schnorr(inputs))
}

fn err_ecdsa(err: ThresholdEcdsaSigInputsError) -> ThresholdSigInputsResult {
    Err(ThresholdSigInputsError::Ecdsa(err))
}

fn err_schnorr(err: ThresholdSchnorrSigInputsError) -> ThresholdSigInputsResult {
    Err(ThresholdSigInputsError::Schnorr(err))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThresholdSigInputsRef {
    Ecdsa(ThresholdEcdsaSigInputsRef),
    Schnorr(ThresholdSchnorrSigInputsRef),
}

impl ThresholdSigInputsRef {
    pub fn pre_signature(&self) -> PreSignatureRef {
        match self {
            ThresholdSigInputsRef::Ecdsa(inputs) => {
                PreSignatureRef::Ecdsa(inputs.presig_quadruple_ref.clone())
            }
            ThresholdSigInputsRef::Schnorr(inputs) => {
                PreSignatureRef::Schnorr(inputs.presig_transcript_ref.clone())
            }
        }
    }

    pub fn caller(&self) -> PrincipalId {
        match self {
            ThresholdSigInputsRef::Ecdsa(inputs) => inputs.derivation_path.caller,
            ThresholdSigInputsRef::Schnorr(inputs) => inputs.derivation_path.caller,
        }
    }

    pub fn scheme(&self) -> SignatureScheme {
        match self {
            ThresholdSigInputsRef::Ecdsa(_) => SignatureScheme::Ecdsa,
            ThresholdSigInputsRef::Schnorr(_) => SignatureScheme::Schnorr,
        }
    }

    pub fn translate(&self, resolver: &dyn IDkgBlockReader) -> ThresholdSigInputsResult {
        match self {
            ThresholdSigInputsRef::Ecdsa(inputs_ref) => inputs_ref
                .translate(resolver)
                .map_or_else(err_ecdsa, ok_ecdsa),
            ThresholdSigInputsRef::Schnorr(inputs_ref) => inputs_ref
                .translate(resolver)
                .map_or_else(err_schnorr, ok_schnorr),
        }
    }
}

pub enum ThresholdSigInputs {
    Ecdsa(ThresholdEcdsaSigInputs),
    Schnorr(ThresholdSchnorrSigInputs),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CombinedSignature {
    Ecdsa(ThresholdEcdsaCombinedSignature),
    Schnorr(ThresholdSchnorrCombinedSignature),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    Ecdsa,
    Schnorr,
}

impl Display for SignatureScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SignatureScheme::Ecdsa => write!(f, "ECDSA"),
            SignatureScheme::Schnorr => write!(f, "Schnorr"),
        }
    }
}
