//! Threshold ECDSA transcript references related defines.
use crate::crypto::{
    canister_threshold_sig::error::{
        EcdsaPresignatureQuadrupleCreationError, IDkgParamsValidationError,
        ThresholdEcdsaSigInputsCreationError,
    },
    canister_threshold_sig::idkg::{
        IDkgTranscript, IDkgTranscriptId, IDkgTranscriptOperation, IDkgTranscriptParams,
        IDkgTranscriptType,
    },
    canister_threshold_sig::{
        EcdsaPreSignatureQuadruple, ExtendedDerivationPath, ThresholdEcdsaSigInputs,
    },
    AlgorithmId,
};
use crate::{Height, Randomness, RegistryVersion};
use ic_base_types::NodeId;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types::EcdsaKeyId;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::registry::subnet::v1 as subnet_pb;
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::convert::{AsMut, AsRef, TryFrom, TryInto};
use std::hash::{Hash, Hasher};

/// PseudoRandomId is defined in execution context as plain 32-byte vector, we give it a synonym here.
pub type PseudoRandomId = [u8; 32];

/// RequestId is used for two purposes:
/// 1. to identify the matching request in sign_with_ecdsa_contexts.
/// 2. to identify which quadruple the request is matched to.
///
/// Quadruples must be matched with requests in the same order as requests
/// are created.
///
/// The height field represents at which block the RequestId is created.
/// It is used for purging purpose.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct RequestId {
    pub quadruple_id: QuadrupleId,
    pub pseudo_random_id: PseudoRandomId,
    pub height: Height,
}

impl From<RequestId> for pb::RequestId {
    fn from(request_id: RequestId) -> Self {
        Self {
            quadruple_id: request_id.quadruple_id.id(),
            key_id: request_id.quadruple_id.key_id().map(Into::into),
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

            let key_id = request_id
                .key_id
                .clone()
                .map(EcdsaKeyId::try_from)
                .transpose()?;

            Ok(Self {
                quadruple_id: QuadrupleId(request_id.quadruple_id, key_id),
                pseudo_random_id,
                height: Height::from(request_id.height),
            })
        }
    }
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
// TODO(kpop): remove the second field
pub struct QuadrupleId(pub(crate) u64, pub(crate) Option<EcdsaKeyId>);

impl QuadrupleId {
    pub fn new(id: u64) -> Self {
        Self(id, None)
    }

    pub fn id(&self) -> u64 {
        self.0
    }

    pub fn key_id(&self) -> Option<&EcdsaKeyId> {
        self.1.as_ref()
    }
}

// Since `QuadrupleId.0` is globally unique across all ecdsa key ids (this is guaranteed by the
// `EcdsaUIDGenerator`), we use only this field to compute the hash of the `QuadrupleId`.
impl Hash for QuadrupleId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id().hash(state);
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

/// ECDSA Quadruple in creation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuadrupleInCreation {
    pub key_id: Option<EcdsaKeyId>,

    pub kappa_masked_config: Option<RandomTranscriptParams>,
    pub kappa_masked: Option<MaskedTranscript>,

    pub lambda_config: RandomTranscriptParams,
    pub lambda_masked: Option<MaskedTranscript>,

    pub kappa_unmasked_config: Option<RandomUnmaskedTranscriptParams>,
    pub unmask_kappa_config: Option<ReshareOfMaskedParams>,
    pub kappa_unmasked: Option<UnmaskedTranscript>,

    pub key_times_lambda_config: Option<UnmaskedTimesMaskedParams>,
    pub key_times_lambda: Option<MaskedTranscript>,

    pub kappa_times_lambda_config: Option<UnmaskedTimesMaskedParams>,
    pub kappa_times_lambda: Option<MaskedTranscript>,
}

impl Hash for QuadrupleInCreation {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Some(key_id) = &self.key_id {
            key_id.hash(state);
        }
        if let Some(config) = &self.kappa_masked_config {
            config.hash(state);
            self.kappa_masked.hash(state);
        }
        self.lambda_config.hash(state);
        self.lambda_masked.hash(state);
        if let Some(config) = &self.kappa_unmasked_config {
            config.hash(state);
        }
        if self.kappa_masked_config.is_some() {
            self.unmask_kappa_config.hash(state);
        }
        self.kappa_unmasked.hash(state);
        self.key_times_lambda_config.hash(state);
        self.key_times_lambda.hash(state);
        self.kappa_times_lambda_config.hash(state);
        self.kappa_times_lambda.hash(state);
    }
}

impl QuadrupleInCreation {
    /// Initialization with the given random param pair.
    pub fn new(
        _key_id: EcdsaKeyId,
        kappa_masked_config: RandomTranscriptParams,
        lambda_config: RandomTranscriptParams,
    ) -> Self {
        Self {
            key_id: None,
            kappa_masked_config: Some(kappa_masked_config),
            kappa_masked: None,
            lambda_config,
            lambda_masked: None,
            kappa_unmasked_config: None,
            unmask_kappa_config: None,
            kappa_unmasked: None,
            key_times_lambda_config: None,
            key_times_lambda: None,
            kappa_times_lambda_config: None,
            kappa_times_lambda: None,
        }
    }

    /// Initialization with unmasked kappa param.
    pub fn new_with_unmasked_kappa(
        kappa_unmasked_config: RandomUnmaskedTranscriptParams,
        lambda_config: RandomTranscriptParams,
    ) -> Self {
        QuadrupleInCreation {
            key_id: None,
            kappa_masked_config: None,
            kappa_masked: None,
            lambda_config,
            lambda_masked: None,
            kappa_unmasked_config: Some(kappa_unmasked_config),
            unmask_kappa_config: None,
            kappa_unmasked: None,
            key_times_lambda_config: None,
            key_times_lambda: None,
            kappa_times_lambda_config: None,
            kappa_times_lambda: None,
        }
    }
}

impl QuadrupleInCreation {
    /// Return an iterator of all transcript configs that have no matching
    /// results yet.
    pub fn iter_transcript_configs_in_creation(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        let mut params = Vec::new();
        if let (Some(config), None) = (&self.kappa_masked_config, &self.kappa_masked) {
            params.push(config.as_ref())
        }
        if self.lambda_masked.is_none() {
            params.push(self.lambda_config.as_ref())
        }
        if let (Some(config), None) = (&self.unmask_kappa_config, &self.kappa_unmasked) {
            params.push(config.as_ref())
        } else if let (Some(config), None) = (&self.kappa_unmasked_config, &self.kappa_unmasked) {
            params.push(config.as_ref())
        }
        if let (Some(config), None) = (&self.key_times_lambda_config, &self.key_times_lambda) {
            params.push(config.as_ref())
        }
        if let (Some(config), None) = (&self.kappa_times_lambda_config, &self.kappa_times_lambda) {
            params.push(config.as_ref())
        }
        Box::new(params.into_iter())
    }

    /// Returns the refs held
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        let mut ret = Vec::new();
        if let Some(config) = &self.kappa_masked_config {
            ret.append(&mut config.as_ref().get_refs());
        }
        if let Some(r) = &self.kappa_masked {
            ret.push(*r.as_ref());
        }

        ret.append(&mut self.lambda_config.as_ref().get_refs());
        if let Some(r) = &self.lambda_masked {
            ret.push(*r.as_ref());
        }

        if let Some(config) = &self.unmask_kappa_config {
            ret.append(&mut config.as_ref().get_refs());
        } else if let Some(config) = &self.kappa_unmasked_config {
            ret.append(&mut config.as_ref().get_refs());
        }
        if let Some(r) = &self.kappa_unmasked {
            ret.push(*r.as_ref());
        }

        if let Some(config) = &self.key_times_lambda_config {
            ret.append(&mut config.as_ref().get_refs());
        }
        if let Some(r) = &self.key_times_lambda {
            ret.push(*r.as_ref());
        }

        if let Some(config) = &self.kappa_times_lambda_config {
            ret.append(&mut config.as_ref().get_refs());
        }
        if let Some(r) = &self.kappa_times_lambda {
            ret.push(*r.as_ref());
        }

        ret
    }

    /// Updates the height of the references.
    pub fn update(&mut self, height: Height) {
        if let Some(config) = &mut self.kappa_masked_config {
            config.as_mut().update(height);
        }
        if let Some(r) = &mut self.kappa_masked {
            r.as_mut().update(height);
        }

        self.lambda_config.as_mut().update(height);
        if let Some(r) = &mut self.lambda_masked {
            r.as_mut().update(height);
        }

        if let Some(config) = &mut self.unmask_kappa_config {
            config.as_mut().update(height);
        } else if let Some(config) = &mut self.kappa_unmasked_config {
            config.as_mut().update(height);
        }
        if let Some(r) = &mut self.kappa_unmasked {
            r.as_mut().update(height);
        }

        if let Some(config) = &mut self.key_times_lambda_config {
            config.as_mut().update(height);
        }
        if let Some(r) = &mut self.key_times_lambda {
            r.as_mut().update(height);
        }

        if let Some(config) = &mut self.kappa_times_lambda_config {
            config.as_mut().update(height);
        }
        if let Some(r) = &mut self.kappa_times_lambda {
            r.as_mut().update(height);
        }
    }
}

impl From<&QuadrupleInCreation> for pb::QuadrupleInCreation {
    fn from(quadruple: &QuadrupleInCreation) -> Self {
        Self {
            key_id: quadruple.key_id.as_ref().map(Into::into),
            kappa_masked_config: quadruple
                .kappa_masked_config
                .as_ref()
                .map(|params| params.into()),
            kappa_masked: quadruple
                .kappa_masked
                .as_ref()
                .map(|transcript| transcript.into()),

            lambda_config: Some((&quadruple.lambda_config).into()),
            lambda_masked: quadruple
                .lambda_masked
                .as_ref()
                .map(|transcript| transcript.into()),

            kappa_unmasked_config: quadruple
                .kappa_unmasked_config
                .as_ref()
                .map(|params| params.into()),
            unmask_kappa_config: quadruple
                .unmask_kappa_config
                .as_ref()
                .map(|params| params.into()),
            kappa_unmasked: quadruple
                .kappa_unmasked
                .as_ref()
                .map(|transcript| transcript.into()),

            key_times_lambda_config: quadruple
                .key_times_lambda_config
                .as_ref()
                .map(|params| params.into()),
            key_times_lambda: quadruple
                .key_times_lambda
                .as_ref()
                .map(|transcript| transcript.into()),

            kappa_times_lambda_config: quadruple
                .kappa_times_lambda_config
                .as_ref()
                .map(|params| params.into()),
            kappa_times_lambda: quadruple
                .kappa_times_lambda
                .as_ref()
                .map(|transcript| transcript.into()),
        }
    }
}

impl TryFrom<&pb::QuadrupleInCreation> for QuadrupleInCreation {
    type Error = ProxyDecodeError;
    fn try_from(quadruple: &pb::QuadrupleInCreation) -> Result<Self, Self::Error> {
        let (kappa_masked_config, kappa_masked) =
            if let Some(config_proto) = &quadruple.kappa_masked_config {
                let config: RandomTranscriptParams = config_proto.try_into()?;
                let transcript: Option<MaskedTranscript> = quadruple
                    .kappa_masked
                    .as_ref()
                    .map(|transcript| transcript.try_into())
                    .transpose()?;
                (Some(config), transcript)
            } else {
                (None, None)
            };

        let lambda_config: RandomTranscriptParams = try_from_option_field(
            quadruple.lambda_config.as_ref(),
            "QuadrupleInCreation::lambda_config",
        )?;

        let lambda_masked: Option<MaskedTranscript> = quadruple
            .lambda_masked
            .as_ref()
            .map(|transcript| transcript.try_into())
            .transpose()?;

        let kappa_unmasked_config = quadruple
            .kappa_unmasked_config
            .as_ref()
            .map(|config_proto| config_proto.try_into())
            .transpose()?;

        let unmask_kappa_config = quadruple
            .unmask_kappa_config
            .as_ref()
            .map(|config_proto| config_proto.try_into())
            .transpose()?;

        let kappa_unmasked = match (&unmask_kappa_config, &kappa_unmasked_config) {
            (None, None) => None,
            _ => quadruple
                .kappa_unmasked
                .as_ref()
                .map(|transcript| transcript.try_into())
                .transpose()?,
        };

        let (key_times_lambda_config, key_times_lambda) =
            if let Some(config_proto) = &quadruple.key_times_lambda_config {
                let config: UnmaskedTimesMaskedParams = config_proto.try_into()?;
                let transcript: Option<MaskedTranscript> = quadruple
                    .key_times_lambda
                    .as_ref()
                    .map(|transcript| transcript.try_into())
                    .transpose()?;
                (Some(config), transcript)
            } else {
                (None, None)
            };

        let (kappa_times_lambda_config, kappa_times_lambda) =
            if let Some(config_proto) = &quadruple.kappa_times_lambda_config {
                let config: UnmaskedTimesMaskedParams = config_proto.try_into()?;
                let transcript: Option<MaskedTranscript> = quadruple
                    .kappa_times_lambda
                    .as_ref()
                    .map(|transcript| transcript.try_into())
                    .transpose()?;
                (Some(config), transcript)
            } else {
                (None, None)
            };

        let key_id = quadruple
            .key_id
            .clone()
            .map(TryInto::try_into)
            .transpose()?;

        Ok(Self {
            key_id,
            kappa_masked_config,
            kappa_masked,
            lambda_config,
            lambda_masked,
            kappa_unmasked_config,
            unmask_kappa_config,
            kappa_unmasked,
            key_times_lambda_config,
            key_times_lambda,
            kappa_times_lambda_config,
            kappa_times_lambda,
        })
    }
}

pub type TranscriptLookupError = String;

/// Wrapper to access the ECDSA related info from the blocks.
pub trait EcdsaBlockReader: Send + Sync {
    /// Returns the height of the tip
    fn tip_height(&self) -> Height;

    /// Returns the transcripts requested by the tip.
    fn requested_transcripts(&self) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_>;

    /// Returns the IDs of quadruples in creation by the tip.
    fn quadruples_in_creation(&self) -> Box<dyn Iterator<Item = &QuadrupleId> + '_>;

    /// For the given quadruple ID, returns the quadruple ref if available.
    fn available_quadruple(&self, id: &QuadrupleId) -> Option<&PreSignatureQuadrupleRef>;

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
        resolver: &dyn EcdsaBlockReader,
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
        resolver: &dyn EcdsaBlockReader,
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

/// Counterpart of PreSignatureQuadruple that holds transcript references,
/// instead of the transcripts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreSignatureQuadrupleRef {
    pub key_id: Option<EcdsaKeyId>,
    pub kappa_unmasked_ref: UnmaskedTranscript,
    pub lambda_masked_ref: MaskedTranscript,
    pub kappa_times_lambda_ref: MaskedTranscript,
    pub key_times_lambda_ref: MaskedTranscript,
    pub key_unmasked_ref: UnmaskedTranscript,
}

impl Hash for PreSignatureQuadrupleRef {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Some(key_id) = &self.key_id {
            key_id.hash(state);
        }

        self.kappa_unmasked_ref.hash(state);
        self.lambda_masked_ref.hash(state);
        self.kappa_times_lambda_ref.hash(state);
        self.key_times_lambda_ref.hash(state);
        self.key_unmasked_ref.hash(state);
    }
}

#[derive(Clone, Debug)]
pub enum PreSignatureQuadrupleError {
    KappaUnmasked(TranscriptLookupError),
    LambdaMasked(TranscriptLookupError),
    KappaTimesLambda(TranscriptLookupError),
    KeyTimesLambda(TranscriptLookupError),
    Failed(EcdsaPresignatureQuadrupleCreationError),
}

impl PreSignatureQuadrupleRef {
    pub fn new(
        kappa_unmasked_ref: UnmaskedTranscript,
        lambda_masked_ref: MaskedTranscript,
        kappa_times_lambda_ref: MaskedTranscript,
        key_times_lambda_ref: MaskedTranscript,
        key_unmasked_ref: UnmaskedTranscript,
    ) -> Self {
        Self {
            key_id: None,
            kappa_unmasked_ref,
            lambda_masked_ref,
            kappa_times_lambda_ref,
            key_times_lambda_ref,
            key_unmasked_ref,
        }
    }

    /// Resolves the refs to get the PreSignatureQuadruple.
    pub fn translate(
        &self,
        resolver: &dyn EcdsaBlockReader,
    ) -> Result<EcdsaPreSignatureQuadruple, PreSignatureQuadrupleError> {
        let kappa_unmasked = resolver
            .transcript(self.kappa_unmasked_ref.as_ref())
            .map_err(PreSignatureQuadrupleError::KappaUnmasked)?;
        let lambda_masked = resolver
            .transcript(self.lambda_masked_ref.as_ref())
            .map_err(PreSignatureQuadrupleError::LambdaMasked)?;
        let kappa_times_lambda = resolver
            .transcript(self.kappa_times_lambda_ref.as_ref())
            .map_err(PreSignatureQuadrupleError::KappaTimesLambda)?;
        let key_times_lambda = resolver
            .transcript(self.key_times_lambda_ref.as_ref())
            .map_err(PreSignatureQuadrupleError::KeyTimesLambda)?;
        EcdsaPreSignatureQuadruple::new(
            kappa_unmasked,
            lambda_masked,
            kappa_times_lambda,
            key_times_lambda,
        )
        .map_err(PreSignatureQuadrupleError::Failed)
    }

    /// Returns the refs held
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        vec![
            *self.kappa_unmasked_ref.as_ref(),
            *self.lambda_masked_ref.as_ref(),
            *self.kappa_times_lambda_ref.as_ref(),
            *self.key_times_lambda_ref.as_ref(),
            *self.key_unmasked_ref.as_ref(),
        ]
    }

    /// Updates the height of the references.
    pub fn update(&mut self, height: Height) {
        self.kappa_unmasked_ref.as_mut().update(height);
        self.lambda_masked_ref.as_mut().update(height);
        self.kappa_times_lambda_ref.as_mut().update(height);
        self.key_times_lambda_ref.as_mut().update(height);
        self.key_unmasked_ref.as_mut().update(height);
    }
}

impl From<&PreSignatureQuadrupleRef> for pb::PreSignatureQuadrupleRef {
    fn from(quadruple: &PreSignatureQuadrupleRef) -> Self {
        Self {
            key_id: quadruple.key_id.as_ref().map(Into::into),
            kappa_unmasked_ref: Some((&quadruple.kappa_unmasked_ref).into()),
            lambda_masked_ref: Some((&quadruple.lambda_masked_ref).into()),
            kappa_times_lambda_ref: Some((&quadruple.kappa_times_lambda_ref).into()),
            key_times_lambda_ref: Some((&quadruple.key_times_lambda_ref).into()),
            key_unmasked_ref: Some((&quadruple.key_unmasked_ref).into()),
        }
    }
}

impl TryFrom<&pb::PreSignatureQuadrupleRef> for PreSignatureQuadrupleRef {
    type Error = ProxyDecodeError;
    fn try_from(quadruple: &pb::PreSignatureQuadrupleRef) -> Result<Self, Self::Error> {
        let kappa_unmasked_ref: UnmaskedTranscript = try_from_option_field(
            quadruple.kappa_unmasked_ref.as_ref(),
            "PreSignatureQuadrupleRef::quadruple::kappa_unmasked_ref",
        )?;

        let lambda_masked_ref: MaskedTranscript = try_from_option_field(
            quadruple.lambda_masked_ref.as_ref(),
            "PreSignatureQuadrupleRef::quadruple::lamdba_masked_ref",
        )?;

        let kappa_times_lambda_ref: MaskedTranscript = try_from_option_field(
            quadruple.kappa_times_lambda_ref.as_ref(),
            "PreSignatureQuadrupleRef::quadruple::kappa_times_lamdba_ref",
        )?;

        let key_times_lambda_ref: MaskedTranscript = try_from_option_field(
            quadruple.key_times_lambda_ref.as_ref(),
            "PreSignatureQuadrupleRef::quadruple::key_times_lamdba_ref",
        )?;

        let key_unmasked_ref: UnmaskedTranscript = try_from_option_field(
            quadruple.key_unmasked_ref.as_ref(),
            "PreSignatureQuadrupleRef::quadruple::key_unmasked_ref",
        )?;

        let key_id = quadruple
            .key_id
            .clone()
            .map(TryInto::try_into)
            .transpose()?;

        Ok(Self {
            key_id,
            kappa_unmasked_ref,
            lambda_masked_ref,
            kappa_times_lambda_ref,
            key_times_lambda_ref,
            key_unmasked_ref,
        })
    }
}

/// Counterpart of ThresholdEcdsaSigInputs that holds transcript references,
/// instead of the transcripts.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct ThresholdEcdsaSigInputsRef {
    pub derivation_path: ExtendedDerivationPath,
    pub hashed_message: [u8; 32],
    pub nonce: Randomness,
    pub presig_quadruple_ref: PreSignatureQuadrupleRef,
    pub key_transcript_ref: UnmaskedTranscript,
}

#[derive(Clone, Debug)]
pub enum ThresholdEcdsaSigInputsError {
    PreSignatureQuadruple(PreSignatureQuadrupleError),
    KeyTranscript(TranscriptLookupError),
    Failed(ThresholdEcdsaSigInputsCreationError),
}

impl ThresholdEcdsaSigInputsRef {
    pub fn new(
        derivation_path: ExtendedDerivationPath,
        hashed_message: [u8; 32],
        nonce: Randomness,
        presig_quadruple_ref: PreSignatureQuadrupleRef,
        key_transcript_ref: UnmaskedTranscript,
    ) -> Self {
        Self {
            derivation_path,
            hashed_message,
            nonce,
            presig_quadruple_ref,
            key_transcript_ref,
        }
    }

    /// Resolves the refs to get the ThresholdEcdsaSigInputs.
    pub fn translate(
        &self,
        resolver: &dyn EcdsaBlockReader,
    ) -> Result<ThresholdEcdsaSigInputs, ThresholdEcdsaSigInputsError> {
        let presig_quadruple = self
            .presig_quadruple_ref
            .translate(resolver)
            .map_err(ThresholdEcdsaSigInputsError::PreSignatureQuadruple)?;
        let key_transcript = resolver
            .transcript(self.key_transcript_ref.as_ref())
            .map_err(ThresholdEcdsaSigInputsError::KeyTranscript)?;
        ThresholdEcdsaSigInputs::new(
            &self.derivation_path,
            &self.hashed_message,
            self.nonce,
            presig_quadruple,
            key_transcript,
        )
        .map_err(ThresholdEcdsaSigInputsError::Failed)
    }
}

impl From<&ThresholdEcdsaSigInputsRef> for pb::ThresholdEcdsaSigInputsRef {
    fn from(sig_inputs: &ThresholdEcdsaSigInputsRef) -> Self {
        Self {
            derivation_path: Some((sig_inputs.derivation_path.clone()).into()),
            hashed_message: sig_inputs.hashed_message.to_vec(),
            nonce: sig_inputs.nonce.get().to_vec(),
            presig_quadruple_ref: Some((&sig_inputs.presig_quadruple_ref).into()),
            key_transcript_ref: Some((&sig_inputs.key_transcript_ref).into()),
        }
    }
}

impl TryFrom<&pb::ThresholdEcdsaSigInputsRef> for ThresholdEcdsaSigInputsRef {
    type Error = ProxyDecodeError;
    fn try_from(sig_inputs: &pb::ThresholdEcdsaSigInputsRef) -> Result<Self, Self::Error> {
        let derivation_path: ExtendedDerivationPath = try_from_option_field(
            sig_inputs.derivation_path.clone(),
            "ThresholdEcdsaSigInputsRef::derivation_path",
        )?;

        if sig_inputs.hashed_message.len() != 32 {
            return Err(ProxyDecodeError::Other(format!(
                "ThresholdEcdsaSigInputsRef:: Invalid hashed_message length: {:?}",
                sig_inputs.nonce.len()
            )));
        }
        let mut hashed_message = [0; 32];
        hashed_message.copy_from_slice(&sig_inputs.hashed_message[0..32]);

        if sig_inputs.nonce.len() != 32 {
            return Err(ProxyDecodeError::Other(format!(
                "ThresholdEcdsaSigInputsRef:: Invalid nonce length: {:?}",
                sig_inputs.nonce.len()
            )));
        }
        let mut nonce = [0; 32];
        nonce.copy_from_slice(&sig_inputs.nonce[0..32]);
        let nonce = Randomness::from(nonce);

        let presig_quadruple_ref: PreSignatureQuadrupleRef = try_from_option_field(
            sig_inputs.presig_quadruple_ref.as_ref(),
            "ThresholdEcdsaSigInputsRef::presig_quadruple_ref",
        )?;

        let key_transcript_ref: UnmaskedTranscript = try_from_option_field(
            sig_inputs.key_transcript_ref.as_ref(),
            "ThresholdEcdsaSigInputsRef::key_transcript_ref",
        )?;

        Ok(Self::new(
            derivation_path,
            hashed_message,
            nonce,
            presig_quadruple_ref,
            key_transcript_ref,
        ))
    }
}
