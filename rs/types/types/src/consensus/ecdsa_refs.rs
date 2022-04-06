//! Threshold ECDSA transcript references related defines.

use ic_base_types::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::convert::{AsMut, AsRef, TryFrom, TryInto};

use crate::crypto::{
    canister_threshold_sig::error::{
        IDkgParamsValidationError, PresignatureQuadrupleCreationError,
        ThresholdEcdsaSigInputsCreationError,
    },
    canister_threshold_sig::idkg::{
        proto_conversions::{idkg_transcript_id_proto, idkg_transcript_id_struct},
        IDkgTranscript, IDkgTranscriptId, IDkgTranscriptOperation, IDkgTranscriptParams,
        IDkgTranscriptType,
    },
    canister_threshold_sig::{
        ExtendedDerivationPath, PreSignatureQuadruple, ThresholdEcdsaSigInputs,
    },
    AlgorithmId,
};
use crate::{Height, Randomness, RegistryVersion};
use ic_protobuf::registry::subnet::v1 as subnet_pb;
use ic_protobuf::types::v1 as pb;
use phantom_newtype::Id;

pub struct RequestIdTag;
pub type RequestId = Id<RequestIdTag, Vec<u8>>;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
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

    /// Updates the height if specified, and returns the value before
    /// the update.
    pub fn get_and_update(&mut self, height: Option<Height>) -> Self {
        let ret = *self;
        if let Some(h) = height {
            self.height = h;
        }
        ret
    }
}

impl From<&TranscriptRef> for pb::TranscriptRef {
    fn from(trancript_ref: &TranscriptRef) -> Self {
        Self {
            height: trancript_ref.height.get(),
            transcript_id: Some(idkg_transcript_id_proto(&trancript_ref.transcript_id)),
        }
    }
}

impl TryFrom<&pb::TranscriptRef> for TranscriptRef {
    type Error = String;
    fn try_from(trancript_ref: &pb::TranscriptRef) -> Result<Self, Self::Error> {
        let transcript_id =
            idkg_transcript_id_struct(&trancript_ref.transcript_id).map_err(|err| {
                format!(
                    "pb::TranscriptRef:: Failed to convert transcript id: {:?}",
                    err
                )
            })?;
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
    type Error = String;
    fn try_from(transcript: &pb::MaskedTranscript) -> Result<Self, Self::Error> {
        let transcript_ref_proto = transcript
            .transcript_ref
            .as_ref()
            .ok_or("pb::MaskedTranscript:: Missing transcript ref")?;
        let transcript_ref = transcript_ref_proto.try_into()?;
        Ok(Self(transcript_ref))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
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
    type Error = String;
    fn try_from(transcript: &pb::UnmaskedTranscript) -> Result<Self, Self::Error> {
        let transcript_ref_proto = transcript
            .transcript_ref
            .as_ref()
            .ok_or("pb::UnmaskedTranscript:: Missing transcript ref")?;
        let transcript_ref = transcript_ref_proto.try_into()?;
        Ok(Self(transcript_ref))
    }
}

/// Wrappers for the common types.

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
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
    type Error = String;
    fn try_from(transcript: &pb::RandomTranscriptParams) -> Result<Self, Self::Error> {
        let transcript_ref_proto = transcript
            .transcript_ref
            .as_ref()
            .ok_or("pb::RandomTranscriptParams:: Missing transcript ref")?;
        let transcript_ref = transcript_ref_proto.try_into()?;
        Ok(Self(transcript_ref))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ReshareOfMaskedParams(IDkgTranscriptParamsRef);
impl ReshareOfMaskedParams {
    pub fn new(
        transcript_id: IDkgTranscriptId,
        dealers: BTreeSet<NodeId>,
        receivers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
        algorithm_id: AlgorithmId,
        transcript: MaskedTranscript,
    ) -> Self {
        Self(IDkgTranscriptParamsRef::new(
            transcript_id,
            dealers,
            receivers,
            registry_version,
            algorithm_id,
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
    type Error = String;
    fn try_from(transcript: &pb::ReshareOfMaskedParams) -> Result<Self, Self::Error> {
        let transcript_ref_proto = transcript
            .transcript_ref
            .as_ref()
            .ok_or("pb::ReshareOfMaskedParams:: Missing transcript ref")?;
        let transcript_ref = transcript_ref_proto.try_into()?;
        Ok(Self(transcript_ref))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ReshareOfUnmaskedParams(IDkgTranscriptParamsRef);
impl ReshareOfUnmaskedParams {
    pub fn new(
        transcript_id: IDkgTranscriptId,
        dealers: BTreeSet<NodeId>,
        receivers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
        algorithm_id: AlgorithmId,
        transcript: UnmaskedTranscript,
    ) -> Self {
        Self(IDkgTranscriptParamsRef::new(
            transcript_id,
            dealers,
            receivers,
            registry_version,
            algorithm_id,
            IDkgTranscriptOperationRef::ReshareOfUnmasked(transcript),
        ))
    }
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
    type Error = String;
    fn try_from(transcript: &pb::ReshareOfUnmaskedParams) -> Result<Self, Self::Error> {
        let transcript_ref_proto = transcript
            .transcript_ref
            .as_ref()
            .ok_or("pb::ReshareOfUnmaskedParams:: Missing transcript ref")?;
        let transcript_ref = transcript_ref_proto.try_into()?;
        Ok(Self(transcript_ref))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct UnmaskedTimesMaskedParams(IDkgTranscriptParamsRef);
impl UnmaskedTimesMaskedParams {
    pub fn new(
        transcript_id: IDkgTranscriptId,
        dealers: BTreeSet<NodeId>,
        receivers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
        algorithm_id: AlgorithmId,
        transcript_1: UnmaskedTranscript,
        transcript_2: MaskedTranscript,
    ) -> Self {
        Self(IDkgTranscriptParamsRef::new(
            transcript_id,
            dealers,
            receivers,
            registry_version,
            algorithm_id,
            IDkgTranscriptOperationRef::UnmaskedTimesMasked(transcript_1, transcript_2),
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
    type Error = String;
    fn try_from(transcript: &pb::UnmaskedTimesMaskedParams) -> Result<Self, Self::Error> {
        let transcript_ref_proto = transcript
            .transcript_ref
            .as_ref()
            .ok_or("pb::UnmaskedTimesMaskedParams:: Missing transcript ref")?;
        let transcript_ref = transcript_ref_proto.try_into()?;
        Ok(Self(transcript_ref))
    }
}

/// ECDSA Quadruple in creation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QuadrupleInCreation {
    pub kappa_config: RandomTranscriptParams,
    pub kappa_masked: Option<MaskedTranscript>,

    pub lambda_config: RandomTranscriptParams,
    pub lambda_masked: Option<MaskedTranscript>,

    pub unmask_kappa_config: Option<ReshareOfMaskedParams>,
    pub kappa_unmasked: Option<UnmaskedTranscript>,

    pub key_times_lambda_config: Option<UnmaskedTimesMaskedParams>,
    pub key_times_lambda: Option<MaskedTranscript>,

    pub kappa_times_lambda_config: Option<UnmaskedTimesMaskedParams>,
    pub kappa_times_lambda: Option<MaskedTranscript>,
}

impl QuadrupleInCreation {
    /// Initialization with the given random param pair.
    pub fn new(
        kappa_config: RandomTranscriptParams,
        lambda_config: RandomTranscriptParams,
    ) -> Self {
        QuadrupleInCreation {
            kappa_config,
            kappa_masked: None,
            lambda_config,
            lambda_masked: None,
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
        if self.kappa_masked.is_none() {
            params.push(self.kappa_config.as_ref())
        }
        if self.lambda_masked.is_none() {
            params.push(self.lambda_config.as_ref())
        }
        if let (Some(config), None) = (&self.unmask_kappa_config, &self.kappa_unmasked) {
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
        ret.append(&mut self.kappa_config.as_ref().get_refs());
        if let Some(r) = &self.kappa_masked {
            ret.push(*r.as_ref());
        }

        ret.append(&mut self.lambda_config.as_ref().get_refs());
        if let Some(r) = &self.lambda_masked {
            ret.push(*r.as_ref());
        }

        if let Some(config) = &self.unmask_kappa_config {
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
        self.kappa_config.as_mut().update(height);
        if let Some(r) = &mut self.kappa_masked {
            r.as_mut().update(height);
        }

        self.lambda_config.as_mut().update(height);
        if let Some(r) = &mut self.lambda_masked {
            r.as_mut().update(height);
        }

        if let Some(config) = &mut self.unmask_kappa_config {
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

    /// Returns the refs held and updates the height if specified
    pub fn get_refs_and_update(&mut self, height: Option<Height>) -> Vec<TranscriptRef> {
        let mut ret = Vec::new();
        ret.append(&mut self.kappa_config.as_mut().get_refs_and_update(height));
        if let Some(r) = &mut self.kappa_masked {
            ret.push(r.as_mut().get_and_update(height));
        }

        ret.append(&mut self.lambda_config.as_mut().get_refs_and_update(height));
        if let Some(r) = &mut self.lambda_masked {
            ret.push(r.as_mut().get_and_update(height));
        }

        if let Some(config) = &mut self.unmask_kappa_config {
            ret.append(&mut config.as_mut().get_refs_and_update(height));
        }
        if let Some(r) = &mut self.kappa_unmasked {
            ret.push(r.as_mut().get_and_update(height));
        }

        if let Some(config) = &mut self.key_times_lambda_config {
            ret.append(&mut config.as_mut().get_refs_and_update(height));
        }
        if let Some(r) = &mut self.key_times_lambda {
            ret.push(r.as_mut().get_and_update(height));
        }

        if let Some(config) = &mut self.kappa_times_lambda_config {
            ret.append(&mut config.as_mut().get_refs_and_update(height));
        }
        if let Some(r) = &mut self.kappa_times_lambda {
            ret.push(r.as_mut().get_and_update(height));
        }

        ret
    }
}

impl From<&QuadrupleInCreation> for pb::QuadrupleInCreation {
    fn from(quadruple: &QuadrupleInCreation) -> Self {
        Self {
            kappa_config: Some((&quadruple.kappa_config).into()),
            kappa_masked: quadruple
                .kappa_masked
                .as_ref()
                .map(|transcript| transcript.into()),

            lambda_config: Some((&quadruple.lambda_config).into()),
            lambda_masked: quadruple
                .lambda_masked
                .as_ref()
                .map(|transcript| transcript.into()),

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
    type Error = String;
    fn try_from(quadruple: &pb::QuadrupleInCreation) -> Result<Self, Self::Error> {
        let kappa_config: RandomTranscriptParams = quadruple
            .kappa_config
            .as_ref()
            .ok_or("pb::QuadrupleInCreation:: Missing kappa config")?
            .try_into()?;
        let kappa_masked: Option<MaskedTranscript> = quadruple
            .kappa_masked
            .as_ref()
            .map(|transcript| transcript.try_into())
            .transpose()?;

        let lambda_config: RandomTranscriptParams = quadruple
            .lambda_config
            .as_ref()
            .ok_or("pb::QuadrupleInCreation:: Missing lambda config")?
            .try_into()?;
        let lambda_masked: Option<MaskedTranscript> = quadruple
            .lambda_masked
            .as_ref()
            .map(|transcript| transcript.try_into())
            .transpose()?;

        let (unmask_kappa_config, kappa_unmasked) =
            if let Some(config_proto) = &quadruple.unmask_kappa_config {
                let config: ReshareOfMaskedParams = config_proto.try_into()?;
                let transcript: Option<UnmaskedTranscript> = quadruple
                    .kappa_unmasked
                    .as_ref()
                    .map(|transcript| transcript.try_into())
                    .transpose()?;
                (Some(config), transcript)
            } else {
                (None, None)
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

        Ok(Self {
            kappa_config,
            kappa_masked,
            lambda_config,
            lambda_masked,
            unmask_kappa_config,
            kappa_unmasked,
            key_times_lambda_config,
            key_times_lambda,
            kappa_times_lambda_config,
            kappa_times_lambda,
        })
    }
}

#[derive(Clone, Debug)]
pub enum TranscriptLookupError {
    BlockNotFound(TranscriptRef),
    NoEcdsaSummary(TranscriptRef),
    NoEcdsaPayload(TranscriptRef),
    TranscriptNotFound(TranscriptRef, bool),
}

/// Wrapper to access the ECDSA related info from the blocks.
pub trait EcdsaBlockReader {
    /// Returns the height of the tip
    fn tip_height(&self) -> Height;

    /// Returns the transcripts requested by the tip.
    fn requested_transcripts(&self) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_>;

    /// Returns the signatures requested by the tip.
    fn requested_signatures(
        &self,
    ) -> Box<dyn Iterator<Item = (&RequestId, &ThresholdEcdsaSigInputsRef)> + '_>;

    /// Returns the set of all the active references.
    fn active_transcripts(&self) -> Vec<TranscriptRef>;

    /// Looks up the transcript for the given transcript ref.
    fn transcript(
        &self,
        transcript_ref: &TranscriptRef,
    ) -> Result<IDkgTranscript, TranscriptLookupError>;
}

/// Counterpart of IDkgTranscriptParams that holds transcript references,
/// instead of the transcripts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum IDkgTranscriptOperationRef {
    Random,
    ReshareOfMasked(MaskedTranscript),
    ReshareOfUnmasked(UnmaskedTranscript),
    UnmaskedTimesMasked(UnmaskedTranscript, MaskedTranscript),
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
            Self::ReshareOfMasked(r) => vec![*r.as_ref()],
            Self::ReshareOfUnmasked(r) => vec![*r.as_ref()],
            Self::UnmaskedTimesMasked(r1, r2) => vec![*r1.as_ref(), *r2.as_ref()],
        }
    }

    /// Updates the height of the references.
    pub fn update(&mut self, height: Height) {
        match self {
            Self::Random => (),
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

    /// Returns the refs held and updates the height if specified
    pub fn get_refs_and_update(&mut self, height: Option<Height>) -> Vec<TranscriptRef> {
        match self {
            Self::Random => vec![],
            Self::ReshareOfMasked(r) => vec![r.as_mut().get_and_update(height)],
            Self::ReshareOfUnmasked(r) => vec![r.as_mut().get_and_update(height)],
            Self::UnmaskedTimesMasked(r1, r2) => {
                vec![
                    r1.as_mut().get_and_update(height),
                    r2.as_mut().get_and_update(height),
                ]
            }
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
    type Error = String;
    fn try_from(op_ref: &pb::IDkgTranscriptOperationRef) -> Result<Self, Self::Error> {
        if op_ref.op_type == (subnet_pb::IDkgTranscriptOperation::Random as i32) {
            Ok(Self::Random)
        } else if op_ref.op_type == (subnet_pb::IDkgTranscriptOperation::ReshareOfMasked as i32) {
            let proto = op_ref
                .masked
                .as_ref()
                .ok_or("pb::IDkgTranscriptOperationRef:: Missing masked transcript")?;
            let masked: MaskedTranscript = proto.try_into()?;
            Ok(Self::ReshareOfMasked(masked))
        } else if op_ref.op_type == (subnet_pb::IDkgTranscriptOperation::ReshareOfUnmasked as i32) {
            let proto = op_ref
                .unmasked
                .as_ref()
                .ok_or("pb::IDkgTranscriptOperationRef:: Missing unmasked transcript")?;
            let unmasked: UnmaskedTranscript = proto.try_into()?;
            Ok(Self::ReshareOfUnmasked(unmasked))
        } else if op_ref.op_type == (subnet_pb::IDkgTranscriptOperation::UnmaskedTimesMasked as i32)
        {
            let proto = op_ref
                .unmasked
                .as_ref()
                .ok_or("pb::IDkgTranscriptOperationRef:: Missing unmasked transcript")?;
            let unmasked: UnmaskedTranscript = proto.try_into()?;

            let proto = op_ref.masked.as_ref().ok_or("Missing masked transcript")?;
            let masked: MaskedTranscript = proto.try_into()?;
            Ok(Self::UnmaskedTimesMasked(unmasked, masked))
        } else {
            Err(format!(
                "pb::IDkgTranscriptOperationRef:: Unknown operation type: {:?}",
                op_ref.op_type
            ))
        }
    }
}

/// Counterpart of IDkgTranscriptParams that holds transcript references,
/// instead of the transcripts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
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
            transcript_id: Some(idkg_transcript_id_proto(&params.transcript_id)),
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
    type Error = String;
    fn try_from(params: &pb::IDkgTranscriptParamsRef) -> Result<Self, Self::Error> {
        let transcript_id: IDkgTranscriptId = idkg_transcript_id_struct(&params.transcript_id)
            .map_err(|err| {
                format!(
                    "pb::IDkgTranscriptParamsRef:: Failed to convert transcript Id: {:?}",
                    err
                )
            })?;

        let mut dealers = BTreeSet::new();
        for pb_node_id in &params.dealers {
            let node_id = crate::node_id_try_from_protobuf(pb_node_id.clone()).map_err(|err| {
                format!(
                    "pb::IDkgTranscriptParamsRef:: Failed to convert dealer: {:?}",
                    err
                )
            })?;
            dealers.insert(node_id);
        }

        let mut receivers = BTreeSet::new();
        for pb_node_id in &params.receivers {
            let node_id = crate::node_id_try_from_protobuf(pb_node_id.clone()).map_err(|err| {
                format!(
                    "pb::IDkgTranscriptParamsRef:: Failed to convert receiver: {:?}",
                    err
                )
            })?;
            receivers.insert(node_id);
        }

        let proto = params
            .operation_type_ref
            .as_ref()
            .ok_or("pb::IDkgTranscriptParamsRef:: Missing operation_type_ref")?;
        let operation_ref: IDkgTranscriptOperationRef = proto.try_into()?;

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

    /// Returns the refs held and updates the height if specified
    pub fn get_refs_and_update(&mut self, height: Option<Height>) -> Vec<TranscriptRef> {
        self.operation_type_ref.get_refs_and_update(height)
    }
}

/// Counterpart of PreSignatureQuadruple that holds transcript references,
/// instead of the transcripts.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PreSignatureQuadrupleRef {
    pub kappa_unmasked_ref: UnmaskedTranscript,
    pub lambda_masked_ref: MaskedTranscript,
    pub kappa_times_lambda_ref: MaskedTranscript,
    pub key_times_lambda_ref: MaskedTranscript,
}

#[derive(Clone, Debug)]
pub enum PreSignatureQuadrupleError {
    KappaUnmasked(TranscriptLookupError),
    LambdaMasked(TranscriptLookupError),
    KappaTimesLambda(TranscriptLookupError),
    KeyTimesLambda(TranscriptLookupError),
    Failed(PresignatureQuadrupleCreationError),
}

impl PreSignatureQuadrupleRef {
    pub fn new(
        kappa_unmasked_ref: UnmaskedTranscript,
        lambda_masked_ref: MaskedTranscript,
        kappa_times_lambda_ref: MaskedTranscript,
        key_times_lambda_ref: MaskedTranscript,
    ) -> Self {
        Self {
            kappa_unmasked_ref,
            lambda_masked_ref,
            kappa_times_lambda_ref,
            key_times_lambda_ref,
        }
    }

    /// Resolves the refs to get the PreSignatureQuadruple.
    pub fn translate(
        &self,
        resolver: &dyn EcdsaBlockReader,
    ) -> Result<PreSignatureQuadruple, PreSignatureQuadrupleError> {
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
        PreSignatureQuadruple::new(
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
        ]
    }

    /// Updates the height of the references.
    pub fn update(&mut self, height: Height) {
        self.kappa_unmasked_ref.as_mut().update(height);
        self.lambda_masked_ref.as_mut().update(height);
        self.kappa_times_lambda_ref.as_mut().update(height);
        self.key_times_lambda_ref.as_mut().update(height);
    }

    /// Returns the refs held and updates the height if specified
    pub fn get_refs_and_update(&mut self, height: Option<Height>) -> Vec<TranscriptRef> {
        vec![
            self.kappa_unmasked_ref.as_mut().get_and_update(height),
            self.lambda_masked_ref.as_mut().get_and_update(height),
            self.kappa_times_lambda_ref.as_mut().get_and_update(height),
            self.key_times_lambda_ref.as_mut().get_and_update(height),
        ]
    }
}

impl From<&PreSignatureQuadrupleRef> for pb::PreSignatureQuadrupleRef {
    fn from(quadruple: &PreSignatureQuadrupleRef) -> Self {
        Self {
            kappa_unmasked_ref: Some((&quadruple.kappa_unmasked_ref).into()),
            lambda_masked_ref: Some((&quadruple.lambda_masked_ref).into()),
            kappa_times_lambda_ref: Some((&quadruple.kappa_times_lambda_ref).into()),
            key_times_lambda_ref: Some((&quadruple.key_times_lambda_ref).into()),
        }
    }
}

impl TryFrom<&pb::PreSignatureQuadrupleRef> for PreSignatureQuadrupleRef {
    type Error = String;
    fn try_from(quadruple: &pb::PreSignatureQuadrupleRef) -> Result<Self, Self::Error> {
        let proto = quadruple
            .kappa_unmasked_ref
            .as_ref()
            .ok_or("pb::PreSignatureQuadrupleRef:: Missing kappa unmasked")?;
        let kappa_unmasked_ref: UnmaskedTranscript = proto.try_into().map_err(|err| {
            format!(
                "pb::PreSignatureQuadrupleRef:: Failed to convert kappa_unmasked_ref : {:?}",
                err
            )
        })?;

        let proto = quadruple
            .lambda_masked_ref
            .as_ref()
            .ok_or("pb::PreSignatureQuadrupleRef:: Missing lambda masked")?;
        let lambda_masked_ref: MaskedTranscript = proto.try_into().map_err(|err| {
            format!(
                "pb::PreSignatureQuadrupleRef:: Failed to convert lambda_masked_ref : {:?}",
                err
            )
        })?;

        let proto = quadruple
            .kappa_times_lambda_ref
            .as_ref()
            .ok_or("Missing kappa times lambda masked")?;
        let kappa_times_lambda_ref: MaskedTranscript = proto.try_into().map_err(|err| {
            format!(
                "pb::PreSignatureQuadrupleRef:: Failed to convert kappa_times_lambda_ref : {:?}",
                err
            )
        })?;

        let proto = quadruple
            .key_times_lambda_ref
            .as_ref()
            .ok_or("pb::PreSignatureQuadrupleRef:: Missing key times lambda masked")?;
        let key_times_lambda_ref: MaskedTranscript = proto.try_into().map_err(|err| {
            format!(
                "pb::PreSignatureQuadrupleRef:: Failed to convert key_times_lambda_ref : {:?}",
                err
            )
        })?;

        Ok(Self::new(
            kappa_unmasked_ref,
            lambda_masked_ref,
            kappa_times_lambda_ref,
            key_times_lambda_ref,
        ))
    }
}

/// Counterpart of ThresholdEcdsaSigInputs that holds transcript references,
/// instead of the transcripts.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdEcdsaSigInputsRef {
    pub derivation_path: ExtendedDerivationPath,
    pub hashed_message: Vec<u8>,
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
        hashed_message: Vec<u8>,
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

    /// Returns the refs held
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        let mut ret = self.presig_quadruple_ref.get_refs();
        ret.push(*self.key_transcript_ref.as_ref());
        ret
    }

    /// Updates the height of the references.
    pub fn update(&mut self, height: Height) {
        self.presig_quadruple_ref.update(height);
        self.key_transcript_ref.as_mut().update(height);
    }

    /// Returns the refs held and updates the height if specified
    pub fn get_refs_and_update(&mut self, height: Option<Height>) -> Vec<TranscriptRef> {
        let mut ret = self.presig_quadruple_ref.get_refs_and_update(height);
        ret.push(self.key_transcript_ref.as_mut().get_and_update(height));
        ret
    }
}

impl From<&ThresholdEcdsaSigInputsRef> for pb::ThresholdEcdsaSigInputsRef {
    fn from(sig_inputs: &ThresholdEcdsaSigInputsRef) -> Self {
        Self {
            derivation_path: Some((sig_inputs.derivation_path.clone()).into()),
            hashed_message: sig_inputs.hashed_message.clone(),
            nonce: sig_inputs.nonce.get().to_vec(),
            presig_quadruple_ref: Some((&sig_inputs.presig_quadruple_ref).into()),
            key_transcript_ref: Some((&sig_inputs.key_transcript_ref).into()),
        }
    }
}

impl TryFrom<&pb::ThresholdEcdsaSigInputsRef> for ThresholdEcdsaSigInputsRef {
    type Error = String;
    fn try_from(sig_inputs: &pb::ThresholdEcdsaSigInputsRef) -> Result<Self, Self::Error> {
        let proto = sig_inputs
            .derivation_path
            .as_ref()
            .ok_or("pb::ThresholdEcdsaSigInputsRef:: Missing derivation_path")?;
        let derivation_path: ExtendedDerivationPath = proto.clone().try_into().map_err(|err| {
            format!(
                "pb::ThresholdEcdsaSigInputsRef:: Failed to convert derivation_path : {:?}",
                err
            )
        })?;

        if sig_inputs.nonce.len() != 32 {
            return Err(format!(
                "pb::ThresholdEcdsaSigInputsRef:: Invalid nonce length: {:?}",
                sig_inputs.nonce.len()
            ));
        }
        let mut nonce = [0; 32];
        nonce.copy_from_slice(&sig_inputs.nonce[0..32]);
        let nonce = Randomness::from(nonce);

        let proto = sig_inputs
            .presig_quadruple_ref
            .as_ref()
            .ok_or("pb::ThresholdEcdsaSigInputsRef:: Missing presig_quadruple_ref")?;
        let presig_quadruple_ref: PreSignatureQuadrupleRef = proto.try_into()?;

        let proto = sig_inputs
            .key_transcript_ref
            .as_ref()
            .ok_or("pb::ThresholdEcdsaSigInputsRef:: Missing key_transcript_ref")?;
        let key_transcript_ref: UnmaskedTranscript = proto.try_into()?;

        Ok(Self::new(
            derivation_path,
            sig_inputs.hashed_message.clone(),
            nonce,
            presig_quadruple_ref,
            key_transcript_ref,
        ))
    }
}
