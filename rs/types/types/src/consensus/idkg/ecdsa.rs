//! Threshold ECDSA transcripts and references related definitions.
use crate::crypto::{
    canister_threshold_sig::error::{
        EcdsaPresignatureQuadrupleCreationError, ThresholdEcdsaSigInputsCreationError,
    },
    canister_threshold_sig::{
        EcdsaPreSignatureQuadruple, ExtendedDerivationPath, ThresholdEcdsaSigInputs,
    },
};
use crate::{Height, Randomness};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types::EcdsaKeyId;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::convert::{AsMut, AsRef, TryFrom, TryInto};
use std::hash::{Hash, Hasher};

use super::common::*;

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
    pub fn new_with_masked_kappa(
        key_id: EcdsaKeyId,
        kappa_masked_config: RandomTranscriptParams,
        lambda_config: RandomTranscriptParams,
    ) -> Self {
        Self {
            key_id: Some(key_id),
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
    pub fn new(
        key_id: EcdsaKeyId,
        kappa_unmasked_config: RandomUnmaskedTranscriptParams,
        lambda_config: RandomTranscriptParams,
    ) -> Self {
        QuadrupleInCreation {
            key_id: Some(key_id),
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
        key_id: EcdsaKeyId,
        kappa_unmasked_ref: UnmaskedTranscript,
        lambda_masked_ref: MaskedTranscript,
        kappa_times_lambda_ref: MaskedTranscript,
        key_times_lambda_ref: MaskedTranscript,
        key_unmasked_ref: UnmaskedTranscript,
    ) -> Self {
        Self {
            key_id: Some(key_id),
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
