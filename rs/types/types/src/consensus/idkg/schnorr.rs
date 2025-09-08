//! Threshold Schnorr transcripts and references related definitions.
use crate::Height;
use crate::crypto::canister_threshold_sig::SchnorrPreSignatureTranscript;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types_private::SchnorrKeyId;
use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::convert::{AsMut, AsRef, TryFrom, TryInto};
use std::hash::Hash;

use super::{
    IDkgBlockReader, IDkgTranscriptParamsRef, RandomUnmaskedTranscriptParams,
    ThresholdSchnorrPresignatureTranscriptCreationError, TranscriptLookupError, TranscriptRef,
    UnmaskedTranscript,
};

/// Schnorr pre-signature in creation.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct TranscriptInCreation {
    pub key_id: SchnorrKeyId,
    pub blinder_unmasked_config: RandomUnmaskedTranscriptParams,
    pub blinder_unmasked: Option<UnmaskedTranscript>,
}

impl TranscriptInCreation {
    /// Initialization with the given random param.
    pub fn new(
        key_id: SchnorrKeyId,
        blinder_unmasked_config: RandomUnmaskedTranscriptParams,
    ) -> Self {
        TranscriptInCreation {
            key_id,
            blinder_unmasked_config,
            blinder_unmasked: None,
        }
    }

    /// Return an iterator of all transcript configs that have no matching
    /// results yet.
    pub fn iter_transcript_configs_in_creation(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        let mut params = Vec::new();
        if self.blinder_unmasked.is_none() {
            params.push(self.blinder_unmasked_config.as_ref())
        }
        Box::new(params.into_iter())
    }

    /// Returns the refs held
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        let mut ret = Vec::new();
        ret.append(&mut self.blinder_unmasked_config.as_ref().get_refs());
        if let Some(r) = &self.blinder_unmasked {
            ret.push(*r.as_ref());
        }
        ret
    }

    /// Updates the height of the references.
    pub fn update(&mut self, height: Height) {
        self.blinder_unmasked_config.as_mut().update(height);
        if let Some(r) = &mut self.blinder_unmasked {
            r.as_mut().update(height);
        }
    }
}

impl From<&TranscriptInCreation> for pb::TranscriptInCreation {
    fn from(pre_signature: &TranscriptInCreation) -> Self {
        Self {
            key_id: Some((&pre_signature.key_id).into()),
            blinder_unmasked_config: Some((&pre_signature.blinder_unmasked_config).into()),
            blinder_unmasked: pre_signature
                .blinder_unmasked
                .as_ref()
                .map(|transcript| transcript.into()),
        }
    }
}

impl TryFrom<&pb::TranscriptInCreation> for TranscriptInCreation {
    type Error = ProxyDecodeError;
    fn try_from(pre_signature: &pb::TranscriptInCreation) -> Result<Self, Self::Error> {
        let key_id: SchnorrKeyId =
            try_from_option_field(pre_signature.key_id.clone(), "TranscriptInCreation::key_id")?;

        let blinder_unmasked_config: RandomUnmaskedTranscriptParams = try_from_option_field(
            pre_signature.blinder_unmasked_config.as_ref(),
            "TranscriptInCreation::blinder_unmasked_config",
        )?;

        let blinder_unmasked: Option<UnmaskedTranscript> = pre_signature
            .blinder_unmasked
            .as_ref()
            .map(|transcript| transcript.try_into())
            .transpose()?;

        Ok(Self {
            key_id,
            blinder_unmasked_config,
            blinder_unmasked,
        })
    }
}

/// Counterpart of PreSignatureTranscript that holds transcript references,
/// instead of the transcripts.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct PreSignatureTranscriptRef {
    pub key_id: SchnorrKeyId,
    pub blinder_unmasked_ref: UnmaskedTranscript,
    pub key_unmasked_ref: UnmaskedTranscript,
}

#[derive(Clone, Debug)]
pub enum PreSignatureTranscriptError {
    BlinderUnmasked(TranscriptLookupError),
    Failed(ThresholdSchnorrPresignatureTranscriptCreationError),
}

impl PreSignatureTranscriptRef {
    pub fn new(
        key_id: SchnorrKeyId,
        blinder_unmasked_ref: UnmaskedTranscript,
        key_unmasked_ref: UnmaskedTranscript,
    ) -> Self {
        Self {
            key_id,
            blinder_unmasked_ref,
            key_unmasked_ref,
        }
    }

    /// Resolves the refs to get the PreSignatureTranscript.
    pub fn translate(
        &self,
        resolver: &dyn IDkgBlockReader,
    ) -> Result<SchnorrPreSignatureTranscript, PreSignatureTranscriptError> {
        let blinder_unmasked = resolver
            .transcript(self.blinder_unmasked_ref.as_ref())
            .map_err(PreSignatureTranscriptError::BlinderUnmasked)?;
        SchnorrPreSignatureTranscript::new(blinder_unmasked)
            .map_err(PreSignatureTranscriptError::Failed)
    }

    /// Returns the refs held
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        vec![
            *self.blinder_unmasked_ref.as_ref(),
            *self.key_unmasked_ref.as_ref(),
        ]
    }

    /// Updates the height of the references.
    pub fn update(&mut self, height: Height) {
        self.blinder_unmasked_ref.as_mut().update(height);
        self.key_unmasked_ref.as_mut().update(height);
    }
}

impl From<&PreSignatureTranscriptRef> for pb::PreSignatureTranscriptRef {
    fn from(pre_signature_ref: &PreSignatureTranscriptRef) -> Self {
        Self {
            key_id: Some((&pre_signature_ref.key_id).into()),
            blinder_unmasked_ref: Some((&pre_signature_ref.blinder_unmasked_ref).into()),
            key_unmasked_ref: Some((&pre_signature_ref.key_unmasked_ref).into()),
        }
    }
}

impl TryFrom<&pb::PreSignatureTranscriptRef> for PreSignatureTranscriptRef {
    type Error = ProxyDecodeError;
    fn try_from(pre_signature: &pb::PreSignatureTranscriptRef) -> Result<Self, Self::Error> {
        let key_id: SchnorrKeyId = try_from_option_field(
            pre_signature.key_id.clone(),
            "PreSignatureTranscriptRef::pre_signature::key_id",
        )?;

        let blinder_unmasked_ref: UnmaskedTranscript = try_from_option_field(
            pre_signature.blinder_unmasked_ref.as_ref(),
            "PreSignatureTranscriptRef::pre_signature::blinder_unmasked_ref",
        )?;

        let key_unmasked_ref: UnmaskedTranscript = try_from_option_field(
            pre_signature.key_unmasked_ref.as_ref(),
            "PreSignatureTranscriptRef::pre_signature::key_unmasked_ref",
        )?;

        Ok(Self::new(key_id, blinder_unmasked_ref, key_unmasked_ref))
    }
}
