//! Threshold ECDSA transcript references related defines.

use serde::{Deserialize, Serialize};

use crate::crypto::{
    canister_threshold_sig::error::{
        IDkgParamsValidationError, PresignatureQuadrupleCreationError,
        ThresholdEcdsaSigInputsCreationError,
    },
    canister_threshold_sig::idkg::{
        IDkgDealers, IDkgReceivers, IDkgTranscript, IDkgTranscriptId, IDkgTranscriptOperation,
        IDkgTranscriptParams,
    },
    canister_threshold_sig::{
        ExtendedDerivationPath, PreSignatureQuadruple, ThresholdEcdsaSigInputs,
    },
    AlgorithmId,
};
use crate::{Height, Randomness, RegistryVersion};
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

/// ECDSA Quadruple in creation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QuadrupleInCreation {
    pub kappa_config: IDkgTranscriptParamsRef,
    pub kappa_masked: Option<TranscriptRef>,

    pub lambda_config: IDkgTranscriptParamsRef,
    pub lambda_masked: Option<TranscriptRef>,

    pub unmask_kappa_config: Option<IDkgTranscriptParamsRef>,
    pub kappa_unmasked: Option<TranscriptRef>,

    pub key_times_lambda_config: Option<IDkgTranscriptParamsRef>,
    pub key_times_lambda: Option<TranscriptRef>,

    pub kappa_times_lambda_config: Option<IDkgTranscriptParamsRef>,
    pub kappa_times_lambda: Option<TranscriptRef>,
}

impl QuadrupleInCreation {
    /// Initialization with the given random param pair.
    pub fn new(
        kappa_config: IDkgTranscriptParamsRef,
        lambda_config: IDkgTranscriptParamsRef,
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
            params.push(&self.kappa_config)
        }
        if self.lambda_masked.is_none() {
            params.push(&self.lambda_config)
        }
        if let (Some(config), None) = (&self.unmask_kappa_config, &self.kappa_unmasked) {
            params.push(config)
        }
        if let (Some(config), None) = (&self.key_times_lambda_config, &self.key_times_lambda) {
            params.push(config)
        }
        if let (Some(config), None) = (&self.kappa_times_lambda_config, &self.kappa_times_lambda) {
            params.push(config)
        }
        Box::new(params.into_iter())
    }

    /// Returns the refs held
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        let mut ret = Vec::new();
        ret.append(&mut self.kappa_config.get_refs());
        if let Some(r) = &self.kappa_masked {
            ret.push(*r);
        }

        ret.append(&mut self.lambda_config.get_refs());
        if let Some(r) = &self.lambda_masked {
            ret.push(*r);
        }

        if let Some(config) = &self.unmask_kappa_config {
            ret.append(&mut config.get_refs());
        }
        if let Some(r) = &self.kappa_unmasked {
            ret.push(*r);
        }

        if let Some(config) = &self.key_times_lambda_config {
            ret.append(&mut config.get_refs());
        }
        if let Some(r) = &self.key_times_lambda {
            ret.push(*r);
        }

        if let Some(config) = &self.kappa_times_lambda_config {
            ret.append(&mut config.get_refs());
        }
        if let Some(r) = &self.kappa_times_lambda {
            ret.push(*r);
        }

        ret
    }

    /// Returns the refs held and updates the height if specified
    pub fn get_refs_and_update(&mut self, height: Option<Height>) -> Vec<TranscriptRef> {
        let mut ret = Vec::new();
        ret.append(&mut self.kappa_config.get_refs_and_update(height));
        if let Some(r) = &mut self.kappa_masked {
            ret.push(r.get_and_update(height));
        }

        ret.append(&mut self.lambda_config.get_refs_and_update(height));
        if let Some(r) = &mut self.lambda_masked {
            ret.push(r.get_and_update(height));
        }

        if let Some(config) = &mut self.unmask_kappa_config {
            ret.append(&mut config.get_refs_and_update(height));
        }
        if let Some(r) = &mut self.kappa_unmasked {
            ret.push(r.get_and_update(height));
        }

        if let Some(config) = &mut self.key_times_lambda_config {
            ret.append(&mut config.get_refs_and_update(height));
        }
        if let Some(r) = &mut self.key_times_lambda {
            ret.push(r.get_and_update(height));
        }

        if let Some(config) = &mut self.kappa_times_lambda_config {
            ret.append(&mut config.get_refs_and_update(height));
        }
        if let Some(r) = &mut self.kappa_times_lambda {
            ret.push(r.get_and_update(height));
        }

        ret
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
    ReshareOfMasked(TranscriptRef),
    ReshareOfUnmasked(TranscriptRef),
    UnmaskedTimesMasked(TranscriptRef, TranscriptRef),
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
                    .transcript(r)
                    .map_err(TranscriptOperationError::ReshareOfMasked)?,
            )),
            Self::ReshareOfUnmasked(r) => Ok(IDkgTranscriptOperation::ReshareOfUnmasked(
                resolver
                    .transcript(r)
                    .map_err(TranscriptOperationError::ReshareOfUnmasked)?,
            )),
            Self::UnmaskedTimesMasked(r1, r2) => Ok(IDkgTranscriptOperation::UnmaskedTimesMasked(
                resolver
                    .transcript(r1)
                    .map_err(TranscriptOperationError::UnmaskedTimesMasked1)?,
                resolver
                    .transcript(r2)
                    .map_err(TranscriptOperationError::UnmaskedTimesMasked2)?,
            )),
        }
    }

    /// Returns the refs held
    pub fn get_refs(&self) -> Vec<TranscriptRef> {
        match self {
            Self::Random => vec![],
            Self::ReshareOfMasked(r) => vec![*r],
            Self::ReshareOfUnmasked(r) => vec![*r],
            Self::UnmaskedTimesMasked(r1, r2) => vec![*r1, *r2],
        }
    }

    /// Returns the refs held and updates the height if specified
    pub fn get_refs_and_update(&mut self, height: Option<Height>) -> Vec<TranscriptRef> {
        match self {
            Self::Random => vec![],
            Self::ReshareOfMasked(r) => vec![r.get_and_update(height)],
            Self::ReshareOfUnmasked(r) => vec![r.get_and_update(height)],
            Self::UnmaskedTimesMasked(r1, r2) => {
                vec![r1.get_and_update(height), r2.get_and_update(height)]
            }
        }
    }
}

impl From<(&IDkgTranscriptOperation, Height)> for IDkgTranscriptOperationRef {
    fn from((op, height): (&IDkgTranscriptOperation, Height)) -> IDkgTranscriptOperationRef {
        match op {
            IDkgTranscriptOperation::Random => IDkgTranscriptOperationRef::Random,
            IDkgTranscriptOperation::ReshareOfMasked(t) => {
                IDkgTranscriptOperationRef::ReshareOfMasked(TranscriptRef::new(
                    height,
                    t.transcript_id,
                ))
            }
            IDkgTranscriptOperation::ReshareOfUnmasked(t) => {
                IDkgTranscriptOperationRef::ReshareOfUnmasked(TranscriptRef::new(
                    height,
                    t.transcript_id,
                ))
            }
            IDkgTranscriptOperation::UnmaskedTimesMasked(t1, t2) => {
                IDkgTranscriptOperationRef::UnmaskedTimesMasked(
                    TranscriptRef::new(height, t1.transcript_id),
                    TranscriptRef::new(height, t2.transcript_id),
                )
            }
        }
    }
}

/// Counterpart of IDkgTranscriptParams that holds transcript references,
/// instead of the transcripts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct IDkgTranscriptParamsRef {
    pub transcript_id: IDkgTranscriptId,
    pub dealers: IDkgDealers,
    pub receivers: IDkgReceivers,
    pub registry_version: RegistryVersion,
    pub algorithm_id: AlgorithmId,
    pub operation_type_ref: IDkgTranscriptOperationRef,
}

#[derive(Clone, Debug)]
pub enum TranscriptParamsError {
    OperationRef(TranscriptOperationError),
    ParamsValidation(IDkgParamsValidationError),
}

impl IDkgTranscriptParamsRef {
    pub fn new(
        transcript_id: IDkgTranscriptId,
        dealers: IDkgDealers,
        receivers: IDkgReceivers,
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

    /// Returns the refs held and updates the height if specified
    pub fn get_refs_and_update(&mut self, height: Option<Height>) -> Vec<TranscriptRef> {
        self.operation_type_ref.get_refs_and_update(height)
    }
}

impl From<(&IDkgTranscriptParams, Height)> for IDkgTranscriptParamsRef {
    fn from((params, height): (&IDkgTranscriptParams, Height)) -> IDkgTranscriptParamsRef {
        IDkgTranscriptParamsRef::new(
            params.transcript_id(),
            params.dealers().clone(),
            params.receivers().clone(),
            params.registry_version(),
            params.algorithm_id(),
            (params.operation_type(), height).into(),
        )
    }
}

/// Counterpart of PreSignatureQuadruple that holds transcript references,
/// instead of the transcripts.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PreSignatureQuadrupleRef {
    pub kappa_unmasked_ref: TranscriptRef,
    pub lambda_masked_ref: TranscriptRef,
    pub kappa_times_lambda_ref: TranscriptRef,
    pub key_times_lambda_ref: TranscriptRef,
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
        kappa_unmasked_ref: TranscriptRef,
        lambda_masked_ref: TranscriptRef,
        kappa_times_lambda_ref: TranscriptRef,
        key_times_lambda_ref: TranscriptRef,
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
            .transcript(&self.kappa_unmasked_ref)
            .map_err(PreSignatureQuadrupleError::KappaUnmasked)?;
        let lambda_masked = resolver
            .transcript(&self.lambda_masked_ref)
            .map_err(PreSignatureQuadrupleError::LambdaMasked)?;
        let kappa_times_lambda = resolver
            .transcript(&self.kappa_times_lambda_ref)
            .map_err(PreSignatureQuadrupleError::KappaTimesLambda)?;
        let key_times_lambda = resolver
            .transcript(&self.key_times_lambda_ref)
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
            self.kappa_unmasked_ref,
            self.lambda_masked_ref,
            self.kappa_times_lambda_ref,
            self.key_times_lambda_ref,
        ]
    }

    /// Returns the refs held and updates the height if specified
    pub fn get_refs_and_update(&mut self, height: Option<Height>) -> Vec<TranscriptRef> {
        vec![
            self.kappa_unmasked_ref.get_and_update(height),
            self.lambda_masked_ref.get_and_update(height),
            self.kappa_times_lambda_ref.get_and_update(height),
            self.key_times_lambda_ref.get_and_update(height),
        ]
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
    pub key_transcript_ref: TranscriptRef,
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
        key_transcript_ref: TranscriptRef,
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
            .transcript(&self.key_transcript_ref)
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
        ret.push(self.key_transcript_ref);
        ret
    }

    /// Returns the refs held and updates the height if specified
    pub fn get_refs_and_update(&mut self, height: Option<Height>) -> Vec<TranscriptRef> {
        let mut ret = self.presig_quadruple_ref.get_refs_and_update(height);
        ret.push(self.key_transcript_ref.get_and_update(height));
        ret
    }
}
