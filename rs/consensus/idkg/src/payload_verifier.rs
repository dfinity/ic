//! This module implements the IDKG payload verifier.
//!
//! It validates a payload by doing an equality check with a payload
//! that would have been created by itself, given the same inputs.
//! This works because the payload creation is a deterministic process
//! once all inputs are fixed.
//!
//! Therefore, it is important to ensure all inputs are indeed the same
//! between all replicas in a subnet. Payload creation only reads completed
//! transcripts, dealings (for xnet resharing), and signatures from idkg
//! pool. In payload verification, we do the following:
//!
//! 1. Extract newly completed artifacts from the payload to be verified.
//! 2. Validate these artifacts.
//! 3. Treat them as inputs, and create a new payload to compare equality.
//!
//! This approach assumes the same deterministic (and correct) payload
//! creation process is adopted by all replicas in a subnet. Not all valid
//! payloads (e.g. those created through a different payload creation
//! algorithm) can be verified this way, but it is a simple and effective
//! approach, similar to what we have been doing in verifying other kinds
//! payloads.
#![allow(clippy::result_large_err)]

use crate::{
    metrics::timed_call,
    payload_builder::IDkgPayloadError,
    payload_builder::{create_data_payload_helper, create_summary_payload},
    pre_signer::IDkgTranscriptBuilder,
    signer::ThresholdSignatureBuilder,
    utils::build_signature_inputs,
    utils::{
        IDkgBlockReaderImpl, InvalidChainCacheError, block_chain_cache,
        get_idkg_chain_key_config_if_enabled,
    },
};
use ic_consensus_utils::{crypto::ConsensusCrypto, pool_reader::PoolReader};
use ic_interfaces::{
    crypto::{ThresholdEcdsaSigVerifier, ThresholdSchnorrSigVerifier},
    validation::{ValidationError, ValidationResult},
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_management_canister_types_private::{
    Payload, ReshareChainKeyResponse, SignWithECDSAReply, SignWithSchnorrReply,
};
use ic_replicated_state::{
    ReplicatedState,
    metadata_state::subnet_call_context_manager::{
        IDkgSignWithThresholdContext, SignWithThresholdContext,
    },
};
use ic_types::{
    Height, SubnetId,
    batch::ValidationContext,
    consensus::{
        Block, BlockPayload, HasHeight,
        idkg::{
            self, IDkgBlockReader, TranscriptRef,
            common::{BuildSignatureInputsError, CombinedSignature, ThresholdSigInputs},
        },
    },
    crypto::canister_threshold_sig::{
        ThresholdEcdsaCombinedSignature, ThresholdSchnorrCombinedSignature,
        error::{
            IDkgVerifyInitialDealingsError, IDkgVerifyTranscriptError,
            ThresholdEcdsaVerifyCombinedSignatureError, ThresholdSchnorrVerifyCombinedSigError,
        },
        idkg::{IDkgTranscript, IDkgTranscriptId, InitialIDkgDealings, SignedIDkgDealing},
    },
    messages::CallbackId,
    registry::RegistryClientError,
    state_manager::StateManagerError,
};
use prometheus::HistogramVec;
use rayon::{
    ThreadPool,
    iter::{IntoParallelIterator, ParallelIterator},
};
use std::{collections::BTreeMap, convert::TryFrom};

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
// The fields are only read by the `Debug` implementation.
// The `dead_code` lint ignores `Debug` impls, see: https://github.com/rust-lang/rust/issues/88900.
#[allow(dead_code)]
/// Possible failures which could occur while validating an idkg payload. They don't imply that the
/// payload is invalid.
pub enum IDkgPayloadValidationFailure {
    RegistryClientError(RegistryClientError),
    StateManagerError(StateManagerError),
    TranscriptParamsError(idkg::TranscriptParamsError),
    ThresholdEcdsaVerifyCombinedSignatureError(ThresholdEcdsaVerifyCombinedSignatureError),
    ThresholdSchnorrVerifyCombinedSignatureError(ThresholdSchnorrVerifyCombinedSigError),
    IDkgVerifyTranscriptError(IDkgVerifyTranscriptError),
    IDkgVerifyInitialDealingsError(IDkgVerifyInitialDealingsError),
    NewSignatureBuildInputsError(BuildSignatureInputsError),
    InvalidChainCacheError(InvalidChainCacheError),
}

#[derive(Debug)]
// The fields are only read by the `Debug` implementation.
// The `dead_code` lint ignores `Debug` impls, see: https://github.com/rust-lang/rust/issues/88900.
#[allow(dead_code)]
/// Reasons for why an idkg payload might be invalid.
pub enum InvalidIDkgPayloadReason {
    // wrapper of other errors
    UnexpectedSummaryPayload(IDkgPayloadError),
    UnexpectedDataPayload(Option<IDkgPayloadError>),
    TranscriptParamsError(idkg::TranscriptParamsError),
    ThresholdEcdsaVerifyCombinedSignatureError(ThresholdEcdsaVerifyCombinedSignatureError),
    ThresholdSchnorrVerifyCombinedSignatureError(ThresholdSchnorrVerifyCombinedSigError),
    IDkgVerifyTranscriptError(IDkgVerifyTranscriptError),
    IDkgVerifyInitialDealingsError(IDkgVerifyInitialDealingsError),
    NewSignatureBuildInputsError(BuildSignatureInputsError),
    // local errors
    ConsensusRegistryVersionNotFound(Height),
    ChainKeyConfigNotFound,
    SummaryPayloadMismatch,
    DataPayloadMismatch,
    MissingIDkgDataPayload,
    NewTranscriptRefWrongHeight(TranscriptRef, Height),
    NewTranscriptNotFound(IDkgTranscriptId),
    NewTranscriptMiscount(u64),
    NewTranscriptMissingParams(IDkgTranscriptId),
    NewSignatureUnexpected(idkg::PseudoRandomId),
    NewSignatureMissingContext(idkg::PseudoRandomId),
    VetKdUnexpected(CallbackId),
    XNetReshareAgreementWithoutRequest(idkg::IDkgReshareRequest),
    XNetReshareRequestDisappeared(idkg::IDkgReshareRequest),
    DecodingError(String),
}

impl From<InvalidIDkgPayloadReason> for IDkgValidationError {
    fn from(err: InvalidIDkgPayloadReason) -> Self {
        ValidationError::InvalidArtifact(err)
    }
}

impl From<IDkgPayloadValidationFailure> for IDkgValidationError {
    fn from(err: IDkgPayloadValidationFailure) -> Self {
        ValidationError::ValidationFailed(err)
    }
}

impl From<InvalidChainCacheError> for IDkgPayloadValidationFailure {
    fn from(err: InvalidChainCacheError) -> Self {
        IDkgPayloadValidationFailure::InvalidChainCacheError(err)
    }
}

impl From<idkg::TranscriptParamsError> for InvalidIDkgPayloadReason {
    fn from(err: idkg::TranscriptParamsError) -> Self {
        InvalidIDkgPayloadReason::TranscriptParamsError(err)
    }
}

impl From<idkg::TranscriptParamsError> for IDkgPayloadValidationFailure {
    fn from(err: idkg::TranscriptParamsError) -> Self {
        IDkgPayloadValidationFailure::TranscriptParamsError(err)
    }
}

impl From<IDkgVerifyTranscriptError> for InvalidIDkgPayloadReason {
    fn from(err: IDkgVerifyTranscriptError) -> Self {
        InvalidIDkgPayloadReason::IDkgVerifyTranscriptError(err)
    }
}

impl From<IDkgVerifyTranscriptError> for IDkgPayloadValidationFailure {
    fn from(err: IDkgVerifyTranscriptError) -> Self {
        IDkgPayloadValidationFailure::IDkgVerifyTranscriptError(err)
    }
}

impl From<IDkgVerifyInitialDealingsError> for InvalidIDkgPayloadReason {
    fn from(err: IDkgVerifyInitialDealingsError) -> Self {
        InvalidIDkgPayloadReason::IDkgVerifyInitialDealingsError(err)
    }
}

impl From<IDkgVerifyInitialDealingsError> for IDkgPayloadValidationFailure {
    fn from(err: IDkgVerifyInitialDealingsError) -> Self {
        IDkgPayloadValidationFailure::IDkgVerifyInitialDealingsError(err)
    }
}

impl From<ThresholdEcdsaVerifyCombinedSignatureError> for InvalidIDkgPayloadReason {
    fn from(err: ThresholdEcdsaVerifyCombinedSignatureError) -> Self {
        InvalidIDkgPayloadReason::ThresholdEcdsaVerifyCombinedSignatureError(err)
    }
}

impl From<ThresholdEcdsaVerifyCombinedSignatureError> for IDkgPayloadValidationFailure {
    fn from(err: ThresholdEcdsaVerifyCombinedSignatureError) -> Self {
        IDkgPayloadValidationFailure::ThresholdEcdsaVerifyCombinedSignatureError(err)
    }
}

impl From<BuildSignatureInputsError> for InvalidIDkgPayloadReason {
    fn from(err: BuildSignatureInputsError) -> Self {
        InvalidIDkgPayloadReason::NewSignatureBuildInputsError(err)
    }
}

impl From<BuildSignatureInputsError> for IDkgPayloadValidationFailure {
    fn from(err: BuildSignatureInputsError) -> Self {
        IDkgPayloadValidationFailure::NewSignatureBuildInputsError(err)
    }
}

impl From<ThresholdSchnorrVerifyCombinedSigError> for InvalidIDkgPayloadReason {
    fn from(err: ThresholdSchnorrVerifyCombinedSigError) -> Self {
        InvalidIDkgPayloadReason::ThresholdSchnorrVerifyCombinedSignatureError(err)
    }
}

impl From<ThresholdSchnorrVerifyCombinedSigError> for IDkgPayloadValidationFailure {
    fn from(err: ThresholdSchnorrVerifyCombinedSigError) -> Self {
        IDkgPayloadValidationFailure::ThresholdSchnorrVerifyCombinedSignatureError(err)
    }
}

impl From<RegistryClientError> for IDkgPayloadValidationFailure {
    fn from(err: RegistryClientError) -> Self {
        IDkgPayloadValidationFailure::RegistryClientError(err)
    }
}

impl From<StateManagerError> for IDkgPayloadValidationFailure {
    fn from(err: StateManagerError) -> Self {
        IDkgPayloadValidationFailure::StateManagerError(err)
    }
}

pub(crate) type IDkgValidationError =
    ValidationError<InvalidIDkgPayloadReason, IDkgPayloadValidationFailure>;

#[allow(clippy::too_many_arguments)]
pub fn validate_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    thread_pool: &ThreadPool,
    pool_reader: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    parent_block: &Block,
    payload: &BlockPayload,
    metrics: HistogramVec,
) -> ValidationResult<IDkgValidationError> {
    if payload.is_summary() {
        timed_call(
            "verify_summary_payload",
            || {
                validate_summary_payload(
                    subnet_id,
                    registry_client,
                    pool_reader,
                    context,
                    parent_block,
                    payload.as_summary().idkg.as_ref(),
                )
            },
            &metrics,
        )
    } else {
        timed_call(
            "verify_data_payload",
            || {
                validate_data_payload(
                    subnet_id,
                    registry_client,
                    crypto,
                    thread_pool,
                    pool_reader,
                    state_manager,
                    context,
                    parent_block,
                    payload.as_data().idkg.as_ref(),
                    &metrics,
                )
            },
            &metrics,
        )
    }
}

/// Validates an IDKG summary payload.
/// This is an entirely deterministic operation, so we can just check if
/// the given summary payload matches what we would have created locally.
fn validate_summary_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    pool_reader: &PoolReader<'_>,
    context: &ValidationContext,
    parent_block: &Block,
    summary_payload: Option<&idkg::IDkgPayload>,
) -> ValidationResult<IDkgValidationError> {
    let height = parent_block.height().increment();
    let registry_version = pool_reader.registry_version(height).ok_or(
        InvalidIDkgPayloadReason::ConsensusRegistryVersionNotFound(height),
    )?;
    let chain_key_config =
        get_idkg_chain_key_config_if_enabled(subnet_id, registry_version, registry_client)
            .map_err(IDkgPayloadValidationFailure::from)?;
    if chain_key_config.is_none() {
        if summary_payload.is_some() {
            return Err(InvalidIDkgPayloadReason::ChainKeyConfigNotFound.into());
        } else {
            return Ok(());
        }
    };
    match create_summary_payload(
        subnet_id,
        registry_client,
        pool_reader,
        context,
        parent_block,
        None,
        &ic_logger::replica_logger::no_op_logger(),
    ) {
        Ok(payload) => {
            if payload.as_ref() == summary_payload {
                Ok(())
            } else {
                Err(InvalidIDkgPayloadReason::SummaryPayloadMismatch.into())
            }
        }
        Err(IDkgPayloadError::RegistryClientError(err)) => {
            Err(IDkgPayloadValidationFailure::RegistryClientError(err).into())
        }
        Err(IDkgPayloadError::StateManagerError(err)) => {
            Err(IDkgPayloadValidationFailure::StateManagerError(err).into())
        }
        Err(err) => Err(InvalidIDkgPayloadReason::UnexpectedSummaryPayload(err).into()),
    }
}

#[allow(clippy::too_many_arguments)]
/// Validates an IDKG data payload.
fn validate_data_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    thread_pool: &ThreadPool,
    pool_reader: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    parent_block: &Block,
    data_payload: Option<&idkg::IDkgPayload>,
    metrics: &HistogramVec,
) -> ValidationResult<IDkgValidationError> {
    if parent_block.payload.as_ref().as_idkg().is_none() {
        if data_payload.is_some() {
            return Err(InvalidIDkgPayloadReason::UnexpectedDataPayload(None).into());
        } else {
            return Ok(());
        }
    }

    let block_payload = &parent_block.payload.as_ref();
    let (prev_payload, curr_payload) = if block_payload.is_summary() {
        match &block_payload.as_summary().idkg {
            None => {
                if data_payload.is_some() {
                    return Err(InvalidIDkgPayloadReason::UnexpectedDataPayload(None).into());
                } else {
                    return Ok(());
                }
            }
            Some(idkg_summary) => {
                if data_payload.is_none() {
                    return Err(InvalidIDkgPayloadReason::MissingIDkgDataPayload.into());
                }
                (idkg_summary.clone(), data_payload.as_ref().unwrap())
            }
        }
    } else {
        match &block_payload.as_data().idkg {
            None => {
                if data_payload.is_some() {
                    return Err(InvalidIDkgPayloadReason::UnexpectedDataPayload(None).into());
                } else {
                    return Ok(());
                }
            }
            Some(payload) => {
                if data_payload.is_none() {
                    return Err(InvalidIDkgPayloadReason::MissingIDkgDataPayload.into());
                }
                (payload.clone(), data_payload.as_ref().unwrap())
            }
        }
    };

    let summary_block = pool_reader
        .dkg_summary_block(parent_block)
        .unwrap_or_else(|| {
            panic!(
                "Impossible: fail to the summary block that governs height {}",
                parent_block.height()
            )
        });
    // In case the certified height is below the summary height, add the heights in
    // between to the blockchain. This is needed to calculate the total number of pre-
    // signatures in the certified state and every block since then.
    // Note that blocks below the summary are not guaranteed to exist, because they are
    // purged once the CUP exists. However, if the CUP exists, that implies there is
    // already a finalized block b with b.certified_height >= summary_height, which means
    // we should not be validating a block referencing a lower certified height manually here.
    // This block should instead be validated via the notarization fast-path.
    let start_height = context
        .certified_height
        .increment()
        .min(summary_block.height());
    let parent_chain = block_chain_cache(pool_reader, start_height, parent_block.clone())
        .map_err(IDkgPayloadValidationFailure::from)?;
    let block_reader = IDkgBlockReaderImpl::new(parent_chain);
    let curr_height = parent_block.height().increment();

    let transcripts = timed_call(
        "validate_transcript_refs",
        || {
            validate_transcript_refs(
                crypto,
                thread_pool,
                &block_reader,
                &prev_payload,
                curr_payload,
                curr_height,
            )
        },
        metrics,
    )?;
    let dealings = timed_call(
        "validate_reshare_dealings",
        || validate_reshare_dealings(crypto, &block_reader, &prev_payload, curr_payload),
        metrics,
    )?;
    let state = state_manager
        .get_state_at(context.certified_height)
        .map_err(IDkgPayloadValidationFailure::StateManagerError)?;
    let signatures = timed_call(
        "validate_new_signature_agreements",
        || validate_new_signature_agreements(crypto, state.get_ref(), &prev_payload, curr_payload),
        metrics,
    )?;

    let builder = CachedBuilder {
        transcripts,
        dealings,
        signatures,
    };

    match create_data_payload_helper(
        subnet_id,
        context,
        parent_block,
        &summary_block,
        &block_reader,
        &builder,
        &builder,
        thread_pool,
        state_manager,
        registry_client,
        None,
        &ic_logger::replica_logger::no_op_logger(),
    ) {
        Ok(idkg_payload) => {
            if idkg_payload.as_ref() == data_payload {
                Ok(())
            } else {
                Err(InvalidIDkgPayloadReason::DataPayloadMismatch.into())
            }
        }
        Err(IDkgPayloadError::RegistryClientError(err)) => {
            Err(IDkgPayloadValidationFailure::RegistryClientError(err).into())
        }
        Err(IDkgPayloadError::StateManagerError(err)) => {
            Err(IDkgPayloadValidationFailure::StateManagerError(err).into())
        }
        Err(err) => Err(InvalidIDkgPayloadReason::UnexpectedDataPayload(Some(err)).into()),
    }
}

struct CachedBuilder {
    transcripts: BTreeMap<IDkgTranscriptId, IDkgTranscript>,
    dealings: BTreeMap<IDkgTranscriptId, Vec<SignedIDkgDealing>>,
    signatures: BTreeMap<CallbackId, CombinedSignature>,
}

impl IDkgTranscriptBuilder for CachedBuilder {
    fn get_completed_transcript(&self, transcript_id: IDkgTranscriptId) -> Option<IDkgTranscript> {
        self.transcripts.get(&transcript_id).cloned()
    }

    fn get_validated_dealings(&self, transcript_id: IDkgTranscriptId) -> Vec<SignedIDkgDealing> {
        self.dealings
            .get(&transcript_id)
            .cloned()
            .unwrap_or_default()
    }
}

impl ThresholdSignatureBuilder for CachedBuilder {
    fn get_completed_signature(
        &self,
        id: CallbackId,
        _context: &SignWithThresholdContext,
    ) -> Option<CombinedSignature> {
        self.signatures.get(&id).cloned()
    }
}

// Validate transcript references
// - All references in the payload should resolve.
// - Newly added transcripts are referenced.
// - Newly added transcripts are valid.
//
// Since this function is only called on data payload, we can assume all references
// in prev_payload resolve correctly. So only new references need to be checked.
fn validate_transcript_refs(
    crypto: &dyn ConsensusCrypto,
    thread_pool: &ThreadPool,
    block_reader: &dyn IDkgBlockReader,
    prev_payload: &idkg::IDkgPayload,
    curr_payload: &idkg::IDkgPayload,
    curr_height: Height,
) -> Result<BTreeMap<IDkgTranscriptId, IDkgTranscript>, IDkgValidationError> {
    use InvalidIDkgPayloadReason::*;
    let idkg_transcripts = &curr_payload.idkg_transcripts;
    let prev_configs = prev_payload
        .iter_transcript_configs_in_creation()
        .map(|config| (config.transcript_id, config))
        .collect::<BTreeMap<_, _>>();

    let mut verify_transcript_args = Vec::new();
    for transcript_ref in curr_payload.active_transcripts().iter() {
        if transcript_ref.height >= curr_height || block_reader.transcript(transcript_ref).is_err()
        {
            if transcript_ref.height != curr_height {
                return Err(NewTranscriptRefWrongHeight(*transcript_ref, curr_height).into());
            }
            let transcript_id = &transcript_ref.transcript_id;
            if let Some(transcript) = idkg_transcripts.get(transcript_id) {
                let config = prev_configs
                    .get(transcript_id)
                    .ok_or(NewTranscriptMissingParams(*transcript_id))?;
                verify_transcript_args.push((config, transcript));
            } else {
                return Err(NewTranscriptNotFound(*transcript_id).into());
            }
        }
    }

    let results = thread_pool
        .install(|| {
            verify_transcript_args
                .into_par_iter()
                .map(|(config, transcript)| {
                    let params = config.translate(block_reader)?;
                    crypto.verify_transcript(&params, transcript)?;
                    Ok(())
                })
        })
        .collect::<Result<Vec<()>, IDkgValidationError>>()?;

    if results.len() != idkg_transcripts.len() {
        return Err(NewTranscriptMiscount(results.len() as u64).into());
    }

    Ok(idkg_transcripts.clone())
}

fn validate_reshare_dealings(
    crypto: &dyn ConsensusCrypto,
    block_reader: &dyn IDkgBlockReader,
    prev_payload: &idkg::IDkgPayload,
    curr_payload: &idkg::IDkgPayload,
) -> Result<BTreeMap<IDkgTranscriptId, Vec<SignedIDkgDealing>>, IDkgValidationError> {
    use InvalidIDkgPayloadReason::*;
    let mut new_reshare_agreement = BTreeMap::new();
    for (request, dealings) in curr_payload.xnet_reshare_agreements.iter() {
        if let idkg::CompletedReshareRequest::Unreported(dealings) = &dealings
            && !prev_payload.xnet_reshare_agreements.contains_key(request)
        {
            if !prev_payload.ongoing_xnet_reshares.contains_key(request) {
                return Err(XNetReshareAgreementWithoutRequest(request.clone()).into());
            }
            new_reshare_agreement.insert(request.clone(), dealings);
        }
    }
    let mut new_dealings = BTreeMap::new();
    for (request, config) in prev_payload.ongoing_xnet_reshares.iter() {
        if !curr_payload.ongoing_xnet_reshares.contains_key(request) {
            if let Some(response) = new_reshare_agreement.get(request) {
                if let ic_types::messages::Payload::Data(data) = &response.payload {
                    let initial_dealings = decode_initial_dealings(data)?;
                    let transcript_id = config.as_ref().transcript_id;
                    let param = config.as_ref().translate(block_reader)?;
                    crypto.verify_initial_dealings(&param, &initial_dealings)?;
                    new_dealings.insert(transcript_id, initial_dealings.dealings().clone());
                }
            } else {
                return Err(XNetReshareRequestDisappeared(request.clone()).into());
            }
        }
    }
    Ok(new_dealings)
}

fn decode_initial_dealings(data: &[u8]) -> Result<InitialIDkgDealings, InvalidIDkgPayloadReason> {
    let reshare_chain_key_response = ReshareChainKeyResponse::decode(data)
        .map_err(|err| InvalidIDkgPayloadReason::DecodingError(format!("{err:?}")))?;

    let initial_dealings = match reshare_chain_key_response {
        ReshareChainKeyResponse::IDkg(initial_idkg_dealings) => initial_idkg_dealings,
        ReshareChainKeyResponse::NiDkg(_) => {
            return Err(InvalidIDkgPayloadReason::DecodingError(
                "Found an NiDkg response".to_string(),
            ));
        }
    };

    InitialIDkgDealings::try_from(&initial_dealings)
        .map_err(|err| InvalidIDkgPayloadReason::DecodingError(format!("{err:?}")))
}

// Validate new signature agreements in the current payload.
// New signatures are those that are Unreported in the curr_payload and not in prev_payload.
fn validate_new_signature_agreements(
    crypto: &dyn ConsensusCrypto,
    state: &ReplicatedState,
    prev_payload: &idkg::IDkgPayload,
    curr_payload: &idkg::IDkgPayload,
) -> Result<BTreeMap<CallbackId, CombinedSignature>, IDkgValidationError> {
    let mut new_signatures = BTreeMap::new();
    let context_map = state
        .signature_request_contexts()
        .iter()
        .flat_map(|(id, ctxt)| {
            IDkgSignWithThresholdContext::try_from(ctxt)
                .map(|ctxt| (ctxt.pseudo_random_id, (*id, ctxt)))
        })
        .collect::<BTreeMap<_, _>>();
    for (random_id, completed) in curr_payload.signature_agreements.iter() {
        if let idkg::CompletedSignature::Unreported(response) = completed
            && let ic_types::messages::Payload::Data(data) = &response.payload
        {
            if prev_payload.signature_agreements.contains_key(random_id) {
                return Err(InvalidIDkgPayloadReason::NewSignatureUnexpected(*random_id).into());
            }
            let (id, context) = context_map.get(random_id).ok_or(
                InvalidIDkgPayloadReason::NewSignatureMissingContext(*random_id),
            )?;
            let (_, input) = build_signature_inputs(*id, context)?;
            match input {
                ThresholdSigInputs::Ecdsa(input) => {
                    let reply = SignWithECDSAReply::decode(data).map_err(|err| {
                        InvalidIDkgPayloadReason::DecodingError(format!("{err:?}"))
                    })?;
                    let signature = ThresholdEcdsaCombinedSignature {
                        signature: reply.signature,
                    };
                    ThresholdEcdsaSigVerifier::verify_combined_sig(crypto, &input, &signature)?;
                    new_signatures.insert(*id, CombinedSignature::Ecdsa(signature));
                }
                ThresholdSigInputs::Schnorr(input) => {
                    let reply = SignWithSchnorrReply::decode(data).map_err(|err| {
                        InvalidIDkgPayloadReason::DecodingError(format!("{err:?}"))
                    })?;
                    let signature = ThresholdSchnorrCombinedSignature {
                        signature: reply.signature,
                    };
                    ThresholdSchnorrSigVerifier::verify_combined_sig(crypto, &input, &signature)?;
                    new_signatures.insert(*id, CombinedSignature::Schnorr(signature));
                }
                ThresholdSigInputs::VetKd(_) => {
                    // We don't expect to find agreements for vet KD contexts in the IDKG payload
                    return Err(InvalidIDkgPayloadReason::VetKdUnexpected(*id).into());
                }
            }
        }
    }
    Ok(new_signatures)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        MAX_IDKG_THREADS,
        payload_builder::{
            filter_idkg_reshare_chain_key_contexts,
            resharing::{initiate_reshare_requests, update_completed_reshare_requests},
            signatures::update_signature_agreements,
        },
        test_utils::*,
        utils::build_thread_pool,
    };
    use assert_matches::assert_matches;
    use ic_crypto_temp_crypto::TempCryptoComponent;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        CanisterThresholdSigTestEnvironment, dummy_values::dummy_dealings,
    };
    use ic_crypto_test_utils_crypto_returning_ok::CryptoReturningOk;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_interfaces_state_manager::CertifiedStateSnapshot;
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types_private::{MasterPublicKeyId, Payload, SignWithECDSAReply};
    use ic_test_utilities_consensus::idkg::*;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{
        Height,
        consensus::idkg::{
            CompletedSignature, IDkgMasterPublicKeyId, common::PreSignatureRef,
            ecdsa::PreSignatureQuadrupleRef,
        },
        crypto::AlgorithmId,
        messages::CallbackId,
    };
    use idkg::RequestId;
    use std::collections::BTreeSet;

    #[test]
    fn test_validate_transcript_refs_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_transcript_refs(key_id);
        }
    }

    fn test_validate_transcript_refs(key_id: IDkgMasterPublicKeyId) {
        let mut rng = reproducible_rng();
        let thread_pool = build_thread_pool(MAX_IDKG_THREADS);
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes, &mut rng);
        let registry_version = env.newest_registry_version;
        let crypto = &CryptoReturningOk::default();
        let mut block_reader = TestIDkgBlockReader::new();
        let mut prev_payload = empty_idkg_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
        let mut curr_payload = prev_payload.clone();

        // Empty payload verifies
        assert!(
            validate_transcript_refs(
                crypto,
                thread_pool.as_ref(),
                &block_reader,
                &prev_payload,
                &curr_payload,
                Height::from(0)
            )
            .is_ok()
        );

        // Add a transcript
        let height_100 = Height::new(100);
        let (transcript_0, transcript_ref_0, _) =
            generate_key_transcript(&key_id, &env, &mut rng, height_100);
        let transcript_id_0 = transcript_0.transcript_id;
        curr_payload
            .idkg_transcripts
            .insert(transcript_id_0, transcript_0);
        // Error because transcript is not referenced
        assert_matches!(
            validate_transcript_refs(
                crypto,
                thread_pool.as_ref(),
                &block_reader,
                &prev_payload,
                &curr_payload,
                height_100
            ),
            Err(ValidationError::InvalidArtifact(
                InvalidIDkgPayloadReason::NewTranscriptMiscount(_)
            ))
        );

        // Add the reference
        prev_payload.single_key_transcript_mut().next_in_creation =
            idkg::KeyTranscriptCreation::RandomTranscriptParams(idkg::RandomTranscriptParams::new(
                transcript_id_0,
                env.nodes.ids(),
                env.nodes.ids(),
                registry_version,
                AlgorithmId::from(key_id.inner()),
            ));
        curr_payload.single_key_transcript_mut().next_in_creation =
            idkg::KeyTranscriptCreation::Created(transcript_ref_0);
        let res = validate_transcript_refs(
            crypto,
            thread_pool.as_ref(),
            &block_reader,
            &prev_payload,
            &curr_payload,
            height_100,
        );
        assert!(res.is_ok());

        let real_crypto = TempCryptoComponent::builder().build_arc();

        // Error because of real crypto should not verify the transcript
        assert_matches!(
            validate_transcript_refs(
                real_crypto.as_ref(),
                thread_pool.as_ref(),
                &block_reader,
                &prev_payload,
                &curr_payload,
                height_100,
            ),
            Err(ValidationError::InvalidArtifact(
                InvalidIDkgPayloadReason::IDkgVerifyTranscriptError(_)
            ))
        );

        // Error because of height mismatch
        assert_matches!(
            validate_transcript_refs(
                crypto,
                thread_pool.as_ref(),
                &block_reader,
                &prev_payload,
                &curr_payload,
                Height::from(99),
            ),
            Err(ValidationError::InvalidArtifact(
                InvalidIDkgPayloadReason::NewTranscriptRefWrongHeight(_, _)
            ))
        );

        // Add another reference
        let (transcript_1, transcript_ref_1, _) =
            generate_key_transcript(&key_id, &env, &mut rng, height_100);
        curr_payload.single_key_transcript_mut().next_in_creation =
            idkg::KeyTranscriptCreation::Created(transcript_ref_1);
        assert_matches!(
            validate_transcript_refs(
                crypto,
                thread_pool.as_ref(),
                &block_reader,
                &prev_payload,
                &curr_payload,
                height_100
            ),
            Err(ValidationError::InvalidArtifact(
                InvalidIDkgPayloadReason::NewTranscriptNotFound(_)
            ))
        );

        curr_payload.idkg_transcripts = BTreeMap::new();
        block_reader.add_transcript(*transcript_ref_1.as_ref(), transcript_1);
        assert!(
            validate_transcript_refs(
                crypto,
                thread_pool.as_ref(),
                &block_reader,
                &prev_payload,
                &curr_payload,
                Height::from(101),
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_reshare_dealings_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_reshare_dealings(key_id);
        }
    }

    fn test_validate_reshare_dealings(key_id: IDkgMasterPublicKeyId) {
        let mut rng = reproducible_rng();
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let crypto = &CryptoReturningOk::default();
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes, &mut rng);

        let mut payload = empty_idkg_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
        let mut block_reader = TestIDkgBlockReader::new();
        let transcript_builder = TestIDkgTranscriptBuilder::new();

        let req_1 = create_reshare_request(key_id.clone(), 1, 1);
        let req_2 = create_reshare_request(key_id.clone(), 2, 2);
        let reshare_requests = BTreeSet::from([req_1.clone(), req_2.clone()]);

        let contexts = BTreeMap::from([
            (
                ic_types::messages::CallbackId::from(0),
                dealings_context_from_reshare_request(req_1.clone()),
            ),
            (
                ic_types::messages::CallbackId::from(1),
                dealings_context_from_reshare_request(req_2.clone()),
            ),
        ]);
        let contexts = filter_idkg_reshare_chain_key_contexts(&contexts);

        let (key_transcript, key_transcript_ref) =
            payload.generate_current_key(&key_id, &env, &mut rng);
        block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript);
        initiate_reshare_requests(&mut payload, reshare_requests.clone());
        let prev_payload = payload.clone();

        // Create completed dealings for request 1.
        let reshare_params = payload.ongoing_xnet_reshares.get(&req_1).unwrap().as_ref();
        assert_eq!(
            reshare_params.algorithm_id,
            AlgorithmId::from(key_id.inner())
        );
        let dealings = dummy_dealings(reshare_params.transcript_id, &reshare_params.dealers);
        transcript_builder.add_dealings(reshare_params.transcript_id, dealings);
        update_completed_reshare_requests(
            &mut payload,
            &contexts,
            &block_reader,
            &transcript_builder,
            &no_op_logger(),
        );
        assert_eq!(payload.xnet_reshare_agreements.len(), 1);
        assert_matches!(
            payload.xnet_reshare_agreements.get(&req_1).unwrap(),
            idkg::CompletedReshareRequest::Unreported(_)
        );

        // The payload should verify, and should return 1 dealing.
        let result = validate_reshare_dealings(crypto, &block_reader, &prev_payload, &payload);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);

        // Removing request 2 from payload should give error.
        let mut payload_ = payload.clone();
        payload_.ongoing_xnet_reshares.remove(&req_2);
        let result = validate_reshare_dealings(crypto, &block_reader, &prev_payload, &payload_);
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidIDkgPayloadReason::XNetReshareRequestDisappeared(_)
            ))
        );

        // Create another request and dealings
        let reshare_params = payload.ongoing_xnet_reshares.get(&req_2).unwrap().as_ref();
        assert_eq!(
            reshare_params.algorithm_id,
            AlgorithmId::from(key_id.inner())
        );
        let dealings = dummy_dealings(reshare_params.transcript_id, &reshare_params.dealers);
        transcript_builder.add_dealings(reshare_params.transcript_id, dealings);
        let mut prev_payload = payload.clone();
        update_completed_reshare_requests(
            &mut payload,
            &contexts,
            &block_reader,
            &transcript_builder,
            &no_op_logger(),
        );

        // The payload should also verify, and should return 1 dealing.
        let result = validate_reshare_dealings(crypto, &block_reader, &prev_payload, &payload);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);

        // remove request 2 from prev_payload, then payload should fail
        // to validate.
        prev_payload.ongoing_xnet_reshares.remove(&req_2);
        let result = validate_reshare_dealings(crypto, &block_reader, &prev_payload, &payload);
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidIDkgPayloadReason::XNetReshareAgreementWithoutRequest(_)
            ))
        );
    }

    #[test]
    fn test_validate_new_signature_agreements_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_new_signature_agreements(&key_id, false);
            test_validate_new_signature_agreements(&key_id, true);
        }
    }

    fn test_validate_new_signature_agreements(
        key_id: &IDkgMasterPublicKeyId,
        store_pre_signatures_in_state: bool,
    ) {
        let subnet_id = subnet_test_id(0);
        let crypto = &CryptoReturningOk::default();
        let height = Height::from(1);
        let mut valid_keys = BTreeSet::new();
        valid_keys.insert(key_id.clone());

        let mut idkg_payload = empty_idkg_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
        let pre_sig_id1 = idkg_payload.uid_generator.next_pre_signature_id();
        let pre_sig_id2 = idkg_payload.uid_generator.next_pre_signature_id();
        let pre_sig_id3 = idkg_payload.uid_generator.next_pre_signature_id();

        let ids = [
            request_id(1, height),
            request_id(2, height),
            request_id(3, height),
        ];

        // There are three requests in state, two are completed, one is still
        // missing its nonce.
        let signature_request_contexts = BTreeMap::from_iter([
            fake_signature_request_context_from_id(key_id.clone().into(), pre_sig_id1, ids[0]),
            fake_signature_request_context_from_id(key_id.clone().into(), pre_sig_id2, ids[1]),
            fake_signature_request_context_with_pre_sig(ids[2], key_id.clone(), Some(pre_sig_id3)),
        ]);
        let snapshot =
            fake_state_with_signature_requests(height, signature_request_contexts.clone());
        let signature_request_contexts = into_idkg_contexts(&signature_request_contexts);

        let pseudo_random_id = |i| {
            let request_id: &RequestId = &ids[i];
            let callback_id = request_id.callback_id;
            signature_request_contexts
                .get(&callback_id)
                .unwrap()
                .pseudo_random_id
        };

        // Only the first context has a completed signature so far
        let mut signature_builder = TestThresholdSignatureBuilder::new();
        signature_builder.signatures.insert(
            ids[0],
            CombinedSignature::Ecdsa(ThresholdEcdsaCombinedSignature {
                signature: vec![1; 32],
            }),
        );

        update_signature_agreements(
            &signature_request_contexts,
            &signature_builder,
            None,
            &mut idkg_payload,
            &valid_keys,
            None,
            store_pre_signatures_in_state,
        );
        // First signature should now be in "unreported" agreement
        assert_eq!(idkg_payload.signature_agreements.len(), 1);
        assert_matches!(
            idkg_payload
                .signature_agreements
                .get(&pseudo_random_id(0))
                .unwrap(),
            CompletedSignature::Unreported(_)
        );

        let prev_payload = idkg_payload.clone();
        // Now the second context has a completed signature as well
        signature_builder.signatures.insert(
            ids[1],
            CombinedSignature::Ecdsa(ThresholdEcdsaCombinedSignature {
                signature: vec![1; 32],
            }),
        );
        update_signature_agreements(
            &signature_request_contexts,
            &signature_builder,
            None,
            &mut idkg_payload,
            &valid_keys,
            None,
            store_pre_signatures_in_state,
        );
        // First signature should now be reported, second unreported.
        assert_eq!(idkg_payload.signature_agreements.len(), 2);
        assert_matches!(
            idkg_payload
                .signature_agreements
                .get(&pseudo_random_id(0))
                .unwrap(),
            CompletedSignature::ReportedToExecution
        );
        assert_matches!(
            idkg_payload
                .signature_agreements
                .get(&pseudo_random_id(1))
                .unwrap(),
            CompletedSignature::Unreported(_)
        );

        // Only unreported signatures are validated.
        let res = validate_new_signature_agreements(
            crypto,
            snapshot.get_state(),
            &prev_payload,
            &idkg_payload,
        )
        .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res.keys().next().unwrap(), &ids[1].callback_id);

        // Repeated signature leads to error
        let res = validate_new_signature_agreements(
            crypto,
            snapshot.get_state(),
            &idkg_payload,
            &idkg_payload,
        );
        assert_matches!(
            res,
            Err(ValidationError::InvalidArtifact(
                InvalidIDkgPayloadReason::NewSignatureUnexpected(id)
            ))
            if id == pseudo_random_id(1)
        );
    }

    #[test]
    fn test_validate_new_signature_agreements_missing_input_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_new_signature_agreements_missing_input(key_id);
        }
    }

    fn test_validate_new_signature_agreements_missing_input(key_id: IDkgMasterPublicKeyId) {
        let height = Height::from(0);
        let subnet_id = subnet_test_id(0);
        let crypto = &CryptoReturningOk::default();

        let mut prev_payload = empty_idkg_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
        let pre_sig_id = prev_payload.uid_generator.next_pre_signature_id();
        let pre_sig_id2 = prev_payload.uid_generator.next_pre_signature_id();
        let pre_sig_id3 = prev_payload.uid_generator.next_pre_signature_id();

        let id1 = request_id(1, height);
        let id2 = request_id(2, height);
        let id3 = request_id(3, height);

        let malformed_context = fake_malformed_signature_request_context_from_id(
            key_id.clone().into(),
            pre_sig_id3,
            id3,
        );

        let signature_request_contexts = BTreeMap::from_iter([
            fake_signature_request_context_with_pre_sig(id1, key_id.clone(), Some(pre_sig_id)),
            fake_signature_request_context_from_id(key_id.clone().into(), pre_sig_id2, id2),
            malformed_context.clone(),
        ]);
        let snapshot =
            fake_state_with_signature_requests(height, signature_request_contexts.clone());

        let fake_context = fake_signature_request_context(key_id.clone().into(), [4; 32]);
        let fake_response =
            CompletedSignature::Unreported(ic_types::batch::ConsensusResponse::new(
                CallbackId::from(0),
                ic_types::messages::Payload::Data(match key_id.inner() {
                    MasterPublicKeyId::Ecdsa(_) => {
                        SignWithECDSAReply { signature: vec![] }.encode()
                    }
                    MasterPublicKeyId::Schnorr(_) => {
                        SignWithSchnorrReply { signature: vec![] }.encode()
                    }
                    MasterPublicKeyId::VetKd(_) => panic!("not applicable to vetKD"),
                }),
            ));

        // Insert agreement for incomplete context
        let mut idkg_payload_incomplete_context =
            empty_idkg_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
        idkg_payload_incomplete_context
            .signature_agreements
            .insert([1; 32], fake_response.clone());
        let res = validate_new_signature_agreements(
            crypto,
            snapshot.get_state(),
            &prev_payload,
            &idkg_payload_incomplete_context,
        );
        assert_matches!(
            res,
            Err(ValidationError::InvalidArtifact(
                InvalidIDkgPayloadReason::NewSignatureBuildInputsError(
                    BuildSignatureInputsError::ContextIncomplete
                )
            ))
        );

        // Insert agreement for unknown context
        let mut idkg_payload_missing_context =
            empty_idkg_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
        idkg_payload_missing_context
            .signature_agreements
            .insert(fake_context.pseudo_random_id, fake_response.clone());
        let res = validate_new_signature_agreements(
            crypto,
            snapshot.get_state(),
            &prev_payload,
            &idkg_payload_missing_context,
        );
        assert_matches!(
            res,
            Err(ValidationError::InvalidArtifact(
                InvalidIDkgPayloadReason::NewSignatureMissingContext(_)
            ))
        );

        // Insert agreement for malformed context
        let mut idkg_payload_malformed_context =
            empty_idkg_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
        idkg_payload_malformed_context
            .signature_agreements
            .insert(malformed_context.1.pseudo_random_id, fake_response);
        let res = validate_new_signature_agreements(
            crypto,
            snapshot.get_state(),
            &prev_payload,
            &idkg_payload_malformed_context,
        );
        assert_matches!(
            res,
            Err(ValidationError::InvalidArtifact(
                InvalidIDkgPayloadReason::NewSignatureBuildInputsError(
                    BuildSignatureInputsError::ThresholdEcdsaSigInputsCreationError(_)
                        | BuildSignatureInputsError::ThresholdSchnorrSigInputsCreationError(_)
                )
            ))
        );
    }

    #[test]
    fn test_reject_new_idkg_signature_agreement_for_vetkd_context() {
        let height = Height::from(0);
        let subnet_id = subnet_test_id(0);
        let crypto = &CryptoReturningOk::default();
        // Create a parent block payload for a subnet with a single ECDSA key
        let ecdsa_key_id = fake_ecdsa_idkg_master_public_key_id();
        let prev_payload = empty_idkg_payload_with_key_ids(subnet_id, vec![ecdsa_key_id.clone()]);

        // Create a state requesting vetKD with callback/random ID '1'.
        let callback_id = CallbackId::from(1);
        let vetkd_key_id = fake_vetkd_master_public_key_id();
        let pseudo_random_id = [1; 32];
        let signature_request_contexts = BTreeMap::from_iter([(
            callback_id,
            fake_signature_request_context(vetkd_key_id, pseudo_random_id),
        )]);
        let snapshot =
            fake_state_with_signature_requests(height, signature_request_contexts.clone());

        // Create an (invalid) signature agreement or the callback ID requested above
        let fake_response =
            CompletedSignature::Unreported(ic_types::batch::ConsensusResponse::new(
                callback_id,
                ic_types::messages::Payload::Data(
                    SignWithSchnorrReply { signature: vec![] }.encode(),
                ),
            ));

        // A malicious node sends us an IDKG payload with a signature agreement
        // that references the requested vetKD context.
        let mut idkg_payload_vetkd_context =
            empty_idkg_payload_with_key_ids(subnet_id, vec![ecdsa_key_id]);
        idkg_payload_vetkd_context
            .signature_agreements
            .insert(pseudo_random_id, fake_response);

        // The payload should be rejected, because there should be no aggreements
        // for vetKD in the IDKG payload
        let res = validate_new_signature_agreements(
            crypto,
            snapshot.get_state(),
            &prev_payload,
            &idkg_payload_vetkd_context,
        );
        // The error should be "Signature missing context", because vetKD contexts
        // should be filtered out during IDKG payload validation.
        assert_matches!(
            res,
            Err(ValidationError::InvalidArtifact(
                InvalidIDkgPayloadReason::NewSignatureMissingContext(_)
            ))
        );
    }

    #[test]
    fn should_not_verify_same_transcript_many_times() {
        let mut rng = reproducible_rng();
        use ic_types::consensus::idkg::*;
        let num_of_nodes = 4;
        let thread_pool = build_thread_pool(MAX_IDKG_THREADS);
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes, &mut rng);
        let registry_version = env.newest_registry_version;
        let algorithm_id = AlgorithmId::ThresholdEcdsaSecp256k1;
        let crypto = &CryptoReturningOk::default();
        let mut block_reader = TestIDkgBlockReader::new();
        let key_id = fake_ecdsa_key_id();
        let master_public_key_id: IDkgMasterPublicKeyId =
            MasterPublicKeyId::Ecdsa(key_id.clone()).try_into().unwrap();
        let mut prev_payload =
            empty_idkg_payload_with_key_ids(subnet_id, vec![master_public_key_id.clone()]);
        let mut curr_payload = prev_payload.clone();

        // Add a unmasked transcript
        let (transcript_0, transcript_ref_0, _) =
            generate_key_transcript(&master_public_key_id, &env, &mut rng, Height::new(100));
        let transcript_id_0 = transcript_0.transcript_id;

        // Add a masked transcript
        let transcript_1 = {
            let transcript_id = transcript_id_0.increment();
            let dealers: BTreeSet<_> = env.nodes.ids();
            let receivers = dealers.clone();
            let param = idkg::RandomTranscriptParams::new(
                transcript_id,
                dealers,
                receivers,
                registry_version,
                AlgorithmId::from(master_public_key_id.inner()),
            );
            env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        let masked_transcript_1 =
            idkg::MaskedTranscript::try_from((Height::new(10), &transcript_1)).unwrap();
        block_reader.add_transcript(
            TranscriptRef::new(Height::new(10), transcript_1.transcript_id),
            transcript_1,
        );

        curr_payload
            .idkg_transcripts
            .insert(transcript_id_0, transcript_0.clone());

        // Add the reference
        let random_params = idkg::RandomTranscriptParams::new(
            transcript_id_0,
            env.nodes.ids(),
            env.nodes.ids(),
            registry_version,
            algorithm_id,
        );
        prev_payload.single_key_transcript_mut().next_in_creation =
            idkg::KeyTranscriptCreation::RandomTranscriptParams(random_params);
        curr_payload.single_key_transcript_mut().next_in_creation =
            idkg::KeyTranscriptCreation::Created(transcript_ref_0);

        const NUM_MALICIOUS_REFS: i32 = 10_000;
        for i in 0..NUM_MALICIOUS_REFS {
            let malicious_transcript_ref =
                idkg::UnmaskedTranscript::try_from((Height::new(i as u64), &transcript_0)).unwrap();
            curr_payload.available_pre_signatures.insert(
                curr_payload.uid_generator.next_pre_signature_id(),
                PreSignatureRef::Ecdsa(PreSignatureQuadrupleRef {
                    key_id: key_id.clone(),
                    kappa_unmasked_ref: malicious_transcript_ref,
                    lambda_masked_ref: masked_transcript_1,
                    kappa_times_lambda_ref: masked_transcript_1,
                    key_times_lambda_ref: masked_transcript_1,
                    key_unmasked_ref: transcript_ref_0,
                }),
            );
        }

        let error = validate_transcript_refs(
            crypto,
            thread_pool.as_ref(),
            &block_reader,
            &prev_payload,
            &curr_payload,
            Height::from(100),
        )
        .unwrap_err();

        // Previously it would report NewTranscriptMiscount error as a proof that
        // the same transcripts have been verified many times.
        // Now that we fixed the problem, it reports NewTranscriptRefWrongHeight instead.
        assert_matches!(
            error,
            ValidationError::InvalidArtifact(
                InvalidIDkgPayloadReason::NewTranscriptRefWrongHeight(_, _)
            )
        );
    }
}
