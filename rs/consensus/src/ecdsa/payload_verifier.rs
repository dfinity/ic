//! This module implements the ECDSA payload verifier.
//!
//! It validates a payload by doing an equality check with a payload
//! that would have been created by itself, given the same inputs.
//! This works because the payload creation is a deterministic process
//! once all inputs are fixed.
//!
//! Therefore, it is important to ensure all inputs are indeed the same
//! between all replicas in a subnet. Payload creation only reads completed
//! transcripts, dealings (for xnet resharing), and signatures from ecdsa
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

use super::payload_builder::EcdsaPayloadError;
use super::pre_signer::EcdsaTranscriptBuilder;
use super::signer::EcdsaSignatureBuilder;
use super::utils::{
    block_chain_cache, get_ecdsa_config_if_enabled, EcdsaBlockReaderImpl, InvalidChainCacheError,
};
use crate::consensus::metrics::timed_call;
use crate::ecdsa::payload_builder::{create_data_payload_helper, create_summary_payload};
use crate::ecdsa::utils::build_signature_inputs;
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces::validation::{ValidationError, ValidationResult};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{StateManager, StateManagerError};
use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithEcdsaContext;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::ValidationContext,
    consensus::{
        ecdsa,
        ecdsa::{EcdsaBlockReader, TranscriptRef},
        Block, BlockPayload, HasHeight,
    },
    crypto::canister_threshold_sig::{
        error::{
            IDkgVerifyInitialDealingsError, IDkgVerifyTranscriptError,
            ThresholdEcdsaVerifyCombinedSignatureError,
        },
        idkg::{IDkgTranscript, IDkgTranscriptId, InitialIDkgDealings, SignedIDkgDealing},
        ThresholdEcdsaCombinedSignature,
    },
    registry::RegistryClientError,
    Height, SubnetId,
};
use prometheus::HistogramVec;
use std::collections::BTreeMap;
use std::convert::TryFrom;

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
// The fields are only read by the `Debug` implementation.
// The `dead_code` lint ignores `Debug` impls, see: https://github.com/rust-lang/rust/issues/88900.
#[allow(dead_code)]
pub(crate) enum TransientError {
    RegistryClientError(RegistryClientError),
    StateManagerError(StateManagerError),
}

#[derive(Debug)]
// The fields are only read by the `Debug` implementation.
// The `dead_code` lint ignores `Debug` impls, see: https://github.com/rust-lang/rust/issues/88900.
#[allow(dead_code)]
pub(crate) enum PermanentError {
    // wrapper of other errors
    UnexpectedSummaryPayload(EcdsaPayloadError),
    UnexpectedDataPayload(Option<EcdsaPayloadError>),
    InvalidChainCacheError(InvalidChainCacheError),
    ThresholdEcdsaSigInputsError(ecdsa::ThresholdEcdsaSigInputsError),
    TranscriptParamsError(ecdsa::TranscriptParamsError),
    ThresholdEcdsaVerifyCombinedSignatureError(ThresholdEcdsaVerifyCombinedSignatureError),
    IDkgVerifyTranscriptError(IDkgVerifyTranscriptError),
    IDkgVerifyInitialDealingsError(IDkgVerifyInitialDealingsError),
    // local errors
    ConsensusRegistryVersionNotFound(Height),
    EcdsaConfigNotFound,
    SummaryPayloadMismatch,
    DataPayloadMismatch,
    MissingEcdsaDataPayload,
    NewTranscriptRefWrongHeight(TranscriptRef, Height),
    NewTranscriptNotFound(IDkgTranscriptId),
    NewTranscriptMiscount(u64),
    NewTranscriptMissingParams(IDkgTranscriptId),
    NewSignatureUnexpected(ecdsa::PseudoRandomId),
    NewSignatureMissingInput(ecdsa::PseudoRandomId),
    NewSignatureMissingContext(ecdsa::PseudoRandomId),
    XNetReshareAgreementWithoutRequest(ecdsa::EcdsaReshareRequest),
    XNetReshareRequestDisappeared(ecdsa::EcdsaReshareRequest),
    DecodingError(String),
}

impl From<PermanentError> for EcdsaValidationError {
    fn from(err: PermanentError) -> Self {
        ValidationError::Permanent(err)
    }
}

impl From<TransientError> for EcdsaValidationError {
    fn from(err: TransientError) -> Self {
        ValidationError::Transient(err)
    }
}

impl From<InvalidChainCacheError> for PermanentError {
    fn from(err: InvalidChainCacheError) -> Self {
        PermanentError::InvalidChainCacheError(err)
    }
}

impl From<ecdsa::ThresholdEcdsaSigInputsError> for PermanentError {
    fn from(err: ecdsa::ThresholdEcdsaSigInputsError) -> Self {
        PermanentError::ThresholdEcdsaSigInputsError(err)
    }
}

impl From<ecdsa::TranscriptParamsError> for PermanentError {
    fn from(err: ecdsa::TranscriptParamsError) -> Self {
        PermanentError::TranscriptParamsError(err)
    }
}

impl From<IDkgVerifyTranscriptError> for PermanentError {
    fn from(err: IDkgVerifyTranscriptError) -> Self {
        PermanentError::IDkgVerifyTranscriptError(err)
    }
}

impl From<IDkgVerifyInitialDealingsError> for PermanentError {
    fn from(err: IDkgVerifyInitialDealingsError) -> Self {
        PermanentError::IDkgVerifyInitialDealingsError(err)
    }
}

impl From<RegistryClientError> for TransientError {
    fn from(err: RegistryClientError) -> Self {
        TransientError::RegistryClientError(err)
    }
}

impl From<StateManagerError> for TransientError {
    fn from(err: StateManagerError) -> Self {
        TransientError::StateManagerError(err)
    }
}

pub(crate) type EcdsaValidationError = ValidationError<PermanentError, TransientError>;

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    parent_block: &Block,
    payload: &BlockPayload,
    metrics: HistogramVec,
) -> ValidationResult<EcdsaValidationError> {
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
                    payload.as_summary().ecdsa.as_ref(),
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
                    pool_reader,
                    state_manager,
                    context,
                    parent_block,
                    payload.as_data().ecdsa.as_ref(),
                    &metrics,
                )
            },
            &metrics,
        )
    }
}

/// Validates a threshold ECDSA summary payload.
/// This is an entirely deterministic operation, so we can just check if
/// the given summary payload matches what we would have created locally.
fn validate_summary_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    pool_reader: &PoolReader<'_>,
    context: &ValidationContext,
    parent_block: &Block,
    summary_payload: Option<&ecdsa::EcdsaPayload>,
) -> ValidationResult<EcdsaValidationError> {
    let height = parent_block.height().increment();
    let registry_version = pool_reader
        .registry_version(height)
        .ok_or(PermanentError::ConsensusRegistryVersionNotFound(height))?;
    let ecdsa_config = get_ecdsa_config_if_enabled(
        subnet_id,
        registry_version,
        registry_client,
        &ic_logger::replica_logger::no_op_logger(),
    )
    .map_err(TransientError::from)?;
    if ecdsa_config.is_none() {
        if summary_payload.is_some() {
            return Err(PermanentError::EcdsaConfigNotFound.into());
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
                Err(PermanentError::SummaryPayloadMismatch.into())
            }
        }
        Err(EcdsaPayloadError::RegistryClientError(err)) => {
            Err(TransientError::RegistryClientError(err).into())
        }
        Err(EcdsaPayloadError::StateManagerError(err)) => {
            Err(TransientError::StateManagerError(err).into())
        }
        Err(err) => Err(PermanentError::UnexpectedSummaryPayload(err).into()),
    }
}

#[allow(clippy::too_many_arguments)]
/// Validates a threshold ECDSA data payload.
fn validate_data_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    parent_block: &Block,
    data_payload: Option<&ecdsa::EcdsaPayload>,
    metrics: &HistogramVec,
) -> ValidationResult<EcdsaValidationError> {
    if parent_block.payload.as_ref().as_ecdsa().is_none() {
        if data_payload.is_some() {
            return Err(PermanentError::UnexpectedDataPayload(None).into());
        } else {
            return Ok(());
        }
    }

    let block_payload = &parent_block.payload.as_ref();
    let (prev_payload, curr_payload) = if block_payload.is_summary() {
        match &block_payload.as_summary().ecdsa {
            None => {
                if data_payload.is_some() {
                    return Err(PermanentError::UnexpectedDataPayload(None).into());
                } else {
                    return Ok(());
                }
            }
            Some(ecdsa_summary) => {
                if data_payload.is_none() {
                    return Err(PermanentError::MissingEcdsaDataPayload.into());
                }
                (ecdsa_summary.clone(), data_payload.as_ref().unwrap())
            }
        }
    } else {
        match &block_payload.as_data().ecdsa {
            None => {
                if data_payload.is_some() {
                    return Err(PermanentError::UnexpectedDataPayload(None).into());
                } else {
                    return Ok(());
                }
            }
            Some(payload) => {
                if data_payload.is_none() {
                    return Err(PermanentError::MissingEcdsaDataPayload.into());
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
    let parent_chain = block_chain_cache(pool_reader, &summary_block, parent_block)
        .map_err(PermanentError::from)?;
    let block_reader = EcdsaBlockReaderImpl::new(parent_chain);
    let curr_height = parent_block.height().increment();

    let transcripts = timed_call(
        "validate_transcript_refs",
        || {
            validate_transcript_refs(
                crypto,
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
        .map_err(TransientError::StateManagerError)?;
    let signatures = timed_call(
        "validate_new_signature_agreements",
        || {
            validate_new_signature_agreements(
                crypto,
                &block_reader,
                state.get_ref(),
                &prev_payload,
                curr_payload,
            )
        },
        metrics,
    )?;

    let builder = CachedBuilder {
        transcripts,
        dealings,
        signatures,
    };

    let ecdsa_payload = create_data_payload_helper(
        subnet_id,
        context,
        parent_block,
        &summary_block,
        &block_reader,
        &builder,
        &builder,
        state_manager,
        registry_client,
        None,
        &ic_logger::replica_logger::no_op_logger(),
    )
    .map_err(|err| PermanentError::UnexpectedDataPayload(Some(err)))?;

    if ecdsa_payload.as_ref() == data_payload {
        Ok(())
    } else {
        Err(PermanentError::DataPayloadMismatch.into())
    }
}

struct CachedBuilder {
    transcripts: BTreeMap<IDkgTranscriptId, IDkgTranscript>,
    dealings: BTreeMap<IDkgTranscriptId, Vec<SignedIDkgDealing>>,
    signatures: BTreeMap<ecdsa::PseudoRandomId, ThresholdEcdsaCombinedSignature>,
}

impl EcdsaTranscriptBuilder for CachedBuilder {
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

impl EcdsaSignatureBuilder for CachedBuilder {
    fn get_completed_signature(
        &self,
        context: &SignWithEcdsaContext,
    ) -> Option<ThresholdEcdsaCombinedSignature> {
        self.signatures.get(&context.pseudo_random_id).cloned()
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
    block_reader: &dyn EcdsaBlockReader,
    prev_payload: &ecdsa::EcdsaPayload,
    curr_payload: &ecdsa::EcdsaPayload,
    curr_height: Height,
) -> Result<BTreeMap<IDkgTranscriptId, IDkgTranscript>, EcdsaValidationError> {
    use PermanentError::*;
    let mut count = 0;
    let idkg_transcripts = &curr_payload.idkg_transcripts;
    let prev_configs = prev_payload
        .iter_transcript_configs_in_creation()
        .map(|config| (config.transcript_id, config))
        .collect::<BTreeMap<_, _>>();
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
                let params = config
                    .translate(block_reader)
                    .map_err(TranscriptParamsError)?;
                crypto
                    .verify_transcript(&params, transcript)
                    .map_err(IDkgVerifyTranscriptError)?;
                count += 1;
            } else {
                return Err(NewTranscriptNotFound(*transcript_id).into());
            }
        }
    }
    if count as usize == idkg_transcripts.len() {
        Ok(idkg_transcripts.clone())
    } else {
        Err(NewTranscriptMiscount(count).into())
    }
}

fn validate_reshare_dealings(
    crypto: &dyn ConsensusCrypto,
    block_reader: &dyn EcdsaBlockReader,
    prev_payload: &ecdsa::EcdsaPayload,
    curr_payload: &ecdsa::EcdsaPayload,
) -> Result<BTreeMap<IDkgTranscriptId, Vec<SignedIDkgDealing>>, EcdsaValidationError> {
    use PermanentError::*;
    let mut new_reshare_agreement = BTreeMap::new();
    for (request, dealings) in curr_payload.xnet_reshare_agreements.iter() {
        if let ecdsa::CompletedReshareRequest::Unreported(dealings) = &dealings {
            if prev_payload.xnet_reshare_agreements.get(request).is_none() {
                if prev_payload.ongoing_xnet_reshares.get(request).is_none() {
                    return Err(XNetReshareAgreementWithoutRequest(request.clone()).into());
                }
                new_reshare_agreement.insert(request.clone(), dealings);
            }
        }
    }
    let mut new_dealings = BTreeMap::new();
    for (request, config) in prev_payload.ongoing_xnet_reshares.iter() {
        if curr_payload.ongoing_xnet_reshares.get(request).is_none() {
            if let Some(response) = new_reshare_agreement.get(request) {
                use ic_management_canister_types::ComputeInitialEcdsaDealingsResponse;
                if let ic_types::messages::Payload::Data(data) = &response.payload {
                    let dealings_response = ComputeInitialEcdsaDealingsResponse::decode(data)
                        .map_err(|err| PermanentError::DecodingError(format!("{:?}", err)))?;
                    let transcript_id = config.as_ref().transcript_id;
                    let param = config
                        .as_ref()
                        .translate(block_reader)
                        .map_err(PermanentError::from)?;
                    let initial_dealings =
                        InitialIDkgDealings::try_from(&dealings_response.initial_dkg_dealings)
                            .map_err(|err| PermanentError::DecodingError(format!("{:?}", err)))?;
                    crypto
                        .verify_initial_dealings(&param, &initial_dealings)
                        .map_err(PermanentError::from)?;
                    new_dealings.insert(transcript_id, initial_dealings.dealings().clone());
                }
            } else {
                return Err(XNetReshareRequestDisappeared(request.clone()).into());
            }
        }
    }
    Ok(new_dealings)
}

// Validate new signature agreements in the current payload.
// New signatures are those that are Unreported in the curr_payload and not in prev_payload.
fn validate_new_signature_agreements(
    crypto: &dyn ConsensusCrypto,
    block_reader: &dyn EcdsaBlockReader,
    state: &ReplicatedState,
    prev_payload: &ecdsa::EcdsaPayload,
    curr_payload: &ecdsa::EcdsaPayload,
) -> Result<BTreeMap<ecdsa::PseudoRandomId, ThresholdEcdsaCombinedSignature>, EcdsaValidationError>
{
    use PermanentError::*;
    let mut new_signatures = BTreeMap::new();
    let context_map = state
        .sign_with_ecdsa_contexts()
        .values()
        .map(|c| (c.pseudo_random_id, c))
        .collect::<BTreeMap<_, _>>();

    for (random_id, completed) in curr_payload.signature_agreements.iter() {
        if let ecdsa::CompletedSignature::Unreported(response) = completed {
            if let ic_types::messages::Payload::Data(data) = &response.payload {
                use ic_management_canister_types::{Payload, SignWithECDSAReply};
                let reply = SignWithECDSAReply::decode(data)
                    .map_err(|err| PermanentError::DecodingError(format!("{:?}", err)))?;
                let signature = ThresholdEcdsaCombinedSignature {
                    signature: reply.signature,
                };
                if prev_payload.signature_agreements.get(random_id).is_some() {
                    return Err(PermanentError::NewSignatureUnexpected(*random_id).into());
                }

                let context = context_map
                    .get(random_id)
                    .ok_or(PermanentError::NewSignatureMissingContext(*random_id))?;
                let (_, input_ref) = build_signature_inputs(context, block_reader)
                    .ok_or(PermanentError::NewSignatureMissingInput(*random_id))?;
                let input = input_ref
                    .translate(block_reader)
                    .map_err(PermanentError::from)?;
                crypto
                    .verify_combined_sig(&input, &signature)
                    .map_err(ThresholdEcdsaVerifyCombinedSignatureError)?;
                new_signatures.insert(*random_id, signature.clone());
            }
        }
    }
    Ok(new_signatures)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ecdsa::{
        payload_builder::{
            resharing::{initiate_reshare_requests, update_completed_reshare_requests},
            signatures::update_signature_agreements,
        },
        test_utils::*,
        utils::get_context_request_id,
    };
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_dealings;
    use ic_crypto_test_utils_canister_threshold_sigs::CanisterThresholdSigTestEnvironment;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_interfaces_state_manager::CertifiedStateSnapshot;
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types::{EcdsaKeyId, Payload, SignWithECDSAReply};
    use ic_test_utilities::crypto::CryptoReturningOk;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{
        consensus::ecdsa::CompletedSignature, crypto::AlgorithmId, messages::CallbackId, Height,
    };
    use std::{collections::BTreeSet, str::FromStr};

    #[test]
    fn test_validate_transcript_refs() {
        let mut rng = reproducible_rng();
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes, &mut rng);
        let registry_version = env.newest_registry_version;
        let algorithm_id = AlgorithmId::ThresholdEcdsaSecp256k1;
        let crypto = &CryptoReturningOk::default();
        let mut block_reader = TestEcdsaBlockReader::new();
        let mut prev_payload = empty_ecdsa_payload(subnet_id);
        let mut curr_payload = prev_payload.clone();

        // Empty payload verifies
        assert!(validate_transcript_refs(
            crypto,
            &block_reader,
            &prev_payload,
            &curr_payload,
            Height::from(0)
        )
        .is_ok());

        // Add a transcript
        let height_100 = Height::new(100);
        let (transcript_0, transcript_ref_0, _) =
            generate_key_transcript(&env, &mut rng, height_100);
        let transcript_id_0 = transcript_0.transcript_id;
        curr_payload
            .idkg_transcripts
            .insert(transcript_id_0, transcript_0);
        // Error because transcript is not referenced
        assert_matches!(
            validate_transcript_refs(
                crypto,
                &block_reader,
                &prev_payload,
                &curr_payload,
                height_100
            ),
            Err(ValidationError::Permanent(
                PermanentError::NewTranscriptMiscount(_)
            ))
        );

        // Add the reference
        prev_payload.key_transcript.next_in_creation =
            ecdsa::KeyTranscriptCreation::RandomTranscriptParams(
                ecdsa::RandomTranscriptParams::new(
                    transcript_id_0,
                    env.nodes.ids(),
                    env.nodes.ids(),
                    registry_version,
                    algorithm_id,
                ),
            );
        curr_payload.key_transcript.next_in_creation =
            ecdsa::KeyTranscriptCreation::Created(transcript_ref_0);
        let res = validate_transcript_refs(
            crypto,
            &block_reader,
            &prev_payload,
            &curr_payload,
            height_100,
        );
        assert!(res.is_ok());

        // Error because of height mismatch
        assert_matches!(
            validate_transcript_refs(
                crypto,
                &block_reader,
                &prev_payload,
                &curr_payload,
                Height::from(99),
            ),
            Err(ValidationError::Permanent(
                PermanentError::NewTranscriptRefWrongHeight(_, _)
            ))
        );

        // Add another reference
        let (transcript_1, transcript_ref_1, _) =
            generate_key_transcript(&env, &mut rng, height_100);
        curr_payload.key_transcript.next_in_creation =
            ecdsa::KeyTranscriptCreation::Created(transcript_ref_1);
        assert_matches!(
            validate_transcript_refs(
                crypto,
                &block_reader,
                &prev_payload,
                &curr_payload,
                height_100
            ),
            Err(ValidationError::Permanent(
                PermanentError::NewTranscriptNotFound(_)
            ))
        );

        curr_payload.idkg_transcripts = BTreeMap::new();
        block_reader.add_transcript(*transcript_ref_1.as_ref(), transcript_1);
        assert!(validate_transcript_refs(
            crypto,
            &block_reader,
            &prev_payload,
            &curr_payload,
            Height::from(101),
        )
        .is_ok());
    }

    fn make_dealings_response(
        _request: &ecdsa::EcdsaReshareRequest,
        initial_dealings: &InitialIDkgDealings,
    ) -> Option<ic_types::batch::ConsensusResponse> {
        use ic_management_canister_types::ComputeInitialEcdsaDealingsResponse;
        let mut response = empty_response();
        response.payload = ic_types::messages::Payload::Data(
            ComputeInitialEcdsaDealingsResponse {
                initial_dkg_dealings: initial_dealings.into(),
            }
            .encode(),
        );
        Some(response)
    }

    #[test]
    fn test_validate_reshare_dealings() {
        let mut rng = reproducible_rng();
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let crypto = &CryptoReturningOk::default();
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes, &mut rng);
        let mut payload = empty_ecdsa_payload(subnet_id);
        let mut block_reader = TestEcdsaBlockReader::new();
        let transcript_builder = TestEcdsaTranscriptBuilder::new();

        let req_1 = create_reshare_request(1, 1);
        let req_2 = create_reshare_request(2, 2);
        let reshare_requests = BTreeSet::from([req_1.clone(), req_2.clone()]);

        let (key_transcript, key_transcript_ref) = payload.generate_current_key(&env, &mut rng);
        block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript);
        initiate_reshare_requests(&mut payload, reshare_requests.clone());
        let prev_payload = payload.clone();

        // Create completed dealings for request 1.
        let reshare_params = payload.ongoing_xnet_reshares.get(&req_1).unwrap().as_ref();
        let dealings = dummy_dealings(reshare_params.transcript_id, &reshare_params.dealers);
        transcript_builder.add_dealings(reshare_params.transcript_id, dealings);
        update_completed_reshare_requests(
            &mut payload,
            &make_dealings_response,
            &block_reader,
            &transcript_builder,
            &no_op_logger(),
        );
        assert_eq!(payload.xnet_reshare_agreements.len(), 1);
        assert_matches!(
            payload.xnet_reshare_agreements.get(&req_1).unwrap(),
            ecdsa::CompletedReshareRequest::Unreported(_)
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
            Err(ValidationError::Permanent(
                PermanentError::XNetReshareRequestDisappeared(_)
            ))
        );

        // Create another request and dealings
        let reshare_params = payload.ongoing_xnet_reshares.get(&req_2).unwrap().as_ref();
        let dealings = dummy_dealings(reshare_params.transcript_id, &reshare_params.dealers);
        transcript_builder.add_dealings(reshare_params.transcript_id, dealings);
        let mut prev_payload = payload.clone();
        update_completed_reshare_requests(
            &mut payload,
            &make_dealings_response,
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
            Err(ValidationError::Permanent(
                PermanentError::XNetReshareAgreementWithoutRequest(_)
            ))
        );
    }

    #[test]
    fn test_validate_new_signature_agreements() {
        let mut rng = reproducible_rng();
        let num_nodes = 4;
        let subnet_id = subnet_test_id(0);
        let env = CanisterThresholdSigTestEnvironment::new(num_nodes, &mut rng);
        let crypto = &CryptoReturningOk::default();
        let mut block_reader = TestEcdsaBlockReader::new();
        let height = Height::from(1);
        let mut valid_keys = BTreeSet::new();
        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        valid_keys.insert(key_id.clone());

        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
        let quadruple_id1 = ecdsa_payload.uid_generator.next_quadruple_id();
        let quadruple_id2 = ecdsa_payload.uid_generator.next_quadruple_id();
        let quadruple_id3 = ecdsa_payload.uid_generator.next_quadruple_id();

        // There are three requests in state, two are completed, one is still
        // missing its nonce.
        let sign_with_ecdsa_contexts = BTreeMap::from_iter([
            fake_completed_sign_with_ecdsa_context(1, quadruple_id1.clone()),
            fake_completed_sign_with_ecdsa_context(2, quadruple_id2.clone()),
            fake_sign_with_ecdsa_context_with_quadruple(
                3,
                key_id.clone(),
                Some(quadruple_id3.clone()),
            ),
        ]);
        let snapshot = fake_state_with_ecdsa_contexts(height, sign_with_ecdsa_contexts.clone());

        let request_ids = sign_with_ecdsa_contexts
            .values()
            .flat_map(get_context_request_id)
            .collect::<Vec<_>>();

        let (key_transcript, key_transcript_ref) =
            ecdsa_payload.generate_current_key(&env, &mut rng);
        block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript.clone());

        // Add the quadruples and transcripts to block reader and payload
        let sig_inputs = (1..4)
            .map(|i| {
                create_sig_inputs_with_args(
                    i,
                    &env.nodes.ids(),
                    key_transcript.clone(),
                    Height::from(44),
                )
            })
            .collect::<Vec<_>>();

        insert_test_sig_inputs(
            &mut block_reader,
            &mut ecdsa_payload,
            [
                (quadruple_id1, sig_inputs[0].clone()),
                (quadruple_id2, sig_inputs[1].clone()),
                (quadruple_id3, sig_inputs[2].clone()),
            ],
        );

        // Only the first context has a completed signature so far
        let mut signature_builder = TestEcdsaSignatureBuilder::new();
        signature_builder.signatures.insert(
            request_ids[0].clone(),
            ThresholdEcdsaCombinedSignature {
                signature: vec![1; 32],
            },
        );

        update_signature_agreements(
            &sign_with_ecdsa_contexts,
            &signature_builder,
            None,
            &mut ecdsa_payload,
            &valid_keys,
            None,
        );
        // First signature should now be in "unreported" agreement
        assert_eq!(ecdsa_payload.signature_agreements.len(), 1);
        assert_matches!(
            ecdsa_payload
                .signature_agreements
                .get(&request_ids[0].pseudo_random_id)
                .unwrap(),
            CompletedSignature::Unreported(_)
        );

        let prev_payload = ecdsa_payload.clone();
        // Now the second context has a completed signature as well
        signature_builder.signatures.insert(
            request_ids[1].clone(),
            ThresholdEcdsaCombinedSignature {
                signature: vec![1; 32],
            },
        );
        update_signature_agreements(
            &sign_with_ecdsa_contexts,
            &signature_builder,
            None,
            &mut ecdsa_payload,
            &valid_keys,
            None,
        );
        // First signature should now be reported, second unreported.
        assert_eq!(ecdsa_payload.signature_agreements.len(), 2);
        assert_matches!(
            ecdsa_payload
                .signature_agreements
                .get(&request_ids[0].pseudo_random_id)
                .unwrap(),
            CompletedSignature::ReportedToExecution
        );
        assert_matches!(
            ecdsa_payload
                .signature_agreements
                .get(&request_ids[1].pseudo_random_id)
                .unwrap(),
            CompletedSignature::Unreported(_)
        );

        // Only unreported signatures are validated.
        let res = validate_new_signature_agreements(
            crypto,
            &block_reader,
            snapshot.get_state(),
            &prev_payload,
            &ecdsa_payload,
        )
        .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res.keys().next().unwrap(), &request_ids[1].pseudo_random_id);

        // Repeated signature leads to error
        let res = validate_new_signature_agreements(
            crypto,
            &block_reader,
            snapshot.get_state(),
            &ecdsa_payload,
            &ecdsa_payload,
        );
        assert_matches!(
            res,
            Err(ValidationError::Permanent(
                PermanentError::NewSignatureUnexpected(id)
            ))
            if id == request_ids[1].pseudo_random_id
        );
    }

    #[test]
    fn test_validate_new_signature_agreements_missing_input() {
        let height = Height::from(0);
        let subnet_id = subnet_test_id(0);
        let crypto = &CryptoReturningOk::default();
        let block_reader = TestEcdsaBlockReader::new();
        let mut valid_keys = BTreeSet::new();
        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        valid_keys.insert(key_id.clone());

        let mut prev_payload = empty_ecdsa_payload(subnet_id);
        let quadruple_id = prev_payload.uid_generator.next_quadruple_id();

        let sign_with_ecdsa_contexts =
            BTreeMap::from_iter([fake_sign_with_ecdsa_context_with_quadruple(
                1,
                key_id.clone(),
                Some(quadruple_id.clone()),
            )]);
        let snapshot = fake_state_with_ecdsa_contexts(height, sign_with_ecdsa_contexts.clone());

        let fake_context = fake_sign_with_ecdsa_context(key_id.clone(), [4; 32]);
        let fake_response =
            CompletedSignature::Unreported(ic_types::batch::ConsensusResponse::new(
                CallbackId::from(0),
                ic_types::messages::Payload::Data(
                    SignWithECDSAReply { signature: vec![] }.encode(),
                ),
            ));

        // Insert agreement for incomplete context
        let mut ecdsa_payload_incomplete_context = empty_ecdsa_payload(subnet_id);
        ecdsa_payload_incomplete_context
            .signature_agreements
            .insert([1; 32], fake_response.clone());
        let res = validate_new_signature_agreements(
            crypto,
            &block_reader,
            snapshot.get_state(),
            &prev_payload,
            &ecdsa_payload_incomplete_context,
        );
        assert_matches!(
            res,
            Err(ValidationError::Permanent(
                PermanentError::NewSignatureMissingInput(_)
            ))
        );

        // Insert agreement for unknown context
        let mut ecdsa_payload_missing_context = empty_ecdsa_payload(subnet_id);
        ecdsa_payload_missing_context
            .signature_agreements
            .insert(fake_context.pseudo_random_id, fake_response);
        let res = validate_new_signature_agreements(
            crypto,
            &block_reader,
            snapshot.get_state(),
            &prev_payload,
            &ecdsa_payload_missing_context,
        );
        assert_matches!(
            res,
            Err(ValidationError::Permanent(
                PermanentError::NewSignatureMissingContext(_)
            ))
        );
    }

    #[test]
    fn should_not_verify_same_transcript_many_times() {
        let mut rng = reproducible_rng();
        use ic_types::consensus::ecdsa::*;
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes, &mut rng);
        let registry_version = env.newest_registry_version;
        let algorithm_id = AlgorithmId::ThresholdEcdsaSecp256k1;
        let crypto = &CryptoReturningOk::default();
        let mut block_reader = TestEcdsaBlockReader::new();
        let key_id = fake_ecdsa_key_id();
        let mut prev_payload = empty_ecdsa_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
        let mut curr_payload = prev_payload.clone();

        // Add a unmasked transcript
        let (transcript_0, transcript_ref_0, _) =
            generate_key_transcript(&env, &mut rng, Height::new(100));
        let transcript_id_0 = transcript_0.transcript_id;

        // Add a masked transcript
        let transcript_1 = {
            let transcript_id = transcript_id_0.increment();
            let dealers: BTreeSet<_> = env.nodes.ids();
            let receivers = dealers.clone();
            let param = ecdsa::RandomTranscriptParams::new(
                transcript_id,
                dealers,
                receivers,
                registry_version,
                AlgorithmId::ThresholdEcdsaSecp256k1,
            );
            env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        let masked_transcript_1 =
            ecdsa::MaskedTranscript::try_from((Height::new(10), &transcript_1)).unwrap();
        block_reader.add_transcript(
            TranscriptRef::new(Height::new(10), transcript_1.transcript_id),
            transcript_1,
        );

        curr_payload
            .idkg_transcripts
            .insert(transcript_id_0, transcript_0.clone());

        // Add the reference
        let random_params = ecdsa::RandomTranscriptParams::new(
            transcript_id_0,
            env.nodes.ids(),
            env.nodes.ids(),
            registry_version,
            algorithm_id,
        );
        prev_payload.key_transcript.next_in_creation =
            ecdsa::KeyTranscriptCreation::RandomTranscriptParams(random_params);
        curr_payload.key_transcript.next_in_creation =
            ecdsa::KeyTranscriptCreation::Created(transcript_ref_0);

        const NUM_MALICIOUS_REFS: i32 = 10_000;
        for i in 0..NUM_MALICIOUS_REFS {
            let malicious_transcript_ref =
                ecdsa::UnmaskedTranscript::try_from((Height::new(i as u64), &transcript_0))
                    .unwrap();
            curr_payload.available_quadruples.insert(
                curr_payload.uid_generator.next_quadruple_id(),
                PreSignatureQuadrupleRef {
                    key_id: Some(curr_payload.key_transcript.key_id.clone()),
                    kappa_unmasked_ref: malicious_transcript_ref,
                    lambda_masked_ref: masked_transcript_1,
                    kappa_times_lambda_ref: masked_transcript_1,
                    key_times_lambda_ref: masked_transcript_1,
                    key_unmasked_ref: transcript_ref_0,
                },
            );
        }

        let error = validate_transcript_refs(
            crypto,
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
            ValidationError::Permanent(PermanentError::NewTranscriptRefWrongHeight(_, _))
        );
    }
}
