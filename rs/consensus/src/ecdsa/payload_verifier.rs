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

use super::payload_builder::{EcdsaPayloadError, InvalidChainCacheError, MembershipError};
use super::pre_signer::EcdsaTranscriptBuilder;
use super::signer::EcdsaSignatureBuilder;
use super::utils::EcdsaBlockReaderImpl;
use crate::consensus::{crypto::ConsensusCrypto, pool_reader::PoolReader};
use crate::ecdsa::payload_builder::{
    block_chain_cache, create_data_payload_helper, create_summary_payload, ecdsa_feature_is_enabled,
};
use ic_interfaces::{
    registry::RegistryClient,
    validation::{ValidationError, ValidationResult},
};
use ic_interfaces_state_manager::{StateManager, StateManagerError};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::ValidationContext,
    consensus::{ecdsa, ecdsa::EcdsaBlockReader, Block, BlockPayload, HasHeight},
    crypto::canister_threshold_sig::{
        error::{
            IDkgVerifyDealingPublicError, IDkgVerifyTranscriptError,
            ThresholdEcdsaVerifyCombinedSignatureError,
        },
        idkg::{IDkgDealing, IDkgTranscript, IDkgTranscriptId},
        ThresholdEcdsaCombinedSignature,
    },
    registry::RegistryClientError,
    NodeId, RegistryVersion, SubnetId,
};
use std::collections::BTreeMap;

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum TransientError {
    RegistryClientError(RegistryClientError),
    EcdsaPayloadError(EcdsaPayloadError),
    StateManagerError(StateManagerError),
}

#[derive(Debug)]
pub enum PermanentError {
    // wrapper of other errors
    UnexpectedSummaryPayload(EcdsaPayloadError),
    UnexpectedDataPayload(Option<EcdsaPayloadError>),
    InvalidChainCacheError(InvalidChainCacheError),
    ThresholdEcdsaSigInputsError(ecdsa::ThresholdEcdsaSigInputsError),
    TranscriptParamsError(ecdsa::TranscriptParamsError),
    ThresholdEcdsaVerifyCombinedSignatureError(ThresholdEcdsaVerifyCombinedSignatureError),
    IDkgVerifyTranscriptError(IDkgVerifyTranscriptError),
    IDkgVerifyDealingPublicError(IDkgVerifyDealingPublicError),
    // local errors
    SubnetWithNoNodes(SubnetId, RegistryVersion),
    EcdsaFeatureDisabled,
    SummaryPayloadMismatch,
    DataPayloadMismatch,
    MissingEcdsaDataPayload,
    MissingParentDataPayload,
    NewTranscriptNotFound(IDkgTranscriptId),
    NewTranscriptMiscount(u64),
    NewTranscriptMissingParams(IDkgTranscriptId),
    NewTranscriptHeightMismatch(IDkgTranscriptId),
    NewSignatureUnexpected(ecdsa::RequestId),
    NewSignatureMissingInput(ecdsa::RequestId),
    XNetReshareAgreementWithoutRequest(ecdsa::EcdsaReshareRequest),
    XNetReshareRequestDisappeared(ecdsa::EcdsaReshareRequest),
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

impl From<MembershipError> for EcdsaValidationError {
    fn from(err: MembershipError) -> Self {
        match err {
            MembershipError::RegistryClientError(err) => {
                TransientError::RegistryClientError(err).into()
            }
            MembershipError::SubnetWithNoNodes(subnet_id, err) => {
                PermanentError::SubnetWithNoNodes(subnet_id, err).into()
            }
        }
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

impl From<IDkgVerifyDealingPublicError> for PermanentError {
    fn from(err: IDkgVerifyDealingPublicError) -> Self {
        PermanentError::IDkgVerifyDealingPublicError(err)
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

pub type EcdsaValidationError = ValidationError<PermanentError, TransientError>;

#[allow(clippy::too_many_arguments)]
pub fn validate_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    parent_block: &Block,
    payload: &BlockPayload,
) -> ValidationResult<EcdsaValidationError> {
    if payload.is_summary() {
        validate_summary_payload(
            subnet_id,
            registry_client,
            pool_reader,
            context,
            parent_block,
            payload.as_summary().ecdsa.as_ref(),
        )
    } else {
        validate_data_payload(
            subnet_id,
            registry_client,
            crypto,
            pool_reader,
            state_manager,
            context,
            parent_block,
            payload.as_data().ecdsa.as_ref(),
        )
    }
}

/// Validates a threshold ECDSA summary payload.
/// This is an entirely deterministic operation, so we can just check if
/// the given summary payload matches what we would have created locally.
pub fn validate_summary_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    pool_reader: &PoolReader<'_>,
    context: &ValidationContext,
    parent_block: &Block,
    summary_payload: Option<&ecdsa::EcdsaPayload>,
) -> ValidationResult<EcdsaValidationError> {
    let height = parent_block.height().increment();
    if !ecdsa_feature_is_enabled(subnet_id, registry_client, pool_reader, height)
        .map_err(TransientError::from)?
    {
        if summary_payload.is_some() {
            return Err(PermanentError::EcdsaFeatureDisabled.into());
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
        ic_logger::replica_logger::no_op_logger(),
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
pub fn validate_data_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    parent_block: &Block,
    data_payload: Option<&ecdsa::EcdsaPayload>,
) -> ValidationResult<EcdsaValidationError> {
    let height = parent_block.height().increment();
    let ecdsa_enabled = ecdsa_feature_is_enabled(subnet_id, registry_client, pool_reader, height)
        .map_err(TransientError::from)?;
    if !ecdsa_enabled {
        if data_payload.is_some() {
            return Err(PermanentError::EcdsaFeatureDisabled.into());
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

    let transcripts = validate_transcript_refs(crypto, &block_reader, &prev_payload, curr_payload)?;
    let dealings = validate_reshare_dealings(crypto, &block_reader, &prev_payload, curr_payload)?;
    let signatures =
        validate_new_signature_agreements(crypto, &block_reader, &prev_payload, curr_payload)?;

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
        ic_logger::replica_logger::no_op_logger(),
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
    dealings: BTreeMap<IDkgTranscriptId, BTreeMap<NodeId, IDkgDealing>>,
    signatures: Vec<(ecdsa::RequestId, ThresholdEcdsaCombinedSignature)>,
}

impl EcdsaTranscriptBuilder for CachedBuilder {
    fn get_completed_transcript(&self, transcript_id: IDkgTranscriptId) -> Option<IDkgTranscript> {
        self.transcripts.get(&transcript_id).cloned()
    }

    fn get_validated_dealings(
        &self,
        transcript_id: IDkgTranscriptId,
    ) -> BTreeMap<NodeId, IDkgDealing> {
        self.dealings
            .get(&transcript_id)
            .cloned()
            .unwrap_or_default()
    }
}

impl EcdsaSignatureBuilder for CachedBuilder {
    fn get_completed_signatures(&self) -> Vec<(ecdsa::RequestId, ThresholdEcdsaCombinedSignature)> {
        self.signatures.clone()
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
) -> Result<BTreeMap<IDkgTranscriptId, IDkgTranscript>, EcdsaValidationError> {
    use PermanentError::*;
    let mut count = 0;
    let idkg_transcripts = &curr_payload.idkg_transcripts;
    let prev_configs = prev_payload
        .iter_transcript_configs_in_creation()
        .map(|config| (config.transcript_id, config))
        .collect::<BTreeMap<_, _>>();
    let prev_refs = prev_payload.active_transcripts();
    for transcript_ref in curr_payload.active_transcripts().iter() {
        if !prev_refs.contains(transcript_ref) && block_reader.transcript(transcript_ref).is_err() {
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
) -> Result<BTreeMap<IDkgTranscriptId, BTreeMap<NodeId, IDkgDealing>>, EcdsaValidationError> {
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
            if let Some(dealings) = new_reshare_agreement.get(request) {
                let transcript_id = config.as_ref().transcript_id;
                let param = config
                    .as_ref()
                    .translate(block_reader)
                    .map_err(PermanentError::from)?;
                let dealings = dealings.dealings();
                for (node_id, dealing) in dealings.iter() {
                    crypto
                        .verify_dealing_public(&param, *node_id, dealing)
                        .map_err(PermanentError::from)?;
                }
                new_dealings.insert(transcript_id, dealings);
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
    prev_payload: &ecdsa::EcdsaPayload,
    curr_payload: &ecdsa::EcdsaPayload,
) -> Result<Vec<(ecdsa::RequestId, ThresholdEcdsaCombinedSignature)>, EcdsaValidationError> {
    use PermanentError::*;
    let mut new_signatures = Vec::new();
    for (request_id, completed) in curr_payload.signature_agreements.iter() {
        if let ecdsa::CompletedSignature::Unreported(signature) = completed {
            if prev_payload.signature_agreements.get(request_id).is_some() {
                return Err(PermanentError::NewSignatureUnexpected(*request_id).into());
            }
            let input = prev_payload
                .ongoing_signatures
                .get(request_id)
                .ok_or(NewSignatureMissingInput(*request_id))?
                .translate(block_reader)
                .map_err(PermanentError::from)?;
            crypto
                .verify_combined_sig(&input, signature)
                .map_err(ThresholdEcdsaVerifyCombinedSignatureError)?;
            new_signatures.push((*request_id, signature.clone()));
        }
    }
    Ok(new_signatures)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ecdsa::{
        payload_builder::{
            get_signing_requests, initiate_reshare_requests, update_completed_reshare_requests,
            update_ongoing_signatures, update_signature_agreements,
        },
        utils::test_utils::*,
    };
    use ic_crypto_test_utils_canister_threshold_sigs::{
        generate_key_transcript, CanisterThresholdSigTestEnvironment,
    };
    use ic_logger::replica_logger::no_op_logger;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::*;
    use ic_test_utilities::{
        crypto::{mock_dealings, CryptoReturningOk},
        mock_time,
        types::{ids::subnet_test_id, messages::RequestBuilder},
    };
    use ic_types::{crypto::AlgorithmId, messages::CallbackId, Height};
    use std::collections::BTreeSet;
    use std::convert::TryFrom;

    #[test]
    fn test_validate_transcript_refs() {
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
        let registry_version = env.newest_registry_version;
        //let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
        let algorithm_id = AlgorithmId::ThresholdEcdsaSecp256k1;
        let crypto = &CryptoReturningOk::default();
        let mut block_reader = TestEcdsaBlockReader::new();
        let mut prev_payload = empty_ecdsa_payload(subnet_id);
        let mut curr_payload = prev_payload.clone();
        // Empty payload verifies
        assert!(
            validate_transcript_refs(crypto, &block_reader, &prev_payload, &curr_payload).is_ok()
        );

        // Add a transcript
        let transcript_0 = generate_key_transcript(&env, algorithm_id);
        let transcript_id_0 = transcript_0.transcript_id;
        let transcript_ref_0 =
            ecdsa::UnmaskedTranscript::try_from((Height::new(100), &transcript_0)).unwrap();
        curr_payload
            .idkg_transcripts
            .insert(transcript_id_0, transcript_0);
        // Error because transcript is not referenced
        assert!(matches!(
            validate_transcript_refs(crypto, &block_reader, &prev_payload, &curr_payload),
            Err(ValidationError::Permanent(
                PermanentError::NewTranscriptMiscount(_)
            ))
        ));

        // Add the reference
        prev_payload.key_transcript.next_in_creation =
            ecdsa::KeyTranscriptCreation::RandomTranscriptParams(
                ecdsa::RandomTranscriptParams::new(
                    transcript_id_0,
                    env.receivers().into_iter().collect(),
                    env.receivers().into_iter().collect(),
                    registry_version,
                    algorithm_id,
                ),
            );
        curr_payload.key_transcript.next_in_creation =
            ecdsa::KeyTranscriptCreation::Created(transcript_ref_0);
        let res = validate_transcript_refs(crypto, &block_reader, &prev_payload, &curr_payload);
        assert!(res.is_ok());

        // Add another reference
        let transcript_1 = generate_key_transcript(&env, algorithm_id);
        let transcript_ref_1 =
            ecdsa::UnmaskedTranscript::try_from((Height::new(100), &transcript_1)).unwrap();
        curr_payload.key_transcript.next_in_creation =
            ecdsa::KeyTranscriptCreation::Created(transcript_ref_1);
        assert!(matches!(
            validate_transcript_refs(crypto, &block_reader, &prev_payload, &curr_payload),
            Err(ValidationError::Permanent(
                PermanentError::NewTranscriptNotFound(_)
            ))
        ));

        curr_payload.idkg_transcripts = BTreeMap::new();
        block_reader.add_transcript(*transcript_ref_1.as_ref(), transcript_1);
        assert!(
            validate_transcript_refs(crypto, &block_reader, &prev_payload, &curr_payload).is_ok()
        );
    }

    #[test]
    fn test_validate_reshare_dealings() {
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let crypto = &CryptoReturningOk::default();
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
        let mut payload = empty_ecdsa_payload(subnet_id);
        let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
        let algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;
        let mut block_reader = TestEcdsaBlockReader::new();
        let transcript_builder = TestEcdsaTranscriptBuilder::new();

        let req_1 = create_reshare_request(1, 1);
        let req_2 = create_reshare_request(2, 2);
        let mut reshare_requests = BTreeSet::new();

        reshare_requests.insert(req_1.clone());
        reshare_requests.insert(req_2.clone());
        let key_transcript = generate_key_transcript(&env, algorithm);
        let key_transcript_ref =
            ecdsa::UnmaskedTranscript::try_from((Height::new(100), &key_transcript)).unwrap();
        block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript);
        initiate_reshare_requests(
            &mut payload,
            Some(&key_transcript_ref),
            &subnet_nodes,
            reshare_requests.clone(),
        );
        let prev_payload = payload.clone();

        // Create completed dealings for request 1.
        let reshare_params = payload.ongoing_xnet_reshares.get(&req_1).unwrap().as_ref();
        let dealings = mock_dealings(reshare_params.transcript_id, &reshare_params.dealers);
        transcript_builder.add_dealings(reshare_params.transcript_id, dealings);
        update_completed_reshare_requests(
            &mut payload,
            Some(&key_transcript_ref),
            &block_reader,
            &transcript_builder,
            &no_op_logger(),
        );
        assert_eq!(payload.xnet_reshare_agreements.len(), 1);
        assert!(matches!(
            payload.xnet_reshare_agreements.get(&req_1).unwrap(),
            ecdsa::CompletedReshareRequest::Unreported(_)
        ));

        // The payload should verify, and should return 1 dealing.
        let result = validate_reshare_dealings(crypto, &block_reader, &prev_payload, &payload);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);

        // Removing request 2 from payload should give error.
        let mut payload_ = payload.clone();
        payload_.ongoing_xnet_reshares.remove(&req_2);
        let result = validate_reshare_dealings(crypto, &block_reader, &prev_payload, &payload_);
        assert!(matches!(
            result,
            Err(ValidationError::Permanent(
                PermanentError::XNetReshareRequestDisappeared(_)
            ))
        ));

        // Create another request and dealings
        let reshare_params = payload.ongoing_xnet_reshares.get(&req_2).unwrap().as_ref();
        let dealings = mock_dealings(reshare_params.transcript_id, &reshare_params.dealers);
        transcript_builder.add_dealings(reshare_params.transcript_id, dealings);
        let mut prev_payload = payload.clone();
        update_completed_reshare_requests(
            &mut payload,
            Some(&key_transcript_ref),
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
        assert!(matches!(
            result,
            Err(ValidationError::Permanent(
                PermanentError::XNetReshareAgreementWithoutRequest(_)
            ))
        ));
    }

    #[test]
    fn test_validate_new_signature_agreements() {
        let num_nodes = 4;
        let subnet_id = subnet_test_id(0);
        let env = CanisterThresholdSigTestEnvironment::new(num_nodes);
        let crypto = &CryptoReturningOk::default();
        let mut block_reader = TestEcdsaBlockReader::new();
        let mut sign_with_ecdsa_contexts = BTreeMap::new();
        sign_with_ecdsa_contexts.insert(
            CallbackId::from(1),
            SignWithEcdsaContext {
                request: RequestBuilder::new().build(),
                pseudo_random_id: [1; 32],
                message_hash: vec![0; 32],
                derivation_path: vec![],
                batch_time: mock_time(),
            },
        );
        sign_with_ecdsa_contexts.insert(
            CallbackId::from(2),
            SignWithEcdsaContext {
                request: RequestBuilder::new().build(),
                pseudo_random_id: [2; 32],
                message_hash: vec![0; 32],
                derivation_path: vec![],
                batch_time: mock_time(),
            },
        );
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let key_transcript_ref =
            ecdsa::UnmaskedTranscript::try_from((Height::from(0), &key_transcript)).unwrap();
        let quadruple_id_1 = ecdsa_payload.uid_generator.next_quadruple_id();
        let quadruple_id_2 = ecdsa_payload.uid_generator.next_quadruple_id();
        // Fill in the ongoing signatures
        let sig_inputs_1 = create_sig_inputs_with_args(
            13,
            &env.receivers(),
            key_transcript.clone(),
            Height::from(44),
        );
        let sig_inputs_2 = create_sig_inputs_with_args(
            14,
            &env.receivers(),
            key_transcript.clone(),
            Height::from(44),
        );
        block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript);
        sig_inputs_1
            .idkg_transcripts
            .iter()
            .for_each(|(transcript_ref, transcript)| {
                block_reader.add_transcript(*transcript_ref, transcript.clone())
            });
        sig_inputs_2
            .idkg_transcripts
            .iter()
            .for_each(|(transcript_ref, transcript)| {
                block_reader.add_transcript(*transcript_ref, transcript.clone())
            });
        //block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript);
        ecdsa_payload.available_quadruples.insert(
            quadruple_id_1,
            sig_inputs_1.sig_inputs_ref.presig_quadruple_ref,
        );
        ecdsa_payload.available_quadruples.insert(
            quadruple_id_2,
            sig_inputs_2.sig_inputs_ref.presig_quadruple_ref,
        );

        let all_requests = get_signing_requests(&ecdsa_payload, &sign_with_ecdsa_contexts);

        update_ongoing_signatures(
            all_requests,
            Some(&key_transcript_ref),
            &mut ecdsa_payload,
            no_op_logger(),
        )
        .unwrap();

        let mut signature_builder = TestEcdsaSignatureBuilder::new();
        signature_builder.signatures.push((
            *ecdsa_payload.ongoing_signatures.keys().next().unwrap(),
            ThresholdEcdsaCombinedSignature {
                signature: vec![1; 32],
            },
        ));
        update_signature_agreements(
            &sign_with_ecdsa_contexts,
            &signature_builder,
            &mut ecdsa_payload,
            no_op_logger(),
        );

        let prev_payload = ecdsa_payload.clone();
        signature_builder.signatures.push((
            *ecdsa_payload.ongoing_signatures.keys().next().unwrap(),
            ThresholdEcdsaCombinedSignature {
                signature: vec![1; 32],
            },
        ));
        update_signature_agreements(
            &sign_with_ecdsa_contexts,
            &signature_builder,
            &mut ecdsa_payload,
            no_op_logger(),
        );

        let res =
            validate_new_signature_agreements(crypto, &block_reader, &prev_payload, &ecdsa_payload);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 1);

        // Repeated signature leads to error
        let res = validate_new_signature_agreements(
            crypto,
            &block_reader,
            &ecdsa_payload,
            &ecdsa_payload,
        );
        assert!(matches!(
            res,
            Err(ValidationError::Permanent(
                PermanentError::NewSignatureUnexpected(_)
            ))
        ));
    }
}
