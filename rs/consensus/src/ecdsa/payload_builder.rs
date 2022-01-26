//! This module implements the ECDSA payload builder and verifier.
#![allow(clippy::too_many_arguments)]
#![allow(clippy::enum_variant_names)]

use super::pre_signer::{EcdsaTranscriptBuilder, EcdsaTranscriptBuilderImpl};
use super::signer::{EcdsaSignatureBuilder, EcdsaSignatureBuilderImpl};
use crate::consensus::{
    crypto::ConsensusCrypto, metrics::EcdsaPayloadMetrics, pool_reader::PoolReader,
};
use ic_interfaces::{
    consensus_pool::ConsensusPoolCache,
    ecdsa::EcdsaPool,
    registry::RegistryClient,
    state_manager::{StateManager, StateManagerError},
};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_protobuf::registry::subnet::v1::EcdsaConfig;
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_replicated_state::{metadata_state::subnet_call_context_manager::*, ReplicatedState};
use ic_types::{
    batch::ValidationContext,
    consensus::{ecdsa, Block, HasHeight, SummaryPayload},
    crypto::{
        canister_threshold_sig::{
            error::{
                IDkgParamsValidationError, PresignatureQuadrupleCreationError,
                ThresholdEcdsaSigInputsCreationError,
            },
            idkg::{
                IDkgDealers, IDkgReceivers, IDkgTranscript, IDkgTranscriptId,
                IDkgTranscriptOperation, IDkgTranscriptParams,
            },
            ExtendedDerivationPath, PreSignatureQuadruple, ThresholdEcdsaSigInputs,
        },
        AlgorithmId,
    },
    registry::RegistryClientError,
    Height, NodeId, RegistryVersion, SubnetId,
};
use phantom_newtype::Id;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug)]
pub enum EcdsaPayloadError {
    RegistryClientError(RegistryClientError),
    StateManagerError(StateManagerError),
    PreSignatureError(PresignatureQuadrupleCreationError),
    IDkgParamsValidationError(IDkgParamsValidationError),
    DkgSummaryBlockNotFound(Height),
    SubnetWithNoNodes(RegistryVersion),
    EcdsaConfigNotFound(RegistryVersion),
    ThresholdEcdsaSigInputsCreationError(ThresholdEcdsaSigInputsCreationError),
    TranscriptCastError(ecdsa::TranscriptCastError),
}

impl From<RegistryClientError> for EcdsaPayloadError {
    fn from(err: RegistryClientError) -> Self {
        EcdsaPayloadError::RegistryClientError(err)
    }
}

impl From<StateManagerError> for EcdsaPayloadError {
    fn from(err: StateManagerError) -> Self {
        EcdsaPayloadError::StateManagerError(err)
    }
}

impl From<PresignatureQuadrupleCreationError> for EcdsaPayloadError {
    fn from(err: PresignatureQuadrupleCreationError) -> Self {
        EcdsaPayloadError::PreSignatureError(err)
    }
}

impl From<IDkgParamsValidationError> for EcdsaPayloadError {
    fn from(err: IDkgParamsValidationError) -> Self {
        EcdsaPayloadError::IDkgParamsValidationError(err)
    }
}

impl From<ThresholdEcdsaSigInputsCreationError> for EcdsaPayloadError {
    fn from(err: ThresholdEcdsaSigInputsCreationError) -> Self {
        EcdsaPayloadError::ThresholdEcdsaSigInputsCreationError(err)
    }
}

impl From<ecdsa::TranscriptCastError> for EcdsaPayloadError {
    fn from(err: ecdsa::TranscriptCastError) -> Self {
        EcdsaPayloadError::TranscriptCastError(err)
    }
}

/// Return true if ecdsa is enabled in subnet features in the subnet record.
fn ecdsa_feature_is_enabled(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    pool_reader: &PoolReader<'_>,
    height: Height,
) -> Result<bool, RegistryClientError> {
    if let Some(registry_version) = pool_reader.registry_version(height) {
        Ok(registry_client
            .get_features(subnet_id, registry_version)?
            .map(|features| features.ecdsa_signatures)
            == Some(true))
    } else {
        Ok(false)
    }
}

/// Creates a threshold ECDSA summary payload.
pub(crate) fn create_summary_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    _crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    _state_manager: &dyn StateManager<State = ReplicatedState>,
    _context: &ValidationContext,
    parent_block: &Block,
    _log: ReplicaLogger,
) -> Result<ecdsa::Summary, EcdsaPayloadError> {
    let height = parent_block.height().increment();
    if !ecdsa_feature_is_enabled(subnet_id, registry_client, pool_reader, height)? {
        return Ok(None);
    }
    match &parent_block.payload.as_ref().as_data().ecdsa {
        None => Ok(None),
        Some(payload) => {
            let key_transcript = match &payload.next_key_transcript_creation {
                Some(ecdsa::KeyTranscriptCreation::Created(transcript)) => transcript.clone(),
                _ => {
                    // TODO: A better approach is to try again, which will require handling
                    // of `next_unused_transcript_id` correctly.
                    panic!("ECDSA key transcript has not been created in the previous interval")
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
            let summary = summary_block.payload.as_ref().as_summary();
            let is_new_key_transcript = summary
                .ecdsa
                .as_ref()
                .map(|ecdsa_summary| ecdsa_summary.current_key_transcript.transcript_id())
                != Some(key_transcript.transcript_id());
            let summary = ecdsa::EcdsaSummaryPayload {
                current_key_transcript: key_transcript,
                ongoing_signatures: if is_new_key_transcript {
                    BTreeMap::new()
                } else {
                    payload.ongoing_signatures.clone()
                },
                available_quadruples: if is_new_key_transcript {
                    BTreeMap::new()
                } else {
                    payload.available_quadruples.clone()
                },
                next_unused_transcript_id: payload.next_unused_transcript_id,
            };
            Ok(Some(summary))
        }
    }
}

fn get_registry_version_and_subnet_nodes_from_summary(
    summary: &SummaryPayload,
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
) -> Result<(RegistryVersion, Vec<NodeId>), EcdsaPayloadError> {
    let summary_registry_version = summary.dkg.registry_version;
    // TODO: shuffle the nodes using random beacon?
    let subnet_nodes = registry_client
        .get_node_ids_on_subnet(subnet_id, summary_registry_version)?
        .ok_or(EcdsaPayloadError::SubnetWithNoNodes(
            summary_registry_version,
        ))?;
    Ok((summary_registry_version, subnet_nodes))
}

/// Creates a threshold ECDSA batch payload.
pub(crate) fn create_data_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    ecdsa_pool: Arc<RwLock<dyn EcdsaPool>>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    parent_block: &Block,
    ecdsa_payload_metrics: &EcdsaPayloadMetrics,
    log: ReplicaLogger,
) -> Result<ecdsa::Payload, EcdsaPayloadError> {
    let height = parent_block.height().increment();
    if !ecdsa_feature_is_enabled(subnet_id, registry_client, pool_reader, height)? {
        return Ok(None);
    }
    let block_payload = &parent_block.payload.as_ref();
    if block_payload.is_summary() {
        let summary = block_payload.as_summary();
        let (summary_registry_version, node_ids) =
            get_registry_version_and_subnet_nodes_from_summary(
                summary,
                registry_client,
                subnet_id,
            )?;
        let ecdsa_config = registry_client
            .get_ecdsa_config(subnet_id, summary_registry_version)?
            .ok_or(EcdsaPayloadError::EcdsaConfigNotFound(
                summary_registry_version,
            ))?;
        match &summary.ecdsa {
            None => {
                // bootstrap ECDSA payload
                let payload = ecdsa::EcdsaDataPayload {
                    signature_agreements: BTreeMap::new(),
                    ongoing_signatures: BTreeMap::new(),
                    available_quadruples: BTreeMap::new(),
                    quadruples_in_creation: BTreeMap::new(),
                    next_unused_transcript_id: IDkgTranscriptId::new(subnet_id, 0),
                    next_key_transcript_creation: None,
                };
                Ok(Some(payload))
            }
            Some(ecdsa_summary) => {
                let mut next_unused_transcript_id = ecdsa_summary.next_unused_transcript_id;
                let quadruples_in_creation = next_quadruples_in_creation(
                    &node_ids,
                    summary_registry_version,
                    ecdsa_summary,
                    ecdsa_config.as_ref(),
                    &mut next_unused_transcript_id,
                )?;
                // TODO: if membership is going to change in the next summary block, we need
                // to start producing a new next_key_transcript (by setting it to None here).
                let payload = ecdsa::EcdsaDataPayload {
                    signature_agreements: BTreeMap::new(),
                    ongoing_signatures: ecdsa_summary.ongoing_signatures.clone(),
                    available_quadruples: ecdsa_summary.available_quadruples.clone(),
                    quadruples_in_creation,
                    next_unused_transcript_id,
                    next_key_transcript_creation: Some(ecdsa::KeyTranscriptCreation::Created(
                        ecdsa_summary.current_key_transcript.clone(),
                    )),
                };
                Ok(Some(payload))
            }
        }
    } else {
        match &block_payload.as_data().ecdsa {
            None => Ok(None),
            Some(prev_payload) => {
                let summary_block =
                    pool_reader
                        .dkg_summary_block(parent_block)
                        .unwrap_or_else(|| {
                            panic!(
                                "Impossible: fail to the summary block that governs height {}",
                                parent_block.height()
                            )
                        });
                let summary = summary_block.payload.as_ref().as_summary();
                let (summary_registry_version, node_ids) =
                    get_registry_version_and_subnet_nodes_from_summary(
                        summary,
                        registry_client,
                        subnet_id,
                    )?;
                let current_key_transcript = summary
                    .ecdsa
                    .as_ref()
                    .map(|ecdsa_summary| &ecdsa_summary.current_key_transcript);
                let mut payload = prev_payload.clone();
                if let Some(key_transcript) = current_key_transcript {
                    update_signature_agreements(
                        pool_reader.as_cache(),
                        ecdsa_pool.clone(),
                        crypto,
                        &mut payload,
                        ecdsa_payload_metrics,
                        log.clone(),
                    );
                    let count = update_signing_requests(
                        state_manager,
                        context,
                        key_transcript,
                        &mut payload,
                        log.clone(),
                    )?;
                    // quadruples are consumed, need to produce more
                    let next_available_quadruple_id = payload
                        .available_quadruples
                        .keys()
                        .last()
                        .cloned()
                        .map(|x| x.increment())
                        .unwrap_or_default();
                    start_making_new_quadruples(
                        count,
                        &node_ids,
                        summary_registry_version,
                        &mut payload.next_unused_transcript_id,
                        &mut payload.quadruples_in_creation,
                        next_available_quadruple_id,
                    )?;
                }
                let mut completed_transcripts = BTreeMap::new();
                let transcript_builder = EcdsaTranscriptBuilderImpl::new(
                    pool_reader.as_cache(),
                    crypto,
                    ecdsa_payload_metrics,
                    log.clone(),
                );
                let ecdsa_pool = ecdsa_pool.read().unwrap();
                for transcript in transcript_builder
                    .get_completed_transcripts(ecdsa_pool.deref())
                    .into_iter()
                {
                    completed_transcripts.insert(transcript.transcript_id, transcript);
                }
                update_next_key_transcript(
                    &node_ids,
                    summary_registry_version,
                    current_key_transcript,
                    &mut payload,
                    &mut completed_transcripts,
                    &log,
                )?;
                if let Some(key_transcript) = current_key_transcript {
                    update_quadruples_in_creation(
                        key_transcript,
                        &mut payload,
                        &mut completed_transcripts,
                        log,
                    )?;
                };
                ecdsa_payload_metrics.payload_metrics_set(
                    "signature_agreements",
                    payload.signature_agreements.len() as i64,
                );
                ecdsa_payload_metrics.payload_metrics_set(
                    "available_quadruples",
                    payload.available_quadruples.len() as i64,
                );
                ecdsa_payload_metrics.payload_metrics_set(
                    "ongoing_signatures",
                    payload.ongoing_signatures.len() as i64,
                );
                ecdsa_payload_metrics.payload_metrics_set(
                    "quaruples_in_creation",
                    payload.quadruples_in_creation.len() as i64,
                );
                Ok(Some(payload))
            }
        }
    }
}

/// Create a new random transcript config and advance the
/// next_unused_transcript_id by one.
fn new_random_config(
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    next_unused_transcript_id: &mut IDkgTranscriptId,
) -> Result<ecdsa::RandomTranscriptParams, EcdsaPayloadError> {
    let transcript_id = *next_unused_transcript_id;
    *next_unused_transcript_id = transcript_id.increment();
    let dealers = IDkgDealers::new(subnet_nodes.iter().copied().collect::<BTreeSet<_>>())?;
    let receivers = IDkgReceivers::new(subnet_nodes.iter().copied().collect::<BTreeSet<_>>())?;
    Ok(ecdsa::RandomTranscriptParams::new(
        transcript_id,
        dealers,
        receivers,
        summary_registry_version,
        AlgorithmId::ThresholdEcdsaSecp256k1,
        IDkgTranscriptOperation::Random,
    )?)
}

/// Initialize the next set of quadruples with random configs from the summary
/// block, and return it together with the next transcript id.
fn next_quadruples_in_creation(
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    summary: &ecdsa::EcdsaSummaryPayload,
    ecdsa_config: Option<&EcdsaConfig>,
    next_unused_transcript_id: &mut IDkgTranscriptId,
) -> Result<BTreeMap<ecdsa::QuadrupleId, ecdsa::QuadrupleInCreation>, EcdsaPayloadError> {
    let next_available_quadruple_id = summary
        .available_quadruples
        .keys()
        .last()
        .cloned()
        .map(|x| x.increment())
        .unwrap_or_default();
    let mut quadruples = BTreeMap::new();
    let num_quadruples = summary.available_quadruples.len();
    let mut to_create = ecdsa_config
        .map(|config| config.quadruples_to_create_in_advance as usize)
        .unwrap_or_default();
    if to_create > num_quadruples {
        to_create -= num_quadruples;
    } else {
        to_create = 0;
    }
    start_making_new_quadruples(
        to_create,
        subnet_nodes,
        summary_registry_version,
        next_unused_transcript_id,
        &mut quadruples,
        next_available_quadruple_id,
    )?;
    Ok(quadruples)
}

/// Start making the given number of new quadruples by adding them to
/// quadruples_in_creation.
fn start_making_new_quadruples(
    num_quadruples_to_create: usize,
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    next_unused_transcript_id: &mut IDkgTranscriptId,
    quadruples_in_creation: &mut BTreeMap<ecdsa::QuadrupleId, ecdsa::QuadrupleInCreation>,
    mut quadruple_id: ecdsa::QuadrupleId,
) -> Result<(), EcdsaPayloadError> {
    // make sure quadruple_id is fresh
    quadruple_id = quadruple_id.max(
        quadruples_in_creation
            .keys()
            .last()
            .cloned()
            .map(|x| x.increment())
            .unwrap_or_default(),
    );
    for _ in 0..num_quadruples_to_create {
        let kappa_config = new_random_config(
            subnet_nodes,
            summary_registry_version,
            next_unused_transcript_id,
        )?;
        let lambda_config = new_random_config(
            subnet_nodes,
            summary_registry_version,
            next_unused_transcript_id,
        )?;
        quadruples_in_creation.insert(
            quadruple_id,
            ecdsa::QuadrupleInCreation::new(kappa_config, lambda_config),
        );
        quadruple_id = quadruple_id.increment();
    }
    Ok(())
}

// Update signature agreements in the data payload by combining
// shares in the ECDSA pool.
// TODO: As an optimization we could also use the signatures we
// are looking for to avoid traversing everything in the pool.
fn update_signature_agreements(
    consensus_cache: &dyn ConsensusPoolCache,
    ecdsa_pool: Arc<RwLock<dyn EcdsaPool>>,
    crypto: &dyn ConsensusCrypto,
    payload: &mut ecdsa::EcdsaDataPayload,
    metrics: &EcdsaPayloadMetrics,
    log: ReplicaLogger,
) {
    let ecdsa_pool = ecdsa_pool.read().unwrap();
    let builder = EcdsaSignatureBuilderImpl::new(consensus_cache, crypto, metrics, log.clone());
    for (request_id, signature) in builder.get_completed_signatures(ecdsa_pool.deref()) {
        if payload.ongoing_signatures.remove(&request_id).is_none() {
            warn!(
                log,
                "ECDSA signing request {:?} is not found in payload but we have a signature for it",
                request_id
            );
        } else {
            payload.signature_agreements.insert(request_id, signature);
        }
    }
}

/// Update data fields related to signing requests in the ECDSA payload:
///
/// - Check if new signatures have been produced, and add them to
/// signature agreements.
/// - Check if there are new signing requests, and start to work on them.
///
/// Return the number of new signing requests that are worked on (or
/// equivalently, the number of quadruples that are consumed).
// Return new signing requests initiated from canisters.
fn update_signing_requests(
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    key_transcript: &ecdsa::UnmaskedTranscript,
    payload: &mut ecdsa::EcdsaDataPayload,
    log: ReplicaLogger,
) -> Result<usize, EcdsaPayloadError> {
    // Get the set of new signing requests that we have not signed, and are
    // not already working on.
    let existing_requests: BTreeSet<&ecdsa::RequestId> = payload
        .signature_agreements
        .keys()
        .chain(payload.ongoing_signatures.keys())
        .collect::<BTreeSet<_>>();
    let new_requests = get_new_signing_requests(
        state_manager,
        &existing_requests,
        &mut payload.available_quadruples,
        key_transcript,
        context.certified_height,
    )?;
    debug!(
        log,
        "update_signing_requests: existing_requests={} new_requests={}",
        existing_requests.len(),
        new_requests.len()
    );
    let mut count = 0;
    for (request_id, sign_inputs) in new_requests {
        payload.ongoing_signatures.insert(request_id, sign_inputs);
        count += 1;
    }
    Ok(count)
}

// Return new signing requests initiated from canisters.
fn get_new_signing_requests(
    state_manager: &dyn StateManager<State = ReplicatedState>,
    existing_requests: &BTreeSet<&ecdsa::RequestId>,
    available_quadruples: &mut BTreeMap<ecdsa::QuadrupleId, PreSignatureQuadruple>,
    key_transcript: &ecdsa::UnmaskedTranscript,
    height: Height,
) -> Result<Vec<(ecdsa::RequestId, ThresholdEcdsaSigInputs)>, EcdsaPayloadError> {
    let state = state_manager.get_state_at(height)?;
    let contexts = &state
        .get_ref()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts;
    let new_requests = contexts
        .iter()
        .filter_map(|(_callback_id, context)| {
            let SignWithEcdsaContext {
                pseudo_random_id, ..
            } = context;
            // request_id is just pseudo_random_id which is guaranteed to be always unique.
            let request_id = ecdsa::RequestId::from(pseudo_random_id.to_vec());
            if !existing_requests.contains(&request_id) {
                Some((request_id, context))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let mut ret = Vec::new();
    let mut consumed_quadruples = Vec::new();
    for ((request_id, context), (quadruple_id, quadruple)) in
        new_requests.iter().zip(available_quadruples.iter())
    {
        let sign_inputs = build_signature_inputs(context, quadruple, key_transcript)?;
        ret.push((request_id.clone(), sign_inputs));
        consumed_quadruples.push(*quadruple_id);
    }

    for quadruple_id in consumed_quadruples {
        available_quadruples.remove(&quadruple_id);
    }
    Ok(ret)
}

/// Update configuration and data about the next ECDSA key transcript.
fn update_next_key_transcript(
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    current_key_transcript: Option<&ecdsa::UnmaskedTranscript>,
    payload: &mut ecdsa::EcdsaDataPayload,
    completed_transcripts: &mut BTreeMap<IDkgTranscriptId, IDkgTranscript>,
    _log: &ReplicaLogger,
) -> Result<(), EcdsaPayloadError> {
    match (
        current_key_transcript,
        &payload.next_key_transcript_creation,
    ) {
        (Some(transcript), None) => {
            // We have an existing key transcript, need to reshare it to create next
            // Create a new reshare config when there is none
            let transcript_id = payload.next_unused_transcript_id;
            payload.next_unused_transcript_id = transcript_id.increment();
            let dealers = IDkgDealers::new(subnet_nodes.iter().copied().collect::<BTreeSet<_>>())?;
            let receivers =
                IDkgReceivers::new(subnet_nodes.iter().copied().collect::<BTreeSet<_>>())?;
            payload.next_key_transcript_creation =
                Some(ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(
                    ecdsa::ReshareOfUnmaskedParams::new(
                        transcript_id,
                        dealers,
                        receivers,
                        summary_registry_version,
                        AlgorithmId::ThresholdEcdsaSecp256k1,
                        IDkgTranscriptOperation::ReshareOfUnmasked(transcript.clone().into()),
                    )?,
                ));
        }
        (Some(_), Some(ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(config))) => {
            // check if the next key transcript has been made
            if let Some(transcript) = completed_transcripts.get(&config.transcript_id()) {
                let unmasked_transcript = ecdsa::Unmasked::try_from(transcript.clone())?;
                payload.next_key_transcript_creation =
                    Some(ecdsa::KeyTranscriptCreation::Created(unmasked_transcript));
            }
        }
        (None, None) => {
            // The first ECDSA key transcript has to be created, starting from a random
            // config.
            let transcript_id = payload.next_unused_transcript_id;
            payload.next_unused_transcript_id = transcript_id.increment();
            let dealers = IDkgDealers::new(subnet_nodes.iter().copied().collect::<BTreeSet<_>>())?;
            let receivers =
                IDkgReceivers::new(subnet_nodes.iter().copied().collect::<BTreeSet<_>>())?;
            payload.next_key_transcript_creation =
                Some(ecdsa::KeyTranscriptCreation::RandomTranscriptParams(
                    ecdsa::RandomTranscriptParams::new(
                        transcript_id,
                        dealers,
                        receivers,
                        summary_registry_version,
                        AlgorithmId::ThresholdEcdsaSecp256k1,
                        IDkgTranscriptOperation::Random,
                    )?,
                ));
        }
        (None, Some(ecdsa::KeyTranscriptCreation::RandomTranscriptParams(config))) => {
            // Check if the random transcript has been created
            if let Some(transcript) = completed_transcripts.get(&config.transcript_id()) {
                let random_transcript = ecdsa::Masked::try_from(transcript.clone())?;
                let transcript_id = payload.next_unused_transcript_id;
                payload.next_unused_transcript_id = transcript_id.increment();
                let dealers =
                    IDkgDealers::new(subnet_nodes.iter().copied().collect::<BTreeSet<_>>())?;
                let receivers =
                    IDkgReceivers::new(subnet_nodes.iter().copied().collect::<BTreeSet<_>>())?;
                payload.next_key_transcript_creation =
                    Some(ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(
                        ecdsa::ReshareOfMaskedParams::new(
                            transcript_id,
                            dealers,
                            receivers,
                            summary_registry_version,
                            AlgorithmId::ThresholdEcdsaSecp256k1,
                            IDkgTranscriptOperation::ReshareOfMasked(random_transcript.into()),
                        )?,
                    ));
            }
        }
        (None, Some(ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(config))) => {
            // Check if the unmasked transcript has been created
            if let Some(transcript) = completed_transcripts.get(&config.transcript_id()) {
                let unmasked_transcript = ecdsa::Unmasked::try_from(transcript.clone())?;
                payload.next_key_transcript_creation =
                    Some(ecdsa::KeyTranscriptCreation::Created(unmasked_transcript));
            }
        }
        (None, Some(ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(_))) => {
            unreachable!("Unexpected ReshareOfUnmaskedParams for key transcript creation");
        }
        (_, Some(ecdsa::KeyTranscriptCreation::Created(_))) => {
            // valid case that we can ignored
        }
        _ => {
            unreachable!("Unexpected next_key_transcript configuration reached!");
        }
    }
    Ok(())
}

/// Update the quadruples in the payload by:
/// - making new configs when pre-conditions are met;
/// - gathering ready results (new transcripts) from ecdsa pool;
/// - moving completed quadruples from "in creation" to "available".
fn update_quadruples_in_creation(
    key_transcript: &ecdsa::UnmaskedTranscript,
    payload: &mut ecdsa::EcdsaDataPayload,
    completed_transcripts: &mut BTreeMap<IDkgTranscriptId, IDkgTranscript>,
    log: ReplicaLogger,
) -> Result<(), EcdsaPayloadError> {
    debug!(
        log,
        "update_quadruples_in_creation: completed transcript = {:?}",
        completed_transcripts.keys()
    );
    let mut newly_available = Vec::new();
    for (key, quadruple) in payload.quadruples_in_creation.iter_mut() {
        // Update quadruple with completed transcripts
        if quadruple.kappa_masked.is_none() {
            if let Some(transcript) =
                completed_transcripts.remove(&quadruple.kappa_config.transcript_id())
            {
                debug!(
                    log,
                    "update_quadruples_in_creation: {:?} kappa_masked transcript is made", key
                );
                quadruple.kappa_masked = Some(ecdsa::Masked::try_from(transcript)?);
            }
        }
        if quadruple.lambda_masked.is_none() {
            if let Some(transcript) =
                completed_transcripts.remove(&quadruple.lambda_config.transcript_id())
            {
                debug!(
                    log,
                    "update_quadruples_in_creation: {:?} lamdba_masked transcript is made", key
                );
                quadruple.lambda_masked = Some(ecdsa::Masked::try_from(transcript)?);
            }
        }
        if quadruple.kappa_unmasked.is_none() {
            if let Some(config) = &quadruple.unmask_kappa_config {
                if let Some(transcript) = completed_transcripts.remove(&config.transcript_id()) {
                    debug!(
                        log,
                        "update_quadruples_in_creation: {:?} kappa_unmasked transcript {:?} is made",
                        key,
                        transcript.get_type()
                    );
                    quadruple.kappa_unmasked = Some(ecdsa::Unmasked::try_from(transcript)?);
                }
            }
        }
        if quadruple.key_times_lambda.is_none() {
            if let Some(config) = &quadruple.key_times_lambda_config {
                if let Some(transcript) = completed_transcripts.remove(&config.transcript_id()) {
                    debug!(
                        log,
                        "update_quadruples_in_creation: {:?} key_times_lambda transcript is made",
                        key
                    );
                    quadruple.key_times_lambda = Some(ecdsa::Masked::try_from(transcript)?);
                }
            }
        }
        if quadruple.kappa_times_lambda.is_none() {
            if let Some(config) = &quadruple.kappa_times_lambda_config {
                if let Some(transcript) = completed_transcripts.remove(&config.transcript_id()) {
                    debug!(
                        log,
                        "update_quadruples_in_creation: {:?} kappa_times_lambda transcript is made",
                        key
                    );
                    quadruple.kappa_times_lambda = Some(ecdsa::Masked::try_from(transcript)?);
                }
            }
        }
        // Check what to do in the next step
        if let (Some(kappa_masked), None) =
            (&quadruple.kappa_masked, &quadruple.unmask_kappa_config)
        {
            quadruple.unmask_kappa_config = Some(IDkgTranscriptParams::new(
                payload.next_unused_transcript_id,
                quadruple.kappa_config.dealers().clone(),
                quadruple.kappa_config.receivers().clone(),
                quadruple.kappa_config.registry_version(),
                quadruple.kappa_config.algorithm_id(),
                IDkgTranscriptOperation::ReshareOfMasked(kappa_masked.clone().into()),
            )?);
            payload.next_unused_transcript_id = payload.next_unused_transcript_id.increment();
        }
        if let (Some(lambda_masked), None) =
            (&quadruple.lambda_masked, &quadruple.key_times_lambda_config)
        {
            quadruple.key_times_lambda_config = Some(IDkgTranscriptParams::new(
                payload.next_unused_transcript_id,
                quadruple.lambda_config.dealers().clone(),
                quadruple.lambda_config.receivers().clone(),
                quadruple.lambda_config.registry_version(),
                quadruple.lambda_config.algorithm_id(),
                IDkgTranscriptOperation::UnmaskedTimesMasked(
                    key_transcript.clone().into(),
                    lambda_masked.clone().into(),
                ),
            )?);
            payload.next_unused_transcript_id = payload.next_unused_transcript_id.increment();
        }
        if let (Some(lambda_masked), Some(kappa_unmasked), None) = (
            &quadruple.lambda_masked,
            &quadruple.kappa_unmasked,
            &quadruple.kappa_times_lambda_config,
        ) {
            quadruple.kappa_times_lambda_config = Some(IDkgTranscriptParams::new(
                payload.next_unused_transcript_id,
                quadruple.lambda_config.dealers().clone(),
                quadruple.lambda_config.receivers().clone(),
                quadruple.lambda_config.registry_version(),
                quadruple.lambda_config.algorithm_id(),
                IDkgTranscriptOperation::UnmaskedTimesMasked(
                    kappa_unmasked.clone().into(),
                    lambda_masked.clone().into(),
                ),
            )?);
            payload.next_unused_transcript_id = payload.next_unused_transcript_id.increment();
        }
        if let (
            Some(_kappa_unmasked),
            Some(_lambda_masked),
            Some(_key_times_lambda),
            Some(_kappa_times_lambda),
        ) = (
            &quadruple.kappa_unmasked,
            &quadruple.lambda_masked,
            &quadruple.key_times_lambda,
            &quadruple.kappa_times_lambda,
        ) {
            newly_available.push(*key);
        }
    }
    for key in newly_available.into_iter() {
        // the following unwraps are safe
        let quadruple = payload.quadruples_in_creation.remove(&key).unwrap();
        let lambda_masked = quadruple.lambda_masked.unwrap();
        let kappa_unmasked = quadruple.kappa_unmasked.unwrap();
        let key_times_lambda = quadruple.key_times_lambda.unwrap();
        let kappa_times_lambda = quadruple.kappa_times_lambda.unwrap();
        debug!(
            log,
            "update_quadruples_in_creation: making of quadruple {:?} is complete", key
        );
        payload.available_quadruples.insert(
            key,
            PreSignatureQuadruple::new(
                kappa_unmasked.into(),
                lambda_masked.into(),
                kappa_times_lambda.into(),
                key_times_lambda.into(),
            )?,
        );
    }
    Ok(())
}

/// Validates a threshold ECDSA summary payload.
pub fn validate_summary_payload(
    _payload: ecdsa::EcdsaSummaryPayload,
) -> Result<(), EcdsaPayloadError> {
    todo!()
}

/// Validates a threshold ECDSA data payload.
pub fn validate_data_payload(_payload: ecdsa::EcdsaDataPayload) -> Result<(), EcdsaPayloadError> {
    todo!()
}

/// Helper to build threshold signature inputs from the context and
/// the pre-signature quadruple
fn build_signature_inputs(
    context: &SignWithEcdsaContext,
    quadruple: &PreSignatureQuadruple,
    key_transcript: &ecdsa::UnmaskedTranscript,
) -> Result<ThresholdEcdsaSigInputs, ThresholdEcdsaSigInputsCreationError> {
    // TODO: decide the appropriate conversion
    fn from_le_bytes(arr: &[u8]) -> Vec<u32> {
        let len = arr.len() / 4;
        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            let mut dst = [0, 0, 0, 0];
            dst.copy_from_slice(&arr[(i * 4)..(i * 4 + 4)]);
            result.push(u32::from_le_bytes(dst));
        }
        result
    }
    let extended_derivation_path = ExtendedDerivationPath {
        caller: context.request.sender.into(),
        bip32_derivation_path: from_le_bytes(&context.derivation_path),
    };
    ThresholdEcdsaSigInputs::new(
        &extended_derivation_path,
        &context.message_hash,
        Id::from(context.pseudo_random_id),
        quadruple.clone(),
        key_transcript.clone().into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        generate_key_transcript, generate_presig_quadruple, run_idkg_and_create_transcript,
        CanisterThresholdSigTestEnvironment,
    };
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::{
        mock_time,
        state::ReplicatedStateBuilder,
        state_manager::MockStateManager,
        types::{
            ids::{node_test_id, subnet_test_id},
            messages::RequestBuilder,
        },
    };
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
    use ic_types::{messages::CallbackId, Height, RegistryVersion};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    fn empty_ecdsa_summary_payload(subnet_id: SubnetId) -> ecdsa::EcdsaSummaryPayload {
        let env = CanisterThresholdSigTestEnvironment::new(4);
        let algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;
        let key_transcript = generate_key_transcript(&env, algorithm);
        ecdsa::EcdsaSummaryPayload {
            ongoing_signatures: BTreeMap::new(),
            current_key_transcript: ecdsa::Unmasked::try_from(key_transcript).unwrap(),
            available_quadruples: BTreeMap::new(),
            next_unused_transcript_id: IDkgTranscriptId::new(subnet_id, 0),
        }
    }

    fn empty_ecdsa_data_payload(subnet_id: SubnetId) -> ecdsa::EcdsaDataPayload {
        ecdsa::EcdsaDataPayload {
            signature_agreements: BTreeMap::new(),
            ongoing_signatures: BTreeMap::new(),
            available_quadruples: BTreeMap::new(),
            quadruples_in_creation: BTreeMap::new(),
            next_unused_transcript_id: IDkgTranscriptId::new(subnet_id, 0),
            next_key_transcript_creation: None,
        }
    }

    #[test]
    fn test_next_quadruples_in_creation() {
        let subnet_id = subnet_test_id(1);
        let subnet_nodes = (0..10).map(node_test_id).collect::<Vec<_>>();
        let summary_registry_version = RegistryVersion::new(10);
        let summary = empty_ecdsa_summary_payload(subnet_id);
        let quadruples_to_create_in_advance = 5;
        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance,
        };
        let mut next_unused_transcript_id = IDkgTranscriptId::new(subnet_id, 10);
        // Success case
        let result = next_quadruples_in_creation(
            &subnet_nodes,
            summary_registry_version,
            &summary,
            Some(&ecdsa_config),
            &mut next_unused_transcript_id,
        );
        assert!(result.is_ok());
        let quadruples = result.unwrap();
        assert_eq!(quadruples.len(), quadruples_to_create_in_advance as usize);
        // Check transcript ids are unique
        let mut transcript_ids = BTreeSet::new();
        for quadruple in quadruples.iter() {
            transcript_ids.insert(quadruple.1.kappa_config.transcript_id());
            transcript_ids.insert(quadruple.1.lambda_config.transcript_id());
        }
        assert_eq!(
            transcript_ids.len(),
            2 * quadruples_to_create_in_advance as usize
        );
        assert_eq!(
            transcript_ids.iter().max().unwrap().increment(),
            next_unused_transcript_id
        );
        // Failure case
        let result = next_quadruples_in_creation(
            &[],
            summary_registry_version,
            &summary,
            Some(&ecdsa_config),
            &mut next_unused_transcript_id,
        );
        assert_matches!(
            result,
            Err(EcdsaPayloadError::IDkgParamsValidationError(
                IDkgParamsValidationError::DealersEmpty
            ))
        );
    }

    #[test]
    fn test_get_new_signing_requests() {
        let pseudo_random_id = [0; 32];
        let mut state = ReplicatedStateBuilder::default().build();
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .insert(
                CallbackId::from(1),
                SignWithEcdsaContext {
                    request: RequestBuilder::new().build(),
                    pseudo_random_id,
                    message_hash: vec![],
                    derivation_path: vec![],
                    batch_time: mock_time(),
                },
            );
        let state = Arc::new(state);
        let mut state_manager = MockStateManager::new();
        let height = Height::new(10);
        state_manager.expect_get_state_at().returning(move |h| {
            if h == height {
                Ok(ic_interfaces::state_manager::Labeled::new(h, state.clone()))
            } else {
                Err(StateManagerError::StateNotCommittedYet(h))
            }
        });
        // Success case
        let mut requests = BTreeSet::new();
        let env = CanisterThresholdSigTestEnvironment::new(4);
        let algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;
        let key_transcript = generate_key_transcript(&env, algorithm);
        let quadruple = generate_presig_quadruple(&env, algorithm, &key_transcript);
        let ecdsa_transcript = ecdsa::Unmasked::try_from(key_transcript).unwrap();
        let mut available_quadruples = BTreeMap::new();
        available_quadruples.insert(ecdsa::QuadrupleId(0), quadruple);
        let result = get_new_signing_requests(
            &state_manager,
            &requests,
            &mut available_quadruples,
            &ecdsa_transcript,
            height,
        );
        assert!(result.is_ok());
        let new_requests = result.unwrap();
        assert_eq!(new_requests.len(), 1);
        // Duplicate is ignored
        let request_id = ecdsa::RequestId::from(pseudo_random_id.to_vec());
        requests.insert(&request_id);
        let result = get_new_signing_requests(
            &state_manager,
            &requests,
            &mut available_quadruples,
            &ecdsa_transcript,
            height,
        );
        assert!(result.is_ok());
        let new_requests = result.unwrap();
        assert_eq!(new_requests.len(), 0);
        // Failure case
        let result = get_new_signing_requests(
            &state_manager,
            &requests,
            &mut available_quadruples,
            &ecdsa_transcript,
            height.increment(),
        );
        assert_matches!(
            result,
            Err(EcdsaPayloadError::StateManagerError(
                StateManagerError::StateNotCommittedYet(_)
            ))
        );
    }

    #[test]
    fn test_update_quadruples_in_creation() {
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
        let registry_version = env.newest_registry_version;
        let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
        let algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;
        let key_transcript =
            ecdsa::Unmasked::try_from(generate_key_transcript(&env, algorithm)).unwrap();
        let mut payload = empty_ecdsa_data_payload(subnet_id);
        let mut completed = BTreeMap::new();
        // Start quadruple creation
        let kappa_config_id = payload.next_unused_transcript_id;
        let kappa_config = new_random_config(
            &subnet_nodes,
            registry_version,
            &mut payload.next_unused_transcript_id,
        )
        .unwrap();
        let lambda_config_id = payload.next_unused_transcript_id;
        let lambda_config = new_random_config(
            &subnet_nodes,
            registry_version,
            &mut payload.next_unused_transcript_id,
        )
        .unwrap();
        let quadruple_id = ecdsa::QuadrupleId(0);
        payload.quadruples_in_creation.insert(
            quadruple_id,
            ecdsa::QuadrupleInCreation::new(kappa_config.clone(), lambda_config.clone()),
        );
        // 1. No action case
        let result = update_quadruples_in_creation(
            &key_transcript,
            &mut payload,
            &mut completed,
            no_op_logger(),
        );
        assert!(result.is_ok());
        let config_ids = |payload: &ecdsa::EcdsaDataPayload| {
            let mut arr = payload
                .iter_transcript_configs_in_creation()
                .map(|x| x.transcript_id().id())
                .collect::<Vec<_>>();
            arr.sort_unstable();
            arr
        };

        // check if nothing has changed
        assert!(payload.available_quadruples.is_empty());
        assert_eq!(payload.next_unused_transcript_id.id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 2);
        assert_eq!(config_ids(&payload), [0, 1]);

        // 1. When kappa_masked is ready, expect a new kappa_unmasked config.
        let kappa_transcript = {
            let param = kappa_config; //env.params_for_random_sharing(algorithm);
            run_idkg_and_create_transcript(&param, &env.crypto_components)
        };
        completed.insert(kappa_config_id, kappa_transcript);
        let result = update_quadruples_in_creation(
            &key_transcript,
            &mut payload,
            &mut completed,
            no_op_logger(),
        );
        assert!(result.is_ok());
        // check if new config is made
        assert!(payload.available_quadruples.is_empty());
        let kappa_unmasked_config_id = IDkgTranscriptId::new(subnet_id, 2);
        assert_eq!(payload.next_unused_transcript_id.id(), 3);
        assert_eq!(config_ids(&payload), [1, 2]);

        // 2. When lambda_masked is ready, expect a new key_times_lambda config.
        let lambda_transcript = {
            let param = lambda_config; //env.params_for_random_sharing(algorithm);
            run_idkg_and_create_transcript(&param, &env.crypto_components)
        };
        completed.insert(lambda_config_id, lambda_transcript);
        let result = update_quadruples_in_creation(
            &key_transcript,
            &mut payload,
            &mut completed,
            no_op_logger(),
        );
        assert!(result.is_ok());
        // check if new config is made
        assert!(payload.available_quadruples.is_empty());
        assert_eq!(payload.next_unused_transcript_id.id(), 4);
        let key_times_lambda_config_id = IDkgTranscriptId::new(subnet_id, 3);
        assert_eq!(config_ids(&payload), [2, 3]);

        // 3. When kappa_unmasked and lambda_masked is ready, expect kappa_times_lambda
        // config.
        let kappa_unmasked_transcript = {
            let param = payload
                .iter_transcript_configs_in_creation()
                .find(|x| x.transcript_id() == kappa_unmasked_config_id)
                .unwrap()
                .clone();
            run_idkg_and_create_transcript(&param, &env.crypto_components)
        };
        completed.insert(kappa_unmasked_config_id, kappa_unmasked_transcript);
        let result = update_quadruples_in_creation(
            &key_transcript,
            &mut payload,
            &mut completed,
            no_op_logger(),
        );
        assert!(result.is_ok());
        // check if new config is made
        assert!(payload.available_quadruples.is_empty());
        assert_eq!(payload.next_unused_transcript_id.id(), 5);
        let kappa_times_lambda_config_id = IDkgTranscriptId::new(subnet_id, 4);
        assert_eq!(config_ids(&payload), [3, 4]);

        // 4. When both kappa_times_lambda and key_times_lambda are ready, quadruple is
        // complete.
        let kappa_times_lambda_transcript = {
            let param = payload
                .iter_transcript_configs_in_creation()
                .find(|x| x.transcript_id() == kappa_times_lambda_config_id)
                .unwrap()
                .clone();
            run_idkg_and_create_transcript(&param, &env.crypto_components)
        };
        completed.insert(kappa_times_lambda_config_id, kappa_times_lambda_transcript);
        let key_times_lambda_transcript = {
            let param = payload
                .iter_transcript_configs_in_creation()
                .find(|x| x.transcript_id() == key_times_lambda_config_id)
                .unwrap()
                .clone();
            run_idkg_and_create_transcript(&param, &env.crypto_components)
        };
        completed.insert(key_times_lambda_config_id, key_times_lambda_transcript);
        let result = update_quadruples_in_creation(
            &key_transcript,
            &mut payload,
            &mut completed,
            no_op_logger(),
        );
        assert!(result.is_ok());
        // check if new config is made
        assert_eq!(payload.available_quadruples.len(), 1);
        assert_eq!(payload.next_unused_transcript_id.id(), 5);
        assert!(config_ids(&payload).is_empty());
    }
}
