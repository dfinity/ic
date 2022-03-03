//! This module implements the ECDSA payload builder and verifier.
#![allow(clippy::too_many_arguments)]
#![allow(clippy::enum_variant_names)]

use super::pre_signer::{EcdsaTranscriptBuilder, EcdsaTranscriptBuilderImpl};
use super::signer::{EcdsaSignatureBuilder, EcdsaSignatureBuilderImpl};
use super::utils::EcdsaBlockReaderImpl;
use crate::consensus::{
    crypto::ConsensusCrypto, metrics::EcdsaPayloadMetrics, pool_reader::PoolReader,
};
use ic_artifact_pool::consensus_pool::build_consensus_block_chain;
use ic_interfaces::{
    consensus_pool::ConsensusBlockChain,
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
    consensus::{ecdsa, ecdsa::EcdsaBlockReader, Block, HasHeight, SummaryPayload},
    crypto::{
        canister_threshold_sig::{
            error::{
                IDkgParamsValidationError, PresignatureQuadrupleCreationError,
                ThresholdEcdsaSigInputsCreationError,
            },
            idkg::{IDkgTranscript, IDkgTranscriptId},
            ExtendedDerivationPath,
        },
        AlgorithmId,
    },
    messages::CallbackId,
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
                Some(ecdsa::KeyTranscriptCreation::Created(transcript)) => *transcript,
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
            let is_new_key_transcript =
                summary.ecdsa.as_ref().map(|ecdsa_summary| {
                    ecdsa_summary.current_key_transcript.as_ref().transcript_id
                }) != Some(key_transcript.as_ref().transcript_id);
            let mut summary = ecdsa::EcdsaSummaryPayload {
                current_key_transcript: key_transcript,
                signature_agreements: payload.signature_agreements.clone(),
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
                idkg_transcripts: BTreeMap::new(),
            };
            update_summary_refs(&mut summary, pool_reader, parent_block);
            Ok(Some(summary))
        }
    }
}

fn update_summary_refs(
    summary: &mut ecdsa::EcdsaSummaryPayload,
    pool_reader: &PoolReader<'_>,
    parent_block: &Block,
) {
    // Gather the refs and update them to point to the new
    // summary block height.
    let height = Some(parent_block.height().increment());
    let mut prev_refs = Vec::new();
    for quadruple in summary.available_quadruples.values_mut() {
        prev_refs.append(&mut quadruple.get_refs_and_update(height));
    }
    for signature in summary.ongoing_signatures.values_mut() {
        prev_refs.append(&mut signature.get_refs_and_update(height));
    }
    prev_refs.push(
        summary
            .current_key_transcript
            .as_mut()
            .get_and_update(height),
    );

    // Resolve the transcript refs pointing into the parent chain,
    // copy the resolved transcripts into the summary block.
    let summary_block = pool_reader.get_highest_summary_block();
    let parent_chain =
        build_consensus_block_chain(pool_reader.pool(), &summary_block, parent_block);
    let block_reader = EcdsaBlockReaderImpl::new(parent_chain);
    summary.idkg_transcripts.clear();
    for transcript_ref in prev_refs {
        // We want to panic here if the transcript reference could not be resolved.
        summary.idkg_transcripts.insert(
            transcript_ref.transcript_id,
            block_reader.transcript(&transcript_ref).unwrap(),
        );
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
            .unwrap_or(EcdsaConfig {
                quadruples_to_create_in_advance: 1, // default value
                ..EcdsaConfig::default()
            });
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
                    idkg_transcripts: BTreeMap::new(),
                };
                Ok(Some(payload))
            }
            Some(ecdsa_summary) => {
                let mut next_unused_transcript_id = ecdsa_summary.next_unused_transcript_id;
                let quadruples_in_creation = next_quadruples_in_creation(
                    &node_ids,
                    summary_registry_version,
                    ecdsa_summary,
                    &ecdsa_config,
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
                        ecdsa_summary.current_key_transcript,
                    )),
                    idkg_transcripts: BTreeMap::new(),
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
                // The notarized tip(parent) may be ahead of the finalized tip, and
                // the last few blocks may have references to heights after the finalized
                // tip. So use the chain ending at the parent to resolve refs, rather than the
                // finalized chain.
                let parent_chain =
                    build_consensus_block_chain(pool_reader.pool(), &summary_block, parent_block);
                if let Some(key_transcript) = current_key_transcript {
                    let state = state_manager.get_state_at(context.certified_height)?;
                    let signing_requests = get_signing_requests(
                        &state
                            .get_ref()
                            .metadata
                            .subnet_call_context_manager
                            .sign_with_ecdsa_contexts,
                    );
                    update_signature_agreements(
                        &signing_requests,
                        parent_chain.clone(),
                        ecdsa_pool.clone(),
                        crypto,
                        &mut payload,
                        ecdsa_payload_metrics,
                        log.clone(),
                    );
                    let count = update_signing_requests(
                        &signing_requests,
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
                let transcript_builder =
                    EcdsaTranscriptBuilderImpl::new(crypto, ecdsa_payload_metrics, log.clone());
                let ecdsa_pool = ecdsa_pool.read().unwrap();
                for transcript in transcript_builder
                    .get_completed_transcripts(parent_chain, ecdsa_pool.deref())
                    .into_iter()
                {
                    completed_transcripts.insert(transcript.transcript_id, transcript);
                }

                let mut new_transcripts = Vec::new();
                let ret = update_next_key_transcript(
                    &node_ids,
                    summary_registry_version,
                    current_key_transcript,
                    &mut payload,
                    &mut completed_transcripts,
                    height,
                    &log,
                )?;
                if let Some(key_transcript) = ret {
                    new_transcripts.push(key_transcript);
                }
                if let Some(key_transcript) = current_key_transcript {
                    let mut transcripts = update_quadruples_in_creation(
                        key_transcript,
                        &mut payload,
                        &mut completed_transcripts,
                        height,
                        log,
                    )?;
                    new_transcripts.append(&mut transcripts);
                };

                // Drop transcripts from last round and keep only the
                // ones created in this round.
                payload.idkg_transcripts.clear();
                for transcript in new_transcripts {
                    payload
                        .idkg_transcripts
                        .insert(transcript.transcript_id, transcript);
                }

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
    let dealers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
    let receivers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
    Ok(ecdsa::RandomTranscriptParams::new(
        transcript_id,
        dealers,
        receivers,
        summary_registry_version,
        AlgorithmId::ThresholdEcdsaSecp256k1,
    ))
}

/// Initialize the next set of quadruples with random configs from the summary
/// block, and return it together with the next transcript id.
fn next_quadruples_in_creation(
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    summary: &ecdsa::EcdsaSummaryPayload,
    ecdsa_config: &EcdsaConfig,
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
    let mut to_create = ecdsa_config.quadruples_to_create_in_advance as usize;
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

/// Turn the given sign_with_ecdsa_contexts into a mapping with request id as the key.
fn get_signing_requests(
    sign_with_ecdsa_contexts: &BTreeMap<CallbackId, SignWithEcdsaContext>,
) -> BTreeMap<ecdsa::RequestId, &SignWithEcdsaContext> {
    sign_with_ecdsa_contexts
        .values()
        .map(|context| {
            (
                // request_id is just pseudo_random_id which is guaranteed to be always unique.
                ecdsa::RequestId::from(context.pseudo_random_id.to_vec()),
                context,
            )
        })
        .collect()
}

// Update signature agreements in the data payload by combining
// shares in the ECDSA pool.
// TODO: As an optimization we could also use the signatures we
// are looking for to avoid traversing everything in the pool.
fn update_signature_agreements(
    signing_requests: &BTreeMap<ecdsa::RequestId, &SignWithEcdsaContext>,
    chain: Arc<dyn ConsensusBlockChain>,
    ecdsa_pool: Arc<RwLock<dyn EcdsaPool>>,
    crypto: &dyn ConsensusCrypto,
    payload: &mut ecdsa::EcdsaDataPayload,
    metrics: &EcdsaPayloadMetrics,
    log: ReplicaLogger,
) {
    let ecdsa_pool = ecdsa_pool.read().unwrap();
    let builder = EcdsaSignatureBuilderImpl::new(crypto, metrics, log.clone());
    // We first clean up the existing signature_agreements by keeping those
    // that can still be found in the signing_requests for dedup purpose.
    // We only need the "Reported" status because they would have already
    // been reported when the previous block become finalized.
    let mut agreements = BTreeMap::new();
    std::mem::swap(&mut payload.signature_agreements, &mut agreements);
    for (request_id, _) in agreements.into_iter() {
        if signing_requests.contains_key(&request_id) {
            payload
                .signature_agreements
                .insert(request_id, ecdsa::CompletedSignature::ReportedToExecution);
        }
    }
    // Then we collect new signatures into the signature_agreements
    for (request_id, signature) in builder.get_completed_signatures(chain, ecdsa_pool.deref()) {
        if payload.ongoing_signatures.remove(&request_id).is_none() {
            warn!(
                log,
                "ECDSA signing request {:?} is not found in payload but we have a signature for it",
                request_id
            );
        } else {
            payload
                .signature_agreements
                .insert(request_id, ecdsa::CompletedSignature::Unreported(signature));
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
    signing_requests: &BTreeMap<ecdsa::RequestId, &SignWithEcdsaContext>,
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
        signing_requests,
        &existing_requests,
        &mut payload.available_quadruples,
        key_transcript,
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
    signing_requests: &BTreeMap<ecdsa::RequestId, &SignWithEcdsaContext>,
    existing_requests: &BTreeSet<&ecdsa::RequestId>,
    available_quadruples: &mut BTreeMap<ecdsa::QuadrupleId, ecdsa::PreSignatureQuadrupleRef>,
    key_transcript: &ecdsa::UnmaskedTranscript,
) -> Result<Vec<(ecdsa::RequestId, ecdsa::ThresholdEcdsaSigInputsRef)>, EcdsaPayloadError> {
    let new_requests = signing_requests
        .iter()
        .filter(|(request_id, _)| !existing_requests.contains(request_id));

    let mut ret = Vec::new();
    let mut consumed_quadruples = Vec::new();
    for ((request_id, context), (quadruple_id, quadruple)) in
        new_requests.zip(available_quadruples.iter())
    {
        let sign_inputs = build_signature_inputs(context, quadruple, key_transcript);
        ret.push((request_id.clone(), sign_inputs));
        consumed_quadruples.push(*quadruple_id);
    }

    for quadruple_id in consumed_quadruples {
        available_quadruples.remove(&quadruple_id);
    }
    Ok(ret)
}

/// Update configuration and data about the next ECDSA key transcript.
/// Returns the newly created transcript, if any.
fn update_next_key_transcript(
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    current_key_transcript: Option<&ecdsa::UnmaskedTranscript>,
    payload: &mut ecdsa::EcdsaDataPayload,
    completed_transcripts: &mut BTreeMap<IDkgTranscriptId, IDkgTranscript>,
    height: Height,
    _log: &ReplicaLogger,
) -> Result<Option<IDkgTranscript>, EcdsaPayloadError> {
    let mut new_transcript = None;
    match (
        current_key_transcript,
        &payload.next_key_transcript_creation,
    ) {
        (Some(transcript), None) => {
            // We have an existing key transcript, need to reshare it to create next
            // Create a new reshare config when there is none
            let transcript_id = payload.next_unused_transcript_id;
            payload.next_unused_transcript_id = transcript_id.increment();
            let dealers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
            let receivers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
            payload.next_key_transcript_creation =
                Some(ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(
                    ecdsa::ReshareOfUnmaskedParams::new(
                        transcript_id,
                        dealers,
                        receivers,
                        summary_registry_version,
                        AlgorithmId::ThresholdEcdsaSecp256k1,
                        *transcript,
                    ),
                ));
        }
        (Some(_), Some(ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(config))) => {
            // check if the next key transcript has been made
            if let Some(transcript) = completed_transcripts.get(&config.as_ref().transcript_id) {
                let transcript_ref = ecdsa::UnmaskedTranscript::try_from((height, transcript))?;
                payload.next_key_transcript_creation =
                    Some(ecdsa::KeyTranscriptCreation::Created(transcript_ref));
                new_transcript = Some(transcript.clone());
            }
        }
        (None, None) => {
            // The first ECDSA key transcript has to be created, starting from a random
            // config.
            let transcript_id = payload.next_unused_transcript_id;
            payload.next_unused_transcript_id = transcript_id.increment();
            let dealers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
            let receivers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
            payload.next_key_transcript_creation =
                Some(ecdsa::KeyTranscriptCreation::RandomTranscriptParams(
                    ecdsa::RandomTranscriptParams::new(
                        transcript_id,
                        dealers,
                        receivers,
                        summary_registry_version,
                        AlgorithmId::ThresholdEcdsaSecp256k1,
                    ),
                ));
        }
        (None, Some(ecdsa::KeyTranscriptCreation::RandomTranscriptParams(config))) => {
            // Check if the random transcript has been created
            if let Some(transcript) = completed_transcripts.get(&config.as_ref().transcript_id) {
                let transcript_id = payload.next_unused_transcript_id;
                payload.next_unused_transcript_id = transcript_id.increment();
                let dealers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
                let receivers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
                let transcript_ref = ecdsa::MaskedTranscript::try_from((height, transcript))?;
                payload.next_key_transcript_creation =
                    Some(ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(
                        ecdsa::ReshareOfMaskedParams::new(
                            transcript_id,
                            dealers,
                            receivers,
                            summary_registry_version,
                            AlgorithmId::ThresholdEcdsaSecp256k1,
                            transcript_ref,
                        ),
                    ));
                new_transcript = Some(transcript.clone());
            }
        }
        (None, Some(ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(config))) => {
            // Check if the unmasked transcript has been created
            if let Some(transcript) = completed_transcripts.get(&config.as_ref().transcript_id) {
                let transcript_ref = ecdsa::UnmaskedTranscript::try_from((height, transcript))?;
                payload.next_key_transcript_creation =
                    Some(ecdsa::KeyTranscriptCreation::Created(transcript_ref));
                new_transcript = Some(transcript.clone());
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
    Ok(new_transcript)
}

/// Update the quadruples in the payload by:
/// - making new configs when pre-conditions are met;
/// - gathering ready results (new transcripts) from ecdsa pool;
/// - moving completed quadruples from "in creation" to "available".
/// Returns the newly created transcripts.
fn update_quadruples_in_creation(
    key_transcript: &ecdsa::UnmaskedTranscript,
    payload: &mut ecdsa::EcdsaDataPayload,
    completed_transcripts: &mut BTreeMap<IDkgTranscriptId, IDkgTranscript>,
    height: Height,
    log: ReplicaLogger,
) -> Result<Vec<IDkgTranscript>, EcdsaPayloadError> {
    debug!(
        log,
        "update_quadruples_in_creation: completed transcript = {:?}",
        completed_transcripts.keys()
    );
    let mut newly_available = Vec::new();
    let mut new_transcripts = Vec::new();
    for (key, quadruple) in payload.quadruples_in_creation.iter_mut() {
        // Update quadruple with completed transcripts
        if quadruple.kappa_masked.is_none() {
            if let Some(transcript) =
                completed_transcripts.remove(&quadruple.kappa_config.as_ref().transcript_id)
            {
                debug!(
                    log,
                    "update_quadruples_in_creation: {:?} kappa_masked transcript is made", key
                );
                quadruple.kappa_masked =
                    Some(ecdsa::MaskedTranscript::try_from((height, &transcript))?);
                new_transcripts.push(transcript);
            }
        }
        if quadruple.lambda_masked.is_none() {
            if let Some(transcript) =
                completed_transcripts.remove(&quadruple.lambda_config.as_ref().transcript_id)
            {
                debug!(
                    log,
                    "update_quadruples_in_creation: {:?} lamdba_masked transcript is made", key
                );
                quadruple.lambda_masked =
                    Some(ecdsa::MaskedTranscript::try_from((height, &transcript))?);
                new_transcripts.push(transcript);
            }
        }
        if quadruple.kappa_unmasked.is_none() {
            if let Some(config) = &quadruple.unmask_kappa_config {
                if let Some(transcript) =
                    completed_transcripts.remove(&config.as_ref().transcript_id)
                {
                    debug!(
                        log,
                        "update_quadruples_in_creation: {:?} kappa_unmasked transcript {:?} is made",
                        key,
                        transcript.get_type()
                    );
                    quadruple.kappa_unmasked =
                        Some(ecdsa::UnmaskedTranscript::try_from((height, &transcript))?);
                    new_transcripts.push(transcript);
                }
            }
        }
        if quadruple.key_times_lambda.is_none() {
            if let Some(config) = &quadruple.key_times_lambda_config {
                if let Some(transcript) =
                    completed_transcripts.remove(&config.as_ref().transcript_id)
                {
                    debug!(
                        log,
                        "update_quadruples_in_creation: {:?} key_times_lambda transcript is made",
                        key
                    );
                    quadruple.key_times_lambda =
                        Some(ecdsa::MaskedTranscript::try_from((height, &transcript))?);
                    new_transcripts.push(transcript);
                }
            }
        }
        if quadruple.kappa_times_lambda.is_none() {
            if let Some(config) = &quadruple.kappa_times_lambda_config {
                if let Some(transcript) =
                    completed_transcripts.remove(&config.as_ref().transcript_id)
                {
                    debug!(
                        log,
                        "update_quadruples_in_creation: {:?} kappa_times_lambda transcript is made",
                        key
                    );
                    quadruple.kappa_times_lambda =
                        Some(ecdsa::MaskedTranscript::try_from((height, &transcript))?);
                    new_transcripts.push(transcript);
                }
            }
        }
        // Check what to do in the next step
        if let (Some(kappa_masked), None) =
            (&quadruple.kappa_masked, &quadruple.unmask_kappa_config)
        {
            let kappa_config = quadruple.kappa_config.as_ref();
            quadruple.unmask_kappa_config = Some(ecdsa::ReshareOfMaskedParams::new(
                payload.next_unused_transcript_id,
                kappa_config.dealers.clone(),
                kappa_config.receivers.clone(),
                kappa_config.registry_version,
                kappa_config.algorithm_id,
                *kappa_masked,
            ));
            payload.next_unused_transcript_id = payload.next_unused_transcript_id.increment();
        }
        if let (Some(lambda_masked), None) =
            (&quadruple.lambda_masked, &quadruple.key_times_lambda_config)
        {
            let lambda_config = quadruple.lambda_config.as_ref();
            quadruple.key_times_lambda_config = Some(ecdsa::UnmaskedTimesMaskedParams::new(
                payload.next_unused_transcript_id,
                lambda_config.dealers.clone(),
                lambda_config.receivers.clone(),
                lambda_config.registry_version,
                lambda_config.algorithm_id,
                *key_transcript,
                *lambda_masked,
            ));
            payload.next_unused_transcript_id = payload.next_unused_transcript_id.increment();
        }
        if let (Some(lambda_masked), Some(kappa_unmasked), None) = (
            &quadruple.lambda_masked,
            &quadruple.kappa_unmasked,
            &quadruple.kappa_times_lambda_config,
        ) {
            let lambda_config = quadruple.lambda_config.as_ref();
            quadruple.kappa_times_lambda_config = Some(ecdsa::UnmaskedTimesMaskedParams::new(
                payload.next_unused_transcript_id,
                lambda_config.dealers.clone(),
                lambda_config.receivers.clone(),
                lambda_config.registry_version,
                lambda_config.algorithm_id,
                *kappa_unmasked,
                *lambda_masked,
            ));
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
            ecdsa::PreSignatureQuadrupleRef::new(
                kappa_unmasked,
                lambda_masked,
                kappa_times_lambda,
                key_times_lambda,
            ),
        );
    }
    Ok(new_transcripts)
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
    quadruple_ref: &ecdsa::PreSignatureQuadrupleRef,
    key_transcript_ref: &ecdsa::UnmaskedTranscript,
) -> ecdsa::ThresholdEcdsaSigInputsRef {
    let extended_derivation_path = ExtendedDerivationPath {
        caller: context.request.sender.into(),
        derivation_path: context.derivation_path.clone(),
    };
    ecdsa::ThresholdEcdsaSigInputsRef::new(
        extended_derivation_path,
        context.message_hash.clone(),
        Id::from(context.pseudo_random_id),
        quadruple_ref.clone(),
        *key_transcript_ref,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::mocks::{dependencies, Dependencies};
    use crate::ecdsa::utils::test_utils::*;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        generate_key_transcript, run_idkg_and_create_and_verify_transcript,
        CanisterThresholdSigTestEnvironment,
    };
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
    use ic_test_utilities::{
        mock_time,
        state::ReplicatedStateBuilder,
        types::{
            ids::{node_test_id, subnet_test_id},
            messages::RequestBuilder,
        },
    };
    use ic_types::batch::BatchPayload;
    use ic_types::consensus::dkg::{Dealings, Summary};
    use ic_types::consensus::{BlockPayload, DataPayload, HashedBlock, Payload, SummaryPayload};
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
    use ic_types::{messages::CallbackId, Height, RegistryVersion};
    use std::collections::BTreeSet;

    fn empty_ecdsa_summary_payload(
        subnet_id: SubnetId,
        current_key_transcript: ecdsa::UnmaskedTranscript,
    ) -> ecdsa::EcdsaSummaryPayload {
        ecdsa::EcdsaSummaryPayload {
            signature_agreements: BTreeMap::new(),
            ongoing_signatures: BTreeMap::new(),
            current_key_transcript,
            available_quadruples: BTreeMap::new(),
            next_unused_transcript_id: IDkgTranscriptId::new(subnet_id, 0),
            idkg_transcripts: BTreeMap::new(),
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
            idkg_transcripts: BTreeMap::new(),
        }
    }

    fn create_summary_block_with_transcripts(
        subnet_id: SubnetId,
        height: Height,
        current_key_transcript: (ecdsa::UnmaskedTranscript, IDkgTranscript),
        transcripts: Vec<BTreeMap<ecdsa::TranscriptRef, IDkgTranscript>>,
    ) -> BlockPayload {
        let mut ecdsa_summary = empty_ecdsa_summary_payload(subnet_id, current_key_transcript.0);
        ecdsa_summary.idkg_transcripts.insert(
            current_key_transcript.0.as_ref().transcript_id,
            current_key_transcript.1,
        );
        for idkg_transcripts in transcripts {
            for (transcript_ref, transcript) in idkg_transcripts {
                ecdsa_summary
                    .idkg_transcripts
                    .insert(transcript_ref.transcript_id, transcript);
            }
        }
        BlockPayload::Summary(SummaryPayload {
            dkg: Summary::new(
                vec![],
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                RegistryVersion::from(0),
                Height::from(100),
                Height::from(100),
                height,
                BTreeMap::new(),
            ),
            ecdsa: Some(ecdsa_summary),
        })
    }

    fn create_payload_block_with_transcripts(
        subnet_id: SubnetId,
        dkg_interval_start_height: Height,
        transcripts: Vec<BTreeMap<ecdsa::TranscriptRef, IDkgTranscript>>,
    ) -> BlockPayload {
        let mut ecdsa_payload = empty_ecdsa_data_payload(subnet_id);
        for idkg_transcripts in transcripts {
            for (transcript_ref, transcript) in idkg_transcripts {
                ecdsa_payload
                    .idkg_transcripts
                    .insert(transcript_ref.transcript_id, transcript);
            }
        }
        BlockPayload::Data(DataPayload {
            batch: BatchPayload::default(),
            dealings: Dealings::new_empty(dkg_interval_start_height),
            ecdsa: Some(ecdsa_payload),
        })
    }

    fn add_block(
        block_payload: BlockPayload,
        advance_by: u64,
        pool: &mut TestConsensusPool,
    ) -> Block {
        pool.advance_round_normal_operation_n(advance_by - 1);
        let mut block_proposal = pool.make_next_block();
        let mut block = block_proposal.content.as_mut();
        block.payload = Payload::new(ic_crypto::crypto_hash, block_payload);
        block_proposal.content = HashedBlock::new(ic_crypto::crypto_hash, block.clone());
        pool.advance_round_with_block(&block_proposal);
        block_proposal.content.as_ref().clone()
    }

    #[test]
    fn test_ecdsa_next_quadruples_in_creation() {
        let subnet_id = subnet_test_id(1);
        let subnet_nodes = (0..10).map(node_test_id).collect::<Vec<_>>();
        let summary_registry_version = RegistryVersion::new(10);
        let env = CanisterThresholdSigTestEnvironment::new(4);
        let algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;
        let key_transcript = generate_key_transcript(&env, algorithm);
        let key_transcript_ref =
            ecdsa::UnmaskedTranscript::try_from((Height::new(1), &key_transcript)).unwrap();
        let summary = empty_ecdsa_summary_payload(subnet_id, key_transcript_ref);
        let quadruples_to_create_in_advance = 5;
        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance,
            ..EcdsaConfig::default()
        };
        let mut next_unused_transcript_id = IDkgTranscriptId::new(subnet_id, 10);
        // Success case
        let result = next_quadruples_in_creation(
            &subnet_nodes,
            summary_registry_version,
            &summary,
            &ecdsa_config,
            &mut next_unused_transcript_id,
        );
        assert!(result.is_ok());
        let quadruples = result.unwrap();
        assert_eq!(quadruples.len(), quadruples_to_create_in_advance as usize);
        // Check transcript ids are unique
        let mut transcript_ids = BTreeSet::new();
        for quadruple in quadruples.iter() {
            transcript_ids.insert(quadruple.1.kappa_config.as_ref().transcript_id);
            transcript_ids.insert(quadruple.1.lambda_config.as_ref().transcript_id);
        }
        assert_eq!(
            transcript_ids.len(),
            2 * quadruples_to_create_in_advance as usize
        );
        assert_eq!(
            transcript_ids.iter().max().unwrap().increment(),
            next_unused_transcript_id
        );
    }

    #[test]
    fn test_ecdsa_get_new_signing_requests() {
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
        let signing_requests = get_signing_requests(
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
        );
        // Success case
        let mut requests = BTreeSet::new();
        let sig_inputs = create_sig_inputs(10);
        let quadruple_ref = &sig_inputs.sig_inputs_ref.presig_quadruple_ref;
        let ecdsa_transcript_ref = &sig_inputs.sig_inputs_ref.key_transcript_ref;
        let mut available_quadruples = BTreeMap::new();
        available_quadruples.insert(ecdsa::QuadrupleId(0), quadruple_ref.clone());
        let result = get_new_signing_requests(
            &signing_requests,
            &requests,
            &mut available_quadruples,
            ecdsa_transcript_ref,
        );
        assert!(result.is_ok());
        let new_requests = result.unwrap();
        assert_eq!(new_requests.len(), 1);
        // Duplicate is ignored
        let request_id = ecdsa::RequestId::from(pseudo_random_id.to_vec());
        requests.insert(&request_id);
        let result = get_new_signing_requests(
            &signing_requests,
            &requests,
            &mut available_quadruples,
            ecdsa_transcript_ref,
        );
        assert!(result.is_ok());
        let new_requests = result.unwrap();
        assert_eq!(new_requests.len(), 0);
    }

    #[test]
    fn test_ecdsa_update_next_key_transcript() {
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
        let registry_version = env.newest_registry_version;
        let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
        let mut block_reader = TestEcdsaBlockReader::new();
        let config_ids = |payload: &ecdsa::EcdsaDataPayload| {
            let mut arr = payload
                .iter_transcript_configs_in_creation()
                .map(|x| x.transcript_id.id())
                .collect::<Vec<_>>();
            arr.sort_unstable();
            arr
        };

        // 1. Nothing initially, masked transcript creation should start
        let cur_height = Height::new(10);
        let mut payload = empty_ecdsa_data_payload(subnet_id);
        let mut completed = BTreeMap::new();
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            None,
            &mut payload,
            &mut completed,
            cur_height,
            &no_op_logger(),
        );
        matches!(result, Ok(None));
        assert_eq!(payload.next_unused_transcript_id.id(), 1);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [0]);

        // 2. Masked random transcript is created, should start reshare of the masked
        // transcript.
        let cur_height = Height::new(20);
        let masked_transcript = {
            let param = match &payload.next_key_transcript_creation {
                Some(ecdsa::KeyTranscriptCreation::RandomTranscriptParams(param)) => param.clone(),
                _ => panic!(
                    "Unexpected state: {:?}",
                    payload.next_key_transcript_creation
                ),
            };
            run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &env.crypto_components,
            )
        };
        completed.insert(masked_transcript.transcript_id, masked_transcript.clone());
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            None,
            &mut payload,
            &mut completed,
            cur_height,
            &no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, masked_transcript);
        block_reader.add_transcript(
            ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
            completed_transcript,
        );
        assert_eq!(payload.next_unused_transcript_id.id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [1]);

        // 3. Unmasked transcript is created, should complete the boot strap sequence
        let cur_height = Height::new(30);
        let unmasked_transcript = {
            let param = match &payload.next_key_transcript_creation {
                Some(ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(param)) => param.clone(),
                _ => panic!(
                    "Unexpected state: {:?}",
                    payload.next_key_transcript_creation
                ),
            };
            run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &env.crypto_components,
            )
        };
        completed.insert(
            unmasked_transcript.transcript_id,
            unmasked_transcript.clone(),
        );
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            None,
            &mut payload,
            &mut completed,
            cur_height,
            &no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, unmasked_transcript);
        block_reader.add_transcript(
            ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
            completed_transcript,
        );
        assert_eq!(payload.next_unused_transcript_id.id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 0);
        assert!(config_ids(&payload).is_empty());
        let current_key_transcript =
            ecdsa::UnmaskedTranscript::try_from((cur_height, &unmasked_transcript)).unwrap();
        ecdsa::TranscriptRef::new(cur_height, unmasked_transcript.transcript_id);
        match &payload.next_key_transcript_creation {
            Some(ecdsa::KeyTranscriptCreation::Created(unmasked)) => {
                assert_eq!(*unmasked.as_ref(), *current_key_transcript.as_ref());
            }
            _ => panic!(
                "Unexpected state: {:?}",
                payload.next_key_transcript_creation
            ),
        }

        // 4. Reshare the current key transcript to get the next one
        let cur_height = Height::new(40);
        payload.next_key_transcript_creation = None;
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            Some(&current_key_transcript),
            &mut payload,
            &mut completed,
            cur_height,
            &no_op_logger(),
        );
        matches!(result, Ok(None));
        assert_eq!(payload.next_unused_transcript_id.id(), 3);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [2]);

        // 5. Reshare completes to get the next unmasked transcript
        let cur_height = Height::new(50);
        let unmasked_transcript = {
            let param = match &payload.next_key_transcript_creation {
                Some(ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(param)) => param.clone(),
                _ => panic!(
                    "Unexpected state: {:?}",
                    payload.next_key_transcript_creation
                ),
            };
            run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &env.crypto_components,
            )
        };
        completed.insert(
            unmasked_transcript.transcript_id,
            unmasked_transcript.clone(),
        );
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            Some(&current_key_transcript),
            &mut payload,
            &mut completed,
            cur_height,
            &no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, unmasked_transcript);
        assert_eq!(payload.next_unused_transcript_id.id(), 3);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 0);
        assert!(config_ids(&payload).is_empty());
        let current_key_transcript =
            ecdsa::UnmaskedTranscript::try_from((cur_height, &unmasked_transcript)).unwrap();
        match &payload.next_key_transcript_creation {
            Some(ecdsa::KeyTranscriptCreation::Created(unmasked)) => {
                assert_eq!(*unmasked.as_ref(), *current_key_transcript.as_ref());
            }
            _ => panic!(
                "Unexpected state: {:?}",
                payload.next_key_transcript_creation
            ),
        }
    }

    #[test]
    fn test_ecdsa_update_quadruples_in_creation() {
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
        let registry_version = env.newest_registry_version;
        let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
        let algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;
        let mut block_reader = TestEcdsaBlockReader::new();

        let key_transcript = generate_key_transcript(&env, algorithm);
        let key_transcript_ref =
            ecdsa::UnmaskedTranscript::try_from((Height::new(100), &key_transcript)).unwrap();
        block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript);
        let mut payload = empty_ecdsa_data_payload(subnet_id);
        let mut completed = BTreeMap::new();
        // Start quadruple creation
        let kappa_config_id = payload.next_unused_transcript_id;
        let kappa_config_ref = new_random_config(
            &subnet_nodes,
            registry_version,
            &mut payload.next_unused_transcript_id,
        )
        .unwrap();
        let lambda_config_id = payload.next_unused_transcript_id;
        let lambda_config_ref = new_random_config(
            &subnet_nodes,
            registry_version,
            &mut payload.next_unused_transcript_id,
        )
        .unwrap();
        let quadruple_id = ecdsa::QuadrupleId(0);
        payload.quadruples_in_creation.insert(
            quadruple_id,
            ecdsa::QuadrupleInCreation::new(kappa_config_ref.clone(), lambda_config_ref.clone()),
        );
        // 1. No action case
        let cur_height = Height::new(1000);
        let result = update_quadruples_in_creation(
            &key_transcript_ref,
            &mut payload,
            &mut completed,
            cur_height,
            no_op_logger(),
        );
        assert!(result.unwrap().is_empty());
        let config_ids = |payload: &ecdsa::EcdsaDataPayload| {
            let mut arr = payload
                .iter_transcript_configs_in_creation()
                .map(|x| x.transcript_id.id())
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
            let param = kappa_config_ref.as_ref(); //env.params_for_random_sharing(algorithm);
            run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &env.crypto_components,
            )
        };
        completed.insert(kappa_config_id, kappa_transcript);
        let cur_height = Height::new(2000);
        let result = update_quadruples_in_creation(
            &key_transcript_ref,
            &mut payload,
            &mut completed,
            cur_height,
            no_op_logger(),
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        for completed_transcript in result {
            block_reader.add_transcript(
                ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
                completed_transcript,
            );
        }
        // check if new config is made
        assert!(payload.available_quadruples.is_empty());
        let kappa_unmasked_config_id = IDkgTranscriptId::new(subnet_id, 2);
        assert_eq!(payload.next_unused_transcript_id.id(), 3);
        assert_eq!(config_ids(&payload), [1, 2]);

        // 2. When lambda_masked is ready, expect a new key_times_lambda config.
        let lambda_transcript = {
            let param = lambda_config_ref.as_ref(); //env.params_for_random_sharing(algorithm);
            run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &env.crypto_components,
            )
        };
        completed.insert(lambda_config_id, lambda_transcript);
        let cur_height = Height::new(3000);
        let result = update_quadruples_in_creation(
            &key_transcript_ref,
            &mut payload,
            &mut completed,
            cur_height,
            no_op_logger(),
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        for completed_transcript in result {
            block_reader.add_transcript(
                ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
                completed_transcript,
            );
        }
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
                .find(|x| x.transcript_id == kappa_unmasked_config_id)
                .unwrap()
                .clone();
            run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &env.crypto_components,
            )
        };
        completed.insert(kappa_unmasked_config_id, kappa_unmasked_transcript);
        let cur_height = Height::new(4000);
        let result = update_quadruples_in_creation(
            &key_transcript_ref,
            &mut payload,
            &mut completed,
            cur_height,
            no_op_logger(),
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        for completed_transcript in result {
            block_reader.add_transcript(
                ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
                completed_transcript,
            );
        }
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
                .find(|x| x.transcript_id == kappa_times_lambda_config_id)
                .unwrap()
                .clone();
            run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &env.crypto_components,
            )
        };
        completed.insert(kappa_times_lambda_config_id, kappa_times_lambda_transcript);
        let key_times_lambda_transcript = {
            let param = payload
                .iter_transcript_configs_in_creation()
                .find(|x| x.transcript_id == key_times_lambda_config_id)
                .unwrap()
                .clone();
            run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &env.crypto_components,
            )
        };
        completed.insert(key_times_lambda_config_id, key_times_lambda_transcript);
        let cur_height = Height::new(5000);
        let result = update_quadruples_in_creation(
            &key_transcript_ref,
            &mut payload,
            &mut completed,
            cur_height,
            no_op_logger(),
        )
        .unwrap();
        assert_eq!(result.len(), 2);
        // check if new config is made
        assert_eq!(payload.available_quadruples.len(), 1);
        assert_eq!(payload.next_unused_transcript_id.id(), 5);
        assert!(config_ids(&payload).is_empty());
    }

    #[test]
    fn test_ecdsa_update_summary_refs() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { mut pool, .. } = dependencies(pool_config, 1);
            let subnet_id = subnet_test_id(1);
            let mut expected_transcripts = BTreeSet::new();
            let mut add_expected_transcripts = |trancript_refs: Vec<ecdsa::TranscriptRef>| {
                for transcript_ref in trancript_refs {
                    expected_transcripts.insert(transcript_ref.transcript_id);
                }
            };

            // Create a summary block with transcripts
            let summary_height = Height::new(5);
            let env = CanisterThresholdSigTestEnvironment::new(4);
            let algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;
            let key_transcript = generate_key_transcript(&env, algorithm);
            let key_transcript_ref =
                ecdsa::UnmaskedTranscript::try_from((summary_height, &key_transcript)).unwrap();

            let inputs_1 = create_sig_inputs_with_height(91, summary_height);
            let inputs_2 = create_sig_inputs_with_height(92, summary_height);
            let summary_block = create_summary_block_with_transcripts(
                subnet_id,
                summary_height,
                (key_transcript_ref, key_transcript),
                vec![
                    inputs_1.idkg_transcripts.clone(),
                    inputs_2.idkg_transcripts.clone(),
                ],
            );
            add_block(summary_block, summary_height.get(), &mut pool);
            let sig_1 = inputs_1.sig_inputs_ref;
            let quad_1 = inputs_2.sig_inputs_ref.presig_quadruple_ref;

            // Create payload blocks with transcripts
            let payload_height_1 = Height::new(10);
            let inputs_1 = create_sig_inputs_with_height(93, payload_height_1);
            let inputs_2 = create_sig_inputs_with_height(94, payload_height_1);
            let payload_block_1 = create_payload_block_with_transcripts(
                subnet_id,
                summary_height,
                vec![
                    inputs_1.idkg_transcripts.clone(),
                    inputs_2.idkg_transcripts.clone(),
                ],
            );
            add_block(
                payload_block_1,
                payload_height_1.get() - summary_height.get(),
                &mut pool,
            );
            let sig_2 = inputs_1.sig_inputs_ref;
            let quad_2 = inputs_2.sig_inputs_ref.presig_quadruple_ref;

            // Create a payload block with references to these past blocks
            let (req_id_1, req_id_2) = (create_request_id(1), create_request_id(2));
            let (quadruple_id_1, quadruple_id_2) =
                (ecdsa::QuadrupleId(1000), ecdsa::QuadrupleId(2000));
            let mut ecdsa_payload = empty_ecdsa_data_payload(subnet_id);
            ecdsa_payload
                .ongoing_signatures
                .insert(req_id_1, sig_1.clone());
            ecdsa_payload
                .ongoing_signatures
                .insert(req_id_2, sig_2.clone());
            ecdsa_payload
                .available_quadruples
                .insert(quadruple_id_1, quad_1.clone());
            ecdsa_payload
                .available_quadruples
                .insert(quadruple_id_2, quad_2.clone());

            add_expected_transcripts(vec![*key_transcript_ref.as_ref()]);
            add_expected_transcripts(sig_1.get_refs());
            add_expected_transcripts(sig_2.get_refs());
            add_expected_transcripts(quad_1.get_refs());
            add_expected_transcripts(quad_2.get_refs());

            let parent_block_height = Height::new(15);
            let parent_block_payload = BlockPayload::Data(DataPayload {
                batch: BatchPayload::default(),
                dealings: Dealings::new_empty(summary_height),
                ecdsa: Some(ecdsa_payload.clone()),
            });
            let parent_block = add_block(
                parent_block_payload,
                parent_block_height.get() - payload_height_1.get(),
                &mut pool,
            );
            let pool_reader = PoolReader::new(&pool);

            // Add a summary block after the payload block
            let new_summary_height = parent_block_height.increment();
            let mut summary = ecdsa::EcdsaSummaryPayload {
                signature_agreements: ecdsa_payload.signature_agreements.clone(),
                current_key_transcript: key_transcript_ref,
                ongoing_signatures: ecdsa_payload.ongoing_signatures.clone(),
                available_quadruples: ecdsa_payload.available_quadruples.clone(),
                next_unused_transcript_id: IDkgTranscriptId::new(subnet_id, 4),
                idkg_transcripts: BTreeMap::new(),
            };
            assert_ne!(
                summary.current_key_transcript.as_ref().height,
                new_summary_height
            );
            for ongoing_signature in summary.ongoing_signatures.values() {
                for transcript_ref in ongoing_signature.get_refs() {
                    assert_ne!(transcript_ref.height, new_summary_height);
                }
            }
            for available_quadruple in summary.available_quadruples.values() {
                for transcript_ref in available_quadruple.get_refs() {
                    assert_ne!(transcript_ref.height, new_summary_height);
                }
            }

            update_summary_refs(&mut summary, &pool_reader, &parent_block);

            // Verify that all the transcript references in the parent block
            // have been updated to point to the new summary height
            assert_eq!(
                summary.current_key_transcript.as_ref().height,
                new_summary_height
            );
            for ongoing_signature in summary.ongoing_signatures.values() {
                for transcript_ref in ongoing_signature.get_refs() {
                    assert_eq!(transcript_ref.height, new_summary_height);
                }
            }
            for available_quadruple in summary.available_quadruples.values() {
                for transcript_ref in available_quadruple.get_refs() {
                    assert_eq!(transcript_ref.height, new_summary_height);
                }
            }

            // Verify that all the transcript references in the parent block
            // have been resolved/copied into the summary block
            assert_eq!(summary.idkg_transcripts.len(), expected_transcripts.len());
            for transcript_id in summary.idkg_transcripts.keys() {
                assert!(expected_transcripts.contains(transcript_id));
            }
        })
    }
}
