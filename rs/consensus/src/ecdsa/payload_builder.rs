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
    consensus_pool::ConsensusBlockChain, ecdsa::EcdsaPool, registry::RegistryClient,
};
use ic_interfaces_state_manager::{StateManager, StateManagerError};
use ic_logger::{debug, info, warn, ReplicaLogger};
use ic_protobuf::registry::subnet::v1::EcdsaConfig;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::{metadata_state::subnet_call_context_manager::*, ReplicatedState};
use ic_types::{
    batch::ValidationContext,
    consensus::{ecdsa, ecdsa::EcdsaBlockReader, Block, HasHeight},
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
use std::collections::{btree_map, BTreeMap, BTreeSet};
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
    InvalidChainCacheError(String),
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

/// Caches the transcripts queried from the TranscriptBuilder
struct TranscriptBuilderCache<'a> {
    transcript_builder: &'a dyn EcdsaTranscriptBuilder,
    ecdsa_pool: &'a dyn EcdsaPool,
    cache: BTreeMap<IDkgTranscriptId, IDkgTranscript>,
}

impl<'a> TranscriptBuilderCache<'a> {
    fn new(
        transcript_builder: &'a dyn EcdsaTranscriptBuilder,
        ecdsa_pool: &'a dyn EcdsaPool,
    ) -> Self {
        Self {
            transcript_builder,
            ecdsa_pool,
            cache: BTreeMap::new(),
        }
    }

    fn get_completed_transcript(
        &mut self,
        transcript_id: IDkgTranscriptId,
    ) -> Option<&'_ IDkgTranscript> {
        if let btree_map::Entry::Vacant(e) = self.cache.entry(transcript_id) {
            // Cache miss: try to build the transcript and update the cache
            if let Some(transcript) = self
                .transcript_builder
                .get_completed_transcript(transcript_id, self.ecdsa_pool)
            {
                e.insert(transcript);
            }
        }

        self.cache.get(&transcript_id)
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
    ecdsa_payload_metrics: &EcdsaPayloadMetrics,
    log: ReplicaLogger,
) -> Result<ecdsa::Summary, EcdsaPayloadError> {
    let height = parent_block.height().increment();
    if !ecdsa_feature_is_enabled(subnet_id, registry_client, pool_reader, height)? {
        return Ok(None);
    }
    match &parent_block.payload.as_ref().as_data().ecdsa {
        None => Ok(None),
        Some(ecdsa::EcdsaDataPayload {
            ecdsa_payload,
            next_key_transcript_creation,
        }) => {
            let current_key_transcript = match &next_key_transcript_creation {
                ecdsa::KeyTranscriptCreation::Created(transcript) => *transcript,
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
                }) != Some(current_key_transcript.as_ref().transcript_id);
            let ecdsa_payload = ecdsa::EcdsaPayload {
                signature_agreements: ecdsa_payload.signature_agreements.clone(),
                ongoing_signatures: ecdsa_payload.ongoing_signatures.clone(),
                available_quadruples: if is_new_key_transcript {
                    BTreeMap::new()
                } else {
                    ecdsa_payload.available_quadruples.clone()
                },
                quadruples_in_creation: if is_new_key_transcript {
                    BTreeMap::new()
                } else {
                    ecdsa_payload.quadruples_in_creation.clone()
                },
                next_unused_transcript_id: ecdsa_payload.next_unused_transcript_id,
                idkg_transcripts: BTreeMap::new(),
                ongoing_xnet_reshares: if is_new_key_transcript {
                    // This will clear the current ongoing reshares, and
                    // the execution requests will be restarted with the
                    // new key and different transcript IDs.
                    BTreeMap::new()
                } else {
                    ecdsa_payload.ongoing_xnet_reshares.clone()
                },
                xnet_reshare_agreements: ecdsa_payload.xnet_reshare_agreements.clone(),
            };
            let mut summary = ecdsa::EcdsaSummaryPayload {
                ecdsa_payload,
                current_key_transcript,
            };
            update_summary_refs(
                &mut summary,
                pool_reader,
                parent_block,
                ecdsa_payload_metrics,
                &log,
            )?;
            Ok(Some(summary))
        }
    }
}

fn update_summary_refs(
    summary: &mut ecdsa::EcdsaSummaryPayload,
    pool_reader: &PoolReader<'_>,
    parent_block: &Block,
    ecdsa_payload_metrics: &EcdsaPayloadMetrics,
    log: &ReplicaLogger,
) -> Result<(), EcdsaPayloadError> {
    // Gather the refs and update them to point to the new
    // summary block height.
    let height = Some(parent_block.height().increment());
    let mut prev_refs = Vec::new();
    for quadruple in summary.ecdsa_payload.available_quadruples.values_mut() {
        prev_refs.append(&mut quadruple.get_refs_and_update(height));
    }
    for signature in summary.ecdsa_payload.ongoing_signatures.values_mut() {
        prev_refs.append(&mut signature.get_refs_and_update(height));
    }
    for quadruples in summary.ecdsa_payload.quadruples_in_creation.values_mut() {
        prev_refs.append(&mut quadruples.get_refs_and_update(height));
    }
    for reshare_params in summary.ecdsa_payload.ongoing_xnet_reshares.values_mut() {
        prev_refs.append(&mut reshare_params.as_mut().get_refs_and_update(height));
    }
    for reshare_agreement in summary.ecdsa_payload.xnet_reshare_agreements.values_mut() {
        if let ecdsa::CompletedReshareRequest::Unreported(response) = reshare_agreement {
            prev_refs.append(&mut response.reshare_param.as_mut().get_refs_and_update(height));
        }
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
    let parent_chain = match block_chain_cache(pool_reader, &summary_block, parent_block) {
        Ok(parent_chain) => parent_chain,
        Err(err) => {
            warn!(
                log,
                "create_summary_payload(): failed to build chain cache: {:?}", err
            );
            ecdsa_payload_metrics.payload_errors_inc("summary_invalid_chain_cache");
            return Err(err);
        }
    };
    let block_reader = EcdsaBlockReaderImpl::new(parent_chain);
    summary.ecdsa_payload.idkg_transcripts.clear();
    for transcript_ref in prev_refs {
        summary
            .ecdsa_payload
            .idkg_transcripts
            .entry(transcript_ref.transcript_id)
            .or_insert_with(
                // We want to panic here if the transcript reference could not be resolved.
                || block_reader.transcript(&transcript_ref).unwrap(),
            );
    }

    Ok(())
}

fn get_subnet_nodes(
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
    subnet_id: SubnetId,
) -> Result<Vec<NodeId>, EcdsaPayloadError> {
    // TODO: shuffle the nodes using random beacon?
    registry_client
        .get_node_ids_on_subnet(subnet_id, registry_version)?
        .ok_or(EcdsaPayloadError::SubnetWithNoNodes(registry_version))
}

fn is_subnet_membership_changing(
    registry_client: &dyn RegistryClient,
    dkg_registry_version: RegistryVersion,
    context_registry_version: RegistryVersion,
    subnet_id: SubnetId,
) -> Result<bool, EcdsaPayloadError> {
    let current_nodes = get_subnet_nodes(registry_client, dkg_registry_version, subnet_id)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let next_nodes = get_subnet_nodes(registry_client, context_registry_version, subnet_id)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    Ok(current_nodes != next_nodes)
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
    let summary_block = pool_reader
        .dkg_summary_block(parent_block)
        .unwrap_or_else(|| {
            panic!(
                "Impossible: fail to the summary block that governs height {}",
                parent_block.height()
            )
        });
    let summary = summary_block.payload.as_ref().as_summary();
    let summary_registry_version = summary.dkg.registry_version;
    let next_summary_registry_version = summary_block.context.registry_version;
    let ecdsa_config = registry_client
        .get_ecdsa_config(subnet_id, summary_registry_version)?
        .unwrap_or(EcdsaConfig {
            quadruples_to_create_in_advance: 1, // default value
            ..EcdsaConfig::default()
        });
    let mut ecdsa_payload;
    let mut next_key_transcript_creation;
    if block_payload.is_summary() {
        match &summary.ecdsa {
            None => {
                // bootstrap ECDSA payload
                ecdsa_payload = ecdsa::EcdsaPayload {
                    signature_agreements: BTreeMap::new(),
                    ongoing_signatures: BTreeMap::new(),
                    available_quadruples: BTreeMap::new(),
                    quadruples_in_creation: BTreeMap::new(),
                    next_unused_transcript_id: IDkgTranscriptId::new(subnet_id, 0),
                    idkg_transcripts: BTreeMap::new(),
                    ongoing_xnet_reshares: BTreeMap::new(),
                    xnet_reshare_agreements: BTreeMap::new(),
                };
                next_key_transcript_creation = ecdsa::KeyTranscriptCreation::Begin;
            }
            Some(ecdsa_summary) => {
                ecdsa_payload = ecdsa_summary.ecdsa_payload.clone();
                // If subnet node membership is going to change in the next summary block,
                // we need to start producing a new next_key_transcript
                next_key_transcript_creation = if is_subnet_membership_changing(
                    registry_client,
                    summary_registry_version,
                    parent_block.context.registry_version,
                    subnet_id,
                )? {
                    info!(
                        log,
                        "Noticed subnet membership change, will start key_transcript_creation."
                    );
                    ecdsa::KeyTranscriptCreation::Begin
                } else {
                    ecdsa::KeyTranscriptCreation::Created(ecdsa_summary.current_key_transcript)
                };
            }
        }
    } else {
        match &block_payload.as_data().ecdsa {
            None => return Ok(None),
            Some(prev_payload) => {
                ecdsa_payload = prev_payload.ecdsa_payload.clone();
                next_key_transcript_creation = prev_payload.next_key_transcript_creation.clone();
            }
        }
    };
    // The notarized tip(parent) may be ahead of the finalized tip, and
    // the last few blocks may have references to heights after the finalized
    // tip. So use the chain ending at the parent to resolve refs, rather than the
    // finalized chain.
    let parent_chain = match block_chain_cache(pool_reader, &summary_block, parent_block) {
        Ok(parent_chain) => parent_chain,
        Err(err) => {
            warn!(
                log,
                "create_data_payload(): failed to build chain cache: {:?}", err
            );
            ecdsa_payload_metrics.payload_errors_inc("payload_invalid_chain_cache");
            return Err(err);
        }
    };
    let current_key_transcript = summary
        .ecdsa
        .as_ref()
        .map(|ecdsa_summary| &ecdsa_summary.current_key_transcript);
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
        &mut ecdsa_payload,
        ecdsa_payload_metrics,
        log.clone(),
    );
    update_signing_requests(
        &signing_requests,
        current_key_transcript,
        &mut ecdsa_payload,
        log.clone(),
    )?;
    let node_ids = get_subnet_nodes(registry_client, summary_registry_version, subnet_id)?;
    make_new_quadruples_if_needed(
        &node_ids,
        summary_registry_version,
        &ecdsa_config,
        &mut ecdsa_payload,
    )?;

    let transcript_builder = EcdsaTranscriptBuilderImpl::new(
        parent_chain.clone(),
        crypto,
        ecdsa_payload_metrics,
        log.clone(),
    );
    let ecdsa_pool = ecdsa_pool.read().unwrap();
    let mut transcript_cache = TranscriptBuilderCache::new(&transcript_builder, ecdsa_pool.deref());

    let mut new_transcripts = update_quadruples_in_creation(
        current_key_transcript,
        &mut ecdsa_payload,
        &mut transcript_cache,
        height,
        &log,
    )?;
    if let Some(new_transcript) = update_next_key_transcript(
        registry_client,
        summary_registry_version,
        next_summary_registry_version,
        subnet_id,
        current_key_transcript,
        &mut next_key_transcript_creation,
        &mut ecdsa_payload.next_unused_transcript_id,
        &mut transcript_cache,
        height,
        log,
    )? {
        new_transcripts.push(new_transcript);
        ecdsa_payload_metrics.payload_metrics_inc("key_transcripts_created");
    };

    // Drop transcripts from last round and keep only the
    // ones created in this round.
    ecdsa_payload.idkg_transcripts.clear();
    for transcript in new_transcripts {
        ecdsa_payload
            .idkg_transcripts
            .insert(transcript.transcript_id, transcript);
    }

    update_completed_reshare_requests(
        &mut ecdsa_payload,
        current_key_transcript,
        &mut transcript_cache,
    );
    initiate_reshare_requests(
        &mut ecdsa_payload,
        current_key_transcript,
        &node_ids,
        get_reshare_requests(),
    );

    ecdsa_payload_metrics.payload_metrics_set(
        "signature_agreements",
        ecdsa_payload.signature_agreements.len() as i64,
    );
    ecdsa_payload_metrics.payload_metrics_set(
        "available_quadruples",
        ecdsa_payload.available_quadruples.len() as i64,
    );
    ecdsa_payload_metrics.payload_metrics_set(
        "ongoing_signatures",
        ecdsa_payload.ongoing_signatures.len() as i64,
    );
    ecdsa_payload_metrics.payload_metrics_set(
        "quaruples_in_creation",
        ecdsa_payload.quadruples_in_creation.len() as i64,
    );
    ecdsa_payload_metrics.payload_metrics_set(
        "ongoing_xnet_reshares",
        ecdsa_payload.ongoing_xnet_reshares.len() as i64,
    );
    ecdsa_payload_metrics.payload_metrics_set(
        "xnet_reshare_agreements",
        ecdsa_payload.xnet_reshare_agreements.len() as i64,
    );
    Ok(Some(ecdsa::EcdsaDataPayload {
        ecdsa_payload,
        next_key_transcript_creation,
    }))
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

/// Creating new quadruples if necessary by updating quadruples_in_creation,
/// considering currently avialable quadruples, quadruples in creation, and
/// ecdsa configs.
fn make_new_quadruples_if_needed(
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    ecdsa_config: &EcdsaConfig,
    ecdsa_payload: &mut ecdsa::EcdsaPayload,
) -> Result<(), EcdsaPayloadError> {
    let next_available_quadruple_id = ecdsa_payload
        .available_quadruples
        .keys()
        .chain(ecdsa_payload.quadruples_in_creation.keys())
        .max()
        .map(|x| x.increment())
        .unwrap_or_default();
    let num_quadruples =
        ecdsa_payload.available_quadruples.len() + ecdsa_payload.quadruples_in_creation.len();
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
        &mut ecdsa_payload.next_unused_transcript_id,
        &mut ecdsa_payload.quadruples_in_creation,
        next_available_quadruple_id,
    )
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
    payload: &mut ecdsa::EcdsaPayload,
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
fn update_signing_requests(
    signing_requests: &BTreeMap<ecdsa::RequestId, &SignWithEcdsaContext>,
    current_key_transcript: Option<&ecdsa::UnmaskedTranscript>,
    payload: &mut ecdsa::EcdsaPayload,
    log: ReplicaLogger,
) -> Result<(), EcdsaPayloadError> {
    if let Some(key_transcript) = current_key_transcript {
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
        for (request_id, sign_inputs) in new_requests {
            payload.ongoing_signatures.insert(request_id, sign_inputs);
        }
    }
    Ok(())
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
///
/// Note that when creating next key transcript we must use the registry version
/// that is going to be put into the next DKG summary.
fn update_next_key_transcript(
    registry_client: &dyn RegistryClient,
    current_registry_version: RegistryVersion,
    next_registry_version: RegistryVersion,
    subnet_id: SubnetId,
    current_key_transcript: Option<&ecdsa::UnmaskedTranscript>,
    next_key_transcript_creation: &mut ecdsa::KeyTranscriptCreation,
    next_unused_transcript_id: &mut IDkgTranscriptId,
    transcript_cache: &mut TranscriptBuilderCache,
    height: Height,
    log: ReplicaLogger,
) -> Result<Option<IDkgTranscript>, EcdsaPayloadError> {
    let dealers = get_subnet_nodes(registry_client, current_registry_version, subnet_id)?;
    let receivers = get_subnet_nodes(registry_client, next_registry_version, subnet_id)?;
    update_next_key_transcript_helper(
        &dealers,
        &receivers,
        current_registry_version,
        current_key_transcript,
        next_key_transcript_creation,
        next_unused_transcript_id,
        transcript_cache,
        height,
        log,
    )
}

fn update_next_key_transcript_helper(
    dealers: &[NodeId],
    receivers: &[NodeId],
    registry_version: RegistryVersion,
    current_key_transcript: Option<&ecdsa::UnmaskedTranscript>,
    next_key_transcript_creation: &mut ecdsa::KeyTranscriptCreation,
    next_unused_transcript_id: &mut IDkgTranscriptId,
    transcript_cache: &mut TranscriptBuilderCache,
    height: Height,
    log: ReplicaLogger,
) -> Result<Option<IDkgTranscript>, EcdsaPayloadError> {
    let mut new_transcript = None;
    match (current_key_transcript, &next_key_transcript_creation) {
        (Some(transcript), ecdsa::KeyTranscriptCreation::Begin) => {
            // We have an existing key transcript, need to reshare it to create next
            // Create a new reshare config when there is none
            let transcript_id = *next_unused_transcript_id;
            *next_unused_transcript_id = transcript_id.increment();
            let dealers_set = dealers.iter().copied().collect::<BTreeSet<_>>();
            let receivers_set = receivers.iter().copied().collect::<BTreeSet<_>>();
            if dealers_set != receivers_set {
                info!(
                    log,
                    "Node membership changed. Reshare key transcript from dealers {:?} to receivers {:?}",
                    dealers,
                    receivers
                );
            }
            *next_key_transcript_creation = ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(
                ecdsa::ReshareOfUnmaskedParams::new(
                    transcript_id,
                    dealers_set,
                    receivers_set,
                    registry_version,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    *transcript,
                ),
            );
        }
        (Some(_), ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(config)) => {
            // check if the next key transcript has been made
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
            {
                let transcript_ref = ecdsa::UnmaskedTranscript::try_from((height, transcript))?;
                *next_key_transcript_creation =
                    ecdsa::KeyTranscriptCreation::Created(transcript_ref);
                new_transcript = Some(transcript.clone());
            }
        }
        (None, ecdsa::KeyTranscriptCreation::Begin) => {
            // The first ECDSA key transcript has to be created, starting from a random
            // config.
            let transcript_id = *next_unused_transcript_id;
            *next_unused_transcript_id = transcript_id.increment();
            let dealers_set = dealers.iter().copied().collect::<BTreeSet<_>>();
            let receivers_set = receivers.iter().copied().collect::<BTreeSet<_>>();
            *next_key_transcript_creation = ecdsa::KeyTranscriptCreation::RandomTranscriptParams(
                ecdsa::RandomTranscriptParams::new(
                    transcript_id,
                    dealers_set,
                    receivers_set,
                    registry_version,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                ),
            );
        }
        (None, ecdsa::KeyTranscriptCreation::RandomTranscriptParams(config)) => {
            // Check if the random transcript has been created
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
            {
                let transcript_id = *next_unused_transcript_id;
                *next_unused_transcript_id = transcript_id.increment();
                let dealers_set = dealers.iter().copied().collect::<BTreeSet<_>>();
                let receivers_set = receivers.iter().copied().collect::<BTreeSet<_>>();
                let transcript_ref = ecdsa::MaskedTranscript::try_from((height, transcript))?;
                *next_key_transcript_creation = ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(
                    ecdsa::ReshareOfMaskedParams::new(
                        transcript_id,
                        dealers_set,
                        receivers_set,
                        registry_version,
                        AlgorithmId::ThresholdEcdsaSecp256k1,
                        transcript_ref,
                    ),
                );
                new_transcript = Some(transcript.clone());
            }
        }
        (None, ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(config)) => {
            // Check if the unmasked transcript has been created
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
            {
                let transcript_ref = ecdsa::UnmaskedTranscript::try_from((height, transcript))?;
                *next_key_transcript_creation =
                    ecdsa::KeyTranscriptCreation::Created(transcript_ref);
                new_transcript = Some(transcript.clone());
            }
        }
        (None, ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(_)) => {
            unreachable!("Unexpected ReshareOfUnmaskedParams for key transcript creation");
        }
        (_, ecdsa::KeyTranscriptCreation::Created(_)) => {
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
    current_key_transcript: Option<&ecdsa::UnmaskedTranscript>,
    payload: &mut ecdsa::EcdsaPayload,
    transcript_cache: &mut TranscriptBuilderCache,
    height: Height,
    log: &ReplicaLogger,
) -> Result<Vec<IDkgTranscript>, EcdsaPayloadError> {
    let mut newly_available = Vec::new();
    let mut new_transcripts = Vec::new();
    if let Some(key_transcript) = current_key_transcript {
        for (key, quadruple) in payload.quadruples_in_creation.iter_mut() {
            // Update quadruple with completed transcripts
            if quadruple.kappa_masked.is_none() {
                if let Some(transcript) = transcript_cache
                    .get_completed_transcript(quadruple.kappa_config.as_ref().transcript_id)
                {
                    debug!(
                        log,
                        "update_quadruples_in_creation: {:?} kappa_masked transcript is made", key
                    );
                    quadruple.kappa_masked =
                        Some(ecdsa::MaskedTranscript::try_from((height, transcript))?);
                    new_transcripts.push(transcript.clone());
                }
            }
            if quadruple.lambda_masked.is_none() {
                if let Some(transcript) = transcript_cache
                    .get_completed_transcript(quadruple.lambda_config.as_ref().transcript_id)
                {
                    debug!(
                        log,
                        "update_quadruples_in_creation: {:?} lamdba_masked transcript is made", key
                    );
                    quadruple.lambda_masked =
                        Some(ecdsa::MaskedTranscript::try_from((height, transcript))?);
                    new_transcripts.push(transcript.clone());
                }
            }
            if quadruple.kappa_unmasked.is_none() {
                if let Some(config) = &quadruple.unmask_kappa_config {
                    if let Some(transcript) =
                        transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
                    {
                        debug!(
                        log,
                        "update_quadruples_in_creation: {:?} kappa_unmasked transcript {:?} is made",
                        key,
                        transcript.get_type()
                    );
                        quadruple.kappa_unmasked =
                            Some(ecdsa::UnmaskedTranscript::try_from((height, transcript))?);
                        new_transcripts.push(transcript.clone());
                    }
                }
            }
            if quadruple.key_times_lambda.is_none() {
                if let Some(config) = &quadruple.key_times_lambda_config {
                    if let Some(transcript) =
                        transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
                    {
                        debug!(
                        log,
                        "update_quadruples_in_creation: {:?} key_times_lambda transcript is made",
                        key
                    );
                        quadruple.key_times_lambda =
                            Some(ecdsa::MaskedTranscript::try_from((height, transcript))?);
                        new_transcripts.push(transcript.clone());
                    }
                }
            }
            if quadruple.kappa_times_lambda.is_none() {
                if let Some(config) = &quadruple.kappa_times_lambda_config {
                    if let Some(transcript) =
                        transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
                    {
                        debug!(
                        log,
                        "update_quadruples_in_creation: {:?} kappa_times_lambda transcript is made",
                        key
                    );
                        quadruple.kappa_times_lambda =
                            Some(ecdsa::MaskedTranscript::try_from((height, transcript))?);
                        new_transcripts.push(transcript.clone());
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

/// Checks for new reshare requests from execution and initiates
/// the processing.
/// TODO: in future, we may need to maintain a key transcript per supported key_id,
/// and reshare the one specified by reshare_request.key_id.
fn initiate_reshare_requests(
    payload: &mut ecdsa::EcdsaPayload,
    current_key_transcript: Option<&ecdsa::UnmaskedTranscript>,
    subnet_nodes: &[NodeId],
    reshare_requests: BTreeSet<ecdsa::EcdsaReshareRequest>,
) {
    let key_transcript = match current_key_transcript {
        Some(key) => key,
        None => return,
    };

    for request in reshare_requests {
        // Ignore requests we already know about
        if payload.ongoing_xnet_reshares.contains_key(&request)
            || payload.xnet_reshare_agreements.contains_key(&request)
        {
            continue;
        }

        // Set up the transcript params for the new request
        let transcript_id = payload.next_unused_transcript_id;
        payload.next_unused_transcript_id = transcript_id.increment();
        let dealers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
        let receivers = request
            .receiving_node_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let transcript_params = ecdsa::ReshareOfUnmaskedParams::new(
            transcript_id,
            dealers,
            receivers,
            // TODO: should it be source subnet registry version?
            request.registry_version,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            *key_transcript,
        );
        payload
            .ongoing_xnet_reshares
            .insert(request, transcript_params);
    }
}

/// Checks and updates the completed reshare requests.
fn update_completed_reshare_requests(
    payload: &mut ecdsa::EcdsaPayload,
    current_key_transcript: Option<&ecdsa::UnmaskedTranscript>,
    transcript_cache: &mut TranscriptBuilderCache,
) {
    if current_key_transcript.is_none() {
        return;
    }

    let mut completed_reshares = BTreeMap::new();
    for (request, reshare_param) in &payload.ongoing_xnet_reshares {
        let transcript_id = reshare_param.as_ref().transcript_id;
        let transcript = match transcript_cache.get_completed_transcript(transcript_id) {
            Some(transcript) => transcript,
            None => continue,
        };

        let mut dealings = Vec::new();
        for signed_dealing in transcript.verified_dealings.values() {
            let dealer = signed_dealing.dealing.idkg_dealing.dealer_id;
            dealings.push((dealer, signed_dealing.dealing.idkg_dealing.clone()));
        }

        completed_reshares.insert(
            request.clone(),
            ecdsa::EcdsaReshareResponse {
                reshare_param: reshare_param.clone(),
                dealings,
            },
        );
    }

    for (request, response) in completed_reshares {
        payload.ongoing_xnet_reshares.remove(&request);
        payload.xnet_reshare_agreements.insert(
            request.clone(),
            ecdsa::CompletedReshareRequest::Unreported(Box::new(response)),
        );
    }
}

/// Translates the reshare requests in the replicated state to the internal format
fn get_reshare_requests() -> BTreeSet<ecdsa::EcdsaReshareRequest> {
    // TODO: once the replicated state context is defined for resharing requests,
    // read/translate from replicated state
    BTreeSet::new()
}

/// Wrapper to build the chain cache and perform sanity checks on the returned chain
pub fn block_chain_cache(
    pool_reader: &PoolReader<'_>,
    start: &Block,
    end: &Block,
) -> Result<Arc<dyn ConsensusBlockChain>, EcdsaPayloadError> {
    let chain = build_consensus_block_chain(pool_reader.pool(), start, end);
    let expected_len = (end.height().get() - start.height().get() + 1) as usize;
    let chain_len = chain.len();
    if chain_len == expected_len {
        Ok(chain)
    } else {
        Err(EcdsaPayloadError::InvalidChainCacheError(format!(
            "Invalid chain cache length: expected = {:?}, actual = {:?}, \
             start = {:?}, end = {:?}, tip = {:?}, \
             notarized_height = {:?}, finalized_height = {:?}, CUP height = {:?}",
            expected_len,
            chain_len,
            start.height(),
            end.height(),
            chain.tip().height(),
            pool_reader.get_notarized_height(),
            pool_reader.get_finalized_height(),
            pool_reader.get_catch_up_height()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::mocks::{dependencies, Dependencies};
    use crate::ecdsa::utils::test_utils::*;
    use ic_artifact_pool::ecdsa_pool::EcdsaPoolImpl;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        generate_key_transcript, run_idkg_and_create_and_verify_transcript,
        CanisterThresholdSigTestEnvironment,
    };
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::types::v1 as pb;
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
    use ic_types::crypto::canister_threshold_sig::ThresholdEcdsaCombinedSignature;
    use ic_types::{messages::CallbackId, Height, RegistryVersion};
    use std::collections::BTreeSet;
    use std::convert::TryInto;

    fn empty_ecdsa_payload(subnet_id: SubnetId) -> ecdsa::EcdsaPayload {
        ecdsa::EcdsaPayload {
            signature_agreements: BTreeMap::new(),
            ongoing_signatures: BTreeMap::new(),
            available_quadruples: BTreeMap::new(),
            quadruples_in_creation: BTreeMap::new(),
            next_unused_transcript_id: IDkgTranscriptId::new(subnet_id, 0),
            idkg_transcripts: BTreeMap::new(),
            ongoing_xnet_reshares: BTreeMap::new(),
            xnet_reshare_agreements: BTreeMap::new(),
        }
    }

    fn empty_ecdsa_summary_payload(
        subnet_id: SubnetId,
        current_key_transcript: ecdsa::UnmaskedTranscript,
    ) -> ecdsa::EcdsaSummaryPayload {
        ecdsa::EcdsaSummaryPayload {
            ecdsa_payload: empty_ecdsa_payload(subnet_id),
            current_key_transcript,
        }
    }

    fn empty_ecdsa_data_payload(subnet_id: SubnetId) -> ecdsa::EcdsaDataPayload {
        ecdsa::EcdsaDataPayload {
            ecdsa_payload: empty_ecdsa_payload(subnet_id),
            next_key_transcript_creation: ecdsa::KeyTranscriptCreation::Begin,
        }
    }

    fn create_summary_block_with_transcripts(
        subnet_id: SubnetId,
        height: Height,
        current_key_transcript: (ecdsa::UnmaskedTranscript, IDkgTranscript),
        transcripts: Vec<BTreeMap<ecdsa::TranscriptRef, IDkgTranscript>>,
    ) -> BlockPayload {
        let mut ecdsa_summary = empty_ecdsa_summary_payload(subnet_id, current_key_transcript.0);
        ecdsa_summary.ecdsa_payload.idkg_transcripts.insert(
            current_key_transcript.0.as_ref().transcript_id,
            current_key_transcript.1,
        );
        for idkg_transcripts in transcripts {
            for (transcript_ref, transcript) in idkg_transcripts {
                ecdsa_summary
                    .ecdsa_payload
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
                    .ecdsa_payload
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

    fn create_reshare_request(num_nodes: u64, registry_version: u64) -> ecdsa::EcdsaReshareRequest {
        ecdsa::EcdsaReshareRequest {
            key_id: vec![],
            receiving_node_ids: (0..num_nodes).map(node_test_id).collect::<Vec<_>>(),
            registry_version: RegistryVersion::from(registry_version),
        }
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
    fn test_ecdsa_make_new_quadruples_if_needed() {
        let subnet_id = subnet_test_id(1);
        let subnet_nodes = (0..10).map(node_test_id).collect::<Vec<_>>();
        let summary_registry_version = RegistryVersion::new(10);
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
        let quadruples_to_create_in_advance = 5;
        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance,
            ..EcdsaConfig::default()
        };
        // Success case
        let result = make_new_quadruples_if_needed(
            &subnet_nodes,
            summary_registry_version,
            &ecdsa_config,
            &mut ecdsa_payload,
        );
        assert!(result.is_ok());
        assert_eq!(
            ecdsa_payload.quadruples_in_creation.len(),
            quadruples_to_create_in_advance as usize
        );
        // Check transcript ids are unique
        let mut transcript_ids = BTreeSet::new();
        for quadruple in ecdsa_payload.quadruples_in_creation.iter() {
            transcript_ids.insert(quadruple.1.kappa_config.as_ref().transcript_id);
            transcript_ids.insert(quadruple.1.lambda_config.as_ref().transcript_id);
        }
        assert_eq!(
            transcript_ids.len(),
            2 * quadruples_to_create_in_advance as usize
        );
        assert_eq!(
            transcript_ids.iter().max().unwrap().increment(),
            ecdsa_payload.next_unused_transcript_id
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
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
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
            let transcript_builder = TestEcdsaTranscriptBuilder::new();
            let ecdsa_pool =
                EcdsaPoolImpl::new(pool_config, no_op_logger(), MetricsRegistry::new());
            let mut transcript_cache =
                TranscriptBuilderCache::new(&transcript_builder, &ecdsa_pool);

            // 1. Nothing initially, masked transcript creation should start
            let cur_height = Height::new(10);
            let mut payload = empty_ecdsa_data_payload(subnet_id);
            let result = update_next_key_transcript_helper(
                &subnet_nodes,
                &subnet_nodes,
                registry_version,
                None,
                &mut payload.next_key_transcript_creation,
                &mut payload.ecdsa_payload.next_unused_transcript_id,
                &mut transcript_cache,
                cur_height,
                no_op_logger(),
            );
            matches!(result, Ok(None));
            assert_eq!(payload.ecdsa_payload.next_unused_transcript_id.id(), 1);
            assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
            assert_eq!(config_ids(&payload), [0]);

            // 2. Masked random transcript is created, should start reshare of the masked
            // transcript.
            let cur_height = Height::new(20);
            let masked_transcript = {
                let param = match &payload.next_key_transcript_creation {
                    ecdsa::KeyTranscriptCreation::RandomTranscriptParams(param) => param.clone(),
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
            transcript_builder
                .add_transcript(masked_transcript.transcript_id, masked_transcript.clone());
            let result = update_next_key_transcript_helper(
                &subnet_nodes,
                &subnet_nodes,
                registry_version,
                None,
                &mut payload.next_key_transcript_creation,
                &mut payload.ecdsa_payload.next_unused_transcript_id,
                &mut transcript_cache,
                cur_height,
                no_op_logger(),
            );
            let completed_transcript = result.unwrap().unwrap();
            assert_eq!(completed_transcript, masked_transcript);
            block_reader.add_transcript(
                ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
                completed_transcript,
            );
            assert_eq!(payload.ecdsa_payload.next_unused_transcript_id.id(), 2);
            assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
            assert_eq!(config_ids(&payload), [1]);

            // 3. Unmasked transcript is created, should complete the boot strap sequence
            let cur_height = Height::new(30);
            let unmasked_transcript = {
                let param = match &payload.next_key_transcript_creation {
                    ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(param) => param.clone(),
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
            transcript_builder.add_transcript(
                unmasked_transcript.transcript_id,
                unmasked_transcript.clone(),
            );
            let result = update_next_key_transcript_helper(
                &subnet_nodes,
                &subnet_nodes,
                registry_version,
                None,
                &mut payload.next_key_transcript_creation,
                &mut payload.ecdsa_payload.next_unused_transcript_id,
                &mut transcript_cache,
                cur_height,
                no_op_logger(),
            );
            let completed_transcript = result.unwrap().unwrap();
            assert_eq!(completed_transcript, unmasked_transcript);
            block_reader.add_transcript(
                ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
                completed_transcript,
            );
            assert_eq!(payload.ecdsa_payload.next_unused_transcript_id.id(), 2);
            assert_eq!(payload.iter_transcript_configs_in_creation().count(), 0);
            assert!(config_ids(&payload).is_empty());
            let current_key_transcript =
                ecdsa::UnmaskedTranscript::try_from((cur_height, &unmasked_transcript)).unwrap();
            ecdsa::TranscriptRef::new(cur_height, unmasked_transcript.transcript_id);
            match &payload.next_key_transcript_creation {
                ecdsa::KeyTranscriptCreation::Created(unmasked) => {
                    assert_eq!(*unmasked.as_ref(), *current_key_transcript.as_ref());
                }
                _ => panic!(
                    "Unexpected state: {:?}",
                    payload.next_key_transcript_creation
                ),
            }

            // 4. Reshare the current key transcript to get the next one
            let cur_height = Height::new(40);
            payload.next_key_transcript_creation = ecdsa::KeyTranscriptCreation::Begin;
            let result = update_next_key_transcript_helper(
                &subnet_nodes,
                &subnet_nodes,
                registry_version,
                Some(&current_key_transcript),
                &mut payload.next_key_transcript_creation,
                &mut payload.ecdsa_payload.next_unused_transcript_id,
                &mut transcript_cache,
                cur_height,
                no_op_logger(),
            );
            matches!(result, Ok(None));
            assert_eq!(payload.ecdsa_payload.next_unused_transcript_id.id(), 3);
            assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
            assert_eq!(config_ids(&payload), [2]);

            // 5. Reshare completes to get the next unmasked transcript
            let cur_height = Height::new(50);
            let unmasked_transcript = {
                let param = match &payload.next_key_transcript_creation {
                    ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(param) => param.clone(),
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
            transcript_builder.add_transcript(
                unmasked_transcript.transcript_id,
                unmasked_transcript.clone(),
            );
            let result = update_next_key_transcript_helper(
                &subnet_nodes,
                &subnet_nodes,
                registry_version,
                Some(&current_key_transcript),
                &mut payload.next_key_transcript_creation,
                &mut payload.ecdsa_payload.next_unused_transcript_id,
                &mut transcript_cache,
                cur_height,
                no_op_logger(),
            );
            let completed_transcript = result.unwrap().unwrap();
            assert_eq!(completed_transcript, unmasked_transcript);
            assert_eq!(payload.ecdsa_payload.next_unused_transcript_id.id(), 3);
            assert_eq!(payload.iter_transcript_configs_in_creation().count(), 0);
            assert!(config_ids(&payload).is_empty());
            let current_key_transcript =
                ecdsa::UnmaskedTranscript::try_from((cur_height, &unmasked_transcript)).unwrap();
            match &payload.next_key_transcript_creation {
                ecdsa::KeyTranscriptCreation::Created(unmasked) => {
                    assert_eq!(*unmasked.as_ref(), *current_key_transcript.as_ref());
                }
                _ => panic!(
                    "Unexpected state: {:?}",
                    payload.next_key_transcript_creation
                ),
            }
        })
    }

    fn create_new_quadruple_in_creation(
        subnet_nodes: &[NodeId],
        registry_version: RegistryVersion,
        next_unused_transcript_id: &mut IDkgTranscriptId,
        quadruple_id: &mut ecdsa::QuadrupleId,
        quadruples_in_creation: &mut BTreeMap<ecdsa::QuadrupleId, ecdsa::QuadrupleInCreation>,
    ) -> (ecdsa::RandomTranscriptParams, ecdsa::RandomTranscriptParams) {
        let kappa_config_ref =
            new_random_config(subnet_nodes, registry_version, next_unused_transcript_id).unwrap();
        let lambda_config_ref =
            new_random_config(subnet_nodes, registry_version, next_unused_transcript_id).unwrap();
        quadruples_in_creation.insert(
            *quadruple_id,
            ecdsa::QuadrupleInCreation::new(kappa_config_ref.clone(), lambda_config_ref.clone()),
        );
        *quadruple_id = quadruple_id.increment();
        (kappa_config_ref, lambda_config_ref)
    }

    #[test]
    fn test_ecdsa_update_quadruples_in_creation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let num_of_nodes = 4;
            let subnet_id = subnet_test_id(1);
            let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
            let registry_version = env.newest_registry_version;
            let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
            let algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;
            let mut block_reader = TestEcdsaBlockReader::new();
            let transcript_builder = TestEcdsaTranscriptBuilder::new();
            let ecdsa_pool =
                EcdsaPoolImpl::new(pool_config, no_op_logger(), MetricsRegistry::new());
            let mut transcript_cache =
                TranscriptBuilderCache::new(&transcript_builder, &ecdsa_pool);

            let key_transcript = generate_key_transcript(&env, algorithm);
            let key_transcript_ref =
                ecdsa::UnmaskedTranscript::try_from((Height::new(100), &key_transcript)).unwrap();
            block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript);
            let mut payload = empty_ecdsa_payload(subnet_id);
            let mut next_quadruple_id = ecdsa::QuadrupleId(0);
            // Start quadruple creation
            let (kappa_config_ref, lambda_config_ref) = create_new_quadruple_in_creation(
                &subnet_nodes,
                registry_version,
                &mut payload.next_unused_transcript_id,
                &mut next_quadruple_id,
                &mut payload.quadruples_in_creation,
            );
            // 0. No action case
            let cur_height = Height::new(1000);
            let result = update_quadruples_in_creation(
                Some(&key_transcript_ref),
                &mut payload,
                &mut transcript_cache,
                cur_height,
                &no_op_logger(),
            );
            assert!(result.unwrap().is_empty());
            let config_ids = |payload: &ecdsa::EcdsaPayload| {
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
                let param = kappa_config_ref.as_ref();
                run_idkg_and_create_and_verify_transcript(
                    &param.translate(&block_reader).unwrap(),
                    &env.crypto_components,
                )
            };
            transcript_builder
                .add_transcript(kappa_config_ref.as_ref().transcript_id, kappa_transcript);
            let cur_height = Height::new(2000);
            let result = update_quadruples_in_creation(
                Some(&key_transcript_ref),
                &mut payload,
                &mut transcript_cache,
                cur_height,
                &no_op_logger(),
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
            transcript_builder
                .add_transcript(lambda_config_ref.as_ref().transcript_id, lambda_transcript);
            let cur_height = Height::new(3000);
            let result = update_quadruples_in_creation(
                Some(&key_transcript_ref),
                &mut payload,
                &mut transcript_cache,
                cur_height,
                &no_op_logger(),
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
            transcript_builder.add_transcript(kappa_unmasked_config_id, kappa_unmasked_transcript);
            let cur_height = Height::new(4000);
            let result = update_quadruples_in_creation(
                Some(&key_transcript_ref),
                &mut payload,
                &mut transcript_cache,
                cur_height,
                &no_op_logger(),
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
            transcript_builder
                .add_transcript(kappa_times_lambda_config_id, kappa_times_lambda_transcript);
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
            transcript_builder
                .add_transcript(key_times_lambda_config_id, key_times_lambda_transcript);
            let cur_height = Height::new(5000);
            let result = update_quadruples_in_creation(
                Some(&key_transcript_ref),
                &mut payload,
                &mut transcript_cache,
                cur_height,
                &no_op_logger(),
            )
            .unwrap();
            assert_eq!(result.len(), 2);
            // check if new config is made
            assert_eq!(payload.available_quadruples.len(), 1);
            assert_eq!(payload.next_unused_transcript_id.id(), 5);
            assert!(config_ids(&payload).is_empty());
        })
    }

    #[test]
    fn test_ecdsa_initiate_reshare_requests() {
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
        let mut payload = empty_ecdsa_payload(subnet_id);
        let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
        let algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;

        let req_1 = create_reshare_request(1, 1);
        let req_2 = create_reshare_request(2, 2);
        let mut reshare_requests = BTreeSet::new();
        reshare_requests.insert(req_1.clone());
        reshare_requests.insert(req_2.clone());

        // Key not yet created, requests should not be accepted
        initiate_reshare_requests(&mut payload, None, &subnet_nodes, reshare_requests.clone());
        assert!(payload.ongoing_xnet_reshares.is_empty());
        assert!(payload.xnet_reshare_agreements.is_empty());

        // Two new requests, should be accepted
        let key_transcript = generate_key_transcript(&env, algorithm);
        let key_transcript_ref =
            ecdsa::UnmaskedTranscript::try_from((Height::new(100), &key_transcript)).unwrap();
        initiate_reshare_requests(
            &mut payload,
            Some(&key_transcript_ref),
            &subnet_nodes,
            reshare_requests.clone(),
        );
        assert_eq!(payload.ongoing_xnet_reshares.len(), 2);
        assert!(payload.ongoing_xnet_reshares.contains_key(&req_1));
        assert!(payload.ongoing_xnet_reshares.contains_key(&req_2));
        assert!(payload.xnet_reshare_agreements.is_empty());

        // One more new request, it should get added incrementally
        let req_3 = create_reshare_request(3, 3);
        reshare_requests.insert(req_3.clone());
        initiate_reshare_requests(
            &mut payload,
            Some(&key_transcript_ref),
            &subnet_nodes,
            reshare_requests.clone(),
        );
        assert_eq!(payload.ongoing_xnet_reshares.len(), 3);
        assert!(payload.ongoing_xnet_reshares.contains_key(&req_1));
        assert!(payload.ongoing_xnet_reshares.contains_key(&req_2));
        assert!(payload.ongoing_xnet_reshares.contains_key(&req_3));
        assert!(payload.xnet_reshare_agreements.is_empty());

        // Request for an entry already in completed list, should
        // not be accepted
        let req_4 = create_reshare_request(4, 4);
        reshare_requests.insert(req_4.clone());
        payload
            .xnet_reshare_agreements
            .insert(req_4, ecdsa::CompletedReshareRequest::ReportedToExecution);
        initiate_reshare_requests(
            &mut payload,
            Some(&key_transcript_ref),
            &subnet_nodes,
            reshare_requests.clone(),
        );
        assert_eq!(payload.ongoing_xnet_reshares.len(), 3);
        assert_eq!(payload.xnet_reshare_agreements.len(), 1);
    }

    #[test]
    fn test_ecdsa_update_completed_reshare_requests() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let num_of_nodes = 4;
            let subnet_id = subnet_test_id(1);
            let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
            let mut payload = empty_ecdsa_payload(subnet_id);
            let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
            let algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;
            let transcript_builder = TestEcdsaTranscriptBuilder::new();
            let ecdsa_pool =
                EcdsaPoolImpl::new(pool_config, no_op_logger(), MetricsRegistry::new());
            let mut transcript_cache =
                TranscriptBuilderCache::new(&transcript_builder, &ecdsa_pool);

            let req_1 = create_reshare_request(1, 1);
            let req_2 = create_reshare_request(2, 2);
            let mut reshare_requests = BTreeSet::new();

            reshare_requests.insert(req_1.clone());
            reshare_requests.insert(req_2.clone());
            let key_transcript = generate_key_transcript(&env, algorithm);
            let key_transcript_ref =
                ecdsa::UnmaskedTranscript::try_from((Height::new(100), &key_transcript)).unwrap();
            initiate_reshare_requests(
                &mut payload,
                Some(&key_transcript_ref),
                &subnet_nodes,
                reshare_requests.clone(),
            );
            assert_eq!(payload.ongoing_xnet_reshares.len(), 2);
            assert!(payload.ongoing_xnet_reshares.contains_key(&req_1));
            assert!(payload.ongoing_xnet_reshares.contains_key(&req_2));
            assert!(payload.xnet_reshare_agreements.is_empty());

            // Request 1 completes, it should be moved from in progress -> completed
            let req_id_1 = payload
                .ongoing_xnet_reshares
                .get(&req_1)
                .unwrap()
                .as_ref()
                .transcript_id;
            transcript_builder
                .add_transcript(req_id_1, create_transcript(req_id_1, &[node_test_id(1)]));
            update_completed_reshare_requests(
                &mut payload,
                Some(&key_transcript_ref),
                &mut transcript_cache,
            );
            assert_eq!(payload.ongoing_xnet_reshares.len(), 1);
            assert!(payload.ongoing_xnet_reshares.contains_key(&req_2));
            assert_eq!(payload.xnet_reshare_agreements.len(), 1);
            assert!(matches!(
                payload.xnet_reshare_agreements.get(&req_1).unwrap(),
                ecdsa::CompletedReshareRequest::Unreported(_)
            ));

            // Request 2 completes, it should be moved from in progress -> completed
            let req_id_2 = payload
                .ongoing_xnet_reshares
                .get(&req_2)
                .unwrap()
                .as_ref()
                .transcript_id;
            transcript_builder
                .add_transcript(req_id_2, create_transcript(req_id_2, &[node_test_id(2)]));
            update_completed_reshare_requests(
                &mut payload,
                Some(&key_transcript_ref),
                &mut transcript_cache,
            );
            assert!(payload.ongoing_xnet_reshares.is_empty());
            assert_eq!(payload.xnet_reshare_agreements.len(), 2);
            assert!(matches!(
                payload.xnet_reshare_agreements.get(&req_1).unwrap(),
                ecdsa::CompletedReshareRequest::Unreported(_)
            ));
            assert!(matches!(
                payload.xnet_reshare_agreements.get(&req_2).unwrap(),
                ecdsa::CompletedReshareRequest::Unreported(_)
            ));

            // No further change should happen
            update_completed_reshare_requests(
                &mut payload,
                Some(&key_transcript_ref),
                &mut transcript_cache,
            );
            assert!(payload.ongoing_xnet_reshares.is_empty());
            assert_eq!(payload.xnet_reshare_agreements.len(), 2);
        })
    }

    #[test]
    fn test_ecdsa_update_summary_refs() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { mut pool, .. } = dependencies(pool_config.clone(), 1);
            let subnet_id = subnet_test_id(1);
            let mut expected_transcripts = BTreeSet::new();
            let transcript_builder = TestEcdsaTranscriptBuilder::new();
            let ecdsa_pool =
                EcdsaPoolImpl::new(pool_config, no_op_logger(), MetricsRegistry::new());
            let mut transcript_cache =
                TranscriptBuilderCache::new(&transcript_builder, &ecdsa_pool);
            let mut add_expected_transcripts = |trancript_refs: Vec<ecdsa::TranscriptRef>| {
                for transcript_ref in trancript_refs {
                    expected_transcripts.insert(transcript_ref.transcript_id);
                }
            };
            let create_key_transcript = || {
                let env = CanisterThresholdSigTestEnvironment::new(4);
                generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1)
            };

            // Create a summary block with transcripts
            let summary_height = Height::new(5);
            let env = CanisterThresholdSigTestEnvironment::new(4);
            let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
            let key_transcript = create_key_transcript();
            let key_transcript_ref =
                ecdsa::UnmaskedTranscript::try_from((summary_height, &key_transcript)).unwrap();
            let reshare_key_transcript = create_key_transcript();
            let reshare_key_transcript_ref =
                ecdsa::UnmaskedTranscript::try_from((summary_height, &reshare_key_transcript))
                    .unwrap();
            let reshare_params_1 = ecdsa::ReshareOfUnmaskedParams::new(
                create_transcript_id(1001),
                BTreeSet::new(),
                BTreeSet::new(),
                RegistryVersion::from(1001),
                AlgorithmId::ThresholdEcdsaSecp256k1,
                reshare_key_transcript_ref,
            );
            let mut reshare_refs = BTreeMap::new();
            reshare_refs.insert(*reshare_key_transcript_ref.as_ref(), reshare_key_transcript);

            let inputs_1 = create_sig_inputs_with_height(91, summary_height);
            let inputs_2 = create_sig_inputs_with_height(92, summary_height);
            let summary_block = create_summary_block_with_transcripts(
                subnet_id,
                summary_height,
                (key_transcript_ref, key_transcript),
                vec![
                    inputs_1.idkg_transcripts.clone(),
                    inputs_2.idkg_transcripts.clone(),
                    reshare_refs,
                ],
            );
            add_block(summary_block, summary_height.get(), &mut pool);
            let sig_1 = inputs_1.sig_inputs_ref;
            let quad_1 = inputs_2.sig_inputs_ref.presig_quadruple_ref;

            // Create payload blocks with transcripts
            let payload_height_1 = Height::new(10);
            let inputs_1 = create_sig_inputs_with_height(93, payload_height_1);
            let inputs_2 = create_sig_inputs_with_height(94, payload_height_1);
            let reshare_key_transcript = create_key_transcript();
            let reshare_key_transcript_ref =
                ecdsa::UnmaskedTranscript::try_from((payload_height_1, &reshare_key_transcript))
                    .unwrap();
            let reshare_params_2 = ecdsa::ReshareOfUnmaskedParams::new(
                create_transcript_id(2001),
                BTreeSet::new(),
                BTreeSet::new(),
                RegistryVersion::from(2001),
                AlgorithmId::ThresholdEcdsaSecp256k1,
                reshare_key_transcript_ref,
            );
            let mut reshare_refs = BTreeMap::new();
            reshare_refs.insert(*reshare_key_transcript_ref.as_ref(), reshare_key_transcript);
            let payload_block_1 = create_payload_block_with_transcripts(
                subnet_id,
                summary_height,
                vec![
                    inputs_1.idkg_transcripts.clone(),
                    inputs_2.idkg_transcripts.clone(),
                    reshare_refs,
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
            let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
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

            let req_1 = create_reshare_request(1, 1);
            let req_2 = create_reshare_request(2, 2);
            let response = ecdsa::EcdsaReshareResponse {
                reshare_param: reshare_params_2.clone(),
                dealings: vec![],
            };
            ecdsa_payload
                .ongoing_xnet_reshares
                .insert(req_1, reshare_params_1.clone());
            ecdsa_payload.xnet_reshare_agreements.insert(
                req_2,
                ecdsa::CompletedReshareRequest::Unreported(Box::new(response)),
            );

            add_expected_transcripts(vec![*key_transcript_ref.as_ref()]);
            add_expected_transcripts(sig_1.get_refs());
            add_expected_transcripts(sig_2.get_refs());
            add_expected_transcripts(quad_1.get_refs());
            add_expected_transcripts(quad_2.get_refs());
            add_expected_transcripts(reshare_params_1.as_ref().get_refs());
            add_expected_transcripts(reshare_params_2.as_ref().get_refs());

            // Add some quadruples in creation
            let mut next_quadruple_id = ecdsa::QuadrupleId(100);
            let block_reader = TestEcdsaBlockReader::new();
            let (kappa_config_ref, _lambda_config_ref) = create_new_quadruple_in_creation(
                &subnet_nodes,
                env.newest_registry_version,
                &mut ecdsa_payload.next_unused_transcript_id,
                &mut next_quadruple_id,
                &mut ecdsa_payload.quadruples_in_creation,
            );
            let kappa_transcript = {
                let param = kappa_config_ref.as_ref();
                run_idkg_and_create_and_verify_transcript(
                    &param.translate(&block_reader).unwrap(),
                    &env.crypto_components,
                )
            };
            transcript_builder.add_transcript(
                kappa_config_ref.as_ref().transcript_id,
                kappa_transcript.clone(),
            );
            ecdsa_payload
                .idkg_transcripts
                .insert(kappa_config_ref.as_ref().transcript_id, kappa_transcript);
            let parent_block_height = Height::new(15);
            let result = update_quadruples_in_creation(
                Some(&key_transcript_ref),
                &mut ecdsa_payload,
                &mut transcript_cache,
                parent_block_height,
                &no_op_logger(),
            )
            .unwrap();
            assert_eq!(result.len(), 1);
            add_expected_transcripts(
                ecdsa_payload
                    .quadruples_in_creation
                    .values()
                    .next()
                    .unwrap()
                    .get_refs(),
            );

            let parent_block_payload = BlockPayload::Data(DataPayload {
                batch: BatchPayload::default(),
                dealings: Dealings::new_empty(summary_height),
                ecdsa: Some(ecdsa::EcdsaDataPayload {
                    ecdsa_payload: ecdsa_payload.clone(),
                    next_key_transcript_creation: ecdsa::KeyTranscriptCreation::Begin,
                }),
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
                ecdsa_payload: ecdsa_payload.clone(),
                current_key_transcript: key_transcript_ref,
            };
            assert_ne!(
                summary.current_key_transcript.as_ref().height,
                new_summary_height
            );
            for ongoing_signature in summary.ecdsa_payload.ongoing_signatures.values() {
                for transcript_ref in ongoing_signature.get_refs() {
                    assert_ne!(transcript_ref.height, new_summary_height);
                }
            }
            for available_quadruple in summary.ecdsa_payload.available_quadruples.values() {
                for transcript_ref in available_quadruple.get_refs() {
                    assert_ne!(transcript_ref.height, new_summary_height);
                }
            }
            for quadruple_in_creation in summary.ecdsa_payload.quadruples_in_creation.values() {
                for transcript_ref in quadruple_in_creation.get_refs() {
                    assert_ne!(transcript_ref.height, new_summary_height);
                }
            }
            for reshare_params in summary.ecdsa_payload.ongoing_xnet_reshares.values() {
                for transcript_ref in reshare_params.as_ref().get_refs() {
                    assert_ne!(transcript_ref.height, new_summary_height);
                }
            }
            for reshare_agreement in summary.ecdsa_payload.xnet_reshare_agreements.values_mut() {
                if let ecdsa::CompletedReshareRequest::Unreported(response) = reshare_agreement {
                    for transcript_ref in response.reshare_param.as_ref().get_refs() {
                        assert_ne!(transcript_ref.height, new_summary_height);
                    }
                }
            }

            assert!(update_summary_refs(
                &mut summary,
                &pool_reader,
                &parent_block,
                &EcdsaPayloadMetrics::new(MetricsRegistry::new()),
                &no_op_logger()
            )
            .is_ok());

            // Verify that all the transcript references in the parent block
            // have been updated to point to the new summary height
            assert_eq!(
                summary.current_key_transcript.as_ref().height,
                new_summary_height
            );
            for ongoing_signature in summary.ecdsa_payload.ongoing_signatures.values() {
                for transcript_ref in ongoing_signature.get_refs() {
                    assert_eq!(transcript_ref.height, new_summary_height);
                }
            }
            for available_quadruple in summary.ecdsa_payload.available_quadruples.values() {
                for transcript_ref in available_quadruple.get_refs() {
                    assert_eq!(transcript_ref.height, new_summary_height);
                }
            }
            for quadruple_in_creation in summary.ecdsa_payload.quadruples_in_creation.values() {
                for transcript_ref in quadruple_in_creation.get_refs() {
                    assert_eq!(transcript_ref.height, new_summary_height);
                }
            }
            for reshare_params in summary.ecdsa_payload.ongoing_xnet_reshares.values() {
                for transcript_ref in reshare_params.as_ref().get_refs() {
                    assert_eq!(transcript_ref.height, new_summary_height);
                }
            }
            for reshare_agreement in summary.ecdsa_payload.xnet_reshare_agreements.values_mut() {
                if let ecdsa::CompletedReshareRequest::Unreported(response) = reshare_agreement {
                    for transcript_ref in response.reshare_param.as_ref().get_refs() {
                        assert_eq!(transcript_ref.height, new_summary_height);
                    }
                }
            }

            // Verify that all the transcript references in the parent block
            // have been resolved/copied into the summary block
            assert_eq!(
                summary.ecdsa_payload.idkg_transcripts.len(),
                expected_transcripts.len()
            );
            for transcript_id in summary.ecdsa_payload.idkg_transcripts.keys() {
                assert!(expected_transcripts.contains(transcript_id));
            }
        })
    }

    #[test]
    fn test_ecdsa_summary_proto_conversion() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { mut pool, .. } = dependencies(pool_config.clone(), 1);
            let subnet_id = subnet_test_id(1);
            let transcript_builder = TestEcdsaTranscriptBuilder::new();
            let ecdsa_pool =
                EcdsaPoolImpl::new(pool_config, no_op_logger(), MetricsRegistry::new());
            let mut transcript_cache =
                TranscriptBuilderCache::new(&transcript_builder, &ecdsa_pool);
            let create_key_transcript = || {
                let env = CanisterThresholdSigTestEnvironment::new(4);
                generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1)
            };

            // Create a summary block with transcripts
            let summary_height = Height::new(5);
            let env = CanisterThresholdSigTestEnvironment::new(4);
            let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
            let key_transcript = create_key_transcript();
            let key_transcript_ref =
                ecdsa::UnmaskedTranscript::try_from((summary_height, &key_transcript)).unwrap();
            let reshare_key_transcript = create_key_transcript();
            let reshare_key_transcript_ref =
                ecdsa::UnmaskedTranscript::try_from((summary_height, &reshare_key_transcript))
                    .unwrap();
            let reshare_params_1 = ecdsa::ReshareOfUnmaskedParams::new(
                create_transcript_id(1001),
                BTreeSet::new(),
                BTreeSet::new(),
                RegistryVersion::from(1001),
                AlgorithmId::ThresholdEcdsaSecp256k1,
                reshare_key_transcript_ref,
            );
            let mut reshare_refs = BTreeMap::new();
            reshare_refs.insert(*reshare_key_transcript_ref.as_ref(), reshare_key_transcript);

            let inputs_1 = create_sig_inputs_with_height(91, summary_height);
            let inputs_2 = create_sig_inputs_with_height(92, summary_height);
            let summary_block = create_summary_block_with_transcripts(
                subnet_id,
                summary_height,
                (key_transcript_ref, key_transcript),
                vec![
                    inputs_1.idkg_transcripts.clone(),
                    inputs_2.idkg_transcripts.clone(),
                    reshare_refs,
                ],
            );
            add_block(summary_block, summary_height.get(), &mut pool);
            let sig_1 = inputs_1.sig_inputs_ref;
            let quad_1 = inputs_2.sig_inputs_ref.presig_quadruple_ref;

            // Create payload blocks with transcripts
            let payload_height_1 = Height::new(10);
            let inputs_1 = create_sig_inputs_with_height(93, payload_height_1);
            let inputs_2 = create_sig_inputs_with_height(94, payload_height_1);
            let reshare_key_transcript = create_key_transcript();
            let reshare_key_transcript_ref =
                ecdsa::UnmaskedTranscript::try_from((payload_height_1, &reshare_key_transcript))
                    .unwrap();
            let reshare_params_2 = ecdsa::ReshareOfUnmaskedParams::new(
                create_transcript_id(2001),
                BTreeSet::new(),
                BTreeSet::new(),
                RegistryVersion::from(2001),
                AlgorithmId::ThresholdEcdsaSecp256k1,
                reshare_key_transcript_ref,
            );
            let mut reshare_refs = BTreeMap::new();
            reshare_refs.insert(*reshare_key_transcript_ref.as_ref(), reshare_key_transcript);
            let payload_block_1 = create_payload_block_with_transcripts(
                subnet_id,
                summary_height,
                vec![
                    inputs_1.idkg_transcripts.clone(),
                    inputs_2.idkg_transcripts.clone(),
                    reshare_refs,
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
            let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
            ecdsa_payload.ongoing_signatures.insert(req_id_1, sig_1);
            ecdsa_payload.ongoing_signatures.insert(req_id_2, sig_2);
            ecdsa_payload
                .available_quadruples
                .insert(quadruple_id_1, quad_1);
            ecdsa_payload
                .available_quadruples
                .insert(quadruple_id_2, quad_2);

            let req_1 = create_reshare_request(1, 1);
            let req_2 = create_reshare_request(2, 2);
            let response = ecdsa::EcdsaReshareResponse {
                reshare_param: reshare_params_2,
                dealings: vec![],
            };
            ecdsa_payload
                .ongoing_xnet_reshares
                .insert(req_1, reshare_params_1);
            ecdsa_payload.xnet_reshare_agreements.insert(
                req_2,
                ecdsa::CompletedReshareRequest::Unreported(Box::new(response)),
            );

            // Add some quadruples in creation
            let mut next_quadruple_id = ecdsa::QuadrupleId(100);
            let block_reader = TestEcdsaBlockReader::new();
            let (kappa_config_ref, _lambda_config_ref) = create_new_quadruple_in_creation(
                &subnet_nodes,
                env.newest_registry_version,
                &mut ecdsa_payload.next_unused_transcript_id,
                &mut next_quadruple_id,
                &mut ecdsa_payload.quadruples_in_creation,
            );
            let kappa_transcript = {
                let param = kappa_config_ref.as_ref();
                run_idkg_and_create_and_verify_transcript(
                    &param.translate(&block_reader).unwrap(),
                    &env.crypto_components,
                )
            };
            transcript_builder.add_transcript(
                kappa_config_ref.as_ref().transcript_id,
                kappa_transcript.clone(),
            );
            ecdsa_payload
                .idkg_transcripts
                .insert(kappa_config_ref.as_ref().transcript_id, kappa_transcript);
            let parent_block_height = Height::new(15);
            let result = update_quadruples_in_creation(
                Some(&key_transcript_ref),
                &mut ecdsa_payload,
                &mut transcript_cache,
                parent_block_height,
                &no_op_logger(),
            )
            .unwrap();
            assert_eq!(result.len(), 1);

            ecdsa_payload.signature_agreements.insert(
                create_request_id(3),
                ecdsa::CompletedSignature::ReportedToExecution,
            );
            ecdsa_payload.signature_agreements.insert(
                create_request_id(4),
                ecdsa::CompletedSignature::Unreported(ThresholdEcdsaCombinedSignature {
                    signature: vec![10; 10],
                }),
            );
            ecdsa_payload.xnet_reshare_agreements.insert(
                create_reshare_request(6, 6),
                ecdsa::CompletedReshareRequest::ReportedToExecution,
            );

            let parent_block_payload = BlockPayload::Data(DataPayload {
                batch: BatchPayload::default(),
                dealings: Dealings::new_empty(summary_height),
                ecdsa: Some(ecdsa::EcdsaDataPayload {
                    ecdsa_payload: ecdsa_payload.clone(),
                    next_key_transcript_creation: ecdsa::KeyTranscriptCreation::Begin,
                }),
            });
            let parent_block = add_block(
                parent_block_payload,
                parent_block_height.get() - payload_height_1.get(),
                &mut pool,
            );
            let pool_reader = PoolReader::new(&pool);

            // Add a summary block after the payload block and update the refs
            let mut summary = ecdsa::EcdsaSummaryPayload {
                ecdsa_payload: ecdsa_payload.clone(),
                current_key_transcript: key_transcript_ref,
            };
            assert!(update_summary_refs(
                &mut summary,
                &pool_reader,
                &parent_block,
                &EcdsaPayloadMetrics::new(MetricsRegistry::new()),
                &no_op_logger()
            )
            .is_ok());

            let (reported, unreported) = {
                let mut reported = 0;
                let mut unreported = 0;
                for agreement in summary.ecdsa_payload.signature_agreements.values() {
                    match agreement {
                        ecdsa::CompletedSignature::ReportedToExecution => {
                            reported += 1;
                        }
                        ecdsa::CompletedSignature::Unreported(_) => {
                            unreported += 1;
                        }
                    }
                }
                (reported, unreported)
            };
            assert!(!summary.ecdsa_payload.signature_agreements.is_empty());
            assert!(reported > 0);
            assert!(unreported > 0);
            assert!(!summary.ecdsa_payload.ongoing_signatures.is_empty());
            assert!(!summary.ecdsa_payload.available_quadruples.is_empty());
            assert!(!summary.ecdsa_payload.quadruples_in_creation.is_empty());
            assert!(!summary.ecdsa_payload.idkg_transcripts.is_empty());
            assert!(!summary.ecdsa_payload.ongoing_xnet_reshares.is_empty());
            let (reported, unreported) = {
                let mut reported = 0;
                let mut unreported = 0;
                for agreement in summary.ecdsa_payload.xnet_reshare_agreements.values() {
                    match agreement {
                        ecdsa::CompletedReshareRequest::ReportedToExecution => {
                            reported += 1;
                        }
                        ecdsa::CompletedReshareRequest::Unreported(_) => {
                            unreported += 1;
                        }
                    }
                }
                (reported, unreported)
            };
            assert!(!summary.ecdsa_payload.xnet_reshare_agreements.is_empty());
            assert!(reported > 0);
            assert!(unreported > 0);

            // Convert to proto format and back
            let new_summary_height = Height::new(parent_block_height.get() + 1234);
            let summary_proto: pb::EcdsaSummaryPayload = (&summary).into();
            let summary_from_proto = (&summary_proto, new_summary_height).try_into().unwrap();
            summary.update_refs(new_summary_height); // expected
            assert_eq!(summary, summary_from_proto);
        })
    }
}
