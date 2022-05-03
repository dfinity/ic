//! This module implements the ECDSA payload builder.
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
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_features::EcdsaConfig;
use ic_replicated_state::{metadata_state::subnet_call_context_manager::*, ReplicatedState};
use ic_types::crypto::canister_threshold_sig::error::IDkgTranscriptIdError;
use ic_types::{
    batch::ValidationContext,
    consensus::{ecdsa, ecdsa::EcdsaBlockReader, Block, HasHeight},
    crypto::{
        canister_threshold_sig::{
            error::{
                IDkgParamsValidationError, InitialIDkgDealingsValidationError,
                PresignatureQuadrupleCreationError, ThresholdEcdsaSigInputsCreationError,
            },
            idkg::{IDkgTranscript, IDkgTranscriptId, InitialIDkgDealings},
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
    SubnetWithNoNodes(SubnetId, RegistryVersion),
    PreSignatureError(PresignatureQuadrupleCreationError),
    IDkgParamsValidationError(IDkgParamsValidationError),
    IDkgTranscriptIdError(IDkgTranscriptIdError),
    DkgSummaryBlockNotFound(Height),
    EcdsaConfigNotFound(RegistryVersion),
    ThresholdEcdsaSigInputsCreationError(ThresholdEcdsaSigInputsCreationError),
    TranscriptCastError(ecdsa::TranscriptCastError),
    InvalidChainCacheError(InvalidChainCacheError),
    InitialIDkgDealingsNotUnmaskedParams(Box<InitialIDkgDealings>),
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

impl From<IDkgTranscriptIdError> for EcdsaPayloadError {
    fn from(err: IDkgTranscriptIdError) -> Self {
        EcdsaPayloadError::IDkgTranscriptIdError(err)
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

#[derive(Clone, Debug)]
pub(crate) enum MembershipError {
    RegistryClientError(RegistryClientError),
    SubnetWithNoNodes(SubnetId, RegistryVersion),
}

impl From<MembershipError> for EcdsaPayloadError {
    fn from(err: MembershipError) -> Self {
        match err {
            MembershipError::RegistryClientError(err) => {
                EcdsaPayloadError::RegistryClientError(err)
            }
            MembershipError::SubnetWithNoNodes(subnet_id, err) => {
                EcdsaPayloadError::SubnetWithNoNodes(subnet_id, err)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct InvalidChainCacheError(String);

impl From<InvalidChainCacheError> for EcdsaPayloadError {
    fn from(err: InvalidChainCacheError) -> Self {
        EcdsaPayloadError::InvalidChainCacheError(err)
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
pub(crate) fn ecdsa_feature_is_enabled(
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

/// Returns the initial dealings from the registry CUP record.
pub fn get_initial_dealings(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
    log: &ReplicaLogger,
) -> Option<InitialIDkgDealings> {
    let record = registry_client
        .get_cup_contents(subnet_id, registry_version)
        .ok()
        .and_then(|record| record.value)?;
    let ret = record
        .ecdsa_initializations
        .iter()
        .filter_map(|initialization| {
            initialization
                .dealings
                .as_ref()
                .map(InitialIDkgDealings::try_from)
                .transpose()
                .map_err(|err| warn!(log, "Failed to convert initial dealings proto: {:?}", err))
                .ok()
                .flatten()
        })
        .collect::<Vec<_>>();
    if ret.len() > 1 {
        warn!(
            log,
            "Resharing of multiple initial ECDSA keys not supported"
        );
    }
    ret.into_iter().next()
}

/// Creates a threshold ECDSA summary payload.
pub(crate) fn create_summary_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    pool_reader: &PoolReader<'_>,
    parent_block: &Block,
    ecdsa_payload_metrics: Option<&EcdsaPayloadMetrics>,
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
                    // TODO: A better approach is to try again
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
                uid_generator: ecdsa_payload.uid_generator.clone(),
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
    ecdsa_payload_metrics: Option<&EcdsaPayloadMetrics>,
    log: &ReplicaLogger,
) -> Result<(), EcdsaPayloadError> {
    // Gather the refs and update them to point to the new
    // summary block height.
    let prev_refs = summary.active_transcripts();
    let height = parent_block.height().increment();
    summary.update_refs(height);

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
            if let Some(metrics) = ecdsa_payload_metrics {
                metrics.payload_errors_inc("summary_invalid_chain_cache");
            };
            return Err(err.into());
        }
    };
    let block_reader = EcdsaBlockReaderImpl::new(parent_chain);
    summary.ecdsa_payload.idkg_transcripts.clear();
    for transcript_ref in prev_refs {
        // We want to panic here if the transcript reference could not be resolved.
        let transcript = block_reader.transcript(&transcript_ref).unwrap();
        summary
            .ecdsa_payload
            .idkg_transcripts
            .insert(transcript_ref.transcript_id, transcript);
    }

    Ok(())
}

fn get_subnet_nodes(
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
    subnet_id: SubnetId,
) -> Result<Vec<NodeId>, MembershipError> {
    // TODO: shuffle the nodes using random beacon?
    registry_client
        .get_node_ids_on_subnet(subnet_id, registry_version)
        .map_err(MembershipError::RegistryClientError)?
        .ok_or(MembershipError::SubnetWithNoNodes(
            subnet_id,
            registry_version,
        ))
}

pub(crate) fn is_subnet_membership_changing(
    registry_client: &dyn RegistryClient,
    dkg_registry_version: RegistryVersion,
    context_registry_version: RegistryVersion,
    subnet_id: SubnetId,
) -> Result<bool, MembershipError> {
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
                    uid_generator: ecdsa::EcdsaUIDGenerator::new(subnet_id, height),
                    idkg_transcripts: BTreeMap::new(),
                    ongoing_xnet_reshares: BTreeMap::new(),
                    xnet_reshare_agreements: BTreeMap::new(),
                };
                let initial_dealings = get_initial_dealings(
                    subnet_id,
                    registry_client,
                    summary_registry_version,
                    &log,
                );
                next_key_transcript_creation = match initial_dealings {
                    Some(dealings) => {
                        // Boot strap from the xnet reshared transcript params in the CUP.
                        let (params, transcript) =
                            ecdsa::unpack_reshare_of_unmasked_params(height, &dealings.params())
                                .ok_or_else(|| {
                                    EcdsaPayloadError::InitialIDkgDealingsNotUnmaskedParams(
                                        Box::new(dealings),
                                    )
                                })?;
                        ecdsa_payload
                            .idkg_transcripts
                            .insert(transcript.transcript_id, transcript);

                        ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams(params)
                    }
                    None => ecdsa::KeyTranscriptCreation::Begin,
                };
            }
            Some(ecdsa_summary) => {
                ecdsa_payload = ecdsa_summary.ecdsa_payload.clone();
                ecdsa_payload.uid_generator.update_height(height)?;
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
                ecdsa_payload.uid_generator.update_height(height)?;
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
            return Err(err.into());
        }
    };
    let current_key_transcript = summary
        .ecdsa
        .as_ref()
        .map(|ecdsa_summary| &ecdsa_summary.current_key_transcript);
    let state = state_manager.get_state_at(context.certified_height)?;
    let all_signing_requests = &state
        .get_ref()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts;

    let new_signing_requests = get_signing_requests(&ecdsa_payload, all_signing_requests);
    update_signature_agreements(
        all_signing_requests,
        parent_chain.clone(),
        ecdsa_pool.clone(),
        crypto,
        &mut ecdsa_payload,
        ecdsa_payload_metrics,
        log.clone(),
    );
    update_ongoing_signatures(
        new_signing_requests,
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
        &mut ecdsa_payload.uid_generator,
        &mut transcript_cache,
        height,
        log.clone(),
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

    let block_reader = EcdsaBlockReaderImpl::new(parent_chain);
    update_completed_reshare_requests(
        &mut ecdsa_payload,
        current_key_transcript,
        ecdsa_pool.deref(),
        &block_reader,
        &transcript_builder,
        &log,
    );
    let reshare_requests = get_reshare_requests(
        &state
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .ecdsa_dealings_contexts,
    );
    initiate_reshare_requests(
        &mut ecdsa_payload,
        current_key_transcript,
        &node_ids,
        reshare_requests,
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
    uid_generator: &mut ecdsa::EcdsaUIDGenerator,
) -> Result<ecdsa::RandomTranscriptParams, EcdsaPayloadError> {
    let transcript_id = uid_generator.next_transcript_id();
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
    let unassigned_quadruples = ecdsa_payload.unassigned_quadruple_ids().count();
    let quadruples_to_create = ecdsa_config.quadruples_to_create_in_advance as usize;
    if quadruples_to_create > unassigned_quadruples {
        let quadruples_in_creation = &mut ecdsa_payload.quadruples_in_creation;
        let uid_generator = &mut ecdsa_payload.uid_generator;
        for _ in 0..(quadruples_to_create - unassigned_quadruples) {
            let kappa_config =
                new_random_config(subnet_nodes, summary_registry_version, uid_generator)?;
            let lambda_config =
                new_random_config(subnet_nodes, summary_registry_version, uid_generator)?;
            quadruples_in_creation.insert(
                uid_generator.next_quadruple_id(),
                ecdsa::QuadrupleInCreation::new(kappa_config, lambda_config),
            );
        }
    }
    Ok(())
}

/// Return the set of new signing requests by assigning them a RequestId.  The
/// logic enforces the requirements set forth in Section A.5 of the ECDSA
/// design doc. Suppose we have signing requests SR_1, SR_2, ...  and
/// quadruples Q_1, Q_2, ... .
///
/// The SR_i's are ordered in the order the requests were made by execution,
/// which is determined by the corresponding callback_id, which is defined in
/// the SubnetCallContextManager struct (see
/// rs/replicated_state/src/metadata_state/subnet_call_context_manager.rs).
/// callback_id's are obtained from a counter that gets incremented as requests
/// get made.  
///
/// The Q_i's are ordered in the order in which their construction was
/// initiated, which is determined by QuadrupleId.  QuadrupleId's are obtained
/// from a counter that gets incremented as new quadruples are initiated.
///
/// The basic idea is that SR_i gets paired with Q_i. These pairings are
/// reflected in the RequestId struct, which consists of a QuadrupleId and a
/// the pseudo_random_id of the signing request.  A pseudo_random_id is the
/// random string generated from the random tape when the signing request is
/// made, as per Section A.5 of the ECDSA design doc. While pseudo_random_id
/// is ultimately used in the crypto layer as the nonce from which the
/// re-randomization value delta is derived, it is also used in consensus as an
/// ID for signing requests.
///
/// The logic here works as follows.
///
/// 1. let known_random_ids = the pseudo_random_id's of all signing requests
/// that are either ongoing or agreed upon.
///
/// 2. let unassigned_quadruple_ids be the list of all QuadrupleIds for
/// quadruples that are currently (a) either in creation or available, but (b)
/// are not paired with any signing requests that are either ongoing or agreed
/// upon.
///
/// 3. Now we build the list of RequestId's by iterating through the signing
/// request contexts in order of callback_id. This is done implicitly by virtue
/// of the fact that sign_with_ecdsa_contexts is a BTreeMap mapping CallBackId
/// to SignWithEcdsaContext and the semantics of the BTreeMap.values method.
/// So for each context considered in the given order, we ignore it if it
/// corresponds to an ongoing or agreed upon signing request (using  the value
/// known_random_ids), and otherwise take the next unassigned quadruple from
/// unassigned_quadruple_ids and pair that with this signing request.
///
/// The main caller of this function is create_data_payload, who uses the
/// result to determine which signing-request/quadruple pairs will be moved to
/// the ongoing signatures state.  This is done via the function
/// update_ongoing_signatures, which moves such a pair to  ongoing signatures
/// if the quadruple is available.
///
/// For example, say in one round we could have SR_1, SR_2, SR_3, SR_4 in the
/// signing request contexts, none of which are yet ongoing, and Q_1, Q_2, Q_3
/// in the unassigned_quadruple_ids list.  So the return value of the function
/// would be ((SR_1,Q_1), (SR_2,Q_2), (SR_3,Q_3)).  In this same round, the
/// calling function, create_data_payload, could move, say, (SR_2,Q_2) to the
/// ongoing signatures state if Q2 were available.  In the next round, we have
/// SR_1, SR_3, SR_4 in the signing requests contexts, with SR_2 now removed
/// because it is in the ongoing signatures state.  We would also have
/// unassigned_quadruple_ids Q_1, Q_3, Q_4.  The return value of the function
/// would be ((SR_1,Q_1), (SR_3,Q_3)).  In this same round, we could move, say,
/// (SR_1,Q_1) to the ongoing signatures state if Q1 were available.
///
/// The above logic ensures that the pairing of SR_i with Q_i is deterministic,
/// and cannot be manipulated by the adversary, as discussed in Section A.5 of
/// the ECDSA design doc. However, as discussed in Section A.5.1 of the ECDSA
/// design doc, it is allowed to essentially dispose of Q_i and replace it with
/// a fresh quadruple Q'_i.  In the implementation, this may happen at a
/// summary block.  The logic in create_summary_payload will ensure that all
/// quadruples that are either in creation or available or disposed of
/// (currently, if a key reshare occurs) or retained (currently, if a key
/// reshare does not occur).  This logic of either either disposing of or
/// retaining all quadruples that are either in creation or available
/// guarantees that the invariants in Section A.5.1 of the ECDSA design doc are
/// maintained.  However, the following logic would also be acceptable: if we
/// dispose of a quadruple Q_i that is in creation or available, then we must
/// dispose of all quadruples Q_j for j > i that are in creation or available.
/// This logic may be useful if and when we implement pro-active resharing of
/// the signing key without subnet membership changes.  In this case, in
/// creat_summary_payload, if Q_i is the first quadruple that is in creation,
/// we can retain Q_1, ..., Q_{i-1} and dispose of all quadruples Q_j for j >=
/// i that are in creation or available.  This logic will allow us to continue
/// using at least some (and typically most) of the quadruples that were
/// already available when we pro-actively reshare the signing key.
pub(crate) fn get_signing_requests<'a>(
    ecdsa_payload: &ecdsa::EcdsaPayload,
    sign_with_ecdsa_contexts: &'a BTreeMap<CallbackId, SignWithEcdsaContext>,
) -> BTreeMap<ecdsa::RequestId, &'a SignWithEcdsaContext> {
    let known_random_ids: BTreeSet<[u8; 32]> = ecdsa_payload
        .iter_request_ids()
        .map(|id| id.pseudo_random_id)
        .collect::<BTreeSet<_>>();
    let mut unassigned_quadruple_ids = ecdsa_payload.unassigned_quadruple_ids().collect::<Vec<_>>();
    // sort in reverse order (bigger to smaller).
    unassigned_quadruple_ids.sort_by(|a, b| b.cmp(a));
    let mut new_requests = BTreeMap::new();
    // The following iteration goes through contexts in the order
    // of their keys, which is the callback_id. Therefore we are
    // traversing the requests in the order they were created.
    for context in sign_with_ecdsa_contexts.values() {
        if known_random_ids.contains(context.pseudo_random_id.as_slice()) {
            continue;
        };
        if let Some(quadruple_id) = unassigned_quadruple_ids.pop() {
            let request_id = ecdsa::RequestId {
                quadruple_id,
                pseudo_random_id: context.pseudo_random_id,
            };
            new_requests.insert(request_id, context);
        } else {
            break;
        }
    }
    new_requests
}

// Update signature agreements in the data payload by combining
// shares in the ECDSA pool.
// TODO: As an optimization we could also use the signatures we
// are looking for to avoid traversing everything in the pool.
fn update_signature_agreements(
    all_requests: &BTreeMap<CallbackId, SignWithEcdsaContext>,
    chain: Arc<dyn ConsensusBlockChain>,
    ecdsa_pool: Arc<RwLock<dyn EcdsaPool>>,
    crypto: &dyn ConsensusCrypto,
    payload: &mut ecdsa::EcdsaPayload,
    metrics: &EcdsaPayloadMetrics,
    log: ReplicaLogger,
) {
    let all_random_ids = all_requests
        .values()
        .map(|context| context.pseudo_random_id)
        .collect::<BTreeSet<_>>();
    let ecdsa_pool = ecdsa_pool.read().unwrap();
    let builder = EcdsaSignatureBuilderImpl::new(crypto, metrics, log.clone());
    // We first clean up the existing signature_agreements by keeping those
    // that can still be found in the signing_requests for dedup purpose.
    // We only need the "Reported" status because they would have already
    // been reported when the previous block become finalized.
    let mut new_agreements = BTreeMap::new();
    let mut old_agreements = BTreeMap::new();
    std::mem::swap(&mut payload.signature_agreements, &mut old_agreements);
    for (request_id, _) in old_agreements.into_iter() {
        if all_random_ids.contains(&request_id.pseudo_random_id) {
            new_agreements.insert(request_id, ecdsa::CompletedSignature::ReportedToExecution);
        }
    }
    payload.signature_agreements = new_agreements;
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

/// For every new signing request, we only start to work on them if
/// their matched quadruple has been fully produced.
fn update_ongoing_signatures(
    new_requests: BTreeMap<ecdsa::RequestId, &SignWithEcdsaContext>,
    current_key_transcript: Option<&ecdsa::UnmaskedTranscript>,
    payload: &mut ecdsa::EcdsaPayload,
    log: ReplicaLogger,
) -> Result<(), EcdsaPayloadError> {
    if let Some(key_transcript) = current_key_transcript {
        debug!(
            log,
            "update_ongoing_signatures: number of new_requests={}",
            new_requests.len()
        );
        for (request_id, context) in new_requests.into_iter() {
            if let Some(quadruple) = payload
                .available_quadruples
                .remove(&request_id.quadruple_id)
            {
                let sign_inputs = build_signature_inputs(context, &quadruple, key_transcript);
                payload.ongoing_signatures.insert(request_id, sign_inputs);
            }
        }
    }
    Ok(())
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
    uid_generator: &mut ecdsa::EcdsaUIDGenerator,
    transcript_cache: &mut TranscriptBuilderCache,
    height: Height,
    log: ReplicaLogger,
) -> Result<Option<IDkgTranscript>, EcdsaPayloadError> {
    let dealers = get_subnet_nodes(registry_client, current_registry_version, subnet_id)?;
    let receivers = get_subnet_nodes(registry_client, next_registry_version, subnet_id)?;
    update_next_key_transcript_helper(
        &dealers,
        &receivers,
        next_registry_version,
        current_key_transcript,
        next_key_transcript_creation,
        uid_generator,
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
    uid_generator: &mut ecdsa::EcdsaUIDGenerator,
    transcript_cache: &mut TranscriptBuilderCache,
    height: Height,
    log: ReplicaLogger,
) -> Result<Option<IDkgTranscript>, EcdsaPayloadError> {
    let mut new_transcript = None;
    match (current_key_transcript, &next_key_transcript_creation) {
        (Some(transcript), ecdsa::KeyTranscriptCreation::Begin) => {
            // We have an existing key transcript, need to reshare it to create next
            // Create a new reshare config when there is none
            let transcript_id = uid_generator.next_transcript_id();
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
                debug!(
                    log,
                    "Key transcript created from ReshareOfUnmasked {:?} registry_version {:?}",
                    config.as_ref().transcript_id,
                    transcript.registry_version,
                );
                let transcript_ref = ecdsa::UnmaskedTranscript::try_from((height, transcript))?;
                *next_key_transcript_creation =
                    ecdsa::KeyTranscriptCreation::Created(transcript_ref);
                new_transcript = Some(transcript.clone());
            }
        }
        (None, ecdsa::KeyTranscriptCreation::Begin) => {
            // The first ECDSA key transcript has to be created, starting from a random
            // config.
            let transcript_id = uid_generator.next_transcript_id();
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
                let transcript_id = uid_generator.next_transcript_id();
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
                debug!(
                    log,
                    "Key transcript created from ReshareOfMasked {:?} registry_version {:?}",
                    config.as_ref().transcript_id,
                    transcript.registry_version,
                );
                let transcript_ref = ecdsa::UnmaskedTranscript::try_from((height, transcript))?;
                *next_key_transcript_creation =
                    ecdsa::KeyTranscriptCreation::Created(transcript_ref);
                new_transcript = Some(transcript.clone());
            }
        }
        (None, ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams(config)) => {
            // Check if the unmasked transcript has been created
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
            {
                // next_unused_transcript_id is not updated, since the transcript_id specified
                // by the reshared param will be used.
                debug!(
                    log,
                    "Key transcript created from XnetReshareOfMasked {:?} registry_version {:?}",
                    config.as_ref().transcript_id,
                    transcript.registry_version,
                );
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
                    payload.uid_generator.next_transcript_id(),
                    kappa_config.dealers.clone(),
                    kappa_config.receivers.clone(),
                    kappa_config.registry_version,
                    kappa_config.algorithm_id,
                    *kappa_masked,
                ));
            }
            if let (Some(lambda_masked), None) =
                (&quadruple.lambda_masked, &quadruple.key_times_lambda_config)
            {
                let lambda_config = quadruple.lambda_config.as_ref();
                quadruple.key_times_lambda_config = Some(ecdsa::UnmaskedTimesMaskedParams::new(
                    payload.uid_generator.next_transcript_id(),
                    lambda_config.dealers.clone(),
                    lambda_config.receivers.clone(),
                    lambda_config.registry_version,
                    lambda_config.algorithm_id,
                    *key_transcript,
                    *lambda_masked,
                ));
            }
            if let (Some(lambda_masked), Some(kappa_unmasked), None) = (
                &quadruple.lambda_masked,
                &quadruple.kappa_unmasked,
                &quadruple.kappa_times_lambda_config,
            ) {
                let lambda_config = quadruple.lambda_config.as_ref();
                quadruple.kappa_times_lambda_config = Some(ecdsa::UnmaskedTimesMaskedParams::new(
                    payload.uid_generator.next_transcript_id(),
                    lambda_config.dealers.clone(),
                    lambda_config.receivers.clone(),
                    lambda_config.registry_version,
                    lambda_config.algorithm_id,
                    *kappa_unmasked,
                    *lambda_masked,
                ));
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

/// Helper to build threshold signature inputs from the context and
/// the pre-signature quadruple
pub(crate) fn build_signature_inputs(
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
        let transcript_id = payload.uid_generator.next_transcript_id();
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
    ecdsa_pool: &dyn EcdsaPool,
    resolver: &dyn EcdsaBlockReader,
    transcript_builder: &dyn EcdsaTranscriptBuilder,
    log: &ReplicaLogger,
) {
    if current_key_transcript.is_none() {
        return;
    }

    let mut completed_reshares = BTreeMap::new();
    for (request, reshare_param) in &payload.ongoing_xnet_reshares {
        // Get the verified dealings for this transcript
        let transcript_id = reshare_param.as_ref().transcript_id;
        let dealings = transcript_builder.get_validated_dealings(transcript_id, ecdsa_pool);

        // Resolve the transcript param refs
        let transcript_params = match reshare_param.as_ref().translate(resolver) {
            Ok(params) => params,
            Err(err) => {
                warn!(
                    log,
                    "Failed to resolve reshare transcript params: {:?}", err
                );
                continue;
            }
        };

        // Build the initial dealings
        match InitialIDkgDealings::new(transcript_params, dealings) {
            Ok(dealings) => {
                completed_reshares.insert(request.clone(), dealings);
            }
            Err(InitialIDkgDealingsValidationError::UnsatisfiedCollectionThreshold { .. }) => (),
            Err(err) => {
                warn!(log, "Failed to create initial dealings: {:?}", err);
            }
        };
    }

    // Changed Unreported to Reported
    payload
        .xnet_reshare_agreements
        .iter_mut()
        .for_each(|(_, value)| *value = ecdsa::CompletedReshareRequest::ReportedToExecution);

    for (request, initial_dealings) in completed_reshares {
        payload.ongoing_xnet_reshares.remove(&request);
        payload.xnet_reshare_agreements.insert(
            request.clone(),
            ecdsa::CompletedReshareRequest::Unreported(Box::new(initial_dealings)),
        );
    }
}

/// Translates the reshare requests in the replicated state to the internal format
fn get_reshare_requests(
    ecdsa_dealings_contexts: &BTreeMap<CallbackId, EcdsaDealingsContext>,
) -> BTreeSet<ecdsa::EcdsaReshareRequest> {
    ecdsa_dealings_contexts
        .values()
        .map(|context| ecdsa::EcdsaReshareRequest {
            key_id: context.key_id.clone(),
            receiving_node_ids: context.nodes.iter().cloned().collect(),
            registry_version: context.registry_version,
        })
        .collect()
}

/// Wrapper to build the chain cache and perform sanity checks on the returned chain
pub fn block_chain_cache(
    pool_reader: &PoolReader<'_>,
    start: &Block,
    end: &Block,
) -> Result<Arc<dyn ConsensusBlockChain>, InvalidChainCacheError> {
    let chain = build_consensus_block_chain(pool_reader.pool(), start, end);
    let expected_len = (end.height().get() - start.height().get() + 1) as usize;
    let chain_len = chain.len();
    if chain_len == expected_len {
        Ok(chain)
    } else {
        Err(InvalidChainCacheError(format!(
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
    use ic_ic00_types::EcdsaKeyId;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::types::v1 as pb;
    use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
    use ic_test_utilities::{
        crypto::{dummy_initial_idkg_dealing_for_tests, mock_dealings},
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
            uid_generator: ecdsa::EcdsaUIDGenerator::new(subnet_id, Height::new(0)),
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
        use std::str::FromStr;
        ecdsa::EcdsaReshareRequest {
            key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
            receiving_node_ids: (0..num_nodes).map(node_test_id).collect::<Vec<_>>(),
            registry_version: RegistryVersion::from(registry_version),
        }
    }

    fn create_new_quadruple_in_creation(
        subnet_nodes: &[NodeId],
        registry_version: RegistryVersion,
        uid_generator: &mut ecdsa::EcdsaUIDGenerator,
        quadruples_in_creation: &mut BTreeMap<ecdsa::QuadrupleId, ecdsa::QuadrupleInCreation>,
    ) -> (ecdsa::RandomTranscriptParams, ecdsa::RandomTranscriptParams) {
        let kappa_config_ref =
            new_random_config(subnet_nodes, registry_version, uid_generator).unwrap();
        let lambda_config_ref =
            new_random_config(subnet_nodes, registry_version, uid_generator).unwrap();
        quadruples_in_creation.insert(
            uid_generator.next_quadruple_id(),
            ecdsa::QuadrupleInCreation::new(kappa_config_ref.clone(), lambda_config_ref.clone()),
        );
        (kappa_config_ref, lambda_config_ref)
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
        let cur_height = Height::new(1);
        let subnet_nodes = (0..10).map(node_test_id).collect::<Vec<_>>();
        let summary_registry_version = RegistryVersion::new(10);
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
        let update_res = ecdsa_payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
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
            ecdsa_payload.uid_generator.next_transcript_id()
        );
    }

    #[test]
    fn test_ecdsa_signing_request_order() {
        let subnet_id = subnet_test_id(1);
        let num_of_nodes = 4;
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
        let registry_version = env.newest_registry_version;
        let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
        let mut state = ReplicatedStateBuilder::default().build();
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .insert(
                CallbackId::from(0),
                SignWithEcdsaContext {
                    request: RequestBuilder::new().build(),
                    pseudo_random_id: [0; 32],
                    message_hash: vec![],
                    derivation_path: vec![],
                    batch_time: mock_time(),
                },
            );
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
        let result = get_signing_requests(
            &ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
        );
        // Because there is no quadruples available, expect empty return
        assert!(result.is_empty());
        // Add two qudruples in creation
        let quadruple_id_0 = ecdsa_payload.uid_generator.clone().next_quadruple_id();
        let (_kappa_config_ref, _lambda_config_ref) = create_new_quadruple_in_creation(
            &subnet_nodes,
            registry_version,
            &mut ecdsa_payload.uid_generator,
            &mut ecdsa_payload.quadruples_in_creation,
        );
        let quadruple_id_1 = ecdsa_payload.uid_generator.clone().next_quadruple_id();
        let (_kappa_config_ref, _lambda_config_ref) = create_new_quadruple_in_creation(
            &subnet_nodes,
            registry_version,
            &mut ecdsa_payload.uid_generator,
            &mut ecdsa_payload.quadruples_in_creation,
        );
        let new_requests = get_signing_requests(
            &ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
        );
        assert_eq!(new_requests.len(), 1);
        // Check if it is matched with the smaller quadruple ID
        let request_id_0 = *new_requests.keys().next().unwrap();
        assert_eq!(request_id_0.quadruple_id, quadruple_id_0);
        // Now we are going to make quadruple_id_1 available.
        let sig_inputs = create_sig_inputs(10);
        let quadruple_ref = &sig_inputs.sig_inputs_ref.presig_quadruple_ref;
        ecdsa_payload
            .available_quadruples
            .insert(quadruple_id_1, quadruple_ref.clone());
        ecdsa_payload.quadruples_in_creation.remove(&quadruple_id_1);
        /*
        let sig_inputs = create_sig_inputs(11);
        let quadruple_ref = &sig_inputs.sig_inputs_ref.presig_quadruple_ref;
        ecdsa_payload.available_quadruples.insert(
            ecdsa_payload.uid_generator.next_quadruple_id(),
            quadruple_ref.clone(),
        );
        */
        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let key_transcript_ref =
            ecdsa::UnmaskedTranscript::try_from((Height::from(0), &key_transcript)).unwrap();
        let result = update_ongoing_signatures(
            result,
            Some(&key_transcript_ref),
            &mut ecdsa_payload,
            no_op_logger(),
        );
        // Now ongoing_signatures should still be empty, because we only have one request
        // and its matching quadruple is not available yet.
        assert!(result.is_ok());
        assert!(ecdsa_payload.ongoing_signatures.is_empty());
        // We insert a second request
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .insert(
                CallbackId::from(1),
                SignWithEcdsaContext {
                    request: RequestBuilder::new().build(),
                    pseudo_random_id: [1; 32],
                    message_hash: vec![],
                    derivation_path: vec![],
                    batch_time: mock_time(),
                },
            );
        // Now there are two signing requests
        let new_requests = get_signing_requests(
            &ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
        );
        assert_eq!(new_requests.len(), 2);
        let request_id_1 = *new_requests.keys().find(|x| x != &&request_id_0).unwrap();
        // We should be able to move the 2nd request into ongoing_signatures.
        let result = update_ongoing_signatures(
            new_requests,
            Some(&key_transcript_ref),
            &mut ecdsa_payload,
            no_op_logger(),
        );
        assert!(result.is_ok());
        assert_eq!(
            *ecdsa_payload.ongoing_signatures.keys().next().unwrap(),
            request_id_1
        );
        // Run get_signing_requests again, we should get request_id_0, but not request_id_1
        let result = get_signing_requests(
            &ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result.keys().next().unwrap().clone(), request_id_0);
    }

    #[test]
    fn test_ecdsa_update_ongoing_signatures() {
        let subnet_id = subnet_test_id(1);
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
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
        let result = get_signing_requests(
            &ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
        );
        // Because there is no quadruples available, expect empty return
        assert!(result.is_empty());
        // Add two quadruples
        let sig_inputs = create_sig_inputs(10);
        let quadruple_id = ecdsa_payload.uid_generator.next_quadruple_id();
        let quadruple_ref = &sig_inputs.sig_inputs_ref.presig_quadruple_ref;
        ecdsa_payload
            .available_quadruples
            .insert(quadruple_id, quadruple_ref.clone());
        let sig_inputs = create_sig_inputs(11);
        let quadruple_ref = &sig_inputs.sig_inputs_ref.presig_quadruple_ref;
        ecdsa_payload.available_quadruples.insert(
            ecdsa_payload.uid_generator.next_quadruple_id(),
            quadruple_ref.clone(),
        );
        let result = get_signing_requests(
            &ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
        );
        assert_eq!(result.len(), 1);
        // Check if it is matched with the smaller quadruple ID
        let request_id = &result.keys().next().unwrap().clone();
        assert_eq!(request_id.quadruple_id, quadruple_id);
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
                &mut payload.ecdsa_payload.uid_generator,
                &mut transcript_cache,
                cur_height,
                no_op_logger(),
            );
            matches!(result, Ok(None));
            assert_eq!(
                payload
                    .ecdsa_payload
                    .uid_generator
                    .clone()
                    .next_transcript_id()
                    .id(),
                1
            );
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
                &mut payload.ecdsa_payload.uid_generator,
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
            assert_eq!(
                payload
                    .ecdsa_payload
                    .uid_generator
                    .clone()
                    .next_transcript_id()
                    .id(),
                2
            );
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
                &mut payload.ecdsa_payload.uid_generator,
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
            assert_eq!(
                payload
                    .ecdsa_payload
                    .uid_generator
                    .clone()
                    .next_transcript_id()
                    .id(),
                2
            );
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
                &mut payload.ecdsa_payload.uid_generator,
                &mut transcript_cache,
                cur_height,
                no_op_logger(),
            );
            matches!(result, Ok(None));
            assert_eq!(
                payload
                    .ecdsa_payload
                    .uid_generator
                    .clone()
                    .next_transcript_id()
                    .id(),
                3
            );
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
                &mut payload.ecdsa_payload.uid_generator,
                &mut transcript_cache,
                cur_height,
                no_op_logger(),
            );
            let completed_transcript = result.unwrap().unwrap();
            assert_eq!(completed_transcript, unmasked_transcript);
            assert_eq!(
                payload
                    .ecdsa_payload
                    .uid_generator
                    .clone()
                    .next_transcript_id()
                    .id(),
                3
            );
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

    #[test]
    fn test_ecdsa_update_next_key_transcript_xnet_target_subnet() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let num_of_nodes = 8;
            let subnet_id = subnet_test_id(1);
            let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
            let registry_version = env.newest_registry_version;
            let mut subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
            let target_subnet_nodes = subnet_nodes.split_off(4);
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
                &mut payload.ecdsa_payload.uid_generator,
                &mut transcript_cache,
                cur_height,
                no_op_logger(),
            );
            matches!(result, Ok(None));
            assert_eq!(
                payload
                    .ecdsa_payload
                    .uid_generator
                    .clone()
                    .next_transcript_id()
                    .id(),
                1
            );
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
                &mut payload.ecdsa_payload.uid_generator,
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
            assert_eq!(
                payload
                    .ecdsa_payload
                    .uid_generator
                    .clone()
                    .next_transcript_id()
                    .id(),
                2
            );
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
                &mut payload.ecdsa_payload.uid_generator,
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
            assert_eq!(
                payload
                    .ecdsa_payload
                    .uid_generator
                    .clone()
                    .next_transcript_id()
                    .id(),
                2
            );
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

            // 4. Reshare the created transcript to a different set of nodes
            let reshare_params = create_reshare_unmasked_transcript_param(
                &unmasked_transcript,
                &target_subnet_nodes,
                registry_version,
            );
            let (params, transcript) =
                ecdsa::unpack_reshare_of_unmasked_params(cur_height, &reshare_params).unwrap();
            block_reader.add_transcript(
                ecdsa::TranscriptRef::new(cur_height, transcript.transcript_id),
                transcript,
            );
            payload.next_key_transcript_creation =
                ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams(params);
            let result = update_next_key_transcript_helper(
                &subnet_nodes,
                &subnet_nodes,
                registry_version,
                None,
                &mut payload.next_key_transcript_creation,
                &mut payload.ecdsa_payload.uid_generator,
                &mut transcript_cache,
                cur_height,
                no_op_logger(),
            );
            matches!(result, Ok(None));
            assert_eq!(
                payload
                    .ecdsa_payload
                    .uid_generator
                    .clone()
                    .next_transcript_id()
                    .id(),
                2
            );
            assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
            assert_eq!(config_ids(&payload), [reshare_params.transcript_id().id()]);

            // 5. Complete the reshared transcript creation. This should cause the key to
            // move to created state.
            let cur_height = Height::new(50);
            let unmasked_transcript = {
                let param = match &payload.next_key_transcript_creation {
                    ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams(param) => {
                        param.clone()
                    }
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
                &target_subnet_nodes,
                registry_version,
                None,
                &mut payload.next_key_transcript_creation,
                &mut payload.ecdsa_payload.uid_generator,
                &mut transcript_cache,
                cur_height,
                no_op_logger(),
            );
            let completed_transcript = result.unwrap().unwrap();
            assert_eq!(completed_transcript, unmasked_transcript);
            assert_eq!(
                payload
                    .ecdsa_payload
                    .uid_generator
                    .clone()
                    .next_transcript_id()
                    .id(),
                2
            );
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

    #[test]
    fn test_ecdsa_update_signature_agreements() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let num_of_nodes = 4;
            let Dependencies {
                mut pool,
                ecdsa_pool,
                crypto,
                ..
            } = dependencies(pool_config, num_of_nodes);
            //let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes as usize);
            let subnet_id = subnet_test_id(0);
            let mut state = ReplicatedStateBuilder::default().build();
            state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts
                .insert(
                    CallbackId::from(1),
                    SignWithEcdsaContext {
                        request: RequestBuilder::new().build(),
                        pseudo_random_id: [1; 32],
                        message_hash: vec![],
                        derivation_path: vec![],
                        batch_time: mock_time(),
                    },
                );
            state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts
                .insert(
                    CallbackId::from(2),
                    SignWithEcdsaContext {
                        request: RequestBuilder::new().build(),
                        pseudo_random_id: [2; 32],
                        message_hash: vec![],
                        derivation_path: vec![],
                        batch_time: mock_time(),
                    },
                );
            let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
            pool.advance_round_normal_operation_n(1);
            let pool_reader = PoolReader::new(&pool);
            let block = pool_reader.get_finalized_block(Height::from(0)).unwrap();
            let chain = build_consensus_block_chain(pool_reader.pool(), &block, &block);
            let all_requests = &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts;

            let quadruple_id_1 = ecdsa_payload.uid_generator.next_quadruple_id();
            ecdsa_payload.signature_agreements.insert(
                ecdsa::RequestId {
                    quadruple_id: quadruple_id_1,
                    pseudo_random_id: [1; 32],
                },
                ecdsa::CompletedSignature::Unreported(ThresholdEcdsaCombinedSignature {
                    signature: vec![1; 32],
                }),
            );
            ecdsa_payload.signature_agreements.insert(
                ecdsa::RequestId {
                    quadruple_id: ecdsa_payload.uid_generator.next_quadruple_id(),
                    pseudo_random_id: [0; 32],
                },
                ecdsa::CompletedSignature::Unreported(ThresholdEcdsaCombinedSignature {
                    signature: vec![2; 32],
                }),
            );
            // old signature in the agreement AND in state is replaced by ReportedToExecution
            // old signature in the agreement but NOT in state is removed.
            update_signature_agreements(
                all_requests,
                chain,
                ecdsa_pool,
                crypto.as_ref(),
                &mut ecdsa_payload,
                &EcdsaPayloadMetrics::new(MetricsRegistry::new()),
                no_op_logger(),
            );
            assert_eq!(ecdsa_payload.signature_agreements.len(), 1);
            assert_eq!(
                ecdsa_payload
                    .signature_agreements
                    .keys()
                    .next()
                    .unwrap()
                    .quadruple_id,
                quadruple_id_1
            );
            assert!(matches!(
                ecdsa_payload.signature_agreements.values().next().unwrap(),
                ecdsa::CompletedSignature::ReportedToExecution
            ));
        })
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
            // Start quadruple creation
            let (kappa_config_ref, lambda_config_ref) = create_new_quadruple_in_creation(
                &subnet_nodes,
                registry_version,
                &mut payload.uid_generator,
                &mut payload.quadruples_in_creation,
            );
            // 0. No action case
            let cur_height = Height::new(1000);
            let update_res = payload.uid_generator.update_height(cur_height);
            assert!(update_res.is_ok());
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
            assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 2);
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
            let update_res = payload.uid_generator.update_height(cur_height);
            assert!(update_res.is_ok());
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
            let kappa_unmasked_config_id = IDkgTranscriptId::new(subnet_id, 2, cur_height);
            assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 3);
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
            let update_res = payload.uid_generator.update_height(cur_height);
            assert!(update_res.is_ok());
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
            assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 4);
            let key_times_lambda_config_id = IDkgTranscriptId::new(subnet_id, 3, cur_height);
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
            let update_res = payload.uid_generator.update_height(cur_height);
            assert!(update_res.is_ok());
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
            assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 5);
            let kappa_times_lambda_config_id = IDkgTranscriptId::new(subnet_id, 4, cur_height);
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
            let update_res = payload.uid_generator.update_height(cur_height);
            assert!(update_res.is_ok());
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
            assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 5);
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
            let mut block_reader = TestEcdsaBlockReader::new();
            let transcript_builder = TestEcdsaTranscriptBuilder::new();
            let ecdsa_pool =
                EcdsaPoolImpl::new(pool_config, no_op_logger(), MetricsRegistry::new());

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
            assert_eq!(payload.ongoing_xnet_reshares.len(), 2);
            assert!(payload.ongoing_xnet_reshares.contains_key(&req_1));
            assert!(payload.ongoing_xnet_reshares.contains_key(&req_2));
            assert!(payload.xnet_reshare_agreements.is_empty());

            // Request 1 dealings are created, it should be moved from in
            // progress -> completed
            let reshare_params = payload.ongoing_xnet_reshares.get(&req_1).unwrap().as_ref();
            let dealings = mock_dealings(reshare_params.transcript_id, &reshare_params.dealers);
            transcript_builder.add_dealings(reshare_params.transcript_id, dealings);
            update_completed_reshare_requests(
                &mut payload,
                Some(&key_transcript_ref),
                &ecdsa_pool,
                &block_reader,
                &transcript_builder,
                &no_op_logger(),
            );
            assert_eq!(payload.ongoing_xnet_reshares.len(), 1);
            assert!(payload.ongoing_xnet_reshares.contains_key(&req_2));
            assert_eq!(payload.xnet_reshare_agreements.len(), 1);
            assert!(matches!(
                payload.xnet_reshare_agreements.get(&req_1).unwrap(),
                ecdsa::CompletedReshareRequest::Unreported(_)
            ));

            // Request 2 dealings are created, it should be moved from in
            // progress -> completed
            let reshare_params = payload.ongoing_xnet_reshares.get(&req_2).unwrap().as_ref();
            let dealings = mock_dealings(reshare_params.transcript_id, &reshare_params.dealers);
            transcript_builder.add_dealings(reshare_params.transcript_id, dealings);
            update_completed_reshare_requests(
                &mut payload,
                Some(&key_transcript_ref),
                &ecdsa_pool,
                &block_reader,
                &transcript_builder,
                &no_op_logger(),
            );
            assert!(payload.ongoing_xnet_reshares.is_empty());
            assert_eq!(payload.xnet_reshare_agreements.len(), 2);
            assert!(matches!(
                payload.xnet_reshare_agreements.get(&req_1).unwrap(),
                ecdsa::CompletedReshareRequest::ReportedToExecution
            ));
            assert!(matches!(
                payload.xnet_reshare_agreements.get(&req_2).unwrap(),
                ecdsa::CompletedReshareRequest::Unreported(_)
            ));

            update_completed_reshare_requests(
                &mut payload,
                Some(&key_transcript_ref),
                &ecdsa_pool,
                &block_reader,
                &transcript_builder,
                &no_op_logger(),
            );
            assert!(payload.ongoing_xnet_reshares.is_empty());
            assert_eq!(payload.xnet_reshare_agreements.len(), 2);
            assert!(matches!(
                payload.xnet_reshare_agreements.get(&req_1).unwrap(),
                ecdsa::CompletedReshareRequest::ReportedToExecution
            ));
            assert!(matches!(
                payload.xnet_reshare_agreements.get(&req_2).unwrap(),
                ecdsa::CompletedReshareRequest::ReportedToExecution
            ));
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
            let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
            let (quadruple_id_1, quadruple_id_2) = (
                ecdsa_payload.uid_generator.next_quadruple_id(),
                ecdsa_payload.uid_generator.next_quadruple_id(),
            );
            let req_id_1 = ecdsa::RequestId {
                quadruple_id: quadruple_id_1,
                pseudo_random_id: [0; 32],
            };
            let req_id_2 = ecdsa::RequestId {
                quadruple_id: quadruple_id_2,
                pseudo_random_id: [1; 32],
            };
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
            ecdsa_payload
                .ongoing_xnet_reshares
                .insert(req_1, reshare_params_1.clone());

            add_expected_transcripts(vec![*key_transcript_ref.as_ref()]);
            add_expected_transcripts(sig_1.get_refs());
            add_expected_transcripts(sig_2.get_refs());
            add_expected_transcripts(quad_1.get_refs());
            add_expected_transcripts(quad_2.get_refs());
            add_expected_transcripts(reshare_params_1.as_ref().get_refs());

            // Add some quadruples in creation
            // let next_quadruple_id = ecdsa_payload.uid_generator.next_quadruple_id();
            let block_reader = TestEcdsaBlockReader::new();
            let (kappa_config_ref, _lambda_config_ref) = create_new_quadruple_in_creation(
                &subnet_nodes,
                env.newest_registry_version,
                &mut ecdsa_payload.uid_generator,
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

            assert!(update_summary_refs(
                &mut summary,
                &pool_reader,
                &parent_block,
                None,
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
            let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
            let uid_generator = &mut ecdsa_payload.uid_generator;
            let quadruple_id_1 = uid_generator.next_quadruple_id();
            let quadruple_id_2 = uid_generator.next_quadruple_id();
            let req_id_1 = ecdsa::RequestId {
                quadruple_id: quadruple_id_1,
                pseudo_random_id: [0; 32],
            };
            let req_id_2 = ecdsa::RequestId {
                quadruple_id: quadruple_id_2,
                pseudo_random_id: [1; 32],
            };
            ecdsa_payload.ongoing_signatures.insert(req_id_1, sig_1);
            ecdsa_payload.ongoing_signatures.insert(req_id_2, sig_2);
            ecdsa_payload
                .available_quadruples
                .insert(quadruple_id_1, quad_1);
            ecdsa_payload
                .available_quadruples
                .insert(quadruple_id_2, quad_2);

            let req_1 = create_reshare_request(1, 1);
            ecdsa_payload
                .ongoing_xnet_reshares
                .insert(req_1, reshare_params_1);
            let req_2 = create_reshare_request(2, 2);
            ecdsa_payload.xnet_reshare_agreements.insert(
                req_2,
                ecdsa::CompletedReshareRequest::Unreported(Box::new(
                    dummy_initial_idkg_dealing_for_tests(),
                )),
            );

            // Add some quadruples in creation
            let block_reader = TestEcdsaBlockReader::new();
            let (kappa_config_ref, _lambda_config_ref) = create_new_quadruple_in_creation(
                &subnet_nodes,
                env.newest_registry_version,
                &mut ecdsa_payload.uid_generator,
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
                ecdsa::RequestId {
                    quadruple_id: ecdsa_payload.uid_generator.next_quadruple_id(),
                    pseudo_random_id: [2; 32],
                },
                ecdsa::CompletedSignature::ReportedToExecution,
            );
            ecdsa_payload.signature_agreements.insert(
                ecdsa::RequestId {
                    quadruple_id: ecdsa_payload.uid_generator.next_quadruple_id(),
                    pseudo_random_id: [3; 32],
                },
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
                None,
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
