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
use ic_error_types::RejectCode;
use ic_ic00_types::{EcdsaKeyId, Payload, SignWithECDSAReply};
use ic_interfaces::{consensus_pool::ConsensusBlockChain, ecdsa::EcdsaPool};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{StateManager, StateManagerError};
use ic_logger::{debug, error, info, warn, ReplicaLogger};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_features::EcdsaConfig;
use ic_replicated_state::{metadata_state::subnet_call_context_manager::*, ReplicatedState};
use ic_types::{
    batch::ValidationContext,
    consensus::{
        ecdsa,
        ecdsa::{EcdsaBlockReader, TranscriptAttributes},
        Block, HasHeight,
    },
    crypto::{
        canister_threshold_sig::{
            error::{
                IDkgParamsValidationError, IDkgTranscriptIdError,
                InitialIDkgDealingsValidationError, PresignatureQuadrupleCreationError,
                ThresholdEcdsaSigInputsCreationError,
            },
            idkg::{IDkgTranscript, InitialIDkgDealings},
            ExtendedDerivationPath,
        },
        AlgorithmId,
    },
    messages::{CallbackId, RejectContext},
    registry::RegistryClientError,
    Height, NodeId, RegistryVersion, SubnetId, Time,
};
use phantom_newtype::Id;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum EcdsaPayloadError {
    RegistryClientError(RegistryClientError),
    ConsensusSummaryBlockNotFound(Height),
    ConsensusRegistryVersionNotFound(Height),
    StateManagerError(StateManagerError),
    SubnetWithNoNodes(SubnetId, RegistryVersion),
    PreSignatureError(PresignatureQuadrupleCreationError),
    IDkgParamsValidationError(IDkgParamsValidationError),
    IDkgTranscriptIdError(IDkgTranscriptIdError),
    DkgSummaryBlockNotFound(Height),
    ThresholdEcdsaSigInputsCreationError(ThresholdEcdsaSigInputsCreationError),
    TranscriptLookupError(ecdsa::TranscriptLookupError),
    TranscriptCastError(ecdsa::TranscriptCastError),
    InvalidChainCacheError(InvalidChainCacheError),
    InitialIDkgDealingsNotUnmaskedParams(Box<InitialIDkgDealings>),
}

impl From<ecdsa::TranscriptLookupError> for EcdsaPayloadError {
    fn from(err: ecdsa::TranscriptLookupError) -> Self {
        EcdsaPayloadError::TranscriptLookupError(err)
    }
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

/// Builds the the very first ecdsa summary block. This would trigger the subsequent
/// data blocks to create the initial key transcript.
pub fn make_bootstrap_summary(
    subnet_id: SubnetId,
    key_id: EcdsaKeyId,
    height: Height,
    initial_dealings: Option<InitialIDkgDealings>,
    log: &ReplicaLogger,
) -> Result<ecdsa::Summary, EcdsaPayloadError> {
    let mut summary_payload = ecdsa::EcdsaPayload {
        signature_agreements: BTreeMap::new(),
        ongoing_signatures: BTreeMap::new(),
        available_quadruples: BTreeMap::new(),
        quadruples_in_creation: BTreeMap::new(),
        uid_generator: ecdsa::EcdsaUIDGenerator::new(subnet_id, height),
        idkg_transcripts: BTreeMap::new(),
        ongoing_xnet_reshares: BTreeMap::new(),
        xnet_reshare_agreements: BTreeMap::new(),
        key_transcript: ecdsa::EcdsaKeyTranscript {
            current: None,
            next_in_creation: ecdsa::KeyTranscriptCreation::Begin,
            key_id,
        },
    };

    // Update the next_in_creation if boot strapping from initial dealings
    if let Some(dealings) = initial_dealings {
        match ecdsa::unpack_reshare_of_unmasked_params(height, dealings.params()) {
            Some((params, transcript)) => {
                summary_payload
                    .idkg_transcripts
                    .insert(transcript.transcript_id, transcript);
                summary_payload.key_transcript.next_in_creation =
                    ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((
                        Box::new(dealings),
                        params,
                    ));
                info!(
                    log,
                    "make_ecdsa_genesis_summary(): height = {:?}, key_transcript = [{}]",
                    height,
                    summary_payload.key_transcript
                );
            }
            None => {
                // Leave the feature disabled if the initial dealings are incorrect.
                warn!(
                    log,
                    "make_ecdsa_genesis_summary(): failed to unpack initial dealings"
                );
                return Err(EcdsaPayloadError::InitialIDkgDealingsNotUnmaskedParams(
                    Box::new(dealings),
                ));
            }
        }
    }
    Ok(Some(summary_payload))
}

/// Return EcdsaConfig if it is enabled for the given subnet.
pub(crate) fn get_ecdsa_config_if_enabled(
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    registry_client: &dyn RegistryClient,
    log: &ReplicaLogger,
) -> Result<Option<EcdsaConfig>, RegistryClientError> {
    if let Some(mut ecdsa_config) = registry_client.get_ecdsa_config(subnet_id, registry_version)? {
        if ecdsa_config.quadruples_to_create_in_advance == 0 {
            warn!(
                log,
                "Wrong ecdsa_config: quadruples_to_create_in_advance is zero"
            );
        } else if ecdsa_config.key_ids.is_empty() {
            // This means it is not enabled
        } else if ecdsa_config.key_ids.len() > 1 {
            warn!(
                log,
                "Wrong ecdsa_config: multiple key_ids is not yet supported. Pick the first one."
            );
            ecdsa_config.key_ids = vec![ecdsa_config.key_ids[0].clone()];
            return Ok(Some(ecdsa_config));
        } else {
            return Ok(Some(ecdsa_config));
        }
    }
    Ok(None)
}

/// Creates a threshold ECDSA summary payload.
pub(crate) fn create_summary_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    pool_reader: &PoolReader<'_>,
    context: &ValidationContext,
    parent_block: &Block,
    ecdsa_payload_metrics: Option<&EcdsaPayloadMetrics>,
    log: ReplicaLogger,
) -> Result<ecdsa::Summary, EcdsaPayloadError> {
    let height = parent_block.height().increment();
    let prev_summary_block = pool_reader
        .dkg_summary_block(parent_block)
        .ok_or_else(|| EcdsaPayloadError::ConsensusSummaryBlockNotFound(parent_block.height()))?;

    // For this interval: context.registry_version from prev summary block
    // which is the same as calling pool_reader.registry_version(height).
    // which is the same as summary.dkg.registry_version (to be created).
    let curr_interval_registry_version = prev_summary_block.context.registry_version;

    // For next interval: context.registry_version from the new summary block
    let next_interval_registry_version = context.registry_version;

    let ecdsa_config = get_ecdsa_config_if_enabled(
        subnet_id,
        curr_interval_registry_version,
        registry_client,
        &log,
    )?;
    if ecdsa_config.is_none() {
        return Ok(None);
    };
    let ecdsa_config = ecdsa_config.unwrap();

    let ecdsa_payload = parent_block.payload.as_ref().as_data().ecdsa.as_ref();
    if ecdsa_payload.is_none() {
        // Parent block doesn't have ECDSA payload and feature is enabled.
        // Create the bootstrap summary block, and create a new key for the given key_id.
        //
        // This is safe because registry's do_update_subnet already ensures that only
        // fresh key_id can be assigned to an existing subnet.
        //
        // Keys already held by existing subnets can only be re-shared when creating
        // a new subnet, which means the genesis summary ECDSA payload is not empty
        // and we won't reach here.
        let key_id = ecdsa_config.key_ids[0].clone();
        info!(
            log,
            "Start to create ECDSA key {} on subnet {} at height {}", key_id, subnet_id, height
        );

        return make_bootstrap_summary(subnet_id, key_id, height, None, &log);
    }
    let ecdsa_payload = ecdsa_payload.unwrap();

    let block_reader = block_chain_reader(
        pool_reader,
        &prev_summary_block,
        parent_block,
        ecdsa_payload_metrics,
        &log,
    )?;
    let created = match &ecdsa_payload.key_transcript.next_in_creation {
        ecdsa::KeyTranscriptCreation::Created(unmasked) => {
            let transcript = block_reader.transcript(unmasked.as_ref())?;
            Some(ecdsa::UnmaskedTranscriptWithAttributes::new(
                transcript.to_attributes(),
                *unmasked,
            ))
        }
        _ => {
            warn!(
                log,
                "Key not created in previous interval, to retry in next interval(height = {:?}), key_transcript = {}",
                height, ecdsa_payload.key_transcript
            );
            None
        }
    };

    let is_new_key_transcript = match &ecdsa_payload.key_transcript.current {
        Some(unmasked) => {
            Some(unmasked.transcript_id())
                != created
                    .as_ref()
                    .map(|transcript| transcript.transcript_id())
        }
        None => created.is_some(),
    };

    // Check for membership change, start next key creation if needed.
    // The registry versions to determine node membership:
    let next_in_creation = if is_subnet_membership_changing(
        registry_client,
        curr_interval_registry_version,
        next_interval_registry_version,
        subnet_id,
    )? {
        info!(
            log,
            "Noticed subnet membership change, will start key_transcript_creation: height = {:?} \
                current_version = {:?}, next_version = {:?}",
            height,
            curr_interval_registry_version,
            next_interval_registry_version
        );
        ecdsa::KeyTranscriptCreation::Begin
    } else {
        // No change, just carry forward the next_in_creation transcript
        ecdsa_payload.key_transcript.next_in_creation.clone()
    };

    let mut ecdsa_summary = ecdsa::EcdsaPayload {
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
        key_transcript: ecdsa::EcdsaKeyTranscript {
            current: if created.is_none() {
                // Keep using previous key transcript if the next hasn't been created
                ecdsa_payload.key_transcript.current.clone()
            } else {
                created
            },
            next_in_creation,
            key_id: ecdsa_payload.key_transcript.key_id.clone(),
        },
    };
    update_summary_refs(height, &mut ecdsa_summary, &block_reader)?;
    Ok(Some(ecdsa_summary))
}

fn update_summary_refs(
    height: Height,
    summary: &mut ecdsa::EcdsaPayload,
    block_reader: &dyn EcdsaBlockReader,
) -> Result<(), EcdsaPayloadError> {
    // Gather the refs and update them to point to the new
    // summary block height.
    let prev_refs = summary.active_transcripts();
    summary.update_refs(height);

    // Resolve the transcript refs pointing into the parent chain,
    // copy the resolved transcripts into the summary block.
    summary.idkg_transcripts.clear();
    for transcript_ref in prev_refs {
        let transcript = block_reader.transcript(&transcript_ref)?;
        summary
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
    curr_interval_registry_version: RegistryVersion,
    next_interval_registry_version: RegistryVersion,
    subnet_id: SubnetId,
) -> Result<bool, MembershipError> {
    let current_nodes =
        get_subnet_nodes(registry_client, curr_interval_registry_version, subnet_id)?
            .into_iter()
            .collect::<BTreeSet<_>>();
    let next_nodes = get_subnet_nodes(registry_client, next_interval_registry_version, subnet_id)?
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
    // Return None if parent block does not have ECDSA payload.
    if parent_block.payload.as_ref().as_ecdsa().is_none() {
        return Ok(None);
    };
    let summary_block = pool_reader
        .dkg_summary_block(parent_block)
        .ok_or_else(|| EcdsaPayloadError::ConsensusSummaryBlockNotFound(parent_block.height()))?;

    // The notarized tip(parent) may be ahead of the finalized tip, and
    // the last few blocks may have references to heights after the finalized
    // tip. So use the chain ending at the parent to resolve refs, rather than the
    // finalized chain.
    let block_reader = block_chain_reader(
        pool_reader,
        &summary_block,
        parent_block,
        Some(ecdsa_payload_metrics),
        &log,
    )?;
    let ecdsa_pool = ecdsa_pool.read().unwrap();

    let signature_builder = EcdsaSignatureBuilderImpl::new(
        &block_reader,
        crypto,
        ecdsa_pool.deref(),
        ecdsa_payload_metrics,
        log.clone(),
    );
    let transcript_builder = EcdsaTranscriptBuilderImpl::new(
        &block_reader,
        crypto,
        ecdsa_pool.deref(),
        ecdsa_payload_metrics,
        log.clone(),
    );
    let new_payload = create_data_payload_helper(
        subnet_id,
        context,
        parent_block,
        &summary_block,
        &block_reader,
        &transcript_builder,
        &signature_builder,
        state_manager,
        registry_client,
        log,
    )?;
    if let Some(ecdsa_payload) = &new_payload {
        let is_key_transcript_created = |payload: &ecdsa::EcdsaPayload| {
            matches!(
                payload.key_transcript.next_in_creation,
                ecdsa::KeyTranscriptCreation::Created(_)
            )
        };
        if is_key_transcript_created(ecdsa_payload)
            && parent_block
                .payload
                .as_ref()
                .as_ecdsa()
                .map(is_key_transcript_created)
                .unwrap_or(false)
        {
            ecdsa_payload_metrics.payload_metrics_inc("key_transcripts_created");
        }

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
    };
    Ok(new_payload)
}

pub(crate) fn create_data_payload_helper(
    subnet_id: SubnetId,
    context: &ValidationContext,
    parent_block: &Block,
    summary_block: &Block,
    block_reader: &dyn EcdsaBlockReader,
    transcript_builder: &dyn EcdsaTranscriptBuilder,
    signature_builder: &dyn EcdsaSignatureBuilder,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    registry_client: &dyn RegistryClient,
    log: ReplicaLogger,
) -> Result<Option<ecdsa::EcdsaPayload>, EcdsaPayloadError> {
    let height = parent_block.height().increment();
    let summary = summary_block.payload.as_ref().as_summary();

    // For this interval: context.registry_version from last summary block,
    // which is the same as calling pool_reader.registry_version(height).
    // which is the same as summary.dkg.registry_version,
    let curr_interval_registry_version = summary.dkg.registry_version;
    // For next interval: context.registry_version from the new summary block
    let next_interval_registry_version = summary_block.context.registry_version;

    let ecdsa_config = get_ecdsa_config_if_enabled(
        subnet_id,
        curr_interval_registry_version,
        registry_client,
        &log,
    )?;
    if ecdsa_config.is_none() {
        return Ok(None);
    }
    let ecdsa_config = ecdsa_config.unwrap();
    let mut ecdsa_payload = if let Some(prev_payload) = parent_block.payload.as_ref().as_ecdsa() {
        prev_payload.clone()
    } else {
        return Ok(None);
    };

    let receivers = get_subnet_nodes(registry_client, next_interval_registry_version, subnet_id)?;
    let state = state_manager.get_state_at(context.certified_height)?;
    let all_signing_requests = &state
        .get_ref()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts;
    let ecdsa_dealings_contexts = &state
        .get_ref()
        .metadata
        .subnet_call_context_manager
        .ecdsa_dealings_contexts;

    create_data_payload_helper_2(
        &mut ecdsa_payload,
        height,
        context.time,
        &ecdsa_config,
        next_interval_registry_version,
        &receivers,
        all_signing_requests,
        ecdsa_dealings_contexts,
        block_reader,
        transcript_builder,
        signature_builder,
        log,
    )?;
    Ok(Some(ecdsa_payload))
}

pub(crate) fn create_data_payload_helper_2(
    ecdsa_payload: &mut ecdsa::EcdsaPayload,
    height: Height,
    context_time: Time,
    ecdsa_config: &EcdsaConfig,
    next_interval_registry_version: RegistryVersion,
    receivers: &[NodeId],
    all_signing_requests: &BTreeMap<CallbackId, SignWithEcdsaContext>,
    ecdsa_dealings_contexts: &BTreeMap<CallbackId, EcdsaDealingsContext>,
    block_reader: &dyn EcdsaBlockReader,
    transcript_builder: &dyn EcdsaTranscriptBuilder,
    signature_builder: &dyn EcdsaSignatureBuilder,
    log: ReplicaLogger,
) -> Result<(), EcdsaPayloadError> {
    // Check if we are creating a new key, if so, start using it immediately.
    if let ecdsa::KeyTranscriptCreation::Created(unmasked) =
        &ecdsa_payload.key_transcript.next_in_creation
    {
        let transcript = block_reader.transcript(unmasked.as_ref())?;
        if ecdsa_payload.key_transcript.current.is_none() {
            ecdsa_payload.key_transcript.current = Some(
                ecdsa::UnmaskedTranscriptWithAttributes::new(transcript.to_attributes(), *unmasked),
            );
        }
    }

    ecdsa_payload.uid_generator.update_height(height)?;
    let current_key_transcript = ecdsa_payload.key_transcript.current.as_ref().cloned();

    let valid_keys: BTreeSet<_> = ecdsa_config.key_ids.iter().cloned().collect();
    let request_expiry_time = ecdsa_config.signature_request_timeout_ns.and_then(|t| {
        let timeout = Duration::from_nanos(t);
        if context_time.as_nanos_since_unix_epoch() >= t {
            Some(context_time - timeout)
        } else {
            None
        }
    });
    update_signature_agreements(all_signing_requests, signature_builder, ecdsa_payload);
    let new_signing_requests = get_signing_requests(
        height,
        request_expiry_time,
        ecdsa_payload,
        all_signing_requests,
        &valid_keys,
    );
    update_ongoing_signatures(
        new_signing_requests,
        current_key_transcript.as_ref(),
        ecdsa_payload,
        log.clone(),
    )?;
    make_new_quadruples_if_needed(current_key_transcript.as_ref(), ecdsa_config, ecdsa_payload)?;

    let mut new_transcripts = update_quadruples_in_creation(
        current_key_transcript.as_ref(),
        ecdsa_payload,
        transcript_builder,
        height,
        &log,
    )?;
    if let Some(new_transcript) = update_next_key_transcript(
        receivers,
        next_interval_registry_version,
        current_key_transcript.as_ref(),
        &mut ecdsa_payload.key_transcript.next_in_creation,
        &mut ecdsa_payload.uid_generator,
        transcript_builder,
        height,
        log.clone(),
    )? {
        new_transcripts.push(new_transcript);
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
        ecdsa_payload,
        &make_reshare_dealings_response(ecdsa_dealings_contexts),
        current_key_transcript.as_ref(),
        block_reader,
        transcript_builder,
        &log,
    );
    let reshare_requests = get_reshare_requests(ecdsa_dealings_contexts);
    initiate_reshare_requests(
        ecdsa_payload,
        current_key_transcript.as_ref(),
        reshare_requests,
    );
    Ok(())
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
    current_key_transcript: Option<&ecdsa::UnmaskedTranscriptWithAttributes>,
    ecdsa_config: &EcdsaConfig,
    ecdsa_payload: &mut ecdsa::EcdsaPayload,
) -> Result<(), EcdsaPayloadError> {
    if let Some(key_transcript) = current_key_transcript {
        let node_ids: Vec<_> = key_transcript.receivers().iter().copied().collect();
        make_new_quadruples_if_needed_helper(
            &node_ids,
            key_transcript.registry_version(),
            ecdsa_config,
            ecdsa_payload,
        )
    } else {
        Ok(())
    }
}

fn make_new_quadruples_if_needed_helper(
    subnet_nodes: &[NodeId],
    registry_version: RegistryVersion,
    ecdsa_config: &EcdsaConfig,
    ecdsa_payload: &mut ecdsa::EcdsaPayload,
) -> Result<(), EcdsaPayloadError> {
    let unassigned_quadruples = ecdsa_payload.unassigned_quadruple_ids().count();
    let quadruples_to_create = ecdsa_config.quadruples_to_create_in_advance as usize;
    if quadruples_to_create > unassigned_quadruples {
        let quadruples_in_creation = &mut ecdsa_payload.quadruples_in_creation;
        let uid_generator = &mut ecdsa_payload.uid_generator;
        for _ in 0..(quadruples_to_create - unassigned_quadruples) {
            let kappa_config = new_random_config(subnet_nodes, registry_version, uid_generator)?;
            let lambda_config = new_random_config(subnet_nodes, registry_version, uid_generator)?;
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
    height: Height,
    request_expiry_time: Option<Time>,
    ecdsa_payload: &mut ecdsa::EcdsaPayload,
    sign_with_ecdsa_contexts: &'a BTreeMap<CallbackId, SignWithEcdsaContext>,
    valid_keys: &BTreeSet<EcdsaKeyId>,
) -> BTreeMap<ecdsa::RequestId, &'a SignWithEcdsaContext> {
    let known_random_ids_completed = ecdsa_payload
        .signature_agreements
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let known_random_ids_ongoing = ecdsa_payload
        .ongoing_signatures
        .keys()
        .map(|id| (id.pseudo_random_id, *id))
        .collect::<BTreeMap<_, _>>();
    let mut unassigned_quadruple_ids = ecdsa_payload.unassigned_quadruple_ids().collect::<Vec<_>>();
    // sort in reverse order (bigger to smaller).
    unassigned_quadruple_ids.sort_by(|a, b| b.cmp(a));
    let mut new_requests = BTreeMap::new();
    // The following iteration goes through contexts in the order
    // of their keys, which is the callback_id. Therefore we are
    // traversing the requests in the order they were created.
    for (callback_id, context) in sign_with_ecdsa_contexts.iter() {
        if known_random_ids_completed.contains(&context.pseudo_random_id) {
            continue;
        };

        // Generate a new request id only when it is not known.
        let known_request_id = known_random_ids_ongoing.get(context.pseudo_random_id.as_slice());
        let request_id = match known_request_id {
            Some(id) => *id,
            None => match unassigned_quadruple_ids.pop() {
                Some(quadruple_id) => ecdsa::RequestId {
                    height,
                    quadruple_id,
                    pseudo_random_id: context.pseudo_random_id,
                },
                None => break,
            },
        };

        // Reject requests that timed out.
        //
        // Note that we only reach this stage when a request gets paired with a quadruple id.
        // If we assume all requests eventually are paired with quadruple ids, expired ones
        // will eventually all be rejected.
        //
        // This assumption holds because we start to make new quadruples whenever there is space.
        // If an ongoing quadruple does not make progress, it will be purged eventually due to
        // the expiry of its corresponding request. This leads to the creation of a new quadruple.
        if let Some(expiry) = request_expiry_time {
            if context.batch_time < expiry {
                let response = ic_types::messages::Response {
                    originator: context.request.sender,
                    respondent: ic_types::CanisterId::ic_00(),
                    originator_reply_callback: *callback_id,
                    refund: context.request.payment,
                    response_payload: ic_types::messages::Payload::Reject(RejectContext {
                        code: RejectCode::CanisterReject,
                        message: "Signature request expired".to_string(),
                    }),
                };
                ecdsa_payload.signature_agreements.insert(
                    request_id.pseudo_random_id,
                    ecdsa::CompletedSignature::Unreported(response),
                );
                // Also remove from other structures
                ecdsa_payload.ongoing_signatures.remove(&request_id);
                ecdsa_payload
                    .quadruples_in_creation
                    .remove(&request_id.quadruple_id);
                ecdsa_payload
                    .available_quadruples
                    .remove(&request_id.quadruple_id);
                continue;
            }
        }

        // For the non-expired requests, we also need to skip those that are already in progress.
        if known_request_id.is_some() {
            continue;
        };
        // Only put them in progress when the key_id matche.
        if valid_keys.contains(&context.key_id) {
            new_requests.insert(request_id, context);
        } else {
            // Reject requests with unknown key Ids.
            // We currently consume a quadruple even if we are rejecting the request, for
            // the following reason:
            //
            // RequestId has an associated quadruple(assumes a quadruple has been assigned).
            // We could create special requests that are rejected early on, with an optional
            // QuadrupleId or reserved quadrupled Id. But this makes other paths (EcdsaPayload,
            // proto conversion, etc) more involved. Since the execution already filters invalid
            // keys, this case is expected to happen only rarely: during key deletion, etc. So it
            // should be fine to burn a quadruple in favor of simple design. Revisit if needed.
            let response = ic_types::messages::Response {
                originator: context.request.sender,
                respondent: ic_types::CanisterId::ic_00(),
                originator_reply_callback: *callback_id,
                refund: context.request.payment,
                response_payload: ic_types::messages::Payload::Reject(RejectContext {
                    code: RejectCode::CanisterReject,
                    message: format!("Invalid key_id in signature request: {:?}", context.key_id),
                }),
            };
            ecdsa_payload.signature_agreements.insert(
                request_id.pseudo_random_id,
                ecdsa::CompletedSignature::Unreported(response),
            );
        }
    }
    new_requests
}

// Update signature agreements in the data payload by combining
// shares in the ECDSA pool.
pub(crate) fn update_signature_agreements(
    all_requests: &BTreeMap<CallbackId, SignWithEcdsaContext>,
    signature_builder: &dyn EcdsaSignatureBuilder,
    payload: &mut ecdsa::EcdsaPayload,
) {
    let all_random_ids = all_requests
        .iter()
        .map(|(callback_id, context)| (context.pseudo_random_id, (callback_id, context)))
        .collect::<BTreeMap<_, _>>();
    // We first clean up the existing signature_agreements by keeping those
    // that can still be found in the signing_requests for dedup purpose.
    // We only need the "Reported" status because they would have already
    // been reported when the previous block become finalized.
    let mut new_agreements = BTreeMap::new();
    let mut old_agreements = BTreeMap::new();
    std::mem::swap(&mut payload.signature_agreements, &mut old_agreements);
    for (random_id, _) in old_agreements.into_iter() {
        if all_random_ids.get(&random_id).is_some() {
            new_agreements.insert(random_id, ecdsa::CompletedSignature::ReportedToExecution);
        }
    }
    payload.signature_agreements = new_agreements;

    // Then we collect new signatures into the signature_agreements
    let mut completed = BTreeMap::new();
    for request_id in payload.ongoing_signatures.keys() {
        let (callback_id, context) = match all_random_ids.get(&request_id.pseudo_random_id) {
            Some((callback_id, context)) => (callback_id, context),
            None => continue,
        };

        let signature = match signature_builder.get_completed_signature(request_id) {
            Some(signature) => signature,
            None => continue,
        };

        let response = ic_types::messages::Response {
            originator: context.request.sender,
            respondent: ic_types::CanisterId::ic_00(),
            originator_reply_callback: **callback_id,
            // Execution is responsible for burning the appropriate cycles
            // before pushing the new context, so any remaining cycles can
            // be refunded to the canister.
            refund: context.request.payment,
            response_payload: ic_types::messages::Payload::Data(
                SignWithECDSAReply {
                    signature: signature.signature.clone(),
                }
                .encode(),
            ),
        };
        completed.insert(*request_id, ecdsa::CompletedSignature::Unreported(response));
    }

    for (request_id, signature) in completed {
        payload.ongoing_signatures.remove(&request_id);
        payload
            .signature_agreements
            .insert(request_id.pseudo_random_id, signature);
    }
}

/// For every new signing request, we only start to work on them if
/// their matched quadruple has been fully produced.
pub(crate) fn update_ongoing_signatures(
    new_requests: BTreeMap<ecdsa::RequestId, &SignWithEcdsaContext>,
    current_key_transcript: Option<&ecdsa::UnmaskedTranscriptWithAttributes>,
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
    receivers: &[NodeId],
    registry_version: RegistryVersion,
    current_key_transcript: Option<&ecdsa::UnmaskedTranscriptWithAttributes>,
    next_key_transcript_creation: &mut ecdsa::KeyTranscriptCreation,
    uid_generator: &mut ecdsa::EcdsaUIDGenerator,
    transcript_cache: &dyn EcdsaTranscriptBuilder,
    height: Height,
    log: ReplicaLogger,
) -> Result<Option<IDkgTranscript>, EcdsaPayloadError> {
    let mut new_transcript = None;
    match (current_key_transcript, &next_key_transcript_creation) {
        (Some(transcript), ecdsa::KeyTranscriptCreation::Begin) => {
            // We have an existing key transcript, need to reshare it to create next
            // Create a new reshare config when there is none
            let dealers = transcript.receivers();
            let dealers_set = dealers.clone();
            let receivers_set = receivers.iter().copied().collect::<BTreeSet<_>>();
            if dealers_set != receivers_set {
                info!(
                    log,
                    "Node membership changed. Reshare key transcript from dealers {:?} to receivers {:?}, height = {:?}",
                    dealers,
                    receivers,
                    height,
                );
            }
            *next_key_transcript_creation = ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(
                ecdsa::ReshareOfUnmaskedParams::new(
                    uid_generator.next_transcript_id(),
                    receivers_set,
                    registry_version,
                    transcript,
                    transcript.unmasked_transcript(),
                ),
            );
        }
        (Some(_), ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(config)) => {
            // check if the next key transcript has been made
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
            {
                info!(
                    log,
                    "ECDSA key transcript created from ReshareOfUnmasked {:?} registry_version {:?} height = {}",
                    config.as_ref().transcript_id,
                    transcript.registry_version,
                    height,
                );
                let transcript_ref = ecdsa::UnmaskedTranscript::try_from((height, &transcript))?;
                *next_key_transcript_creation =
                    ecdsa::KeyTranscriptCreation::Created(transcript_ref);
                new_transcript = Some(transcript);
            }
        }
        (None, ecdsa::KeyTranscriptCreation::Begin) => {
            // The first ECDSA key transcript has to be created, starting from a random
            // config. Here receivers and dealers are the same set.
            let transcript_id = uid_generator.next_transcript_id();
            let receivers_set = receivers.iter().copied().collect::<BTreeSet<_>>();
            let dealers_set = receivers_set.clone();
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
                let receivers_set = receivers.iter().copied().collect::<BTreeSet<_>>();
                let transcript_ref = ecdsa::MaskedTranscript::try_from((height, &transcript))?;
                *next_key_transcript_creation = ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(
                    ecdsa::ReshareOfMaskedParams::new(
                        uid_generator.next_transcript_id(),
                        receivers_set,
                        registry_version,
                        &transcript,
                        transcript_ref,
                    ),
                );
                new_transcript = Some(transcript);
            }
        }
        (None, ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(config)) => {
            // Check if the unmasked transcript has been created
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
            {
                info!(
                    log,
                    "ECDSA key transcript created from ReshareOfMasked {:?} registry_version {:?} height = {}",
                    config.as_ref().transcript_id,
                    transcript.registry_version,
                    height,
                );
                let transcript_ref = ecdsa::UnmaskedTranscript::try_from((height, &transcript))?;
                *next_key_transcript_creation =
                    ecdsa::KeyTranscriptCreation::Created(transcript_ref);
                new_transcript = Some(transcript);
            }
        }
        (None, ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((_, config))) => {
            // Check if the unmasked transcript has been created
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
            {
                // next_unused_transcript_id is not updated, since the transcript_id specified
                // by the reshared param will be used.
                info!(
                    log,
                    "ECDSA Key transcript created from XnetReshareOfMasked {:?}, registry_version {:?}, height = {}",
                    config.as_ref().transcript_id,
                    transcript.registry_version,
                    height,
                );
                let transcript_ref = ecdsa::UnmaskedTranscript::try_from((height, &transcript))?;
                *next_key_transcript_creation =
                    ecdsa::KeyTranscriptCreation::Created(transcript_ref);
                new_transcript = Some(transcript);
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
    current_key_transcript: Option<&ecdsa::UnmaskedTranscriptWithAttributes>,
    payload: &mut ecdsa::EcdsaPayload,
    transcript_cache: &dyn EcdsaTranscriptBuilder,
    height: Height,
    log: &ReplicaLogger,
) -> Result<Vec<IDkgTranscript>, EcdsaPayloadError> {
    let mut newly_available = Vec::new();
    let mut new_transcripts = Vec::new();
    if let Some(key_transcript) = current_key_transcript {
        let registry_version = key_transcript.registry_version();
        let receivers = key_transcript.receivers().clone();
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
                        Some(ecdsa::MaskedTranscript::try_from((height, &transcript))?);
                    new_transcripts.push(transcript);
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
                        Some(ecdsa::MaskedTranscript::try_from((height, &transcript))?);
                    new_transcripts.push(transcript);
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
                            Some(ecdsa::UnmaskedTranscript::try_from((height, &transcript))?);
                        new_transcripts.push(transcript);
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
                            Some(ecdsa::MaskedTranscript::try_from((height, &transcript))?);
                        new_transcripts.push(transcript);
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
                    payload.uid_generator.next_transcript_id(),
                    receivers.clone(),
                    registry_version,
                    kappa_config,
                    *kappa_masked,
                ));
            }
            if let (Some(lambda_masked), None) =
                (&quadruple.lambda_masked, &quadruple.key_times_lambda_config)
            {
                let lambda_config = quadruple.lambda_config.as_ref();
                if key_transcript.receivers() != lambda_config.receivers() {
                    error!(
                        log,
                        "Key transcript has a different receiver set than lambda_config: {:?} {:?}",
                        key_transcript,
                        lambda_config
                    );
                } else {
                    quadruple.key_times_lambda_config =
                        Some(ecdsa::UnmaskedTimesMaskedParams::new(
                            payload.uid_generator.next_transcript_id(),
                            receivers.clone(),
                            registry_version,
                            (key_transcript, key_transcript.unmasked_transcript()),
                            (lambda_config, *lambda_masked),
                        ));
                }
            }
            if let (Some(lambda_masked), Some(kappa_unmasked), None) = (
                &quadruple.lambda_masked,
                &quadruple.kappa_unmasked,
                &quadruple.kappa_times_lambda_config,
            ) {
                let kappa_config = quadruple.kappa_config.as_ref();
                let lambda_config = quadruple.lambda_config.as_ref();
                if kappa_config.receivers() != lambda_config.receivers() {
                    error!(
                        log,
                        "kappa_config has a different receiver set than lambda_config: {:?} {:?}",
                        kappa_config,
                        lambda_config
                    );
                } else {
                    quadruple.kappa_times_lambda_config =
                        Some(ecdsa::UnmaskedTimesMaskedParams::new(
                            payload.uid_generator.next_transcript_id(),
                            receivers.clone(),
                            registry_version,
                            (kappa_config, *kappa_unmasked),
                            (lambda_config, *lambda_masked),
                        ));
                }
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
    key_transcript_ref: &ecdsa::UnmaskedTranscriptWithAttributes,
) -> ecdsa::ThresholdEcdsaSigInputsRef {
    let extended_derivation_path = ExtendedDerivationPath {
        caller: context.request.sender.into(),
        derivation_path: context.derivation_path.clone(),
    };
    ecdsa::ThresholdEcdsaSigInputsRef::new(
        extended_derivation_path,
        context.message_hash,
        Id::from(context.pseudo_random_id),
        quadruple_ref.clone(),
        key_transcript_ref.unmasked_transcript(),
    )
}

/// Checks for new reshare requests from execution and initiates
/// the processing.
/// TODO: in future, we may need to maintain a key transcript per supported key_id,
/// and reshare the one specified by reshare_request.key_id.
pub(crate) fn initiate_reshare_requests(
    payload: &mut ecdsa::EcdsaPayload,
    current_key_transcript: Option<&ecdsa::UnmaskedTranscriptWithAttributes>,
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
        let receivers = request
            .receiving_node_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let transcript_params = ecdsa::ReshareOfUnmaskedParams::new(
            transcript_id,
            receivers,
            request.registry_version,
            key_transcript,
            key_transcript.unmasked_transcript(),
        );
        payload
            .ongoing_xnet_reshares
            .insert(request, transcript_params);
    }
}

fn make_reshare_dealings_response(
    ecdsa_dealings_contexts: &'_ BTreeMap<CallbackId, EcdsaDealingsContext>,
) -> impl Fn(&ecdsa::EcdsaReshareRequest, &InitialIDkgDealings) -> Option<ic_types::messages::Response>
       + '_ {
    Box::new(
        move |request: &ecdsa::EcdsaReshareRequest, initial_dealings: &InitialIDkgDealings| {
            for (callback_id, context) in ecdsa_dealings_contexts.iter() {
                if request
                    == &(ecdsa::EcdsaReshareRequest {
                        key_id: context.key_id.clone(),
                        receiving_node_ids: context.nodes.iter().cloned().collect(),
                        registry_version: context.registry_version,
                    })
                {
                    use ic_ic00_types::ComputeInitialEcdsaDealingsResponse;
                    return Some(ic_types::messages::Response {
                        originator: context.request.sender,
                        respondent: ic_types::CanisterId::ic_00(),
                        originator_reply_callback: *callback_id,
                        refund: context.request.payment,
                        response_payload: ic_types::messages::Payload::Data(
                            ComputeInitialEcdsaDealingsResponse {
                                initial_dkg_dealings: initial_dealings.into(),
                            }
                            .encode(),
                        ),
                    });
                }
            }
            None
        },
    )
}

/// Checks and updates the completed reshare requests.
pub(crate) fn update_completed_reshare_requests(
    payload: &mut ecdsa::EcdsaPayload,
    make_reshare_dealings_response: &dyn Fn(
        &ecdsa::EcdsaReshareRequest,
        &InitialIDkgDealings,
    ) -> Option<ic_types::messages::Response>,
    current_key_transcript: Option<&ecdsa::UnmaskedTranscriptWithAttributes>,
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
        let dealings = transcript_builder.get_validated_dealings(transcript_id);

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
        if let Some(response) = make_reshare_dealings_response(&request, &initial_dealings) {
            payload.ongoing_xnet_reshares.remove(&request);
            payload.xnet_reshare_agreements.insert(
                request.clone(),
                ecdsa::CompletedReshareRequest::Unreported(response),
            );
        } else {
            warn!(
                log,
                "Cannot find the request for the initial dealings created: {:?}", request
            );
        }
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

pub(crate) fn block_chain_reader(
    pool_reader: &PoolReader<'_>,
    summary_block: &Block,
    parent_block: &Block,
    ecdsa_payload_metrics: Option<&EcdsaPayloadMetrics>,
    log: &ReplicaLogger,
) -> Result<EcdsaBlockReaderImpl, EcdsaPayloadError> {
    // Resolve the transcript refs pointing into the parent chain,
    // copy the resolved transcripts into the summary block.
    block_chain_cache(pool_reader, summary_block, parent_block)
        .map(EcdsaBlockReaderImpl::new)
        .map_err(|err| {
            warn!(
                log,
                "block_chain_reader(): failed to build chain cache: {:?}", err
            );
            if let Some(metrics) = ecdsa_payload_metrics {
                metrics.payload_errors_inc("summary_invalid_chain_cache");
            };
            err.into()
        })
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
            chain.tip().0,
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
    use ic_crypto_test_utils_canister_threshold_sigs::{
        generate_key_transcript, run_idkg_and_create_and_verify_transcript,
        CanisterThresholdSigTestEnvironment,
    };
    use ic_logger::replica_logger::no_op_logger;
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
    use ic_types::crypto::canister_threshold_sig::{
        idkg::IDkgTranscriptId, ThresholdEcdsaCombinedSignature,
    };
    use ic_types::{messages::CallbackId, Height, RegistryVersion};
    use std::collections::BTreeSet;
    use std::convert::TryInto;
    use std::str::FromStr;

    fn empty_ecdsa_summary_payload(
        subnet_id: SubnetId,
        current_key_transcript: (ecdsa::UnmaskedTranscript, IDkgTranscript),
    ) -> ecdsa::EcdsaPayload {
        let mut ret = empty_ecdsa_payload(subnet_id);
        ret.key_transcript.current = Some(ecdsa::UnmaskedTranscriptWithAttributes::new(
            current_key_transcript.1.to_attributes(),
            current_key_transcript.0,
        ));
        ret
    }

    fn empty_ecdsa_data_payload(subnet_id: SubnetId) -> ecdsa::EcdsaPayload {
        empty_ecdsa_payload(subnet_id)
    }

    fn create_summary_block_with_transcripts(
        subnet_id: SubnetId,
        height: Height,
        current_key_transcript: (ecdsa::UnmaskedTranscript, IDkgTranscript),
        transcripts: Vec<BTreeMap<ecdsa::TranscriptRef, IDkgTranscript>>,
    ) -> BlockPayload {
        let mut ecdsa_summary =
            empty_ecdsa_summary_payload(subnet_id, current_key_transcript.clone());
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
                Vec::new(),
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

    fn create_reshare_request(num_nodes: u64, registry_version: u64) -> ecdsa::EcdsaReshareRequest {
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
        block.payload = Payload::new(ic_types::crypto::crypto_hash, block_payload);
        block_proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
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
        let result = make_new_quadruples_if_needed_helper(
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
        let mut valid_keys = BTreeSet::new();
        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        valid_keys.insert(key_id.clone());
        let mut state = ReplicatedStateBuilder::default().build();
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .insert(
                CallbackId::from(0),
                SignWithEcdsaContext {
                    request: RequestBuilder::new().build(),
                    key_id,
                    pseudo_random_id: [0; 32],
                    message_hash: [0; 32],
                    derivation_path: vec![],
                    batch_time: mock_time(),
                },
            );
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
        let height = Height::from(1);
        let result = get_signing_requests(
            height,
            None,
            &mut ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
            &valid_keys,
        );
        // Because there is no quadruples available, expect empty return
        assert!(result.is_empty());
        // Add two quadruples in creation
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
            height,
            None,
            &mut ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
            &valid_keys,
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
        let idkg_key_transcript =
            generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let key_transcript_ref =
            ecdsa::UnmaskedTranscript::try_from((Height::from(0), &idkg_key_transcript)).unwrap();
        let key_transcript = ecdsa::UnmaskedTranscriptWithAttributes::new(
            idkg_key_transcript.to_attributes(),
            key_transcript_ref,
        );
        let result = update_ongoing_signatures(
            result,
            Some(&key_transcript),
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
                    key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
                    pseudo_random_id: [1; 32],
                    message_hash: [0; 32],
                    derivation_path: vec![],
                    batch_time: mock_time(),
                },
            );
        // Now there are two signing requests
        let new_requests = get_signing_requests(
            height,
            None,
            &mut ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
            &valid_keys,
        );
        assert_eq!(new_requests.len(), 2);
        let request_id_1 = *new_requests.keys().find(|x| x != &&request_id_0).unwrap();
        // We should be able to move the 2nd request into ongoing_signatures.
        let result = update_ongoing_signatures(
            new_requests,
            Some(&key_transcript),
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
            height,
            None,
            &mut ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
            &valid_keys,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result.keys().next().unwrap().clone(), request_id_0);
    }

    #[test]
    fn test_ecdsa_update_ongoing_signatures() {
        let subnet_id = subnet_test_id(1);
        let pseudo_random_id = [0; 32];
        let mut state = ReplicatedStateBuilder::default().build();
        let mut valid_keys = BTreeSet::new();
        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        valid_keys.insert(key_id.clone());
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .insert(
                CallbackId::from(1),
                SignWithEcdsaContext {
                    request: RequestBuilder::new().build(),
                    key_id,
                    pseudo_random_id,
                    message_hash: [0; 32],
                    derivation_path: vec![],
                    batch_time: mock_time(),
                },
            );
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
        let height = Height::from(1);
        let result = get_signing_requests(
            height,
            None,
            &mut ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
            &valid_keys,
        );
        // Because there is no quadruples available, expect empty return
        assert!(result.is_empty());
        // Add a quadruple
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
            height,
            None,
            &mut ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
            &valid_keys,
        );
        assert_eq!(result.len(), 1);
        // Check if it is matched with the smaller quadruple ID
        let request_id = &result.keys().next().unwrap().clone();
        assert_eq!(request_id.quadruple_id, quadruple_id);
    }

    #[test]
    fn test_ecdsa_signing_request_timeout() {
        let subnet_id = subnet_test_id(1);
        let mut state = ReplicatedStateBuilder::default().build();
        let mut valid_keys = BTreeSet::new();
        let expired_time = mock_time() + Duration::from_secs(10);
        let expiry_time = mock_time() + Duration::from_secs(11);
        let non_expired_time = mock_time() + Duration::from_secs(12);
        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        valid_keys.insert(key_id.clone());
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .insert(
                CallbackId::from(1),
                SignWithEcdsaContext {
                    request: RequestBuilder::new().build(),
                    key_id: key_id.clone(),
                    pseudo_random_id: [0; 32],
                    message_hash: [0; 32],
                    derivation_path: vec![],
                    batch_time: expired_time,
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
                    key_id,
                    pseudo_random_id: [1; 32],
                    message_hash: [0; 32],
                    derivation_path: vec![],
                    batch_time: non_expired_time,
                },
            );
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
        let height = Height::from(1);
        // Add quadruples
        let sig_inputs = create_sig_inputs(10);
        let quadruple_ref = &sig_inputs.sig_inputs_ref.presig_quadruple_ref;
        ecdsa_payload.available_quadruples.insert(
            ecdsa_payload.uid_generator.next_quadruple_id(),
            quadruple_ref.clone(),
        );
        let sig_inputs = create_sig_inputs(11);
        let quadruple_ref = &sig_inputs.sig_inputs_ref.presig_quadruple_ref;
        let quadruple_id = ecdsa_payload.uid_generator.next_quadruple_id();
        ecdsa_payload
            .available_quadruples
            .insert(quadruple_id, quadruple_ref.clone());
        let result = get_signing_requests(
            height,
            Some(expiry_time),
            &mut ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
            &valid_keys,
        );
        assert_eq!(result.len(), 1);
        // Check if it is matched with the quadruple ID 1, because quadruple ID 0 is discard too.
        let request_id = &result.keys().next().unwrap().clone();
        assert_eq!(request_id.quadruple_id, quadruple_id);
    }

    #[test]
    fn test_ecdsa_request_with_invalid_key() {
        let subnet_id = subnet_test_id(1);
        let pseudo_random_id = [0; 32];
        let mut state = ReplicatedStateBuilder::default().build();
        let mut valid_keys = BTreeSet::new();
        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        valid_keys.insert(key_id);

        // Add a request with a non-existent key.
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .insert(
                CallbackId::from(1),
                SignWithEcdsaContext {
                    request: RequestBuilder::new().build(),
                    key_id: EcdsaKeyId::from_str("Secp256k1:some_invalid_key").unwrap(),
                    pseudo_random_id,
                    message_hash: [0; 32],
                    derivation_path: vec![],
                    batch_time: mock_time(),
                },
            );
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
        let height = Height::from(1);
        let result = get_signing_requests(
            height,
            None,
            &mut ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
            &valid_keys,
        );
        // Because there is no quadruples available, expect empty return
        assert!(result.is_empty());
        // Add a quadruple
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
            height,
            None,
            &mut ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
            &valid_keys,
        );

        // Verify the request is rejected.
        assert_eq!(result.len(), 0);
        assert_eq!(ecdsa_payload.ongoing_signatures.len(), 0);
        assert_eq!(ecdsa_payload.signature_agreements.len(), 1);
        let (_, response) = ecdsa_payload.signature_agreements.iter().next().unwrap();
        if let ecdsa::CompletedSignature::Unreported(response) = response {
            assert!(matches!(
                response.response_payload,
                ic_types::messages::Payload::Reject(..)
            ));
        } else {
            panic!("Unexpected response");
        }
    }

    #[test]
    fn test_ecdsa_update_next_key_transcript() {
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
        let registry_version = env.newest_registry_version;
        let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
        let mut block_reader = TestEcdsaBlockReader::new();
        let config_ids = |payload: &ecdsa::EcdsaPayload| {
            let mut arr = payload
                .iter_transcript_configs_in_creation()
                .map(|x| x.transcript_id.id())
                .collect::<Vec<_>>();
            arr.sort_unstable();
            arr
        };
        let transcript_builder = TestEcdsaTranscriptBuilder::new();

        // 1. Nothing initially, masked transcript creation should start
        let cur_height = Height::new(10);
        let mut payload = empty_ecdsa_data_payload(subnet_id);
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            None,
            &mut payload.key_transcript.next_in_creation,
            &mut payload.uid_generator,
            &transcript_builder,
            cur_height,
            no_op_logger(),
        );
        matches!(result, Ok(None));
        assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 1);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [0]);

        // 2. Masked random transcript is created, should start reshare of the masked
        // transcript.
        let cur_height = Height::new(20);
        let masked_transcript = {
            let param = match &payload.key_transcript.next_in_creation {
                ecdsa::KeyTranscriptCreation::RandomTranscriptParams(param) => param.clone(),
                _ => panic!(
                    "Unexpected state: {:?}",
                    payload.key_transcript.next_in_creation
                ),
            };
            run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &env.crypto_components,
            )
        };
        transcript_builder
            .add_transcript(masked_transcript.transcript_id, masked_transcript.clone());
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            None,
            &mut payload.key_transcript.next_in_creation,
            &mut payload.uid_generator,
            &transcript_builder,
            cur_height,
            no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, masked_transcript);
        block_reader.add_transcript(
            ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
            completed_transcript,
        );
        assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [1]);

        // 3. Unmasked transcript is created, should complete the boot strap sequence
        let cur_height = Height::new(30);
        let unmasked_transcript = {
            let param = match &payload.key_transcript.next_in_creation {
                ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(param) => param.clone(),
                _ => panic!(
                    "Unexpected state: {:?}",
                    payload.key_transcript.next_in_creation
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
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            None,
            &mut payload.key_transcript.next_in_creation,
            &mut payload.uid_generator,
            &transcript_builder,
            cur_height,
            no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, unmasked_transcript);
        let current_key_transcript = ecdsa::UnmaskedTranscriptWithAttributes::new(
            completed_transcript.to_attributes(),
            ecdsa::UnmaskedTranscript::try_from((cur_height, &unmasked_transcript)).unwrap(),
        );
        block_reader.add_transcript(
            ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
            completed_transcript,
        );
        assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 0);
        assert!(config_ids(&payload).is_empty());
        ecdsa::TranscriptRef::new(cur_height, unmasked_transcript.transcript_id);
        match &payload.key_transcript.next_in_creation {
            ecdsa::KeyTranscriptCreation::Created(unmasked) => {
                assert_eq!(*unmasked.as_ref(), *current_key_transcript.as_ref());
            }
            _ => panic!(
                "Unexpected state: {:?}",
                payload.key_transcript.next_in_creation
            ),
        }

        // 4. Reshare the current key transcript to get the next one
        let cur_height = Height::new(40);
        payload.key_transcript.next_in_creation = ecdsa::KeyTranscriptCreation::Begin;
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            Some(&current_key_transcript),
            &mut payload.key_transcript.next_in_creation,
            &mut payload.uid_generator,
            &transcript_builder,
            cur_height,
            no_op_logger(),
        );
        matches!(result, Ok(None));
        assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 3);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [2]);

        // 5. Reshare completes to get the next unmasked transcript
        let cur_height = Height::new(50);
        let unmasked_transcript = {
            let param = match &payload.key_transcript.next_in_creation {
                ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(param) => param.clone(),
                _ => panic!(
                    "Unexpected state: {:?}",
                    payload.key_transcript.next_in_creation
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
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            Some(&current_key_transcript),
            &mut payload.key_transcript.next_in_creation,
            &mut payload.uid_generator,
            &transcript_builder,
            cur_height,
            no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, unmasked_transcript);
        assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 3);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 0);
        assert!(config_ids(&payload).is_empty());
        let current_key_transcript =
            ecdsa::UnmaskedTranscript::try_from((cur_height, &unmasked_transcript)).unwrap();
        match &payload.key_transcript.next_in_creation {
            ecdsa::KeyTranscriptCreation::Created(unmasked) => {
                assert_eq!(*unmasked.as_ref(), *current_key_transcript.as_ref());
            }
            _ => panic!(
                "Unexpected state: {:?}",
                payload.key_transcript.next_in_creation
            ),
        }
    }

    #[test]
    fn test_ecdsa_update_next_key_transcript_xnet_target_subnet() {
        let num_of_nodes = 8;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
        let registry_version = env.newest_registry_version;
        let mut subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
        let target_subnet_nodes = subnet_nodes.split_off(4);
        let mut block_reader = TestEcdsaBlockReader::new();
        let config_ids = |payload: &ecdsa::EcdsaPayload| {
            let mut arr = payload
                .iter_transcript_configs_in_creation()
                .map(|x| x.transcript_id.id())
                .collect::<Vec<_>>();
            arr.sort_unstable();
            arr
        };
        let transcript_builder = TestEcdsaTranscriptBuilder::new();

        // 1. Nothing initially, masked transcript creation should start
        let cur_height = Height::new(10);
        let mut payload = empty_ecdsa_data_payload(subnet_id);
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            None,
            &mut payload.key_transcript.next_in_creation,
            &mut payload.uid_generator,
            &transcript_builder,
            cur_height,
            no_op_logger(),
        );
        matches!(result, Ok(None));
        assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 1);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [0]);

        // 2. Masked random transcript is created, should start reshare of the masked
        // transcript.
        let cur_height = Height::new(20);
        let masked_transcript = {
            let param = match &payload.key_transcript.next_in_creation {
                ecdsa::KeyTranscriptCreation::RandomTranscriptParams(param) => param.clone(),
                _ => panic!(
                    "Unexpected state: {:?}",
                    payload.key_transcript.next_in_creation
                ),
            };
            run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &env.crypto_components,
            )
        };
        transcript_builder
            .add_transcript(masked_transcript.transcript_id, masked_transcript.clone());
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            None,
            &mut payload.key_transcript.next_in_creation,
            &mut payload.uid_generator,
            &transcript_builder,
            cur_height,
            no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, masked_transcript);
        block_reader.add_transcript(
            ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
            completed_transcript,
        );
        assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [1]);

        // 3. Unmasked transcript is created, should complete the boot strap sequence
        let cur_height = Height::new(30);
        let unmasked_transcript = {
            let param = match &payload.key_transcript.next_in_creation {
                ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(param) => param.clone(),
                _ => panic!(
                    "Unexpected state: {:?}",
                    payload.key_transcript.next_in_creation
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
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            None,
            &mut payload.key_transcript.next_in_creation,
            &mut payload.uid_generator,
            &transcript_builder,
            cur_height,
            no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, unmasked_transcript);
        block_reader.add_transcript(
            ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
            completed_transcript,
        );
        assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 0);
        assert!(config_ids(&payload).is_empty());
        let current_key_transcript =
            ecdsa::UnmaskedTranscript::try_from((cur_height, &unmasked_transcript)).unwrap();
        ecdsa::TranscriptRef::new(cur_height, unmasked_transcript.transcript_id);
        match &payload.key_transcript.next_in_creation {
            ecdsa::KeyTranscriptCreation::Created(unmasked) => {
                assert_eq!(*unmasked.as_ref(), *current_key_transcript.as_ref());
            }
            _ => panic!(
                "Unexpected state: {:?}",
                payload.key_transcript.next_in_creation
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
        payload.key_transcript.next_in_creation =
            ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((
                Box::new(dummy_initial_idkg_dealing_for_tests()),
                params,
            ));
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            None,
            &mut payload.key_transcript.next_in_creation,
            &mut payload.uid_generator,
            &transcript_builder,
            cur_height,
            no_op_logger(),
        );
        matches!(result, Ok(None));
        assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [reshare_params.transcript_id().id()]);

        // 5. Complete the reshared transcript creation. This should cause the key to
        // move to created state.
        let cur_height = Height::new(50);
        let unmasked_transcript = {
            let param = match &payload.key_transcript.next_in_creation {
                ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((_, param)) => {
                    param.clone()
                }
                _ => panic!(
                    "Unexpected state: {:?}",
                    payload.key_transcript.next_in_creation
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
        let result = update_next_key_transcript(
            &target_subnet_nodes,
            registry_version,
            None,
            &mut payload.key_transcript.next_in_creation,
            &mut payload.uid_generator,
            &transcript_builder,
            cur_height,
            no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, unmasked_transcript);
        assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 0);
        assert!(config_ids(&payload).is_empty());
        let current_key_transcript =
            ecdsa::UnmaskedTranscript::try_from((cur_height, &unmasked_transcript)).unwrap();
        match &payload.key_transcript.next_in_creation {
            ecdsa::KeyTranscriptCreation::Created(unmasked) => {
                assert_eq!(*unmasked.as_ref(), *current_key_transcript.as_ref());
            }
            _ => panic!(
                "Unexpected state: {:?}",
                payload.key_transcript.next_in_creation
            ),
        }
    }

    #[test]
    fn test_ecdsa_update_signature_agreements() {
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
                    key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
                    pseudo_random_id: [1; 32],
                    message_hash: [0; 32],
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
                    key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
                    pseudo_random_id: [2; 32],
                    message_hash: [0; 32],
                    derivation_path: vec![],
                    batch_time: mock_time(),
                },
            );
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);

        let all_requests = &state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts;

        ecdsa_payload.signature_agreements.insert(
            [1; 32],
            ecdsa::CompletedSignature::Unreported(empty_response()),
        );
        ecdsa_payload.signature_agreements.insert(
            [0; 32],
            ecdsa::CompletedSignature::Unreported(empty_response()),
        );
        let signature_builder = TestEcdsaSignatureBuilder::new();
        // old signature in the agreement AND in state is replaced by ReportedToExecution
        // old signature in the agreement but NOT in state is removed.
        update_signature_agreements(all_requests, &signature_builder, &mut ecdsa_payload);
        assert_eq!(ecdsa_payload.signature_agreements.len(), 1);
        assert_eq!(
            ecdsa_payload.signature_agreements.keys().next().unwrap(),
            &[1; 32],
        );
        assert!(matches!(
            ecdsa_payload.signature_agreements.values().next().unwrap(),
            ecdsa::CompletedSignature::ReportedToExecution
        ));
    }

    /// Test that ECDSA signature agreement is only delivered once.
    #[test]
    fn test_ecdsa_signature_is_only_delivered_once() {
        use crate::consensus::batch_delivery::generate_responses_to_sign_with_ecdsa_calls;

        let num_nodes = 4;
        let subnet_id = subnet_test_id(0);
        let env = CanisterThresholdSigTestEnvironment::new(num_nodes);
        let mut block_reader = TestEcdsaBlockReader::new();
        let transcript_builder = TestEcdsaTranscriptBuilder::new();
        let mut sign_with_ecdsa_contexts = BTreeMap::new();
        let mut valid_keys = BTreeSet::new();
        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        valid_keys.insert(key_id.clone());
        sign_with_ecdsa_contexts.insert(
            CallbackId::from(1),
            SignWithEcdsaContext {
                request: RequestBuilder::new().build(),
                key_id,
                pseudo_random_id: [1; 32],
                message_hash: [0; 32],
                derivation_path: vec![],
                batch_time: mock_time(),
            },
        );
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let key_transcript_ref =
            ecdsa::UnmaskedTranscript::try_from((Height::from(0), &key_transcript)).unwrap();
        let current_key_transcript = ecdsa::UnmaskedTranscriptWithAttributes::new(
            key_transcript.to_attributes(),
            key_transcript_ref,
        );
        let quadruple_id_1 = ecdsa_payload.uid_generator.next_quadruple_id();
        // Fill in the ongoing signatures
        let sig_inputs_1 = create_sig_inputs_with_args(
            13,
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
        ecdsa_payload.available_quadruples.insert(
            quadruple_id_1,
            sig_inputs_1.sig_inputs_ref.presig_quadruple_ref,
        );

        let all_requests = get_signing_requests(
            Height::from(0),
            None,
            &mut ecdsa_payload,
            &sign_with_ecdsa_contexts,
            &valid_keys,
        );

        update_ongoing_signatures(
            all_requests,
            Some(&current_key_transcript),
            &mut ecdsa_payload,
            no_op_logger(),
        )
        .unwrap();

        let mut signature_builder = TestEcdsaSignatureBuilder::new();
        signature_builder.signatures.insert(
            *ecdsa_payload.ongoing_signatures.keys().next().unwrap(),
            ThresholdEcdsaCombinedSignature {
                signature: vec![1; 32],
            },
        );

        // create first ecdsa payload
        create_data_payload_helper_2(
            &mut ecdsa_payload,
            Height::from(5),
            mock_time(),
            &EcdsaConfig::default(),
            RegistryVersion::from(9),
            &[node_test_id(0)],
            &sign_with_ecdsa_contexts,
            &BTreeMap::default(),
            &block_reader,
            &transcript_builder,
            &signature_builder,
            ic_logger::replica_logger::no_op_logger(),
        )
        .unwrap();

        // Assert that we got a response
        let response1 = generate_responses_to_sign_with_ecdsa_calls(&ecdsa_payload);
        assert_eq!(response1.len(), 1);

        // create next ecdsa payload
        create_data_payload_helper_2(
            &mut ecdsa_payload,
            Height::from(5),
            mock_time(),
            &EcdsaConfig::default(),
            RegistryVersion::from(9),
            &[node_test_id(0)],
            &sign_with_ecdsa_contexts,
            &BTreeMap::default(),
            &block_reader,
            &transcript_builder,
            &signature_builder,
            ic_logger::replica_logger::no_op_logger(),
        )
        .unwrap();

        // assert that same signature isn't delivered again.
        let response2 = generate_responses_to_sign_with_ecdsa_calls(&ecdsa_payload);
        assert!(response2.is_empty());
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
        let transcript_builder = TestEcdsaTranscriptBuilder::new();

        let idkg_key_transcript = generate_key_transcript(&env, algorithm);
        let key_transcript_ref =
            ecdsa::UnmaskedTranscript::try_from((Height::new(100), &idkg_key_transcript)).unwrap();
        let current_key_transcript = ecdsa::UnmaskedTranscriptWithAttributes::new(
            idkg_key_transcript.to_attributes(),
            key_transcript_ref,
        );
        block_reader.add_transcript(*key_transcript_ref.as_ref(), idkg_key_transcript);
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
            Some(&current_key_transcript),
            &mut payload,
            &transcript_builder,
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
            Some(&current_key_transcript),
            &mut payload,
            &transcript_builder,
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
            Some(&current_key_transcript),
            &mut payload,
            &transcript_builder,
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
            Some(&current_key_transcript),
            &mut payload,
            &transcript_builder,
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
        transcript_builder.add_transcript(key_times_lambda_config_id, key_times_lambda_transcript);
        let cur_height = Height::new(5000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_quadruples_in_creation(
            Some(&current_key_transcript),
            &mut payload,
            &transcript_builder,
            cur_height,
            &no_op_logger(),
        )
        .unwrap();
        assert_eq!(result.len(), 2);
        // check if new config is made
        assert_eq!(payload.available_quadruples.len(), 1);
        assert_eq!(payload.uid_generator.clone().next_transcript_id().id(), 5);
        assert!(config_ids(&payload).is_empty());
    }

    #[test]
    fn test_ecdsa_initiate_reshare_requests() {
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
        let mut payload = empty_ecdsa_payload(subnet_id);
        let algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;
        let req_1 = create_reshare_request(1, 1);
        let req_2 = create_reshare_request(2, 2);
        let mut reshare_requests = BTreeSet::new();
        reshare_requests.insert(req_1.clone());
        reshare_requests.insert(req_2.clone());

        // Key not yet created, requests should not be accepted
        initiate_reshare_requests(&mut payload, None, reshare_requests.clone());
        assert!(payload.ongoing_xnet_reshares.is_empty());
        assert!(payload.xnet_reshare_agreements.is_empty());

        // Two new requests, should be accepted
        let key_transcript = generate_key_transcript(&env, algorithm);
        let key_transcript_ref =
            ecdsa::UnmaskedTranscript::try_from((Height::new(100), &key_transcript)).unwrap();
        let current_key_transcript = ecdsa::UnmaskedTranscriptWithAttributes::new(
            key_transcript.to_attributes(),
            key_transcript_ref,
        );
        initiate_reshare_requests(
            &mut payload,
            Some(&current_key_transcript),
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
            Some(&current_key_transcript),
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
            Some(&current_key_transcript),
            reshare_requests.clone(),
        );
        assert_eq!(payload.ongoing_xnet_reshares.len(), 3);
        assert_eq!(payload.xnet_reshare_agreements.len(), 1);
    }

    #[test]
    fn test_ecdsa_update_completed_reshare_requests() {
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
        let mut payload = empty_ecdsa_payload(subnet_id);
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
        let current_key_transcript = ecdsa::UnmaskedTranscriptWithAttributes::new(
            key_transcript.to_attributes(),
            key_transcript_ref,
        );
        block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript);
        initiate_reshare_requests(
            &mut payload,
            Some(&current_key_transcript),
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
            &|_, _| Some(empty_response()),
            Some(&current_key_transcript),
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
            &|_, _| Some(empty_response()),
            Some(&current_key_transcript),
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
            &|_, _| Some(empty_response()),
            Some(&current_key_transcript),
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
    }

    #[test]
    fn test_ecdsa_update_summary_refs() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { mut pool, .. } = dependencies(pool_config, 1);
            let subnet_id = subnet_test_id(1);
            let mut expected_transcripts = BTreeSet::new();
            let transcript_builder = TestEcdsaTranscriptBuilder::new();
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
            let current_key_transcript = ecdsa::UnmaskedTranscriptWithAttributes::new(
                key_transcript.to_attributes(),
                key_transcript_ref,
            );
            let reshare_key_transcript = create_key_transcript();
            let reshare_key_transcript_ref =
                ecdsa::UnmaskedTranscript::try_from((summary_height, &reshare_key_transcript))
                    .unwrap();
            let reshare_params_1 = ecdsa::ReshareOfUnmaskedParams::new(
                create_transcript_id(1001),
                BTreeSet::new(),
                RegistryVersion::from(1001),
                &reshare_key_transcript,
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
                height: payload_height_1,
            };
            let req_id_2 = ecdsa::RequestId {
                quadruple_id: quadruple_id_2,
                pseudo_random_id: [1; 32],
                height: payload_height_1,
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
                Some(&current_key_transcript),
                &mut ecdsa_payload,
                &transcript_builder,
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

            let mut data_payload = ecdsa_payload.clone();
            data_payload.key_transcript.next_in_creation =
                ecdsa::KeyTranscriptCreation::Created(key_transcript_ref);
            let parent_block_payload = BlockPayload::Data(DataPayload {
                batch: BatchPayload::default(),
                dealings: Dealings::new_empty(summary_height),
                ecdsa: Some(data_payload),
            });
            let parent_block = add_block(
                parent_block_payload,
                parent_block_height.get() - payload_height_1.get(),
                &mut pool,
            );
            let pool_reader = PoolReader::new(&pool);

            // Add a summary block after the payload block
            let new_summary_height = parent_block_height.increment();
            let mut summary = ecdsa_payload.clone();
            summary.key_transcript.current = Some(current_key_transcript);
            summary.key_transcript.next_in_creation = ecdsa::KeyTranscriptCreation::Begin;
            assert_ne!(
                summary
                    .key_transcript
                    .current
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .height,
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
            for quadruple_in_creation in summary.quadruples_in_creation.values() {
                for transcript_ref in quadruple_in_creation.get_refs() {
                    assert_ne!(transcript_ref.height, new_summary_height);
                }
            }
            for reshare_params in summary.ongoing_xnet_reshares.values() {
                for transcript_ref in reshare_params.as_ref().get_refs() {
                    assert_ne!(transcript_ref.height, new_summary_height);
                }
            }
            let block_reader = block_chain_reader(
                &pool_reader,
                &pool_reader.get_highest_summary_block(),
                &parent_block,
                None,
                &no_op_logger(),
            )
            .unwrap();

            assert!(update_summary_refs(
                parent_block.height().increment(),
                &mut summary,
                &block_reader
            )
            .is_ok());

            // Verify that all the transcript references in the parent block
            // have been updated to point to the new summary height
            assert_eq!(
                summary
                    .key_transcript
                    .current
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .height,
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
            for quadruple_in_creation in summary.quadruples_in_creation.values() {
                for transcript_ref in quadruple_in_creation.get_refs() {
                    assert_eq!(transcript_ref.height, new_summary_height);
                }
            }
            for reshare_params in summary.ongoing_xnet_reshares.values() {
                for transcript_ref in reshare_params.as_ref().get_refs() {
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

    #[test]
    fn test_ecdsa_summary_proto_conversion() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { mut pool, .. } = dependencies(pool_config, 1);
            let subnet_id = subnet_test_id(1);
            let transcript_builder = TestEcdsaTranscriptBuilder::new();
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
            let current_key_transcript = ecdsa::UnmaskedTranscriptWithAttributes::new(
                key_transcript.to_attributes(),
                key_transcript_ref,
            );
            let reshare_key_transcript = create_key_transcript();
            let reshare_key_transcript_ref =
                ecdsa::UnmaskedTranscript::try_from((summary_height, &reshare_key_transcript))
                    .unwrap();
            let reshare_params_1 = ecdsa::ReshareOfUnmaskedParams::new(
                create_transcript_id(1001),
                BTreeSet::new(),
                RegistryVersion::from(1001),
                &reshare_key_transcript,
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
                height: payload_height_1,
            };
            let req_id_2 = ecdsa::RequestId {
                quadruple_id: quadruple_id_2,
                pseudo_random_id: [1; 32],
                height: payload_height_1,
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
                ecdsa::CompletedReshareRequest::Unreported(empty_response()),
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
                Some(&current_key_transcript),
                &mut ecdsa_payload,
                &transcript_builder,
                parent_block_height,
                &no_op_logger(),
            )
            .unwrap();
            assert_eq!(result.len(), 1);

            ecdsa_payload
                .signature_agreements
                .insert([2; 32], ecdsa::CompletedSignature::ReportedToExecution);
            ecdsa_payload.signature_agreements.insert(
                [3; 32],
                ecdsa::CompletedSignature::Unreported(empty_response()),
            );
            ecdsa_payload.xnet_reshare_agreements.insert(
                create_reshare_request(6, 6),
                ecdsa::CompletedReshareRequest::ReportedToExecution,
            );

            let mut data_payload = ecdsa_payload.clone();
            data_payload.key_transcript.next_in_creation = ecdsa::KeyTranscriptCreation::Begin;
            let parent_block_payload = BlockPayload::Data(DataPayload {
                batch: BatchPayload::default(),
                dealings: Dealings::new_empty(summary_height),
                ecdsa: Some(data_payload),
            });
            let parent_block = add_block(
                parent_block_payload,
                parent_block_height.get() - payload_height_1.get(),
                &mut pool,
            );
            let pool_reader = PoolReader::new(&pool);

            // Add a summary block after the payload block and update the refs
            let mut summary = ecdsa_payload.clone();
            summary.key_transcript.current = Some(current_key_transcript);
            let block_reader = block_chain_reader(
                &pool_reader,
                &pool_reader.get_highest_summary_block(),
                &parent_block,
                None,
                &no_op_logger(),
            )
            .unwrap();
            assert!(update_summary_refs(
                parent_block.height().increment(),
                &mut summary,
                &block_reader,
            )
            .is_ok());

            let (reported, unreported) = {
                let mut reported = 0;
                let mut unreported = 0;
                for agreement in summary.signature_agreements.values() {
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
            assert!(!summary.signature_agreements.is_empty());
            assert!(reported > 0);
            assert!(unreported > 0);
            assert!(!summary.ongoing_signatures.is_empty());
            assert!(!summary.available_quadruples.is_empty());
            assert!(!summary.quadruples_in_creation.is_empty());
            assert!(!summary.idkg_transcripts.is_empty());
            assert!(!summary.ongoing_xnet_reshares.is_empty());
            let (reported, unreported) = {
                let mut reported = 0;
                let mut unreported = 0;
                for agreement in summary.xnet_reshare_agreements.values() {
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
            assert!(!summary.xnet_reshare_agreements.is_empty());
            assert!(reported > 0);
            assert!(unreported > 0);

            // Convert to proto format and back
            let new_summary_height = Height::new(parent_block_height.get() + 1234);
            let mut summary_proto: pb::EcdsaSummaryPayload = (&summary).into();
            let summary_from_proto = (&summary_proto, new_summary_height).try_into().unwrap();
            summary.update_refs(new_summary_height); // expected
            assert_eq!(summary, summary_from_proto);

            // Check signature_agreement upgrade compatiblity
            summary_proto
                .signature_agreements
                .push(pb::CompletedSignature {
                    request_id: Some(pb::RequestId {
                        pseudo_random_id: vec![4; 32],
                        quadruple_id: 1000,
                        height: 100,
                    }),
                    pseudo_random_id: vec![0; 32],
                    unreported: None,
                });
            let summary_from_proto: ecdsa::EcdsaPayload =
                (&summary_proto, new_summary_height).try_into().unwrap();
            // Make sure the previous RequestId record can be retrieved by its pseudo_random_id.
            assert!(summary_from_proto
                .signature_agreements
                .get(&[4; 32])
                .is_some());
        })
    }
}
