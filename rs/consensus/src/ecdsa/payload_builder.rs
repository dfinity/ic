//! This module implements the ECDSA payload builder.
#![allow(clippy::too_many_arguments)]
#![allow(clippy::enum_variant_names)]
#![allow(clippy::result_large_err)]

use super::pre_signer::{EcdsaTranscriptBuilder, EcdsaTranscriptBuilderImpl};
use super::signer::{EcdsaSignatureBuilder, EcdsaSignatureBuilderImpl};
use super::utils::{block_chain_reader, get_ecdsa_config_if_enabled, InvalidChainCacheError};
use crate::consensus::metrics::{EcdsaPayloadMetrics, CRITICAL_ERROR_ECDSA_KEY_TRANSCRIPT_MISSING};
pub(super) use errors::EcdsaPayloadError;
use errors::MembershipError;
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_crypto::retrieve_mega_public_key_from_registry;
use ic_interfaces::ecdsa::EcdsaPool;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{error, info, warn, ReplicaLogger};
use ic_management_canister_types::EcdsaKeyId;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_features::EcdsaConfig;
use ic_replicated_state::{metadata_state::subnet_call_context_manager::*, ReplicatedState};
use ic_types::{
    batch::ValidationContext,
    consensus::{
        ecdsa,
        ecdsa::{EcdsaBlockReader, HasEcdsaKeyId, TranscriptAttributes},
        Block, HasHeight,
    },
    crypto::canister_threshold_sig::idkg::InitialIDkgDealings,
    messages::CallbackId,
    Height, NodeId, RegistryVersion, SubnetId, Time,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use std::time::Duration;

mod errors;
mod key_transcript;
mod quadruples;
pub(super) mod resharing;
pub(super) mod signatures;

/// Builds the very first ecdsa summary block. This would trigger the subsequent
/// data blocks to create the initial key transcript.
pub(crate) fn make_bootstrap_summary(
    subnet_id: SubnetId,
    key_id: EcdsaKeyId,
    height: Height,
) -> ecdsa::Summary {
    Some(ecdsa::EcdsaPayload {
        signature_agreements: BTreeMap::new(),
        deprecated_ongoing_signatures: BTreeMap::new(),
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
    })
}

/// Builds the very first ecdsa summary block. This would trigger the subsequent
/// data blocks to create the initial key transcript.
pub(crate) fn make_bootstrap_summary_with_initial_dealings(
    subnet_id: SubnetId,
    key_id: EcdsaKeyId,
    height: Height,
    initial_dealings: InitialIDkgDealings,
    log: &ReplicaLogger,
) -> Result<ecdsa::Summary, EcdsaPayloadError> {
    let mut summary_payload = ecdsa::EcdsaPayload {
        signature_agreements: BTreeMap::new(),
        deprecated_ongoing_signatures: BTreeMap::new(),
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

    match ecdsa::unpack_reshare_of_unmasked_params(height, initial_dealings.params()) {
        Some((params, transcript)) => {
            summary_payload
                .idkg_transcripts
                .insert(transcript.transcript_id, transcript);
            summary_payload.key_transcript.next_in_creation =
                ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((
                    Box::new(initial_dealings),
                    params,
                ));

            info!(
                log,
                "make_ecdsa_genesis_summary(): height = {}, key_transcript = [{}]",
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
                Box::new(initial_dealings),
            ));
        }
    }

    Ok(Some(summary_payload))
}

/// Creates a threshold ECDSA summary payload.
pub(crate) fn create_summary_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    pool_reader: &PoolReader<'_>,
    context: &ValidationContext,
    parent_block: &Block,
    ecdsa_payload_metrics: Option<&EcdsaPayloadMetrics>,
    log: &ReplicaLogger,
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

    // Get ecdsa_config from registry if it exists
    let Some(ecdsa_config) = get_ecdsa_config_if_enabled(
        subnet_id,
        curr_interval_registry_version,
        registry_client,
        log,
    )?
    else {
        return Ok(None);
    };

    // Get ecdsa_payload from parent block if it exists
    let Some(ecdsa_payload) = parent_block.payload.as_ref().as_data().ecdsa.as_ref() else {
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

        return Ok(make_bootstrap_summary(subnet_id, key_id, height));
    };

    let block_reader = block_chain_reader(
        pool_reader,
        &prev_summary_block,
        parent_block,
        ecdsa_payload_metrics,
        log,
    )?;

    create_summary_payload_helper(
        subnet_id,
        registry_client,
        &block_reader,
        height,
        curr_interval_registry_version,
        next_interval_registry_version,
        ecdsa_payload,
        ecdsa_payload_metrics,
        log,
    )
}

fn create_summary_payload_helper(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    block_reader: &dyn EcdsaBlockReader,
    height: Height,
    curr_interval_registry_version: RegistryVersion,
    next_interval_registry_version: RegistryVersion,
    ecdsa_payload: &ecdsa::EcdsaPayload,
    ecdsa_payload_metrics: Option<&EcdsaPayloadMetrics>,
    log: &ReplicaLogger,
) -> Result<ecdsa::Summary, EcdsaPayloadError> {
    let current_key_transcript = ecdsa_payload.key_transcript.current.as_ref();

    let created_key_transcript =
        key_transcript::get_created_key_transcript(&ecdsa_payload.key_transcript, block_reader)?;

    // Registry version as recorded in the (new) current key transcript if it exists.
    // Otherwise use curr_interval_registry_version.
    let curr_key_registry_version = created_key_transcript
        .as_ref()
        .map(ecdsa::UnmaskedTranscriptWithAttributes::registry_version)
        .or_else(|| {
            current_key_transcript.map(ecdsa::UnmaskedTranscriptWithAttributes::registry_version)
        })
        .unwrap_or(curr_interval_registry_version);

    if created_key_transcript.is_none() {
        if let Some(metrics) = ecdsa_payload_metrics {
            metrics.critical_error_ecdsa_key_transcript_missing.inc();
        }

        error!(
            log,
            "{}: Key not created in previous interval, \
                keep trying in next interval(height = {}), key_transcript = {}",
            CRITICAL_ERROR_ECDSA_KEY_TRANSCRIPT_MISSING,
            height,
            ecdsa_payload.key_transcript
        );
    }

    let is_new_key_transcript = created_key_transcript.as_ref().is_some_and(|transcript| {
        Some(transcript.transcript_id())
            != current_key_transcript.map(ecdsa::UnmaskedTranscriptWithAttributes::transcript_id)
    });

    // Check for membership change, start next key creation only when both of the following are
    // satisfied:
    // 1. Time to reshare key transcript (either due to membership change, or node key change)
    // 2. We don't have a key transcript creation in progress.
    let next_in_creation = if is_time_to_reshare_key_transcript(
        registry_client,
        curr_key_registry_version,
        next_interval_registry_version,
        subnet_id,
    )? && created_key_transcript.is_some()
    {
        info!(
            log,
            "Noticed subnet membership or mega encryption key change, \
            will start key_transcript_creation: height = {} \
            current_version = {}, next_version = {}",
            height,
            curr_key_registry_version,
            next_interval_registry_version
        );
        ecdsa::KeyTranscriptCreation::Begin
    } else {
        // No change, just carry forward the next_in_creation transcript
        ecdsa_payload.key_transcript.next_in_creation.clone()
    };

    let key_transcript = ecdsa::EcdsaKeyTranscript {
        // Keep using previous key transcript if the next hasn't been created
        current: created_key_transcript.or_else(|| current_key_transcript.cloned()),
        next_in_creation,
        key_id: ecdsa_payload.key_transcript.key_id.clone(),
    };

    let mut ecdsa_summary = if is_new_key_transcript {
        ecdsa::EcdsaPayload {
            signature_agreements: ecdsa_payload.signature_agreements.clone(),
            deprecated_ongoing_signatures: BTreeMap::new(),
            // We keep available quadruples for now, even if the key transcript
            // changed, as we don't know if they are part of ongoing signature
            // requests. Instead we will purge them once the certified state
            // height catches up with the height of this summary block.
            available_quadruples: ecdsa_payload.available_quadruples.clone(),
            quadruples_in_creation: BTreeMap::new(),
            uid_generator: ecdsa_payload.uid_generator.clone(),
            // This will clear the current ongoing reshares, and
            // the execution requests will be restarted with the
            // new key and different transcript IDs.
            ongoing_xnet_reshares: BTreeMap::new(),
            xnet_reshare_agreements: ecdsa_payload.xnet_reshare_agreements.clone(),
            idkg_transcripts: BTreeMap::new(),
            key_transcript,
        }
    } else {
        ecdsa::EcdsaPayload {
            signature_agreements: ecdsa_payload.signature_agreements.clone(),
            deprecated_ongoing_signatures: BTreeMap::new(),
            available_quadruples: ecdsa_payload.available_quadruples.clone(),
            quadruples_in_creation: ecdsa_payload.quadruples_in_creation.clone(),
            uid_generator: ecdsa_payload.uid_generator.clone(),
            ongoing_xnet_reshares: ecdsa_payload.ongoing_xnet_reshares.clone(),
            xnet_reshare_agreements: ecdsa_payload.xnet_reshare_agreements.clone(),
            idkg_transcripts: BTreeMap::new(),
            key_transcript,
        }
    };

    ecdsa_summary.uid_generator.update_height(height)?;
    update_summary_refs(height, &mut ecdsa_summary, block_reader)?;
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

// Like `get_subnet_nodes`, but return empty Vec instead of SubnetWithNoNodes error.
// This is used to avoid throwing error, for example, when we do subnet recovery
// the old registry version may not have the new subnet members.
fn get_subnet_nodes_(
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
    subnet_id: SubnetId,
) -> Result<Vec<NodeId>, MembershipError> {
    Ok(registry_client
        .get_node_ids_on_subnet(subnet_id, registry_version)
        .map_err(MembershipError::RegistryClientError)?
        .unwrap_or_default())
}

fn is_time_to_reshare_key_transcript(
    registry_client: &dyn RegistryClient,
    curr_registry_version: RegistryVersion,
    next_registry_version: RegistryVersion,
    subnet_id: SubnetId,
) -> Result<bool, MembershipError> {
    // Shortcut the case where registry version didn't change
    if curr_registry_version == next_registry_version {
        return Ok(false);
    }
    let current_nodes = get_subnet_nodes_(registry_client, curr_registry_version, subnet_id)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let next_nodes = get_subnet_nodes(registry_client, next_registry_version, subnet_id)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if current_nodes != next_nodes {
        return Ok(true);
    }
    // Check if node's key has changed, which should also trigger key transcript resharing.
    for node in current_nodes {
        let curr_key =
            retrieve_mega_public_key_from_registry(&node, registry_client, curr_registry_version)
                .map_err(MembershipError::MegaKeyFromRegistryError)?;
        let next_key =
            retrieve_mega_public_key_from_registry(&node, registry_client, next_registry_version)
                .map_err(MembershipError::MegaKeyFromRegistryError)?;
        if curr_key != next_key {
            return Ok(true);
        }
    }
    Ok(false)
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
    log: &ReplicaLogger,
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
        log,
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
        Some(ecdsa_payload_metrics),
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
            && !parent_block
                .payload
                .as_ref()
                .as_ecdsa()
                .is_some_and(is_key_transcript_created)
        {
            ecdsa_payload_metrics.payload_metrics_inc(
                "key_transcripts_created",
                ecdsa_payload.key_transcript.key_id(),
            );
        }

        ecdsa_payload_metrics.report(ecdsa_payload);
    };

    Ok(new_payload)
}

pub(crate) enum CertifiedHeight {
    ReachedSummaryHeight,
    BelowSummaryHeight,
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
    ecdsa_payload_metrics: Option<&EcdsaPayloadMetrics>,
    log: &ReplicaLogger,
) -> Result<Option<ecdsa::EcdsaPayload>, EcdsaPayloadError> {
    let height = parent_block.height().increment();
    let summary = summary_block.payload.as_ref().as_summary();

    // For this interval: context.registry_version from last summary block,
    // which is the same as calling pool_reader.registry_version(height).
    // which is the same as summary.dkg.registry_version,
    let curr_interval_registry_version = summary.dkg.registry_version;
    // For next interval: context.registry_version from the new summary block
    let next_interval_registry_version = summary_block.context.registry_version;

    let Some(ecdsa_config) = get_ecdsa_config_if_enabled(
        subnet_id,
        curr_interval_registry_version,
        registry_client,
        log,
    )?
    else {
        return Ok(None);
    };
    let valid_keys: BTreeSet<_> = ecdsa_config.key_ids.iter().cloned().collect();

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

    let certified_height = if context.certified_height >= summary_block.height() {
        CertifiedHeight::ReachedSummaryHeight
    } else {
        CertifiedHeight::BelowSummaryHeight
    };

    create_data_payload_helper_2(
        &mut ecdsa_payload,
        height,
        context.time,
        &ecdsa_config,
        &valid_keys,
        next_interval_registry_version,
        certified_height,
        &receivers,
        all_signing_requests,
        ecdsa_dealings_contexts,
        block_reader,
        transcript_builder,
        signature_builder,
        ecdsa_payload_metrics,
        log,
    )?;
    Ok(Some(ecdsa_payload))
}

pub(crate) fn create_data_payload_helper_2(
    ecdsa_payload: &mut ecdsa::EcdsaPayload,
    height: Height,
    context_time: Time,
    ecdsa_config: &EcdsaConfig,
    valid_keys: &BTreeSet<EcdsaKeyId>,
    next_interval_registry_version: RegistryVersion,
    certified_height: CertifiedHeight,
    receivers: &[NodeId],
    all_signing_requests: &BTreeMap<CallbackId, SignWithEcdsaContext>,
    ecdsa_dealings_contexts: &BTreeMap<CallbackId, EcdsaDealingsContext>,
    block_reader: &dyn EcdsaBlockReader,
    transcript_builder: &dyn EcdsaTranscriptBuilder,
    signature_builder: &dyn EcdsaSignatureBuilder,
    ecdsa_payload_metrics: Option<&EcdsaPayloadMetrics>,
    log: &ReplicaLogger,
) -> Result<(), EcdsaPayloadError> {
    // Check if we are creating a new key, if so, start using it immediately.
    if ecdsa_payload.key_transcript.current.is_none() {
        ecdsa_payload.key_transcript.current = key_transcript::get_created_key_transcript(
            &ecdsa_payload.key_transcript,
            block_reader,
        )?;
    }

    ecdsa_payload.uid_generator.update_height(height)?;

    let request_expiry_time = ecdsa_config
        .signature_request_timeout_ns
        .and_then(|timeout| context_time.checked_sub(Duration::from_nanos(timeout)));

    signatures::update_signature_agreements(
        all_signing_requests,
        signature_builder,
        request_expiry_time,
        ecdsa_payload,
        valid_keys,
        ecdsa_payload_metrics,
    );

    if matches!(certified_height, CertifiedHeight::ReachedSummaryHeight) {
        quadruples::purge_old_key_quadruples(ecdsa_payload, all_signing_requests);
    }

    // We count the number of quadruples in the payload that were already matched,
    // such that they can be replenished.
    let matched_quadruples = all_signing_requests
        .values()
        .filter_map(|context| context.matched_quadruple.as_ref())
        .filter(|(qid, _)| ecdsa_payload.available_quadruples.contains_key(qid))
        .count();
    quadruples::make_new_quadruples_if_needed(ecdsa_config, ecdsa_payload, matched_quadruples);

    let mut new_transcripts =
        quadruples::update_quadruples_in_creation(ecdsa_payload, transcript_builder, height, log)?;
    if let Some(new_transcript) = key_transcript::update_next_key_transcript(
        receivers,
        next_interval_registry_version,
        ecdsa_payload,
        transcript_builder,
        height,
        log,
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

    resharing::update_completed_reshare_requests(
        ecdsa_payload,
        &resharing::make_reshare_dealings_response(ecdsa_dealings_contexts),
        block_reader,
        transcript_builder,
        log,
    );
    resharing::initiate_reshare_requests(
        ecdsa_payload,
        resharing::get_reshare_requests(ecdsa_dealings_contexts),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::batch_delivery::generate_responses_to_sign_with_ecdsa_calls;
    use crate::ecdsa::payload_builder::quadruples::test_utils::create_available_quadruple;
    use crate::ecdsa::payload_builder::quadruples::test_utils::create_new_quadruple_in_creation;
    use crate::ecdsa::test_utils::*;
    use crate::ecdsa::utils::block_chain_reader;
    use crate::ecdsa::utils::get_context_request_id;
    use assert_matches::assert_matches;
    use ic_consensus_mocks::{dependencies, Dependencies};
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_initial_idkg_dealing_for_tests;
    use ic_crypto_test_utils_canister_threshold_sigs::generate_tecdsa_protocol_inputs;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        CanisterThresholdSigTestEnvironment, IDkgParticipants,
    };
    use ic_crypto_test_utils_reproducible_rng::{reproducible_rng, ReproducibleRng};
    use ic_interfaces_registry::RegistryValue;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::types::v1 as pb;
    use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
    use ic_test_utilities_consensus::fake::{Fake, FakeContentSigner};
    use ic_test_utilities_registry::{add_subnet_record, SubnetRecordBuilder};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id, user_test_id};
    use ic_types::batch::BatchPayload;
    use ic_types::consensus::dkg::{Dealings, Summary};
    use ic_types::consensus::ecdsa::EcdsaPayload;
    use ic_types::consensus::ecdsa::QuadrupleId;
    use ic_types::consensus::ecdsa::ReshareOfUnmaskedParams;
    use ic_types::consensus::ecdsa::TranscriptRef;
    use ic_types::consensus::ecdsa::UnmaskedTranscript;
    use ic_types::consensus::ecdsa::UnmaskedTranscriptWithAttributes;
    use ic_types::consensus::{
        BlockPayload, BlockProposal, DataPayload, HashedBlock, Payload, Rank, SummaryPayload,
    };
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscript;
    use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
    use ic_types::crypto::canister_threshold_sig::ThresholdEcdsaCombinedSignature;
    use ic_types::crypto::AlgorithmId;
    use ic_types::crypto::{CryptoHash, CryptoHashOf};
    use ic_types::time::UNIX_EPOCH;
    use ic_types::Randomness;
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

    fn add_block(
        block_payload: BlockPayload,
        advance_by: u64,
        pool: &mut TestConsensusPool,
    ) -> Block {
        pool.advance_round_normal_operation_n(advance_by - 1);
        let mut block_proposal = pool.make_next_block();
        let block = block_proposal.content.as_mut();
        block.payload = Payload::new(ic_types::crypto::crypto_hash, block_payload);
        block_proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
        pool.advance_round_with_block(&block_proposal);
        block_proposal.content.as_ref().clone()
    }

    fn set_up_ecdsa_payload_with_keys(
        key_ids: Vec<EcdsaKeyId>,
    ) -> (EcdsaPayload, CanisterThresholdSigTestEnvironment) {
        let mut rng = reproducible_rng();
        let (ecdsa_payload, env, _block_reader) = set_up_ecdsa_payload(
            &mut rng,
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            key_ids,
            /*should_create_key_transcript=*/ true,
        );
        (ecdsa_payload, env)
    }

    fn set_up_sign_with_ecdsa_contexts(
        parameters: Vec<(EcdsaKeyId, u8, Time, Option<QuadrupleId>)>,
    ) -> BTreeMap<CallbackId, SignWithEcdsaContext> {
        let mut contexts = BTreeMap::new();
        for (key_id, id, batch_time, quadruple) in parameters {
            let (callback_id, mut context) =
                fake_sign_with_ecdsa_context_with_quadruple(id, key_id, quadruple);
            context.batch_time = batch_time;
            contexts.insert(callback_id, context);
        }
        contexts
    }

    #[test]
    fn test_quadruple_recreation() {
        let valid_key_id = EcdsaKeyId::from_str("Secp256k1:valid_key").unwrap();
        let disabled_key_id = EcdsaKeyId::from_str("Secp256k1:disabled_key").unwrap();
        let valid_keys = BTreeSet::from([valid_key_id.clone()]);

        let (mut ecdsa_payload, _env) = set_up_ecdsa_payload_with_keys(vec![valid_key_id.clone()]);
        // Add two quadruples
        let quadruple_for_valid_key =
            create_available_quadruple(&mut ecdsa_payload, valid_key_id.clone(), 10);
        let quadruple_for_disabled_key =
            create_available_quadruple(&mut ecdsa_payload, disabled_key_id.clone(), 11);
        let non_existant_quadruple_for_valid_key = ecdsa_payload.uid_generator.next_quadruple_id();

        let contexts = set_up_sign_with_ecdsa_contexts(vec![
            // Two request contexts without quadruple
            (valid_key_id.clone(), 0, UNIX_EPOCH, None),
            (disabled_key_id.clone(), 1, UNIX_EPOCH, None),
            // One valid context with matched quadruple
            (
                valid_key_id.clone(),
                2,
                UNIX_EPOCH,
                Some(quadruple_for_valid_key),
            ),
            // One invalid context with matched quadruple
            (
                disabled_key_id.clone(),
                3,
                UNIX_EPOCH,
                Some(quadruple_for_disabled_key),
            ),
            // One valid context matched to non-existant quadruple
            (
                valid_key_id.clone(),
                4,
                UNIX_EPOCH,
                Some(non_existant_quadruple_for_valid_key),
            ),
        ]);

        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance: 5,
            key_ids: vec![valid_key_id.clone()],
            ..EcdsaConfig::default()
        };

        assert_eq!(ecdsa_payload.quadruples_in_creation.len(), 0);
        assert_eq!(ecdsa_payload.available_quadruples.len(), 2);

        create_data_payload_helper_2(
            &mut ecdsa_payload,
            Height::from(5),
            UNIX_EPOCH,
            &ecdsa_config,
            &valid_keys,
            RegistryVersion::from(9),
            CertifiedHeight::ReachedSummaryHeight,
            &[node_test_id(0)],
            &contexts,
            &BTreeMap::default(),
            &TestEcdsaBlockReader::new(),
            &TestEcdsaTranscriptBuilder::new(),
            &TestEcdsaSignatureBuilder::new(),
            /*ecdsa_payload_metrics*/ None,
            &ic_logger::replica_logger::no_op_logger(),
        )
        .unwrap();

        let num_quadruples_in_creation = ecdsa_payload.quadruples_in_creation.len() as u32;
        let num_available_quadruples = ecdsa_payload.available_quadruples.len() as u32;
        // The two matched quadruples remain
        // in available_quadruples.
        assert_eq!(num_available_quadruples, 2);
        // Usually, matched quadruples are replenished, but since one
        // of them was matched to a disabled key id whose request context
        // is rejected, the quadruple is "reused" and not replenished.
        assert_eq!(
            num_quadruples_in_creation,
            ecdsa_config.quadruples_to_create_in_advance
        );
    }

    #[test]
    fn test_ecdsa_signing_request_timeout() {
        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        let expired_time = UNIX_EPOCH + Duration::from_secs(10);
        let expiry_time = UNIX_EPOCH + Duration::from_secs(11);
        let non_expired_time = UNIX_EPOCH + Duration::from_secs(12);

        let (mut ecdsa_payload, _env) = set_up_ecdsa_payload_with_keys(vec![key_id.clone()]);
        // Add quadruples
        let discarded_quadruple_id =
            create_available_quadruple(&mut ecdsa_payload, key_id.clone(), 10);
        let matched_quadruple_id =
            create_available_quadruple(&mut ecdsa_payload, key_id.clone(), 11);

        let contexts = set_up_sign_with_ecdsa_contexts(vec![
            // One expired context without quadruple
            (key_id.clone(), 0, expired_time, None),
            // One expired context with matched quadruple
            (
                key_id.clone(),
                1,
                expired_time,
                Some(discarded_quadruple_id),
            ),
            // One non-expired context with matched quadruple
            (
                key_id.clone(),
                2,
                non_expired_time,
                Some(matched_quadruple_id.clone()),
            ),
        ]);

        assert_eq!(ecdsa_payload.signature_agreements.len(), 0);
        assert_eq!(ecdsa_payload.available_quadruples.len(), 2);

        let signature_builder = TestEcdsaSignatureBuilder::new();
        signatures::update_signature_agreements(
            &contexts,
            &signature_builder,
            Some(expiry_time),
            &mut ecdsa_payload,
            &BTreeSet::from([key_id]),
            None,
        );

        // Only the expired context with matched quadruple should receive a reject response
        assert_eq!(ecdsa_payload.signature_agreements.len(), 1);
        let Some(ecdsa::CompletedSignature::Unreported(response)) =
            ecdsa_payload.signature_agreements.get(&[1; 32])
        else {
            panic!("Request 1 should have a response");
        };
        assert_matches!(
            &response.payload,
            ic_types::messages::Payload::Reject(context)
            if context.message().contains("request expired")
        );

        // The quadruple matched with the expired context should be deleted
        assert_eq!(ecdsa_payload.available_quadruples.len(), 1);
        assert_eq!(
            ecdsa_payload.available_quadruples.keys().next().unwrap(),
            &matched_quadruple_id
        );
    }

    #[test]
    fn test_ecdsa_request_with_invalid_key() {
        let valid_key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        let invalid_key_id = EcdsaKeyId::from_str("Secp256k1:some_invalid_key").unwrap();
        let (mut ecdsa_payload, _env) = set_up_ecdsa_payload_with_keys(vec![valid_key_id.clone()]);
        // Add quadruples
        let quadruple_id1 = create_available_quadruple(&mut ecdsa_payload, valid_key_id.clone(), 1);
        let quadruple_id2 =
            create_available_quadruple(&mut ecdsa_payload, invalid_key_id.clone(), 2);

        let contexts = set_up_sign_with_ecdsa_contexts(vec![
            // One matched context with valid key
            (valid_key_id.clone(), 1, UNIX_EPOCH, Some(quadruple_id1)),
            // One matched context with invalid key
            (
                invalid_key_id.clone(),
                2,
                UNIX_EPOCH,
                Some(quadruple_id2.clone()),
            ),
            // One unmatched context with invalid key
            (invalid_key_id.clone(), 3, UNIX_EPOCH, None),
        ]);

        assert_eq!(ecdsa_payload.signature_agreements.len(), 0);
        assert_eq!(ecdsa_payload.available_quadruples.len(), 2);

        let signature_builder = TestEcdsaSignatureBuilder::new();
        signatures::update_signature_agreements(
            &contexts,
            &signature_builder,
            None,
            &mut ecdsa_payload,
            &BTreeSet::from([valid_key_id]),
            None,
        );

        // The contexts with invalid key should receive a reject response
        assert_eq!(ecdsa_payload.signature_agreements.len(), 2);
        let Some(ecdsa::CompletedSignature::Unreported(response_1)) =
            ecdsa_payload.signature_agreements.get(&[2; 32])
        else {
            panic!("Request 2 should have a response");
        };
        assert_matches!(
            &response_1.payload,
            ic_types::messages::Payload::Reject(context)
            if context.message().contains("Invalid key_id")
        );

        let Some(ecdsa::CompletedSignature::Unreported(response_2)) =
            ecdsa_payload.signature_agreements.get(&[3; 32])
        else {
            panic!("Request 3 should have a response");
        };
        assert_matches!(
            &response_2.payload,
            ic_types::messages::Payload::Reject(context)
            if context.message().contains("Invalid key_id")
        );

        // The quadruple matched with the expired context should not be deleted
        assert_eq!(ecdsa_payload.available_quadruples.len(), 2);
    }

    #[test]
    fn test_ecdsa_signature_is_only_delivered_once() {
        let key_id = fake_ecdsa_key_id();
        let (mut ecdsa_payload, _env) = set_up_ecdsa_payload_with_keys(vec![key_id.clone()]);
        let quadruple_id = create_available_quadruple(&mut ecdsa_payload, key_id.clone(), 13);
        let context = fake_completed_sign_with_ecdsa_context(0, quadruple_id.clone());
        let sign_with_ecdsa_contexts = BTreeMap::from([context.clone()]);

        let valid_keys = BTreeSet::from([key_id.clone()]);

        let block_reader = TestEcdsaBlockReader::new();
        let transcript_builder = TestEcdsaTranscriptBuilder::new();
        let mut signature_builder = TestEcdsaSignatureBuilder::new();

        signature_builder.signatures.insert(
            get_context_request_id(&context.1).unwrap(),
            ThresholdEcdsaCombinedSignature {
                signature: vec![1; 32],
            },
        );

        // create first ecdsa payload
        create_data_payload_helper_2(
            &mut ecdsa_payload,
            Height::from(5),
            UNIX_EPOCH,
            &EcdsaConfig::default(),
            &valid_keys,
            RegistryVersion::from(9),
            CertifiedHeight::ReachedSummaryHeight,
            &[node_test_id(0)],
            &sign_with_ecdsa_contexts,
            &BTreeMap::default(),
            &block_reader,
            &transcript_builder,
            &signature_builder,
            /*ecdsa_payload_metrics*/ None,
            &ic_logger::replica_logger::no_op_logger(),
        )
        .unwrap();

        // Assert that we got a response
        let response1 = generate_responses_to_sign_with_ecdsa_calls(&ecdsa_payload);
        assert_eq!(response1.len(), 1);

        // create next ecdsa payload
        create_data_payload_helper_2(
            &mut ecdsa_payload,
            Height::from(5),
            UNIX_EPOCH,
            &EcdsaConfig::default(),
            &valid_keys,
            RegistryVersion::from(9),
            CertifiedHeight::ReachedSummaryHeight,
            &[node_test_id(0)],
            &sign_with_ecdsa_contexts,
            &BTreeMap::default(),
            &block_reader,
            &transcript_builder,
            &signature_builder,
            /*ecdsa_payload_metrics*/ None,
            &ic_logger::replica_logger::no_op_logger(),
        )
        .unwrap();

        // assert that same signature isn't delivered again.
        let response2 = generate_responses_to_sign_with_ecdsa_calls(&ecdsa_payload);
        assert!(response2.is_empty());
    }

    #[test]
    fn test_ecdsa_update_summary_refs() {
        let mut rng = reproducible_rng();
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

            // Create a summary block with transcripts
            let summary_height = Height::new(5);
            let env = CanisterThresholdSigTestEnvironment::new(4, &mut rng);
            let subnet_nodes: Vec<_> = env.nodes.ids();
            let (key_transcript, key_transcript_ref, current_key_transcript) =
                generate_key_transcript(&env, &mut rng, summary_height);
            let (reshare_key_transcript, reshare_key_transcript_ref, _) =
                generate_key_transcript(&env, &mut rng, summary_height);
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
            let quad_1 = inputs_2.sig_inputs_ref.presig_quadruple_ref;

            // Create payload blocks with transcripts
            let payload_height_1 = Height::new(10);
            let inputs_1 = create_sig_inputs_with_height(93, payload_height_1);
            let inputs_2 = create_sig_inputs_with_height(94, payload_height_1);
            let (reshare_key_transcript, reshare_key_transcript_ref, _) =
                generate_key_transcript(&env, &mut rng, payload_height_1);
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
            let quad_2 = inputs_2.sig_inputs_ref.presig_quadruple_ref;

            // Create a payload block with references to these past blocks
            let key_id = fake_ecdsa_key_id();
            let mut ecdsa_payload =
                empty_ecdsa_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
            ecdsa_payload.key_transcript.current = Some(current_key_transcript.clone());
            let (quadruple_id_1, quadruple_id_2) = (
                ecdsa_payload.uid_generator.next_quadruple_id(),
                ecdsa_payload.uid_generator.next_quadruple_id(),
            );

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
            add_expected_transcripts(quad_1.get_refs());
            add_expected_transcripts(quad_2.get_refs());
            add_expected_transcripts(reshare_params_1.as_ref().get_refs());

            // Add some quadruples in creation
            let block_reader = TestEcdsaBlockReader::new();
            let (kappa_config_ref, _lambda_config_ref) =
                quadruples::test_utils::create_new_quadruple_in_creation(
                    &subnet_nodes,
                    env.newest_registry_version,
                    &mut ecdsa_payload.uid_generator,
                    key_id.clone(),
                    &mut ecdsa_payload.quadruples_in_creation,
                );
            let kappa_transcript = {
                let param = kappa_config_ref.as_ref();
                env.nodes.run_idkg_and_create_and_verify_transcript(
                    &param.translate(&block_reader).unwrap(),
                    &mut rng,
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
            let result = quadruples::update_quadruples_in_creation(
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
                    .single_key_transcript()
                    .current
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .height,
                new_summary_height
            );
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

            assert_eq!(
                update_summary_refs(
                    parent_block.height().increment(),
                    &mut summary,
                    &block_reader
                ),
                Ok(())
            );

            // Verify that all the transcript references in the parent block
            // have been updated to point to the new summary height
            assert_eq!(
                summary
                    .single_key_transcript()
                    .current
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .height,
                new_summary_height
            );
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
            let mut rng = reproducible_rng();
            let Dependencies { mut pool, .. } = dependencies(pool_config, 1);
            let subnet_id = subnet_test_id(1);
            let transcript_builder = TestEcdsaTranscriptBuilder::new();
            // Create a summary block with transcripts
            let summary_height = Height::new(5);
            let env = CanisterThresholdSigTestEnvironment::new(4, &mut rng);
            let subnet_nodes: Vec<_> = env.nodes.ids();
            let (key_transcript, key_transcript_ref, current_key_transcript) =
                generate_key_transcript(&env, &mut rng, summary_height);
            let (reshare_key_transcript, reshare_key_transcript_ref, _) =
                generate_key_transcript(&env, &mut rng, summary_height);
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
            let b = add_block(summary_block, summary_height.get(), &mut pool);
            assert_proposal_conversion(b);

            let quad_1 = inputs_2.sig_inputs_ref.presig_quadruple_ref;

            // Create payload blocks with transcripts
            let payload_height_1 = Height::new(10);
            let inputs_1 = create_sig_inputs_with_height(93, payload_height_1);
            let inputs_2 = create_sig_inputs_with_height(94, payload_height_1);
            let (reshare_key_transcript, reshare_key_transcript_ref, _) =
                generate_key_transcript(&env, &mut rng, payload_height_1);
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

            let b = add_block(
                payload_block_1,
                payload_height_1.get() - summary_height.get(),
                &mut pool,
            );
            assert_proposal_conversion(b);

            let quad_2 = inputs_2.sig_inputs_ref.presig_quadruple_ref;

            // Create a payload block with references to these past blocks
            let key_id = fake_ecdsa_key_id();
            let mut ecdsa_payload =
                empty_ecdsa_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
            let uid_generator = &mut ecdsa_payload.uid_generator;
            let quadruple_id_1 = uid_generator.next_quadruple_id();
            let quadruple_id_2 = uid_generator.next_quadruple_id();
            ecdsa_payload.key_transcript.current = Some(current_key_transcript.clone());
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
            let (kappa_config_ref, _lambda_config_ref) =
                quadruples::test_utils::create_new_quadruple_in_creation(
                    &subnet_nodes,
                    env.newest_registry_version,
                    &mut ecdsa_payload.uid_generator,
                    key_id.clone(),
                    &mut ecdsa_payload.quadruples_in_creation,
                );
            let kappa_transcript = {
                let param = kappa_config_ref.as_ref();
                env.nodes.run_idkg_and_create_and_verify_transcript(
                    &param.translate(&block_reader).unwrap(),
                    &mut rng,
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
            let result = quadruples::update_quadruples_in_creation(
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
            assert_proposal_conversion(parent_block.clone());

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
            assert_eq!(
                update_summary_refs(
                    parent_block.height().increment(),
                    &mut summary,
                    &block_reader,
                ),
                Ok(())
            );

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

            let pl = BlockPayload::Summary(SummaryPayload {
                dkg: Summary::fake(),
                ecdsa: Some(summary.clone()),
            });
            let b = Block::new(
                CryptoHashOf::from(CryptoHash(Vec::new())),
                Payload::new(ic_types::crypto::crypto_hash, pl),
                Height::from(123),
                Rank(456),
                ValidationContext {
                    registry_version: RegistryVersion::from(99),
                    certified_height: Height::from(42),
                    time: UNIX_EPOCH,
                },
            );
            assert_proposal_conversion(b);

            // Convert to proto format and back
            let new_summary_height = Height::new(parent_block_height.get() + 1234);
            let mut summary_proto: pb::EcdsaPayload = (&summary).into();
            let summary_from_proto: EcdsaPayload =
                (&summary_proto, new_summary_height).try_into().unwrap();
            summary.update_refs(new_summary_height); // expected
            assert_eq!(summary, summary_from_proto);

            // Check signature_agreement upgrade compatibility
            summary_proto
                .signature_agreements
                .push(pb::CompletedSignature {
                    pseudo_random_id: vec![4; 32],
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

    fn assert_proposal_conversion(b: Block) {
        let artifact = BlockProposal::fake(b, node_test_id(333));
        let mut buf = Vec::new();
        pb::BlockProposal::from(&artifact).encode(&mut buf).unwrap();
        assert_eq!(
            artifact,
            BlockProposal::try_from(pb::BlockProposal::decode(buf.as_slice()).unwrap()).unwrap()
        );
    }

    fn create_key_transcript_and_refs(
        rng: &mut ReproducibleRng,
        height: Height,
    ) -> (
        IDkgTranscript,
        UnmaskedTranscript,
        UnmaskedTranscriptWithAttributes,
    ) {
        let env = CanisterThresholdSigTestEnvironment::new(4, rng);
        generate_key_transcript(&env, rng, height)
    }

    #[test]
    fn test_no_creation_after_successful_creation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut rng = reproducible_rng();
            let Dependencies {
                registry,
                registry_data_provider,
                ..
            } = dependencies(pool_config, 1);
            let subnet_id = subnet_test_id(1);
            let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
            let mut block_reader = TestEcdsaBlockReader::new();

            // Create two key transcripts
            let (mut key_transcript, mut key_transcript_ref, mut current_key_transcript) =
                create_key_transcript_and_refs(&mut rng, Height::from(1));
            let (
                mut reshare_key_transcript,
                mut reshare_key_transcript_ref,
                mut next_key_transcript,
            ) = create_key_transcript_and_refs(&mut rng, Height::from(1));

            // Reshared transcript should use higher registry version
            if key_transcript.registry_version() > reshare_key_transcript.registry_version() {
                std::mem::swap(&mut key_transcript, &mut reshare_key_transcript);
                std::mem::swap(&mut key_transcript_ref, &mut reshare_key_transcript_ref);
                std::mem::swap(&mut current_key_transcript, &mut next_key_transcript);
            }

            block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript);

            // Membership changes between the registry versions
            let subnet_record1 = SubnetRecordBuilder::from(&[node_test_id(0)])
                .with_dkg_interval_length(9)
                .build();
            add_subnet_record(
                &registry_data_provider,
                current_key_transcript.registry_version().get(),
                subnet_id,
                subnet_record1,
            );

            let subnet_record2 = SubnetRecordBuilder::from(&[node_test_id(0), node_test_id(1)])
                .with_dkg_interval_length(9)
                .build();
            add_subnet_record(
                &registry_data_provider,
                next_key_transcript.registry_version().get(),
                subnet_id,
                subnet_record2,
            );

            registry.update_to_latest_version();

            // We only have the current transcript initially
            let key_transcript = ecdsa::EcdsaKeyTranscript {
                current: Some(current_key_transcript.clone()),
                next_in_creation: ecdsa::KeyTranscriptCreation::Created(
                    current_key_transcript.unmasked_transcript(),
                ),
                key_id: key_id.clone(),
            };

            // Initial bootstrap payload should be created successfully
            let mut payload_0 =
                make_bootstrap_summary(subnet_id, key_id.clone(), Height::from(0)).unwrap();
            payload_0.key_transcript = key_transcript;

            // A new summary payload should be created successfully, with next_in_creation
            // set to Begin (membership changed).
            let payload_1 = create_summary_payload_helper(
                subnet_id,
                registry.as_ref(),
                &block_reader,
                Height::from(1),
                RegistryVersion::from(0),
                next_key_transcript.registry_version(),
                &payload_0,
                None,
                &no_op_logger(),
            )
            .unwrap()
            .unwrap();

            // As membership changed between the registry versions, next_in_creation should be set to begin
            assert_eq!(
                payload_1.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::Begin
            );

            // Simulate successful creation of the next key transcript
            let key_transcript = ecdsa::EcdsaKeyTranscript {
                current: Some(current_key_transcript.clone()),
                next_in_creation: ecdsa::KeyTranscriptCreation::Created(
                    next_key_transcript.unmasked_transcript(),
                ),
                key_id: key_id.clone(),
            };

            let mut payload_2 = payload_1.clone();
            payload_2.key_transcript = key_transcript;

            block_reader
                .add_transcript(*reshare_key_transcript_ref.as_ref(), reshare_key_transcript);

            // After the next key transcript was created, it should be carried over into the next payload.
            let expected = ecdsa::EcdsaKeyTranscript {
                current: Some(next_key_transcript.clone()),
                next_in_creation: ecdsa::KeyTranscriptCreation::Created(
                    next_key_transcript.unmasked_transcript(),
                ),
                key_id,
            };

            let payload_3 = create_summary_payload_helper(
                subnet_id,
                registry.as_ref(),
                &block_reader,
                Height::from(1),
                RegistryVersion::from(0),
                next_key_transcript.registry_version(),
                &payload_2,
                None,
                &no_op_logger(),
            )
            .unwrap()
            .unwrap();

            assert_eq!(expected, *payload_3.single_key_transcript());
        })
    }

    #[test]
    fn test_incomplete_reshare_doesnt_purge_quadruples() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut rng = reproducible_rng();
            let Dependencies {
                registry,
                registry_data_provider,
                ..
            } = dependencies(pool_config, 1);
            let subnet_id = subnet_test_id(1);
            let mut valid_keys = BTreeSet::new();
            let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
            valid_keys.insert(key_id.clone());
            let mut block_reader = TestEcdsaBlockReader::new();

            // Create a key transcript
            let env = CanisterThresholdSigTestEnvironment::new(4, &mut rng);
            let (dealers, receivers) = env.choose_dealers_and_receivers(
                &IDkgParticipants::AllNodesAsDealersAndReceivers,
                &mut rng,
            );
            let (key_transcript, key_transcript_ref, current_key_transcript) =
                generate_key_transcript(&env, &mut rng, Height::new(0));
            block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript.clone());

            // Membership changes between the registry versions
            let node_ids = vec![node_test_id(0), node_test_id(1)];
            let subnet_record1 = SubnetRecordBuilder::from(&node_ids[..1])
                .with_dkg_interval_length(9)
                .build();
            add_subnet_record(
                &registry_data_provider,
                current_key_transcript.registry_version().get(),
                subnet_id,
                subnet_record1,
            );
            let subnet_record2 = SubnetRecordBuilder::from(&node_ids)
                .with_dkg_interval_length(9)
                .build();
            add_subnet_record(
                &registry_data_provider,
                current_key_transcript.registry_version().get() + 1,
                subnet_id,
                subnet_record2,
            );
            registry.update_to_latest_version();

            // We only have the current transcript initially
            let key_transcripts = ecdsa::EcdsaKeyTranscript {
                current: Some(current_key_transcript.clone()),
                next_in_creation: ecdsa::KeyTranscriptCreation::Created(
                    current_key_transcript.unmasked_transcript(),
                ),
                key_id: key_id.clone(),
            };

            let mut payload_0 =
                make_bootstrap_summary(subnet_id, key_id.clone(), Height::from(0)).unwrap();
            payload_0.key_transcript = key_transcripts;

            // Add some quadruples and xnet reshares
            let derivation_path = ExtendedDerivationPath {
                caller: user_test_id(1).get(),
                derivation_path: vec![],
            };
            let sig_inputs = generate_tecdsa_protocol_inputs(
                &env,
                &dealers,
                &receivers,
                &key_transcript,
                &[0; 32],
                Randomness::from([0; 32]),
                &derivation_path,
                AlgorithmId::ThresholdEcdsaSecp256k1,
                false,
                &mut rng,
            );
            let test_inputs = TestSigInputs::from(&sig_inputs);
            payload_0.available_quadruples.insert(
                payload_0.uid_generator.next_quadruple_id(),
                test_inputs.sig_inputs_ref.presig_quadruple_ref.clone(),
            );
            for (transcript_ref, transcript) in test_inputs.idkg_transcripts {
                block_reader.add_transcript(transcript_ref, transcript);
            }
            create_new_quadruple_in_creation(
                &env.nodes.ids::<Vec<_>>(),
                env.newest_registry_version,
                &mut payload_0.uid_generator,
                key_id.clone(),
                &mut payload_0.quadruples_in_creation,
            );
            payload_0.ongoing_xnet_reshares.insert(
                create_reshare_request(1, 1),
                ReshareOfUnmaskedParams::new(
                    key_transcript.transcript_id,
                    BTreeSet::new(),
                    RegistryVersion::from(0),
                    &current_key_transcript.to_attributes(),
                    key_transcript_ref,
                ),
            );
            let metrics = EcdsaPayloadMetrics::new(MetricsRegistry::new());

            // A new summary payload should be created successfully, with next_in_creation
            // set to Begin (membership changed).
            let payload_1 = create_summary_payload_helper(
                subnet_id,
                registry.as_ref(),
                &block_reader,
                Height::from(1),
                RegistryVersion::from(0),
                current_key_transcript.registry_version().increment(),
                &payload_0,
                Some(&metrics),
                &no_op_logger(),
            )
            .unwrap()
            .unwrap();

            // As membership changed between the registry versions, next_in_creation should be set to begin
            assert_eq!(
                payload_1.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::Begin
            );
            // Critical error counter should be set to 0
            assert_eq!(metrics.critical_error_ecdsa_key_transcript_missing.get(), 0);
            // Quadruples and xnet reshares should still be unchanged:
            assert_eq!(
                payload_0.available_quadruples.len(),
                payload_1.available_quadruples.len()
            );
            assert_eq!(
                payload_0.quadruples_in_creation.len(),
                payload_1.quadruples_in_creation.len()
            );
            assert_eq!(
                payload_0.ongoing_xnet_reshares.len(),
                payload_1.ongoing_xnet_reshares.len()
            );

            // Simulate unsuccessful creation of the next key transcript
            for (id, transcript) in payload_1.idkg_transcripts.clone() {
                block_reader.add_transcript(TranscriptRef::new(Height::from(1), id), transcript)
            }

            let payload_2 = create_summary_payload_helper(
                subnet_id,
                registry.as_ref(),
                &block_reader,
                Height::from(1),
                RegistryVersion::from(0),
                current_key_transcript.registry_version().increment(),
                &payload_1,
                Some(&metrics),
                &no_op_logger(),
            )
            .unwrap()
            .unwrap();

            // next_in_creation should still be set to begin
            assert_eq!(
                payload_2.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::Begin
            );
            // Current key transcript should sill be the same
            assert_eq!(
                payload_2
                    .single_key_transcript()
                    .current
                    .clone()
                    .unwrap()
                    .transcript_id(),
                current_key_transcript.transcript_id(),
            );
            // Critical error counter should be set to 1
            assert_eq!(metrics.critical_error_ecdsa_key_transcript_missing.get(), 1);
            // Quadruples and xnet reshares should still be unchanged:
            assert_eq!(
                payload_2.available_quadruples.len(),
                payload_1.available_quadruples.len()
            );
            assert_eq!(
                payload_2.quadruples_in_creation.len(),
                payload_1.quadruples_in_creation.len()
            );
            assert_eq!(
                payload_2.ongoing_xnet_reshares.len(),
                payload_1.ongoing_xnet_reshares.len()
            );

            let (transcript, transcript_ref, next_key_transcript) =
                create_key_transcript_and_refs(&mut rng, Height::from(1));
            block_reader.add_transcript(*transcript_ref.as_ref(), transcript);
            for (id, transcript) in payload_2.idkg_transcripts.clone() {
                block_reader.add_transcript(TranscriptRef::new(Height::from(2), id), transcript)
            }

            // Simulate successful key trancript creation
            let mut key_transcript = payload_2.single_key_transcript().clone();
            key_transcript.next_in_creation = ecdsa::KeyTranscriptCreation::Created(transcript_ref);
            let mut payload_3 = payload_2.clone();
            payload_3.key_transcript = key_transcript.clone();

            let payload_4 = create_summary_payload_helper(
                subnet_id,
                registry.as_ref(),
                &block_reader,
                Height::from(2),
                RegistryVersion::from(0),
                next_key_transcript.registry_version(),
                &payload_3,
                Some(&metrics),
                &no_op_logger(),
            )
            .unwrap()
            .unwrap();

            // Current key transcript should be the new one
            assert_eq!(
                payload_4
                    .single_key_transcript()
                    .current
                    .clone()
                    .unwrap()
                    .transcript_id(),
                next_key_transcript.transcript_id(),
            );
            assert_matches!(
                payload_4.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::Created(_)
            );

            // Critical error counter should still be set to 1
            assert_eq!(metrics.critical_error_ecdsa_key_transcript_missing.get(), 1);

            // Now, quadruples and xnet reshares should be purged
            assert!(payload_4.quadruples_in_creation.is_empty());
            assert!(payload_4.ongoing_xnet_reshares.is_empty());
            // Available quadruples cannot be purged yet,
            // as we don't know if they are matched to ongoing signature requests.
            assert_eq!(
                payload_4.available_quadruples.len(),
                payload_3.available_quadruples.len()
            );

            let transcript_builder = TestEcdsaTranscriptBuilder::new();
            let signature_builder = TestEcdsaSignatureBuilder::new();
            let ecdsa_config = EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key_id.clone()],
                signature_request_timeout_ns: Some(100000),
                ..EcdsaConfig::default()
            };

            // Create a data payload following the summary making the key change
            let mut payload_5 = payload_4.clone();
            create_data_payload_helper_2(
                &mut payload_5,
                Height::from(3),
                UNIX_EPOCH,
                &ecdsa_config,
                &valid_keys,
                next_key_transcript.registry_version(),
                // Referenced certified height is still below the summary
                CertifiedHeight::BelowSummaryHeight,
                &node_ids,
                &BTreeMap::default(),
                &BTreeMap::default(),
                &block_reader,
                &transcript_builder,
                &signature_builder,
                None,
                &no_op_logger(),
            )
            .unwrap();
            // Quadruples still cannot be deleted, as we haven't seen the state
            // at the summary height yet
            assert_eq!(
                payload_4.available_quadruples.len(),
                payload_5.available_quadruples.len()
            );

            // Create another data payload, this time the referenced certified height
            // reached the last summary height.
            let mut payload_6 = payload_5.clone();
            create_data_payload_helper_2(
                &mut payload_6,
                Height::from(4),
                UNIX_EPOCH,
                &ecdsa_config,
                &valid_keys,
                next_key_transcript.registry_version(),
                CertifiedHeight::ReachedSummaryHeight,
                &node_ids,
                &BTreeMap::default(),
                &BTreeMap::default(),
                &block_reader,
                &transcript_builder,
                &signature_builder,
                None,
                &no_op_logger(),
            )
            .unwrap();
            // Now, available quadruples referencing the old key transcript are deleted.
            assert!(payload_6.available_quadruples.is_empty());
        })
    }

    #[test]
    fn test_if_next_in_creation_continues() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                registry,
                registry_data_provider,
                ..
            } = dependencies(pool_config, 1);
            let subnet_id = subnet_test_id(1);
            let node_ids = vec![node_test_id(0)];
            let subnet_record = SubnetRecordBuilder::from(&node_ids)
                .with_dkg_interval_length(9)
                .build();
            add_subnet_record(&registry_data_provider, 11, subnet_id, subnet_record);
            registry.update_to_latest_version();
            let registry_version = registry.get_latest_version();
            let mut valid_keys = BTreeSet::new();
            let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
            valid_keys.insert(key_id.clone());
            let block_reader = TestEcdsaBlockReader::new();
            let transcript_builder = TestEcdsaTranscriptBuilder::new();
            let signature_builder = TestEcdsaSignatureBuilder::new();
            let ecdsa_config = EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key_id.clone()],
                ..EcdsaConfig::default()
            };

            // Step 1: initial bootstrap payload should be created successfully
            let payload_0 = make_bootstrap_summary(subnet_id, key_id, Height::from(0));
            assert!(payload_0.is_some());
            let payload_0 = payload_0.unwrap();

            // Step 2: a summary payload should be created successfully, with next_in_creation
            // set to Begin.
            let payload_1 = create_summary_payload_helper(
                subnet_id,
                registry.as_ref(),
                &block_reader,
                Height::from(1),
                registry_version,
                registry_version,
                &payload_0,
                None,
                &no_op_logger(),
            );
            assert_matches!(payload_1, Ok(Some(_)));
            let payload_1 = payload_1.unwrap().unwrap();
            assert_matches!(
                payload_1.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::Begin
            );

            // Step 3: a data payload be created successfully
            let mut payload_2 = payload_1;
            let result = create_data_payload_helper_2(
                &mut payload_2,
                Height::from(2),
                UNIX_EPOCH,
                &ecdsa_config,
                &valid_keys,
                registry_version,
                CertifiedHeight::ReachedSummaryHeight,
                &node_ids,
                &BTreeMap::default(),
                &BTreeMap::default(),
                &block_reader,
                &transcript_builder,
                &signature_builder,
                None,
                &no_op_logger(),
            );
            assert!(result.is_ok());
            assert_matches!(
                payload_2.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::RandomTranscriptParams(_)
            );

            // Step 4: the summary payload should be created successfully, carrying forward
            // unfinished next_in_creation
            let payload_3 = create_summary_payload_helper(
                subnet_id,
                registry.as_ref(),
                &block_reader,
                Height::from(3),
                registry_version,
                registry_version,
                &payload_2,
                None,
                &no_op_logger(),
            );
            assert_matches!(payload_3, Ok(Some(_)));
            let payload_3 = payload_3.unwrap().unwrap();
            assert_matches!(
                payload_3.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::RandomTranscriptParams(_)
            );

            // Step 5: the summary payload should be created successfully, carrying forward
            // unfinished next_in_creation even when membership changes
            let node_ids = vec![node_test_id(0), node_test_id(1)];
            let subnet_record = SubnetRecordBuilder::from(&node_ids)
                .with_dkg_interval_length(9)
                .build();
            add_subnet_record(&registry_data_provider, 12, subnet_id, subnet_record);
            registry.update_to_latest_version();
            let new_registry_version = registry.get_latest_version();
            assert_matches!(
                is_time_to_reshare_key_transcript(
                    registry.as_ref(),
                    registry_version,
                    new_registry_version,
                    subnet_id,
                ),
                Ok(true)
            );
            let payload_4 = create_summary_payload_helper(
                subnet_id,
                registry.as_ref(),
                &block_reader,
                Height::from(3),
                registry_version,
                registry_version,
                &payload_2,
                None,
                &no_op_logger(),
            );
            assert_matches!(payload_4, Ok(Some(_)));
            let payload_4 = payload_4.unwrap().unwrap();
            assert_matches!(
                payload_4.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::RandomTranscriptParams(_)
            );
        })
    }

    #[test]
    fn test_next_in_creation_with_initial_dealings() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut rng = reproducible_rng();
            let Dependencies {
                registry,
                registry_data_provider,
                ..
            } = dependencies(pool_config, 1);
            let subnet_id = subnet_test_id(1);
            let node_ids = vec![node_test_id(0)];
            let subnet_record = SubnetRecordBuilder::from(&node_ids)
                .with_dkg_interval_length(9)
                .build();
            let mut valid_keys = BTreeSet::new();
            let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
            valid_keys.insert(key_id.clone());
            let mut block_reader = TestEcdsaBlockReader::new();
            let transcript_builder = TestEcdsaTranscriptBuilder::new();
            let signature_builder = TestEcdsaSignatureBuilder::new();
            let ecdsa_config = EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key_id.clone()],
                signature_request_timeout_ns: Some(100000),
                ..EcdsaConfig::default()
            };

            // Generate initial dealings
            let initial_dealings = dummy_initial_idkg_dealing_for_tests(
                AlgorithmId::ThresholdEcdsaSecp256k1,
                &mut rng,
            );
            let init_tid = initial_dealings.params().transcript_id();

            // Step 1: initial bootstrap payload should be created successfully
            let payload_0 = make_bootstrap_summary_with_initial_dealings(
                subnet_id,
                key_id,
                Height::from(0),
                initial_dealings,
                &no_op_logger(),
            );
            assert_matches!(payload_0, Ok(Some(_)));
            let payload_0 = payload_0.unwrap().unwrap();
            // Add initial reshare transcript to block reader
            let transcript = payload_0.idkg_transcripts.values().next().unwrap().clone();
            for &h in &[0, 3, 4] {
                block_reader.add_transcript(
                    TranscriptRef::new(Height::from(h), transcript.transcript_id),
                    transcript.clone(),
                );
            }

            add_subnet_record(
                &registry_data_provider,
                transcript.registry_version().get(),
                subnet_id,
                subnet_record,
            );
            registry.update_to_latest_version();
            let registry_version = registry.get_latest_version();

            // Step 2: a summary payload should be created successfully, with next_in_creation
            // set to XnetReshareOfUnmaskedParams.
            let payload_1 = create_summary_payload_helper(
                subnet_id,
                registry.as_ref(),
                &block_reader,
                Height::from(1),
                registry_version,
                registry_version,
                &payload_0,
                None,
                &no_op_logger(),
            );
            assert_matches!(payload_1, Ok(Some(_)));
            let payload_1 = payload_1.unwrap().unwrap();
            assert_matches!(
                payload_1.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((ref init, ref params))
                if init.params().transcript_id() == init_tid && params.as_ref().transcript_id == init_tid
            );

            // Step 3: a data payload be created successfully
            let mut payload_2 = payload_1;
            let result = create_data_payload_helper_2(
                &mut payload_2,
                Height::from(2),
                UNIX_EPOCH,
                &ecdsa_config,
                &valid_keys,
                registry_version,
                CertifiedHeight::ReachedSummaryHeight,
                &node_ids,
                &BTreeMap::default(),
                &BTreeMap::default(),
                &block_reader,
                &transcript_builder,
                &signature_builder,
                None,
                &no_op_logger(),
            );
            assert!(result.is_ok());
            assert_matches!(
                payload_2.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((ref init, ref params))
                if init.params().transcript_id() == init_tid && params.as_ref().transcript_id == init_tid
            );

            // Step 4: Allow the transcript to be completed
            transcript_builder.add_transcript(init_tid, transcript.clone());

            // Step 5: a data payload with created key should be created successfully
            let mut payload_3 = payload_2.clone();
            let result = create_data_payload_helper_2(
                &mut payload_3,
                Height::from(3),
                UNIX_EPOCH,
                &ecdsa_config,
                &valid_keys,
                registry_version,
                CertifiedHeight::ReachedSummaryHeight,
                &node_ids,
                &BTreeMap::default(),
                &BTreeMap::default(),
                &block_reader,
                &transcript_builder,
                &signature_builder,
                None,
                &no_op_logger(),
            );
            assert!(result.is_ok());
            assert_matches!(
                payload_3.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::Created(ref unmasked)
                if unmasked.as_ref().transcript_id == transcript.transcript_id
            );
            assert!(payload_3.single_key_transcript().current.is_none());

            // Step 6: a data payload with existing current key should be created successfully
            let mut payload_4 = payload_3.clone();
            let result = create_data_payload_helper_2(
                &mut payload_4,
                Height::from(3),
                UNIX_EPOCH,
                &ecdsa_config,
                &valid_keys,
                registry_version,
                CertifiedHeight::ReachedSummaryHeight,
                &node_ids,
                &BTreeMap::default(),
                &BTreeMap::default(),
                &block_reader,
                &transcript_builder,
                &signature_builder,
                None,
                &no_op_logger(),
            );
            assert!(result.is_ok());
            assert_eq!(
                payload_3.single_key_transcript().next_in_creation,
                payload_4.single_key_transcript().next_in_creation
            );
            assert!(payload_4.single_key_transcript().current.is_some());
            let refs = payload_4.single_key_transcript().get_refs();
            assert_eq!(refs.len(), 2);
            assert_eq!(refs[0], refs[1]);

            // Step 7: the summary payload with created key, based on payload_3
            // should be created successfully
            let payload_5 = create_summary_payload_helper(
                subnet_id,
                registry.as_ref(),
                &block_reader,
                Height::from(4),
                registry_version,
                registry_version,
                &payload_3,
                None,
                &no_op_logger(),
            );
            assert_matches!(payload_5, Ok(Some(_)));
            let payload_5 = payload_5.unwrap().unwrap();
            assert_matches!(
                payload_5.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::Created(ref unmasked)
                if unmasked.as_ref().transcript_id == transcript.transcript_id
            );
            let refs = payload_5.single_key_transcript().get_refs();
            assert_eq!(refs.len(), 2);
            assert_eq!(refs[0], refs[1]);

            // Step 8: the summary payload with created key, based on payload_4
            // should be created successfully
            let payload_6 = create_summary_payload_helper(
                subnet_id,
                registry.as_ref(),
                &block_reader,
                Height::from(5),
                registry_version,
                registry_version,
                &payload_4,
                None,
                &no_op_logger(),
            );
            assert_matches!(payload_6, Ok(Some(_)));
            let payload_6 = payload_6.unwrap().unwrap();
            // next_in_creation should be equal to current
            assert_matches!(
                payload_6.single_key_transcript().next_in_creation,
                ecdsa::KeyTranscriptCreation::Created(ref unmasked)
                if unmasked.as_ref().transcript_id == transcript.transcript_id
            );
            assert!(payload_6.single_key_transcript().current.is_some());
            let refs = payload_6.single_key_transcript().get_refs();
            assert_eq!(refs.len(), 2);
            assert_eq!(refs[0], refs[1]);
        })
    }
}
