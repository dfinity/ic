//! This module implements the IDKG payload builder.
#![allow(clippy::too_many_arguments)]
#![allow(clippy::enum_variant_names)]
#![allow(clippy::result_large_err)]

use super::pre_signer::{IDkgTranscriptBuilder, IDkgTranscriptBuilderImpl};
use super::signer::{ThresholdSignatureBuilder, ThresholdSignatureBuilderImpl};
use super::utils::{block_chain_reader, get_chain_key_config_if_enabled, InvalidChainCacheError};
use crate::idkg::metrics::{IDkgPayloadMetrics, CRITICAL_ERROR_MASTER_KEY_TRANSCRIPT_MISSING};
pub(super) use errors::IDkgPayloadError;
use errors::MembershipError;
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_crypto::retrieve_mega_public_key_from_registry;
use ic_interfaces::idkg::IDkgPool;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{error, info, warn, ReplicaLogger};
use ic_management_canister_types::MasterPublicKeyId;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_features::ChainKeyConfig;
use ic_replicated_state::{metadata_state::subnet_call_context_manager::*, ReplicatedState};
use ic_types::consensus::idkg::HasMasterPublicKeyId;
use ic_types::{
    batch::ValidationContext,
    consensus::{
        idkg::{self, IDkgBlockReader, IDkgPayload, MasterKeyTranscript, TranscriptAttributes},
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
mod pre_signatures;
pub(super) mod resharing;
pub(super) mod signatures;

/// Builds the very first idkg summary block. This would trigger the subsequent
/// data blocks to create the initial key transcript.
pub(crate) fn make_bootstrap_summary(
    subnet_id: SubnetId,
    key_ids: Vec<MasterPublicKeyId>,
    height: Height,
) -> idkg::Summary {
    let key_transcripts = key_ids
        .into_iter()
        .map(|key_id| MasterKeyTranscript::new(key_id, idkg::KeyTranscriptCreation::Begin))
        .collect();

    Some(IDkgPayload::empty(height, subnet_id, key_transcripts))
}

/// Builds the very first idkg summary block. This would trigger the subsequent
/// data blocks to create the initial key transcript.
pub(crate) fn make_bootstrap_summary_with_initial_dealings(
    subnet_id: SubnetId,
    height: Height,
    initial_dealings_per_key_id: BTreeMap<MasterPublicKeyId, InitialIDkgDealings>,
    log: &ReplicaLogger,
) -> Result<idkg::Summary, IDkgPayloadError> {
    let mut idkg_transcripts = BTreeMap::new();
    let mut key_transcripts = Vec::new();

    for (key_id, initial_dealings) in initial_dealings_per_key_id {
        match idkg::unpack_reshare_of_unmasked_params(height, initial_dealings.params()) {
            Some((params, transcript)) => {
                idkg_transcripts.insert(transcript.transcript_id, transcript);

                key_transcripts.push(MasterKeyTranscript::new(
                    key_id,
                    idkg::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((
                        Box::new(initial_dealings),
                        params,
                    )),
                ));
            }
            None => {
                // Leave the feature disabled if the initial dealings are incorrect.
                warn!(
                    log,
                    "make_idkg_genesis_summary(): failed to unpack initial dealings"
                );

                return Err(IDkgPayloadError::InitialIDkgDealingsNotUnmaskedParams(
                    Box::new(initial_dealings),
                ));
            }
        }
    }

    info!(
        log,
        "make_idkg_genesis_summary(): height = {}, key_transcript = [{:?}]",
        height,
        key_transcripts
    );

    let mut payload = IDkgPayload::empty(height, subnet_id, key_transcripts);
    payload.idkg_transcripts = idkg_transcripts;

    Ok(Some(payload))
}

/// Creates an IDKG summary payload.
pub(crate) fn create_summary_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    pool_reader: &PoolReader<'_>,
    context: &ValidationContext,
    parent_block: &Block,
    idkg_payload_metrics: Option<&IDkgPayloadMetrics>,
    log: &ReplicaLogger,
) -> Result<idkg::Summary, IDkgPayloadError> {
    let height = parent_block.height().increment();
    let prev_summary_block = pool_reader
        .dkg_summary_block(parent_block)
        .ok_or_else(|| IDkgPayloadError::ConsensusSummaryBlockNotFound(parent_block.height()))?;

    // For this interval: context.registry_version from prev summary block
    // which is the same as calling pool_reader.registry_version(height).
    // which is the same as summary.dkg.registry_version (to be created).
    let curr_interval_registry_version = prev_summary_block.context.registry_version;

    // For next interval: context.registry_version from the new summary block
    let next_interval_registry_version = context.registry_version;

    // Get chain_key_config from registry if it exists
    let Some(chain_key_config) = get_chain_key_config_if_enabled(
        subnet_id,
        curr_interval_registry_version,
        registry_client,
    )?
    else {
        return Ok(None);
    };

    let key_ids: Vec<_> = chain_key_config
        .key_configs
        .iter()
        .map(|key_config| key_config.key_id.clone())
        .collect();

    // Get idkg_payload from parent block if it exists
    let Some(idkg_payload) = parent_block.payload.as_ref().as_data().idkg.as_ref() else {
        // Parent block doesn't have IDKG payload and feature is enabled.
        // Create the bootstrap summary block, and create new keys for the given key_ids.
        //
        // This is safe because registry's do_update_subnet already ensures that only
        // fresh key_id can be assigned to an existing subnet.
        //
        // Keys already held by existing subnets can only be re-shared when creating or
        // recovering a subnet, which means the genesis summary IDKG payload is not empty
        // and we won't reach here.
        info!(
            log,
            "Start to create Chain keys {:?} on subnet {} at height {}", key_ids, subnet_id, height
        );

        return Ok(make_bootstrap_summary(subnet_id, key_ids.clone(), height));
    };

    let block_reader = block_chain_reader(
        pool_reader,
        &prev_summary_block,
        parent_block,
        idkg_payload_metrics,
        log,
    )?;

    create_summary_payload_helper(
        subnet_id,
        &key_ids,
        registry_client,
        &block_reader,
        height,
        curr_interval_registry_version,
        next_interval_registry_version,
        idkg_payload,
        idkg_payload_metrics,
        log,
    )
}

fn create_summary_payload_helper(
    subnet_id: SubnetId,
    key_ids: &[MasterPublicKeyId],
    registry_client: &dyn RegistryClient,
    block_reader: &dyn IDkgBlockReader,
    height: Height,
    curr_interval_registry_version: RegistryVersion,
    next_interval_registry_version: RegistryVersion,
    idkg_payload: &IDkgPayload,
    idkg_payload_metrics: Option<&IDkgPayloadMetrics>,
    log: &ReplicaLogger,
) -> Result<idkg::Summary, IDkgPayloadError> {
    let mut key_transcripts = BTreeMap::new();
    let mut new_key_transcripts = BTreeSet::new();

    for (key_id, key_transcript) in &idkg_payload.key_transcripts {
        let current_key_transcript = key_transcript.current.as_ref();

        let created_key_transcript =
            key_transcript::get_created_key_transcript(key_transcript, block_reader)?;

        // Registry version as recorded in the (new) current key transcript if it exists.
        // Otherwise use curr_interval_registry_version.
        let curr_key_registry_version = created_key_transcript
            .as_ref()
            .map(idkg::UnmaskedTranscriptWithAttributes::registry_version)
            .or_else(|| {
                current_key_transcript.map(idkg::UnmaskedTranscriptWithAttributes::registry_version)
            })
            .unwrap_or(curr_interval_registry_version);

        if created_key_transcript.is_none() {
            if let Some(metrics) = idkg_payload_metrics {
                metrics.critical_error_master_key_transcript_missing.inc();
            }

            error!(
                log,
                "{}: Key not created in previous interval, \
                keep trying in next interval(height = {}), key_transcript = {}",
                CRITICAL_ERROR_MASTER_KEY_TRANSCRIPT_MISSING,
                height,
                key_transcript
            );
        }

        let is_new_key_transcript = created_key_transcript.as_ref().is_some_and(|transcript| {
            Some(transcript.transcript_id())
                != current_key_transcript.map(idkg::UnmaskedTranscriptWithAttributes::transcript_id)
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
                "Noticed subnet membership or mega encryption key change for key id {}, \
                will start key_transcript_creation: height = {} \
                current_version = {}, next_version = {}",
                key_id,
                height,
                curr_key_registry_version,
                next_interval_registry_version
            );
            idkg::KeyTranscriptCreation::Begin
        } else {
            // No change, just carry forward the next_in_creation transcript
            key_transcript.next_in_creation.clone()
        };

        key_transcripts.insert(
            key_id.clone(),
            key_transcript.update(created_key_transcript, next_in_creation),
        );
        if is_new_key_transcript {
            new_key_transcripts.insert(key_id);
        }
    }

    let mut idkg_summary = idkg_payload.clone();
    idkg_summary.key_transcripts = key_transcripts;
    // Start creating key transcripts for all new key ids.
    for key_id in key_ids {
        #[allow(clippy::map_entry)]
        if !idkg_summary.key_transcripts.contains_key(key_id) {
            idkg_summary.key_transcripts.insert(
                key_id.clone(),
                MasterKeyTranscript::new(key_id.clone(), idkg::KeyTranscriptCreation::Begin),
            );
        }
    }

    idkg_summary.idkg_transcripts.clear();

    // We keep available pre-signatures for now, even if the key transcript changed, as we don't know if
    // they are part of ongoing signature requests. Instead we will purge them once the certified
    // state height catches up with the height of this summary block.
    // We do purge the pre-signatures in creation, though.
    idkg_summary
        .pre_signatures_in_creation
        .retain(|_, pre_sig| !new_key_transcripts.contains(&pre_sig.key_id()));
    // This will clear the current ongoing reshares, and the execution requests will be restarted
    // with the new key and different transcript IDs.
    idkg_summary
        .ongoing_xnet_reshares
        .retain(|request, _| !new_key_transcripts.contains(&request.master_key_id));

    idkg_summary.uid_generator.update_height(height)?;
    update_summary_refs(height, &mut idkg_summary, block_reader)?;

    Ok(Some(idkg_summary))
}

fn update_summary_refs(
    height: Height,
    summary: &mut IDkgPayload,
    block_reader: &dyn IDkgBlockReader,
) -> Result<(), IDkgPayloadError> {
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

/// Creates an IDKG batch payload.
pub(crate) fn create_data_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    idkg_pool: Arc<RwLock<dyn IDkgPool>>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    parent_block: &Block,
    idkg_payload_metrics: &IDkgPayloadMetrics,
    log: &ReplicaLogger,
) -> Result<idkg::Payload, IDkgPayloadError> {
    // Return None if parent block does not have IDKG payload.
    if parent_block.payload.as_ref().as_idkg().is_none() {
        return Ok(None);
    };
    let summary_block = pool_reader
        .dkg_summary_block(parent_block)
        .ok_or_else(|| IDkgPayloadError::ConsensusSummaryBlockNotFound(parent_block.height()))?;

    // The notarized tip(parent) may be ahead of the finalized tip, and
    // the last few blocks may have references to heights after the finalized
    // tip. So use the chain ending at the parent to resolve refs, rather than the
    // finalized chain.
    let block_reader = block_chain_reader(
        pool_reader,
        &summary_block,
        parent_block,
        Some(idkg_payload_metrics),
        log,
    )?;
    let idkg_pool = idkg_pool.read().unwrap();

    let signature_builder = ThresholdSignatureBuilderImpl::new(
        &block_reader,
        crypto,
        idkg_pool.deref(),
        idkg_payload_metrics,
        log.clone(),
    );
    let transcript_builder = IDkgTranscriptBuilderImpl::new(
        &block_reader,
        crypto,
        idkg_pool.deref(),
        idkg_payload_metrics,
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
        Some(idkg_payload_metrics),
        log,
    )?;

    if let Some(idkg_payload) = &new_payload {
        let is_key_transcript_created = |key_transcript: &MasterKeyTranscript| {
            matches!(
                key_transcript.next_in_creation,
                idkg::KeyTranscriptCreation::Created(_)
            )
        };

        for (key_id, key_transcript) in &idkg_payload.key_transcripts {
            if is_key_transcript_created(key_transcript)
                && !parent_block
                    .payload
                    .as_ref()
                    .as_idkg()
                    .and_then(|idkg_payload| idkg_payload.key_transcripts.get(key_id))
                    .is_some_and(is_key_transcript_created)
            {
                idkg_payload_metrics.payload_metrics_inc("key_transcripts_created", Some(key_id));
            }
        }

        idkg_payload_metrics.report(idkg_payload);
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
    block_reader: &dyn IDkgBlockReader,
    transcript_builder: &dyn IDkgTranscriptBuilder,
    signature_builder: &dyn ThresholdSignatureBuilder,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    registry_client: &dyn RegistryClient,
    idkg_payload_metrics: Option<&IDkgPayloadMetrics>,
    log: &ReplicaLogger,
) -> Result<Option<IDkgPayload>, IDkgPayloadError> {
    let height = parent_block.height().increment();
    let summary = summary_block.payload.as_ref().as_summary();

    // For this interval: context.registry_version from last summary block,
    // which is the same as calling pool_reader.registry_version(height).
    // which is the same as summary.dkg.registry_version,
    let curr_interval_registry_version = summary.dkg.registry_version;
    // For next interval: context.registry_version from the new summary block
    let next_interval_registry_version = summary_block.context.registry_version;

    let Some(chain_key_config) = get_chain_key_config_if_enabled(
        subnet_id,
        curr_interval_registry_version,
        registry_client,
    )?
    else {
        return Ok(None);
    };

    let valid_keys: BTreeSet<_> = chain_key_config
        .key_configs
        .iter()
        .map(|key_config| key_config.key_id.clone())
        .collect();

    let mut idkg_payload = if let Some(prev_payload) = parent_block.payload.as_ref().as_idkg() {
        prev_payload.clone()
    } else {
        return Ok(None);
    };

    let receivers = get_subnet_nodes(registry_client, next_interval_registry_version, subnet_id)?;
    let state = state_manager.get_state_at(context.certified_height)?;
    let all_signing_requests = state.get_ref().signature_request_contexts();
    let idkg_dealings_contexts = state.get_ref().idkg_dealings_contexts();

    let certified_height = if context.certified_height >= summary_block.height() {
        CertifiedHeight::ReachedSummaryHeight
    } else {
        CertifiedHeight::BelowSummaryHeight
    };

    create_data_payload_helper_2(
        &mut idkg_payload,
        height,
        context.time,
        &chain_key_config,
        &valid_keys,
        next_interval_registry_version,
        certified_height,
        &receivers,
        all_signing_requests,
        idkg_dealings_contexts,
        block_reader,
        transcript_builder,
        signature_builder,
        idkg_payload_metrics,
        log,
    )?;

    Ok(Some(idkg_payload))
}

pub(crate) fn create_data_payload_helper_2(
    idkg_payload: &mut IDkgPayload,
    height: Height,
    context_time: Time,
    chain_key_config: &ChainKeyConfig,
    valid_keys: &BTreeSet<MasterPublicKeyId>,
    next_interval_registry_version: RegistryVersion,
    certified_height: CertifiedHeight,
    receivers: &[NodeId],
    all_signing_requests: &BTreeMap<CallbackId, SignWithThresholdContext>,
    idkg_dealings_contexts: &BTreeMap<CallbackId, IDkgDealingsContext>,
    block_reader: &dyn IDkgBlockReader,
    transcript_builder: &dyn IDkgTranscriptBuilder,
    signature_builder: &dyn ThresholdSignatureBuilder,
    idkg_payload_metrics: Option<&IDkgPayloadMetrics>,
    log: &ReplicaLogger,
) -> Result<(), IDkgPayloadError> {
    // Check if we are creating a new key, if so, start using it immediately.
    for key_transcript in idkg_payload.key_transcripts.values_mut() {
        if key_transcript.current.is_none() {
            key_transcript.current =
                key_transcript::get_created_key_transcript(key_transcript, block_reader)?;
        }
    }

    idkg_payload.uid_generator.update_height(height)?;

    let request_expiry_time = chain_key_config
        .signature_request_timeout_ns
        .and_then(|timeout| context_time.checked_sub(Duration::from_nanos(timeout)));

    signatures::update_signature_agreements(
        all_signing_requests,
        signature_builder,
        request_expiry_time,
        idkg_payload,
        valid_keys,
        idkg_payload_metrics,
    );

    if matches!(certified_height, CertifiedHeight::ReachedSummaryHeight) {
        pre_signatures::purge_old_key_pre_signatures(idkg_payload, all_signing_requests);
    }

    // We count the number of pre-signatures in the payload that were already matched,
    // such that they can be replenished.
    let mut matched_pre_signatures_per_key_id = BTreeMap::new();

    for context in all_signing_requests.values() {
        if context
            .matched_pre_signature
            .as_ref()
            .is_some_and(|(pid, _)| idkg_payload.available_pre_signatures.contains_key(pid))
        {
            *matched_pre_signatures_per_key_id
                .entry(context.key_id())
                .or_insert(0) += 1;
        }
    }

    pre_signatures::make_new_pre_signatures_if_needed(
        chain_key_config,
        idkg_payload,
        &matched_pre_signatures_per_key_id,
    );

    let new_transcripts = [
        pre_signatures::update_pre_signatures_in_creation(
            idkg_payload,
            transcript_builder,
            height,
            log,
        )?,
        key_transcript::update_next_key_transcripts(
            receivers,
            next_interval_registry_version,
            idkg_payload,
            transcript_builder,
            height,
            log,
        )?,
    ]
    .into_iter()
    .flatten();

    // Drop transcripts from last round and keep only the
    // ones created in this round.
    idkg_payload.idkg_transcripts.clear();
    for transcript in new_transcripts {
        idkg_payload
            .idkg_transcripts
            .insert(transcript.transcript_id, transcript);
    }

    resharing::update_completed_reshare_requests(
        idkg_payload,
        idkg_dealings_contexts,
        block_reader,
        transcript_builder,
        log,
    );
    resharing::initiate_reshare_requests(
        idkg_payload,
        resharing::get_reshare_requests(idkg_dealings_contexts),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::batch_delivery::generate_responses_to_signature_request_contexts;
    use crate::idkg::test_utils::*;
    use crate::idkg::utils::algorithm_for_key_id;
    use crate::idkg::utils::block_chain_reader;
    use crate::idkg::utils::get_context_request_id;
    use assert_matches::assert_matches;
    use ic_consensus_mocks::{dependencies, Dependencies};
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_initial_idkg_dealing_for_tests;
    use ic_crypto_test_utils_canister_threshold_sigs::generate_tecdsa_protocol_inputs;
    use ic_crypto_test_utils_canister_threshold_sigs::generate_tschnorr_protocol_inputs;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        CanisterThresholdSigTestEnvironment, IDkgParticipants,
    };
    use ic_crypto_test_utils_reproducible_rng::{reproducible_rng, ReproducibleRng};
    use ic_interfaces_registry::RegistryValue;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::types::v1 as pb;
    use ic_registry_subnet_features::KeyConfig;
    use ic_test_utilities_artifact_pool::consensus_pool::TestConsensusPool;
    use ic_test_utilities_consensus::fake::{Fake, FakeContentSigner};
    use ic_test_utilities_registry::{add_subnet_record, SubnetRecordBuilder};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id, user_test_id};
    use ic_types::batch::BatchPayload;
    use ic_types::consensus::dkg::{Dealings, Summary};
    use ic_types::consensus::idkg::IDkgPayload;
    use ic_types::consensus::idkg::PreSigId;
    use ic_types::consensus::idkg::ReshareOfUnmaskedParams;
    use ic_types::consensus::idkg::TranscriptRef;
    use ic_types::consensus::idkg::UnmaskedTranscript;
    use ic_types::consensus::idkg::UnmaskedTranscriptWithAttributes;
    use ic_types::consensus::{
        BlockPayload, BlockProposal, DataPayload, HashedBlock, Payload, Rank, SummaryPayload,
    };
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscript;
    use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
    use ic_types::crypto::canister_threshold_sig::ThresholdEcdsaCombinedSignature;
    use ic_types::crypto::canister_threshold_sig::ThresholdSchnorrCombinedSignature;
    use ic_types::crypto::{CryptoHash, CryptoHashOf};
    use ic_types::time::UNIX_EPOCH;
    use ic_types::Randomness;
    use ic_types::{messages::CallbackId, Height, RegistryVersion};
    use idkg::common::CombinedSignature;
    use std::collections::BTreeSet;
    use std::convert::TryInto;

    fn create_summary_block_with_transcripts(
        key_id: MasterPublicKeyId,
        subnet_id: SubnetId,
        height: Height,
        current_key_transcript: (idkg::UnmaskedTranscript, IDkgTranscript),
        transcripts: Vec<BTreeMap<idkg::TranscriptRef, IDkgTranscript>>,
    ) -> BlockPayload {
        let mut idkg_summary = empty_idkg_payload_with_key_ids(subnet_id, vec![key_id]);
        idkg_summary.single_key_transcript_mut().current =
            Some(idkg::UnmaskedTranscriptWithAttributes::new(
                current_key_transcript.1.to_attributes(),
                current_key_transcript.0,
            ));
        idkg_summary.idkg_transcripts.insert(
            current_key_transcript.0.as_ref().transcript_id,
            current_key_transcript.1,
        );
        for idkg_transcripts in transcripts {
            for (transcript_ref, transcript) in idkg_transcripts {
                idkg_summary
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
            idkg: Some(idkg_summary),
        })
    }

    fn create_payload_block_with_transcripts(
        key_id: MasterPublicKeyId,
        subnet_id: SubnetId,
        dkg_interval_start_height: Height,
        transcripts: Vec<BTreeMap<idkg::TranscriptRef, IDkgTranscript>>,
    ) -> BlockPayload {
        let mut idkg_payload = empty_idkg_payload_with_key_ids(subnet_id, vec![key_id]);
        for idkg_transcripts in transcripts {
            for (transcript_ref, transcript) in idkg_transcripts {
                idkg_payload
                    .idkg_transcripts
                    .insert(transcript_ref.transcript_id, transcript);
            }
        }
        BlockPayload::Data(DataPayload {
            batch: BatchPayload::default(),
            dealings: Dealings::new_empty(dkg_interval_start_height),
            idkg: Some(idkg_payload),
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

    fn set_up_idkg_payload_with_keys(
        key_ids: Vec<MasterPublicKeyId>,
    ) -> (IDkgPayload, CanisterThresholdSigTestEnvironment) {
        let mut rng = reproducible_rng();
        let (idkg_payload, env, _block_reader) = set_up_idkg_payload(
            &mut rng,
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            key_ids,
            /*should_create_key_transcript=*/ true,
        );
        (idkg_payload, env)
    }

    fn set_up_signature_request_contexts(
        parameters: Vec<(MasterPublicKeyId, u8, Time, Option<PreSigId>)>,
    ) -> BTreeMap<CallbackId, SignWithThresholdContext> {
        let mut contexts = BTreeMap::new();
        for (key_id, id, batch_time, pre_sig) in parameters {
            let (callback_id, mut context) =
                fake_signature_request_context_with_pre_sig(id, key_id, pre_sig);
            context.batch_time = batch_time;
            contexts.insert(callback_id, context);
        }
        contexts
    }

    #[test]
    fn test_pre_signature_recreation_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_pre_signature_recreation(key_id);
        }
    }

    fn test_pre_signature_recreation(valid_key_id: MasterPublicKeyId) {
        const PRE_SIGNATURES_TO_CREATE_IN_ADVANCE: u32 = 5;
        let disabled_key_id = key_id_with_name(&valid_key_id, "disabled");
        let valid_keys = BTreeSet::from([valid_key_id.clone()]);

        let (mut idkg_payload, _env) = set_up_idkg_payload_with_keys(vec![valid_key_id.clone()]);
        // Add two pre-signatures
        let pre_sig_for_valid_key =
            create_available_pre_signature(&mut idkg_payload, valid_key_id.clone(), 10);
        let pre_sig_for_disabled_key =
            create_available_pre_signature(&mut idkg_payload, disabled_key_id.clone(), 11);
        let non_existent_pre_sig_for_valid_key = idkg_payload.uid_generator.next_pre_signature_id();

        let contexts = set_up_signature_request_contexts(vec![
            // Two request contexts without pre-signature
            (valid_key_id.clone(), 0, UNIX_EPOCH, None),
            (disabled_key_id.clone(), 1, UNIX_EPOCH, None),
            // One valid context with matched pre-signature
            (
                valid_key_id.clone(),
                2,
                UNIX_EPOCH,
                Some(pre_sig_for_valid_key),
            ),
            // One invalid context with matched pre-signature
            (
                disabled_key_id.clone(),
                3,
                UNIX_EPOCH,
                Some(pre_sig_for_disabled_key),
            ),
            // One valid context matched to non-existent pre-signature
            (
                valid_key_id.clone(),
                4,
                UNIX_EPOCH,
                Some(non_existent_pre_sig_for_valid_key),
            ),
        ]);

        let chain_key_config = ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: valid_key_id.clone(),
                pre_signatures_to_create_in_advance: PRE_SIGNATURES_TO_CREATE_IN_ADVANCE,
                max_queue_size: 1,
            }],
            ..ChainKeyConfig::default()
        };

        assert_eq!(idkg_payload.pre_signatures_in_creation.len(), 0);
        assert_eq!(idkg_payload.available_pre_signatures.len(), 2);

        create_data_payload_helper_2(
            &mut idkg_payload,
            Height::from(5),
            UNIX_EPOCH,
            &chain_key_config,
            &valid_keys,
            RegistryVersion::from(9),
            CertifiedHeight::ReachedSummaryHeight,
            &[node_test_id(0)],
            &contexts,
            &BTreeMap::default(),
            &TestIDkgBlockReader::new(),
            &TestIDkgTranscriptBuilder::new(),
            &TestThresholdSignatureBuilder::new(),
            /*idkg_payload_metrics*/ None,
            &ic_logger::replica_logger::no_op_logger(),
        )
        .unwrap();

        let num_pre_sigs_in_creation = idkg_payload.pre_signatures_in_creation.len() as u32;
        let num_available_pre_sigs = idkg_payload.available_pre_signatures.len() as u32;
        // The two matched pre-signature remain
        // in available_pre_signatures.
        assert_eq!(num_available_pre_sigs, 2);
        // Usually, matched pre-signatures are replenished, but since one
        // of them was matched to a disabled key id whose request context
        // is rejected, the pre-signature is "reused" and not replenished.
        assert_eq!(
            num_pre_sigs_in_creation,
            PRE_SIGNATURES_TO_CREATE_IN_ADVANCE
        );
    }

    #[test]
    fn test_signing_request_timeout_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_signing_request_timeout(key_id);
        }
    }

    fn test_signing_request_timeout(key_id: MasterPublicKeyId) {
        let expired_time = UNIX_EPOCH + Duration::from_secs(10);
        let expiry_time = UNIX_EPOCH + Duration::from_secs(11);
        let non_expired_time = UNIX_EPOCH + Duration::from_secs(12);

        let (mut idkg_payload, _env) = set_up_idkg_payload_with_keys(vec![key_id.clone()]);
        // Add pre-signatures
        let discarded_pre_sig_id =
            create_available_pre_signature(&mut idkg_payload, key_id.clone(), 10);
        let matched_pre_sig_id =
            create_available_pre_signature(&mut idkg_payload, key_id.clone(), 11);

        let contexts = set_up_signature_request_contexts(vec![
            // One expired context without pre-signature
            (key_id.clone(), 0, expired_time, None),
            // One expired context with matched pre-signature
            (key_id.clone(), 1, expired_time, Some(discarded_pre_sig_id)),
            // One non-expired context with matched pre-signature
            (
                key_id.clone(),
                2,
                non_expired_time,
                Some(matched_pre_sig_id),
            ),
        ]);

        assert_eq!(idkg_payload.signature_agreements.len(), 0);
        assert_eq!(idkg_payload.available_pre_signatures.len(), 2);

        let signature_builder = TestThresholdSignatureBuilder::new();
        signatures::update_signature_agreements(
            &contexts,
            &signature_builder,
            Some(expiry_time),
            &mut idkg_payload,
            &BTreeSet::from([key_id]),
            None,
        );

        // Only the expired context with matched pre-signature should receive a reject response
        assert_eq!(idkg_payload.signature_agreements.len(), 1);
        let Some(idkg::CompletedSignature::Unreported(response)) =
            idkg_payload.signature_agreements.get(&[1; 32])
        else {
            panic!("Request 1 should have a response");
        };
        assert_matches!(
            &response.payload,
            ic_types::messages::Payload::Reject(context)
            if context.message().contains("request expired")
        );

        // The pre-signature matched with the expired context should be deleted
        assert_eq!(idkg_payload.available_pre_signatures.len(), 1);
        assert_eq!(
            idkg_payload.available_pre_signatures.keys().next().unwrap(),
            &matched_pre_sig_id
        );
    }

    #[test]
    fn test_request_with_invalid_key_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_request_with_invalid_key(key_id);
        }
    }

    fn test_request_with_invalid_key(valid_key_id: MasterPublicKeyId) {
        let invalid_key_id = key_id_with_name(&valid_key_id, "invalid");
        let (mut idkg_payload, _env) = set_up_idkg_payload_with_keys(vec![valid_key_id.clone()]);
        // Add pre-signatures
        let pre_sig_id1 =
            create_available_pre_signature(&mut idkg_payload, valid_key_id.clone(), 1);
        let pre_sig_id2 =
            create_available_pre_signature(&mut idkg_payload, invalid_key_id.clone(), 2);

        let contexts = set_up_signature_request_contexts(vec![
            // One matched context with valid key
            (valid_key_id.clone(), 1, UNIX_EPOCH, Some(pre_sig_id1)),
            // One matched context with invalid key
            (invalid_key_id.clone(), 2, UNIX_EPOCH, Some(pre_sig_id2)),
            // One unmatched context with invalid key
            (invalid_key_id.clone(), 3, UNIX_EPOCH, None),
        ]);

        assert_eq!(idkg_payload.signature_agreements.len(), 0);
        assert_eq!(idkg_payload.available_pre_signatures.len(), 2);

        let signature_builder = TestThresholdSignatureBuilder::new();
        signatures::update_signature_agreements(
            &contexts,
            &signature_builder,
            None,
            &mut idkg_payload,
            &BTreeSet::from([valid_key_id]),
            None,
        );

        // The contexts with invalid key should receive a reject response
        assert_eq!(idkg_payload.signature_agreements.len(), 2);
        let Some(idkg::CompletedSignature::Unreported(response_1)) =
            idkg_payload.signature_agreements.get(&[2; 32])
        else {
            panic!("Request 2 should have a response");
        };
        assert_matches!(
            &response_1.payload,
            ic_types::messages::Payload::Reject(context)
            if context.message().contains("Invalid key_id")
        );

        let Some(idkg::CompletedSignature::Unreported(response_2)) =
            idkg_payload.signature_agreements.get(&[3; 32])
        else {
            panic!("Request 3 should have a response");
        };
        assert_matches!(
            &response_2.payload,
            ic_types::messages::Payload::Reject(context)
            if context.message().contains("Invalid key_id")
        );

        // The pre-signature matched with the expired context should not be deleted
        assert_eq!(idkg_payload.available_pre_signatures.len(), 2);
    }

    #[test]
    fn test_signature_is_only_delivered_once_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_signature_is_only_delivered_once(key_id);
        }
    }

    fn test_signature_is_only_delivered_once(key_id: MasterPublicKeyId) {
        let (mut idkg_payload, _env) = set_up_idkg_payload_with_keys(vec![key_id.clone()]);
        let pre_sig_id = create_available_pre_signature(&mut idkg_payload, key_id.clone(), 13);
        let context = fake_completed_signature_request_context(0, key_id.clone(), pre_sig_id);
        let signature_request_contexts = BTreeMap::from([context.clone()]);

        let valid_keys = BTreeSet::from([key_id.clone()]);

        let block_reader = TestIDkgBlockReader::new();
        let transcript_builder = TestIDkgTranscriptBuilder::new();
        let mut signature_builder = TestThresholdSignatureBuilder::new();

        signature_builder.signatures.insert(
            get_context_request_id(&context.1).unwrap(),
            match key_id {
                MasterPublicKeyId::Ecdsa(_) => {
                    CombinedSignature::Ecdsa(ThresholdEcdsaCombinedSignature {
                        signature: vec![1; 32],
                    })
                }
                MasterPublicKeyId::Schnorr(_) => {
                    CombinedSignature::Schnorr(ThresholdSchnorrCombinedSignature {
                        signature: vec![2; 32],
                    })
                }
            },
        );

        // create first payload
        create_data_payload_helper_2(
            &mut idkg_payload,
            Height::from(5),
            UNIX_EPOCH,
            &ChainKeyConfig::default(),
            &valid_keys,
            RegistryVersion::from(9),
            CertifiedHeight::ReachedSummaryHeight,
            &[node_test_id(0)],
            &signature_request_contexts,
            &BTreeMap::default(),
            &block_reader,
            &transcript_builder,
            &signature_builder,
            /*idkg_payload_metrics*/ None,
            &ic_logger::replica_logger::no_op_logger(),
        )
        .unwrap();

        // Assert that we got a response
        let response1 = generate_responses_to_signature_request_contexts(&idkg_payload);
        assert_eq!(response1.len(), 1);

        // create next payload
        create_data_payload_helper_2(
            &mut idkg_payload,
            Height::from(5),
            UNIX_EPOCH,
            &ChainKeyConfig::default(),
            &valid_keys,
            RegistryVersion::from(9),
            CertifiedHeight::ReachedSummaryHeight,
            &[node_test_id(0)],
            &signature_request_contexts,
            &BTreeMap::default(),
            &block_reader,
            &transcript_builder,
            &signature_builder,
            /*idkg_payload_metrics*/ None,
            &ic_logger::replica_logger::no_op_logger(),
        )
        .unwrap();

        // assert that same signature isn't delivered again.
        let response2 = generate_responses_to_signature_request_contexts(&idkg_payload);
        assert!(response2.is_empty());
    }

    #[test]
    fn test_update_summary_refs_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_update_summary_refs(key_id);
        }
    }

    fn test_update_summary_refs(key_id: MasterPublicKeyId) {
        let mut rng = reproducible_rng();
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                let Dependencies { mut pool, .. } = dependencies(pool_config, 1);
                let subnet_id = subnet_test_id(1);
                let mut expected_transcripts = BTreeSet::new();
                let transcript_builder = TestIDkgTranscriptBuilder::new();
                let mut add_expected_transcripts = |trancript_refs: Vec<idkg::TranscriptRef>| {
                    for transcript_ref in trancript_refs {
                        expected_transcripts.insert(transcript_ref.transcript_id);
                    }
                };

                // Create a summary block with transcripts
                let summary_height = Height::new(5);
                let env = CanisterThresholdSigTestEnvironment::new(4, &mut rng);
                let subnet_nodes: Vec<_> = env.nodes.ids();
                let (key_transcript, key_transcript_ref, current_key_transcript) =
                    generate_key_transcript(&key_id, &env, &mut rng, summary_height);
                let (reshare_key_transcript, reshare_key_transcript_ref, _) =
                    generate_key_transcript(&key_id, &env, &mut rng, summary_height);
                let reshare_params_1 = idkg::ReshareOfUnmaskedParams::new(
                    create_transcript_id(1001),
                    BTreeSet::new(),
                    RegistryVersion::from(1001),
                    &reshare_key_transcript,
                    reshare_key_transcript_ref,
                );
                let mut reshare_refs = BTreeMap::new();
                reshare_refs.insert(*reshare_key_transcript_ref.as_ref(), reshare_key_transcript);

                let inputs_1 = create_sig_inputs_with_height(91, summary_height, key_id.clone());
                let inputs_2 = create_sig_inputs_with_height(92, summary_height, key_id.clone());
                let summary_block = create_summary_block_with_transcripts(
                    key_id.clone(),
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
                let presig_1 = inputs_2.sig_inputs_ref.pre_signature();

                // Create payload blocks with transcripts
                let payload_height_1 = Height::new(10);
                let inputs_1 = create_sig_inputs_with_height(93, payload_height_1, key_id.clone());
                let inputs_2 = create_sig_inputs_with_height(94, payload_height_1, key_id.clone());
                let (reshare_key_transcript, reshare_key_transcript_ref, _) =
                    generate_key_transcript(&key_id, &env, &mut rng, payload_height_1);
                let mut reshare_refs = BTreeMap::new();
                reshare_refs.insert(*reshare_key_transcript_ref.as_ref(), reshare_key_transcript);
                let payload_block_1 = create_payload_block_with_transcripts(
                    key_id.clone(),
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
                let presig_2 = inputs_2.sig_inputs_ref.pre_signature();

                // Create a payload block with references to these past blocks
                let mut idkg_payload =
                    empty_idkg_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
                idkg_payload.single_key_transcript_mut().current =
                    Some(current_key_transcript.clone());
                let (pre_sig_id_1, pre_sig_id_2) = (
                    idkg_payload.uid_generator.next_pre_signature_id(),
                    idkg_payload.uid_generator.next_pre_signature_id(),
                );
                idkg_payload
                    .available_pre_signatures
                    .insert(pre_sig_id_1, presig_1.clone());
                idkg_payload
                    .available_pre_signatures
                    .insert(pre_sig_id_2, presig_2.clone());

                let req_1 = create_reshare_request(key_id.clone(), 1, 1);
                idkg_payload
                    .ongoing_xnet_reshares
                    .insert(req_1, reshare_params_1.clone());

                add_expected_transcripts(vec![*key_transcript_ref.as_ref()]);
                add_expected_transcripts(reshare_params_1.as_ref().get_refs());

                let block_reader = TestIDkgBlockReader::new();
                // Add a pre-signatures in creation without progress
                pre_signatures::test_utils::create_new_pre_signature_in_creation(
                    &subnet_nodes,
                    env.newest_registry_version,
                    &mut idkg_payload.uid_generator,
                    key_id.clone(),
                    &mut idkg_payload.pre_signatures_in_creation,
                );

                // Add a pre-signatures in creation with some progress
                let config_ref = &pre_signatures::test_utils::create_new_pre_signature_in_creation(
                    &subnet_nodes,
                    env.newest_registry_version,
                    &mut idkg_payload.uid_generator,
                    key_id.clone(),
                    &mut idkg_payload.pre_signatures_in_creation,
                )[0];
                let transcript = env.nodes.run_idkg_and_create_and_verify_transcript(
                    &config_ref.translate(&block_reader).unwrap(),
                    &mut rng,
                );
                transcript_builder.add_transcript(config_ref.transcript_id, transcript.clone());
                idkg_payload
                    .idkg_transcripts
                    .insert(config_ref.transcript_id, transcript);
                let parent_block_height = Height::new(15);
                let result = pre_signatures::update_pre_signatures_in_creation(
                    &mut idkg_payload,
                    &transcript_builder,
                    parent_block_height,
                    &no_op_logger(),
                )
                .unwrap();
                assert_eq!(result.len(), 1);
                for pre_signature in idkg_payload.pre_signatures_in_creation.values() {
                    add_expected_transcripts(pre_signature.get_refs());
                }
                for pre_signature in idkg_payload.available_pre_signatures.values() {
                    add_expected_transcripts(pre_signature.get_refs());
                }

                let mut data_payload = idkg_payload.clone();
                data_payload.single_key_transcript_mut().next_in_creation =
                    idkg::KeyTranscriptCreation::Created(key_transcript_ref);
                let parent_block_payload = BlockPayload::Data(DataPayload {
                    batch: BatchPayload::default(),
                    dealings: Dealings::new_empty(summary_height),
                    idkg: Some(data_payload),
                });
                let parent_block = add_block(
                    parent_block_payload,
                    parent_block_height.get() - payload_height_1.get(),
                    &mut pool,
                );
                let pool_reader = PoolReader::new(&pool);

                // Add a summary block after the payload block
                let new_summary_height = parent_block_height.increment();
                let mut summary = idkg_payload.clone();
                summary.single_key_transcript_mut().current = Some(current_key_transcript);
                summary.single_key_transcript_mut().next_in_creation =
                    idkg::KeyTranscriptCreation::Begin;
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
                for pre_signature in summary.available_pre_signatures.values() {
                    assert_eq!(pre_signature.key_id(), key_id);
                    for transcript_ref in pre_signature.get_refs() {
                        assert_ne!(transcript_ref.height, new_summary_height);
                    }
                }
                for pre_signature in summary.pre_signatures_in_creation.values() {
                    assert_eq!(pre_signature.key_id(), key_id);
                    for transcript_ref in pre_signature.get_refs() {
                        assert_ne!(transcript_ref.height, new_summary_height);
                    }
                }
                for (request, reshare_params) in &summary.ongoing_xnet_reshares {
                    assert_eq!(request.key_id(), key_id);
                    assert_eq!(
                        reshare_params.as_ref().algorithm_id,
                        algorithm_for_key_id(&key_id)
                    );
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
                for pre_signature in summary.available_pre_signatures.values() {
                    assert_eq!(pre_signature.key_id(), key_id);
                    for transcript_ref in pre_signature.get_refs() {
                        assert_eq!(transcript_ref.height, new_summary_height);
                    }
                }
                for pre_signature in summary.pre_signatures_in_creation.values() {
                    assert_eq!(pre_signature.key_id(), key_id);
                    for transcript_ref in pre_signature.get_refs() {
                        assert_eq!(transcript_ref.height, new_summary_height);
                    }
                }
                for (request, reshare_params) in &summary.ongoing_xnet_reshares {
                    assert_eq!(request.key_id(), key_id);
                    assert_eq!(
                        reshare_params.as_ref().algorithm_id,
                        algorithm_for_key_id(&key_id)
                    );
                    for transcript_ref in reshare_params.as_ref().get_refs() {
                        assert_eq!(transcript_ref.height, new_summary_height);
                    }
                }

                // Verify that all the transcript references in the parent block
                // have been resolved/copied into the summary block
                assert_eq!(summary.idkg_transcripts.len(), expected_transcripts.len());
                for (id, transcript) in &summary.idkg_transcripts {
                    assert_eq!(transcript.algorithm_id, algorithm_for_key_id(&key_id));
                    assert!(expected_transcripts.contains(id));
                }
            },
        )
    }

    #[test]
    fn test_summary_proto_conversion_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_summary_proto_conversion(key_id);
        }
    }

    fn test_summary_proto_conversion(key_id: MasterPublicKeyId) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                let mut rng = reproducible_rng();
                let Dependencies { mut pool, .. } = dependencies(pool_config, 1);
                let subnet_id = subnet_test_id(1);
                let transcript_builder = TestIDkgTranscriptBuilder::new();
                // Create a summary block with transcripts
                let summary_height = Height::new(5);
                let env = CanisterThresholdSigTestEnvironment::new(4, &mut rng);
                let subnet_nodes: Vec<_> = env.nodes.ids();
                let (key_transcript, key_transcript_ref, current_key_transcript) =
                    generate_key_transcript(&key_id, &env, &mut rng, summary_height);
                let (reshare_key_transcript, reshare_key_transcript_ref, _) =
                    generate_key_transcript(&key_id, &env, &mut rng, summary_height);
                let reshare_params_1 = idkg::ReshareOfUnmaskedParams::new(
                    create_transcript_id(1001),
                    BTreeSet::new(),
                    RegistryVersion::from(1001),
                    &reshare_key_transcript,
                    reshare_key_transcript_ref,
                );
                let mut reshare_refs = BTreeMap::new();
                reshare_refs.insert(*reshare_key_transcript_ref.as_ref(), reshare_key_transcript);

                let inputs_1 = create_sig_inputs_with_height(91, summary_height, key_id.clone());
                let inputs_2 = create_sig_inputs_with_height(92, summary_height, key_id.clone());
                let summary_block = create_summary_block_with_transcripts(
                    key_id.clone(),
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

                let presig_1 = inputs_2.sig_inputs_ref.pre_signature();

                // Create payload blocks with transcripts
                let payload_height_1 = Height::new(10);
                let inputs_1 = create_sig_inputs_with_height(93, payload_height_1, key_id.clone());
                let inputs_2 = create_sig_inputs_with_height(94, payload_height_1, key_id.clone());
                let (reshare_key_transcript, reshare_key_transcript_ref, _) =
                    generate_key_transcript(&key_id, &env, &mut rng, payload_height_1);
                let mut reshare_refs = BTreeMap::new();
                reshare_refs.insert(*reshare_key_transcript_ref.as_ref(), reshare_key_transcript);
                let payload_block_1 = create_payload_block_with_transcripts(
                    key_id.clone(),
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

                let presig_2 = inputs_2.sig_inputs_ref.pre_signature();

                // Create a payload block with references to these past blocks
                let mut idkg_payload =
                    empty_idkg_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
                let uid_generator = &mut idkg_payload.uid_generator;
                let pre_sig_id_1 = uid_generator.next_pre_signature_id();
                let pre_sig_id_2 = uid_generator.next_pre_signature_id();
                idkg_payload.single_key_transcript_mut().current =
                    Some(current_key_transcript.clone());
                idkg_payload
                    .available_pre_signatures
                    .insert(pre_sig_id_1, presig_1);
                idkg_payload
                    .available_pre_signatures
                    .insert(pre_sig_id_2, presig_2);

                let req_1 = create_reshare_request(key_id.clone(), 1, 1);
                idkg_payload
                    .ongoing_xnet_reshares
                    .insert(req_1, reshare_params_1);
                let req_2 = create_reshare_request(key_id.clone(), 2, 2);
                idkg_payload.xnet_reshare_agreements.insert(
                    req_2,
                    idkg::CompletedReshareRequest::Unreported(empty_response()),
                );

                let block_reader = TestIDkgBlockReader::new();
                // Add a pre-signature in creation without progress
                pre_signatures::test_utils::create_new_pre_signature_in_creation(
                    &subnet_nodes,
                    env.newest_registry_version,
                    &mut idkg_payload.uid_generator,
                    key_id.clone(),
                    &mut idkg_payload.pre_signatures_in_creation,
                );

                // Add a pre-signature in creation with some progress
                let config_ref = &pre_signatures::test_utils::create_new_pre_signature_in_creation(
                    &subnet_nodes,
                    env.newest_registry_version,
                    &mut idkg_payload.uid_generator,
                    key_id.clone(),
                    &mut idkg_payload.pre_signatures_in_creation,
                )[0];
                let transcript = env.nodes.run_idkg_and_create_and_verify_transcript(
                    &config_ref.translate(&block_reader).unwrap(),
                    &mut rng,
                );
                transcript_builder.add_transcript(config_ref.transcript_id, transcript.clone());
                idkg_payload
                    .idkg_transcripts
                    .insert(config_ref.transcript_id, transcript);
                let parent_block_height = Height::new(15);
                let result = pre_signatures::update_pre_signatures_in_creation(
                    &mut idkg_payload,
                    &transcript_builder,
                    parent_block_height,
                    &no_op_logger(),
                )
                .unwrap();
                assert_eq!(result.len(), 1);

                idkg_payload
                    .signature_agreements
                    .insert([2; 32], idkg::CompletedSignature::ReportedToExecution);
                idkg_payload.signature_agreements.insert(
                    [3; 32],
                    idkg::CompletedSignature::Unreported(empty_response()),
                );
                idkg_payload.xnet_reshare_agreements.insert(
                    create_reshare_request(key_id, 6, 6),
                    idkg::CompletedReshareRequest::ReportedToExecution,
                );

                let mut data_payload = idkg_payload.clone();
                data_payload.single_key_transcript_mut().next_in_creation =
                    idkg::KeyTranscriptCreation::Begin;
                let parent_block_payload = BlockPayload::Data(DataPayload {
                    batch: BatchPayload::default(),
                    dealings: Dealings::new_empty(summary_height),
                    idkg: Some(data_payload),
                });
                let parent_block = add_block(
                    parent_block_payload,
                    parent_block_height.get() - payload_height_1.get(),
                    &mut pool,
                );
                assert_proposal_conversion(parent_block.clone());

                let pool_reader = PoolReader::new(&pool);

                // Add a summary block after the payload block and update the refs
                let mut summary = idkg_payload.clone();
                summary.single_key_transcript_mut().current = Some(current_key_transcript);
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
                            idkg::CompletedSignature::ReportedToExecution => {
                                reported += 1;
                            }
                            idkg::CompletedSignature::Unreported(_) => {
                                unreported += 1;
                            }
                        }
                    }
                    (reported, unreported)
                };
                assert!(!summary.signature_agreements.is_empty());
                assert!(reported > 0);
                assert!(unreported > 0);
                assert!(!summary.available_pre_signatures.is_empty());
                assert!(!summary.pre_signatures_in_creation.is_empty());
                assert!(!summary.idkg_transcripts.is_empty());
                assert!(!summary.ongoing_xnet_reshares.is_empty());
                let (reported, unreported) = {
                    let mut reported = 0;
                    let mut unreported = 0;
                    for agreement in summary.xnet_reshare_agreements.values() {
                        match agreement {
                            idkg::CompletedReshareRequest::ReportedToExecution => {
                                reported += 1;
                            }
                            idkg::CompletedReshareRequest::Unreported(_) => {
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
                    idkg: Some(summary.clone()),
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
                let mut summary_proto: pb::IDkgPayload = (&summary).into();
                let summary_from_proto: IDkgPayload =
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
                let summary_from_proto: idkg::IDkgPayload =
                    (&summary_proto, new_summary_height).try_into().unwrap();
                // Make sure the previous RequestId record can be retrieved by its pseudo_random_id.
                assert!(summary_from_proto
                    .signature_agreements
                    .contains_key(&[4; 32]));
            },
        )
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
        key_id: &MasterPublicKeyId,
        rng: &mut ReproducibleRng,
        height: Height,
    ) -> (
        IDkgTranscript,
        UnmaskedTranscript,
        UnmaskedTranscriptWithAttributes,
    ) {
        let env = CanisterThresholdSigTestEnvironment::new(4, rng);
        generate_key_transcript(key_id, &env, rng, height)
    }

    #[test]
    fn test_no_creation_after_successful_creation_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_no_creation_after_successful_creation(key_id);
        }
    }

    fn test_no_creation_after_successful_creation(key_id: MasterPublicKeyId) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                let mut rng = reproducible_rng();
                let Dependencies {
                    registry,
                    registry_data_provider,
                    ..
                } = dependencies(pool_config, 1);
                let subnet_id = subnet_test_id(1);
                let mut block_reader = TestIDkgBlockReader::new();

                // Create two key transcripts
                let (mut key_transcript, mut key_transcript_ref, mut current_key_transcript) =
                    create_key_transcript_and_refs(&key_id, &mut rng, Height::from(1));
                let (
                    mut reshare_key_transcript,
                    mut reshare_key_transcript_ref,
                    mut next_key_transcript,
                ) = create_key_transcript_and_refs(&key_id, &mut rng, Height::from(1));

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
                let key_transcript = idkg::MasterKeyTranscript {
                    current: Some(current_key_transcript.clone()),
                    next_in_creation: idkg::KeyTranscriptCreation::Created(
                        current_key_transcript.unmasked_transcript(),
                    ),
                    master_key_id: key_id.clone(),
                };

                // Initial bootstrap payload should be created successfully
                let mut payload_0 =
                    make_bootstrap_summary(subnet_id, vec![key_id.clone()], Height::from(0))
                        .unwrap();
                *payload_0.single_key_transcript_mut() = key_transcript;

                // A new summary payload should be created successfully, with next_in_creation
                // set to Begin (membership changed).
                let payload_1 = create_summary_payload_helper(
                    subnet_id,
                    &[key_id.clone()],
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
                    idkg::KeyTranscriptCreation::Begin
                );

                // Simulate successful creation of the next key transcript
                let key_transcript = idkg::MasterKeyTranscript {
                    current: Some(current_key_transcript.clone()),
                    next_in_creation: idkg::KeyTranscriptCreation::Created(
                        next_key_transcript.unmasked_transcript(),
                    ),
                    master_key_id: key_id.clone(),
                };

                let mut payload_2 = payload_1.clone();
                *payload_2.single_key_transcript_mut() = key_transcript;

                block_reader
                    .add_transcript(*reshare_key_transcript_ref.as_ref(), reshare_key_transcript);

                // After the next key transcript was created, it should be carried over into the next payload.
                let expected = idkg::MasterKeyTranscript {
                    current: Some(next_key_transcript.clone()),
                    next_in_creation: idkg::KeyTranscriptCreation::Created(
                        next_key_transcript.unmasked_transcript(),
                    ),
                    master_key_id: key_id.clone(),
                };

                let payload_3 = create_summary_payload_helper(
                    subnet_id,
                    &[key_id.clone()],
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
            },
        )
    }

    #[test]
    fn test_incomplete_reshare_doesnt_purge_pre_signatures_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_incomplete_reshare_doesnt_purge_pre_signatures(key_id);
        }
    }

    fn test_incomplete_reshare_doesnt_purge_pre_signatures(key_id: MasterPublicKeyId) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                let mut rng = reproducible_rng();
                let Dependencies {
                    registry,
                    registry_data_provider,
                    ..
                } = dependencies(pool_config, 1);
                let subnet_id = subnet_test_id(1);
                let mut valid_keys = BTreeSet::new();
                valid_keys.insert(key_id.clone());
                let mut block_reader = TestIDkgBlockReader::new();

                // Create a key transcript
                let env = CanisterThresholdSigTestEnvironment::new(4, &mut rng);
                let (dealers, receivers) = env.choose_dealers_and_receivers(
                    &IDkgParticipants::AllNodesAsDealersAndReceivers,
                    &mut rng,
                );
                let (key_transcript, key_transcript_ref, current_key_transcript) =
                    generate_key_transcript(&key_id, &env, &mut rng, Height::new(0));
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
                let key_transcripts = idkg::MasterKeyTranscript {
                    current: Some(current_key_transcript.clone()),
                    next_in_creation: idkg::KeyTranscriptCreation::Created(
                        current_key_transcript.unmasked_transcript(),
                    ),
                    master_key_id: key_id.clone(),
                };

                let mut payload_0 =
                    make_bootstrap_summary(subnet_id, vec![key_id.clone()], Height::from(0))
                        .unwrap();
                *payload_0.single_key_transcript_mut() = key_transcripts;

                // Add some pre-signatures and xnet reshares
                let derivation_path = ExtendedDerivationPath {
                    caller: user_test_id(1).get(),
                    derivation_path: vec![],
                };
                let algorithm = algorithm_for_key_id(&key_id);
                let test_inputs = match key_id {
                    MasterPublicKeyId::Ecdsa(_) => {
                        TestSigInputs::from(&generate_tecdsa_protocol_inputs(
                            &env,
                            &dealers,
                            &receivers,
                            &key_transcript,
                            &[0; 32],
                            Randomness::from([0; 32]),
                            &derivation_path,
                            algorithm,
                            &mut rng,
                        ))
                    }
                    MasterPublicKeyId::Schnorr(_) => {
                        TestSigInputs::from(&generate_tschnorr_protocol_inputs(
                            &env,
                            &dealers,
                            &receivers,
                            &key_transcript,
                            &[1; 64],
                            Randomness::from([0; 32]),
                            &derivation_path,
                            algorithm,
                            &mut rng,
                        ))
                    }
                };
                payload_0.available_pre_signatures.insert(
                    payload_0.uid_generator.next_pre_signature_id(),
                    test_inputs.sig_inputs_ref.pre_signature(),
                );
                for (transcript_ref, transcript) in test_inputs.idkg_transcripts {
                    block_reader.add_transcript(transcript_ref, transcript);
                }
                pre_signatures::test_utils::create_new_pre_signature_in_creation(
                    &env.nodes.ids::<Vec<_>>(),
                    env.newest_registry_version,
                    &mut payload_0.uid_generator,
                    key_id.clone(),
                    &mut payload_0.pre_signatures_in_creation,
                );
                payload_0.ongoing_xnet_reshares.insert(
                    create_reshare_request(key_id.clone(), 1, 1),
                    ReshareOfUnmaskedParams::new(
                        key_transcript.transcript_id,
                        BTreeSet::new(),
                        RegistryVersion::from(0),
                        &current_key_transcript.to_attributes(),
                        key_transcript_ref,
                    ),
                );
                let metrics = IDkgPayloadMetrics::new(MetricsRegistry::new());

                // A new summary payload should be created successfully, with next_in_creation
                // set to Begin (membership changed).
                let payload_1 = create_summary_payload_helper(
                    subnet_id,
                    &[key_id.clone()],
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
                    idkg::KeyTranscriptCreation::Begin
                );
                // Critical error counter should be set to 0
                assert_eq!(
                    metrics.critical_error_master_key_transcript_missing.get(),
                    0
                );
                // pre-signatures and xnet reshares should still be unchanged:
                assert_eq!(
                    payload_0.available_pre_signatures.len(),
                    payload_1.available_pre_signatures.len()
                );
                assert_eq!(
                    payload_0.pre_signatures_in_creation.len(),
                    payload_1.pre_signatures_in_creation.len()
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
                    &[key_id.clone()],
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
                    idkg::KeyTranscriptCreation::Begin
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
                assert_eq!(
                    metrics.critical_error_master_key_transcript_missing.get(),
                    1
                );
                // pre-signatures and xnet reshares should still be unchanged:
                assert_eq!(
                    payload_2.available_pre_signatures.len(),
                    payload_1.available_pre_signatures.len()
                );
                assert_eq!(
                    payload_2.pre_signatures_in_creation.len(),
                    payload_1.pre_signatures_in_creation.len()
                );
                assert_eq!(
                    payload_2.ongoing_xnet_reshares.len(),
                    payload_1.ongoing_xnet_reshares.len()
                );

                let (transcript, transcript_ref, next_key_transcript) =
                    create_key_transcript_and_refs(&key_id, &mut rng, Height::from(1));
                block_reader.add_transcript(*transcript_ref.as_ref(), transcript);
                for (id, transcript) in payload_2.idkg_transcripts.clone() {
                    block_reader.add_transcript(TranscriptRef::new(Height::from(2), id), transcript)
                }

                // Simulate successful key trancript creation
                let mut key_transcript = payload_2.single_key_transcript().clone();
                key_transcript.next_in_creation =
                    idkg::KeyTranscriptCreation::Created(transcript_ref);
                let mut payload_3 = payload_2.clone();
                *payload_3.single_key_transcript_mut() = key_transcript.clone();

                let payload_4 = create_summary_payload_helper(
                    subnet_id,
                    &[key_id.clone()],
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
                    idkg::KeyTranscriptCreation::Created(_)
                );

                // Critical error counter should still be set to 1
                assert_eq!(
                    metrics.critical_error_master_key_transcript_missing.get(),
                    1
                );

                // Now, pre-signatures and xnet reshares should be purged
                assert!(payload_4.pre_signatures_in_creation.is_empty());
                assert!(payload_4.ongoing_xnet_reshares.is_empty());
                // Available pre-signatures cannot be purged yet,
                // as we don't know if they are matched to ongoing signature requests.
                assert_eq!(
                    payload_4.available_pre_signatures.len(),
                    payload_3.available_pre_signatures.len()
                );
                assert!(!payload_4.available_pre_signatures.is_empty());

                let transcript_builder = TestIDkgTranscriptBuilder::new();
                let signature_builder = TestThresholdSignatureBuilder::new();
                let chain_key_config = ChainKeyConfig {
                    key_configs: vec![KeyConfig {
                        key_id: key_id.clone(),
                        pre_signatures_to_create_in_advance: 1,
                        max_queue_size: 1,
                    }],
                    signature_request_timeout_ns: Some(100000),
                    ..ChainKeyConfig::default()
                };

                // Create a data payload following the summary making the key change
                let mut payload_5 = payload_4.clone();
                create_data_payload_helper_2(
                    &mut payload_5,
                    Height::from(3),
                    UNIX_EPOCH,
                    &chain_key_config,
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
                // pre-signatures still cannot be deleted, as we haven't seen the state
                // at the summary height yet
                assert_eq!(
                    payload_4.available_pre_signatures.len(),
                    payload_5.available_pre_signatures.len()
                );

                // Create another data payload, this time the referenced certified height
                // reached the last summary height.
                let mut payload_6 = payload_5.clone();
                create_data_payload_helper_2(
                    &mut payload_6,
                    Height::from(4),
                    UNIX_EPOCH,
                    &chain_key_config,
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
                // Now, available pre-signatures referencing the old key transcript are deleted.
                assert!(payload_6.available_pre_signatures.is_empty());
            },
        )
    }

    #[test]
    fn test_if_next_in_creation_continues_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_if_next_in_creation_continues(key_id);
        }
    }

    fn test_if_next_in_creation_continues(key_id: MasterPublicKeyId) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
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
                valid_keys.insert(key_id.clone());
                let block_reader = TestIDkgBlockReader::new();
                let transcript_builder = TestIDkgTranscriptBuilder::new();
                let signature_builder = TestThresholdSignatureBuilder::new();
                let chain_key_config = ChainKeyConfig {
                    key_configs: vec![KeyConfig {
                        key_id: key_id.clone(),
                        pre_signatures_to_create_in_advance: 1,
                        max_queue_size: 1,
                    }],
                    signature_request_timeout_ns: Some(100000),
                    ..ChainKeyConfig::default()
                };

                // Step 1: initial bootstrap payload should be created successfully
                let payload_0 =
                    make_bootstrap_summary(subnet_id, vec![key_id.clone()], Height::from(0));
                assert!(payload_0.is_some());
                let payload_0 = payload_0.unwrap();

                // Step 2: a summary payload should be created successfully, with next_in_creation
                // set to Begin.
                let payload_1 = create_summary_payload_helper(
                    subnet_id,
                    &[key_id.clone()],
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
                    idkg::KeyTranscriptCreation::Begin
                );

                // Step 3: a data payload be created successfully
                let mut payload_2 = payload_1;
                let result = create_data_payload_helper_2(
                    &mut payload_2,
                    Height::from(2),
                    UNIX_EPOCH,
                    &chain_key_config,
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
                    idkg::KeyTranscriptCreation::RandomTranscriptParams(_)
                );

                // Step 4: the summary payload should be created successfully, carrying forward
                // unfinished next_in_creation
                let payload_3 = create_summary_payload_helper(
                    subnet_id,
                    &[key_id.clone()],
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
                    idkg::KeyTranscriptCreation::RandomTranscriptParams(_)
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
                    &[key_id.clone()],
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
                    idkg::KeyTranscriptCreation::RandomTranscriptParams(_)
                );
            },
        )
    }

    #[test]
    fn test_next_in_creation_with_initial_dealings_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_next_in_creation_with_initial_dealings(key_id);
        }
    }

    fn test_next_in_creation_with_initial_dealings(key_id: MasterPublicKeyId) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
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
                valid_keys.insert(key_id.clone());
                let mut block_reader = TestIDkgBlockReader::new();
                let transcript_builder = TestIDkgTranscriptBuilder::new();
                let signature_builder = TestThresholdSignatureBuilder::new();
                let chain_key_config = ChainKeyConfig {
                    key_configs: vec![KeyConfig {
                        key_id: key_id.clone(),
                        pre_signatures_to_create_in_advance: 1,
                        max_queue_size: 1,
                    }],
                    signature_request_timeout_ns: Some(100000),
                    ..ChainKeyConfig::default()
                };

                // Generate initial dealings
                let initial_dealings =
                    dummy_initial_idkg_dealing_for_tests(algorithm_for_key_id(&key_id), &mut rng);
                let init_tid = initial_dealings.params().transcript_id();

                // Step 1: initial bootstrap payload should be created successfully
                let payload_0 = make_bootstrap_summary_with_initial_dealings(
                    subnet_id,
                    Height::from(0),
                    BTreeMap::from([(key_id.clone(), initial_dealings)]),
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
                    &[key_id.clone()],
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
                    idkg::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((ref init, ref params))
                    if init.params().transcript_id() == init_tid && params.as_ref().transcript_id == init_tid
                );

                // Step 3: a data payload be created successfully
                let mut payload_2 = payload_1;
                let result = create_data_payload_helper_2(
                    &mut payload_2,
                    Height::from(2),
                    UNIX_EPOCH,
                    &chain_key_config,
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
                    idkg::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((ref init, ref params))
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
                    &chain_key_config,
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
                    idkg::KeyTranscriptCreation::Created(ref unmasked)
                    if unmasked.as_ref().transcript_id == transcript.transcript_id
                );
                assert!(payload_3.single_key_transcript().current.is_none());

                // Step 6: a data payload with existing current key should be created successfully
                let mut payload_4 = payload_3.clone();
                let result = create_data_payload_helper_2(
                    &mut payload_4,
                    Height::from(3),
                    UNIX_EPOCH,
                    &chain_key_config,
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
                    &[key_id.clone()],
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
                    idkg::KeyTranscriptCreation::Created(ref unmasked)
                    if unmasked.as_ref().transcript_id == transcript.transcript_id
                );
                let refs = payload_5.single_key_transcript().get_refs();
                assert_eq!(refs.len(), 2);
                assert_eq!(refs[0], refs[1]);

                // Step 8: the summary payload with created key, based on payload_4
                // should be created successfully
                let payload_6 = create_summary_payload_helper(
                    subnet_id,
                    &[key_id.clone()],
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
                    idkg::KeyTranscriptCreation::Created(ref unmasked)
                    if unmasked.as_ref().transcript_id == transcript.transcript_id
                );
                assert!(payload_6.single_key_transcript().current.is_some());
                let refs = payload_6.single_key_transcript().get_refs();
                assert_eq!(refs.len(), 2);
                assert_eq!(refs[0], refs[1]);

                // Step 9: the summary payload with a created key & a new key initialization,
                // based on payload_4 should be created successfully
                let key_id_2 = key_id_with_name(&key_id, "some_other_key");
                let payload_7 = create_summary_payload_helper(
                    subnet_id,
                    &[key_id.clone(), key_id_2.clone()],
                    registry.as_ref(),
                    &block_reader,
                    Height::from(5),
                    registry_version,
                    registry_version,
                    &payload_4,
                    None,
                    &no_op_logger(),
                );
                assert_matches!(payload_7, Ok(Some(_)));
                let payload_7 = payload_7.unwrap().unwrap();
                // next_in_creation should be equal to current
                assert_matches!(
                    payload_7.key_transcripts.get(&key_id).expect("Should still have the pre-existing key_Id").next_in_creation,
                    idkg::KeyTranscriptCreation::Created(ref unmasked)
                    if unmasked.as_ref().transcript_id == transcript.transcript_id
                );
                assert_matches!(
                    payload_7
                        .key_transcripts
                        .get(&key_id_2)
                        .expect("Should have the new key_id")
                        .next_in_creation,
                    idkg::KeyTranscriptCreation::Begin
                );
            },
        )
    }
}
