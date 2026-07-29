use crate::{
    MAX_REMOTE_DKGS_PER_INTERVAL, MAX_REMOTE_TRANSCRIPTS_PER_PAYLOAD,
    metrics::{DkgPayloadMetrics, DkgPayloadMetricsOptionExt},
    remote::{
        ConfigResult, build_callback_id_config_map, get_updated_remote_dkg_attempts, merge_configs,
    },
    utils::{self, tags_iter, vetkd_key_ids_for_subnet},
};
use ic_consensus_utils::{crypto::ConsensusCrypto, pool_reader::PoolReader};
use ic_interfaces::{
    crypto::{ErrorReproducibility, NiDkgAlgorithm},
    dkg::DkgPool,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{ReplicaLogger, error, info, warn};
use ic_protobuf::registry::subnet::v1::{
    CatchUpPackageContents, chain_key_initialization::Initialization,
};
use ic_registry_client_helpers::{
    crypto::initial_ni_dkg_transcript_from_registry_record, subnet::SubnetRegistry,
};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    Height, NodeId, NumberOfNodes, RegistryVersion, SubnetId,
    batch::ValidationContext,
    consensus::{
        Block,
        dkg::{
            DkgDataPayload, DkgPayload, DkgPayloadCreationError, DkgSummary, Message,
            RemoteTranscriptResult,
        },
        get_faults_tolerated,
    },
    crypto::threshold_sig::ni_dkg::{
        NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
        NiDkgTranscript,
        config::{NiDkgConfig, NiDkgConfigData, errors::NiDkgConfigValidationError},
    },
    messages::CallbackId,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::{Arc, RwLock},
};

/// Creates the DKG payload for a new block proposal with the given parent. If
/// the new height corresponds to a new DKG start interval, creates a summary,
/// otherwise it creates a payload containing new dealings for the current
/// interval.
#[allow(clippy::too_many_arguments)]
pub fn create_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    dkg_pool: Arc<RwLock<dyn DkgPool>>,
    parent: &Block,
    state_reader: &dyn StateReader<State = ReplicatedState>,
    validation_context: &ValidationContext,
    logger: ReplicaLogger,
    max_dealings_per_block: usize,
    dkg_payload_metrics: Option<&DkgPayloadMetrics>,
) -> Result<DkgPayload, DkgPayloadCreationError> {
    let height = parent.height.increment();
    // Get the last summary from the chain.
    let last_summary_block = pool_reader
        .dkg_summary_block(parent)
        .ok_or(DkgPayloadCreationError::MissingDkgStartBlock)?;
    let last_dkg_summary = &last_summary_block.payload.as_ref().as_summary().dkg;

    if last_dkg_summary.get_next_start_height() == height {
        // Since `height` corresponds to the start of a new DKG interval, we create a
        // new summary.
        create_summary_payload(
            subnet_id,
            registry_client,
            crypto,
            pool_reader,
            last_dkg_summary,
            parent,
            last_summary_block.context.registry_version,
            state_reader,
            validation_context,
            logger,
            dkg_payload_metrics,
        )
        .map(DkgPayload::Summary)
    } else {
        // If the height is not a start height, create a payload with new dealings,
        // and possibly remote transcripts.
        create_data_payload(
            subnet_id,
            registry_client,
            pool_reader,
            dkg_pool,
            parent,
            max_dealings_per_block,
            &last_summary_block,
            last_dkg_summary,
            crypto,
            state_reader,
            validation_context,
            logger,
            dkg_payload_metrics,
        )
        .map(DkgPayload::Data)
    }
}

#[allow(clippy::too_many_arguments)]
fn create_data_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    pool_reader: &PoolReader<'_>,
    dkg_pool: Arc<RwLock<dyn DkgPool>>,
    parent: &Block,
    max_dealings_per_block: usize,
    last_summary_block: &Block,
    last_dkg_summary: &DkgSummary,
    crypto: &dyn ConsensusCrypto,
    state_reader: &dyn StateReader<State = ReplicatedState>,
    validation_context: &ValidationContext,
    logger: ReplicaLogger,
    dkg_payload_metrics: Option<&DkgPayloadMetrics>,
) -> Result<DkgDataPayload, DkgPayloadCreationError> {
    let _timer = dkg_payload_metrics.payload_creation_timer("data");

    // Get all existing dealer ids from the chain.
    let dealers_from_chain = utils::get_dealers_from_chain(pool_reader, parent);

    // Determine all current configs.
    let state = state_reader
        .get_state_at(validation_context.certified_height)
        .map_err(DkgPayloadCreationError::StateManagerError)?;
    let remote_config_results = build_callback_id_config_map(
        subnet_id,
        registry_client,
        state.get_ref(),
        validation_context.registry_version,
        last_dkg_summary,
        &logger,
    )?;
    let configs = merge_configs(&last_dkg_summary.configs, &remote_config_results);

    // Select new dealings for the payload.
    let new_validated_dealings = select_dealings_for_payload(
        &configs,
        &dealers_from_chain,
        &*dkg_pool
            .read()
            .expect("Couldn't lock DKG pool for reading."),
        max_dealings_per_block,
    );

    let remote_dkg_transcripts = create_remote_transcripts(
        pool_reader,
        crypto,
        parent,
        remote_config_results,
        &logger,
        dkg_payload_metrics,
    )?;

    if !remote_dkg_transcripts.is_empty() {
        info!(
            logger,
            "Including {} remote DKG transcripts in data block payload at height {}",
            remote_dkg_transcripts.len(),
            parent.height.increment(),
        );
    }

    Ok(DkgDataPayload::new_with_remote_dkg_transcripts(
        last_summary_block.height,
        new_validated_dealings,
        remote_dkg_transcripts,
    ))
}

pub(crate) fn create_remote_transcripts(
    pool_reader: &PoolReader<'_>,
    crypto: &dyn ConsensusCrypto,
    parent: &Block,
    callback_id_map: BTreeMap<CallbackId, ConfigResult>,
    logger: &ReplicaLogger,
    dkg_payload_metrics: Option<&DkgPayloadMetrics>,
) -> Result<Vec<RemoteTranscriptResult>, DkgPayloadCreationError> {
    //  Since this function is relatively expensive, we simply return if there are no outstanding DKG contexts
    if callback_id_map.is_empty() {
        return Ok(vec![]);
    }

    // Get all dealings for DKGs that have not been completed yet
    let (mut all_dealings, completed_dkgs) = utils::get_dkg_dealings(pool_reader, parent);

    // Try to create transcripts for all configs of each target_id. Note that we either include
    // all transcript results for a target_id or none of them.
    let mut selected_transcripts = vec![];
    for (callback_id, config_results) in callback_id_map.into_iter() {
        let configs = match config_results {
            Ok(configs) => configs,
            Err(errs) => {
                // Skip requests for which we already have a transcript result on chain.
                if errs
                    .iter()
                    .any(|(dkg_id, _)| completed_dkgs.contains(dkg_id))
                {
                    continue;
                }
                // Skip requests that would exceed the maximum number of remote transcripts.
                if selected_transcripts.len() + errs.len() > MAX_REMOTE_TRANSCRIPTS_PER_PAYLOAD {
                    continue;
                }
                // Reject contexts for which we failed to create configs.
                for (dkg_id, err) in errs {
                    dkg_payload_metrics.payload_errors_inc("remote_config_creation_failed");
                    error!(
                        logger,
                        "Failed to create remote transcript config for dkg id {:?} at height {}: {}",
                        dkg_id,
                        parent.height.increment(),
                        err
                    );
                    // Including the error in the payload will cause the context to receive
                    // a reject response.
                    selected_transcripts.push(RemoteTranscriptResult::new(
                        dkg_id,
                        callback_id,
                        Err(err),
                    ));
                }
                continue;
            }
        };

        // Ensure that creating these transcripts would not exceed the maximum number of
        // remote transcripts. We continue with the next target_id in case it requires less
        // transcripts.
        if selected_transcripts.len() + configs.len() > MAX_REMOTE_TRANSCRIPTS_PER_PAYLOAD {
            continue;
        }

        // If any of the configs has less dealings than the threshold, we skip this target_id
        if configs.iter().any(|config: &NiDkgConfig| {
            let dealings_count = all_dealings
                .get(config.dkg_id())
                .map_or(0, |dealings| dealings.len());
            dealings_count < config.collection_threshold().get() as usize
        }) {
            continue;
        }

        // For each config, try to build the necessary [`RemoteTranscriptResult`].
        for config in configs.iter() {
            let dealings = all_dealings.remove(config.dkg_id()).unwrap_or_else(|| {
                dkg_payload_metrics
                    .payload_errors_inc("remote_dealings_missing_after_capacity_check");
                error!(
                    logger,
                    "We checked that all configs have enough dealings above. This is a bug."
                );
                // Just in case, return an empty map of dealings to make the next call to
                // `create_transcript` fail with a reproducible error for not having enough
                // dealings. This will send back a reject response to the canister.
                BTreeMap::new()
            });
            // Generate the transcript. We need to retry transient errors, as a payload containing
            // transient errors may not be verifiable by peers.
            let result = match NiDkgAlgorithm::create_transcript(crypto, config, dealings) {
                Ok(transcript) => Ok(transcript),
                // Note that we handled the reproducible error case of not having enough dealings
                // already beforehand.
                Err(err) if err.is_reproducible() => {
                    dkg_payload_metrics.payload_errors_inc("remote_transcript_reproducible_error");
                    // Including the error in the payload will cause the context to receive
                    // a reject response.
                    let error_message = format!(
                        "Failed to create remote transcript for dkg id {:?} at height {}: {}",
                        config.dkg_id(),
                        parent.height.increment(),
                        err
                    );
                    error!(logger, "{error_message}");
                    Err(error_message)
                }
                Err(err) => {
                    dkg_payload_metrics.payload_errors_inc("remote_transcript_transient_error");
                    // Return on transient crypto errors
                    return Err(DkgPayloadCreationError::DkgCreateTranscriptError(err));
                }
            };
            selected_transcripts.push(RemoteTranscriptResult::new(
                config.dkg_id().clone(),
                callback_id,
                result,
            ));
        }
    }

    Ok(selected_transcripts)
}

/// Selects dealings from the validated pool to include in a block payload.
///
/// When selecting dealings, the following constraints apply:
/// - A dealing must correspond to an existing config passed to this function.
/// - There are less than `collection_threshold` many dealings for the same config already on chain.
/// - There isn't already a dealing on chain for the same config from the same dealer.
///
/// Since the number of dealings to be included into a single block is limited, the pre-selected
/// dealings are prioritized according to the following (in order of precedence):
/// 1. While there are less than `MAX_REMOTE_DKGS_PER_INTERVAL` completed remote targets, prioritize
///    remote dealings. Otherwise, prioritize local dealings.
/// 2. Among remote targets, prioritize dealings for targets that are closer to their threshold.
/// 3. Use `target_subnet` as a tie-breaker between dealings for targets with the same remaining capacity.
fn select_dealings_for_payload(
    configs: &BTreeMap<&NiDkgId, &NiDkgConfig>,
    dealers_from_chain: &HashSet<(NiDkgId, NodeId)>,
    dkg_pool: &dyn DkgPool,
    max_dealings_per_block: usize,
) -> Vec<Message> {
    // Compute remaining capacity (collection_threshold - dealings on chain) for each config.
    let mut remaining_capacity: BTreeMap<&NiDkgId, usize> = configs
        .iter()
        .map(|(&dkg_id, config)| (dkg_id, config.collection_threshold().get() as usize))
        .collect();
    for (dkg_id, _) in dealers_from_chain {
        if let Some(cap) = remaining_capacity.get_mut(dkg_id) {
            *cap = cap.saturating_sub(1);
        }
    }

    // Compute the total remaining capacity for remote target IDs.
    let mut remaining_remote_target_capacity: BTreeMap<NiDkgTargetId, usize> = BTreeMap::new();
    for (dkg_id, cap) in &remaining_capacity {
        if let NiDkgTargetSubnet::Remote(target_id) = dkg_id.target_subnet {
            remaining_remote_target_capacity
                .entry(target_id)
                .and_modify(|target_cap| *target_cap += *cap)
                .or_insert(*cap);
        }
    }

    // Only select dealings for configs that still have capacity left,
    // and whose dealer has no dealing on chain yet.
    let mut selected_candidates: Vec<_> = dkg_pool
        .get_validated()
        .filter(|msg| {
            let Some(cap) = remaining_capacity.get_mut(&msg.content.dkg_id) else {
                return false;
            };
            if dealers_from_chain.contains(&(msg.content.dkg_id.clone(), msg.signature.signer)) {
                return false;
            }
            if *cap > 0 {
                *cap -= 1;
                true
            } else {
                false
            }
        })
        .collect();

    // If there are less than or equal to the max dealings per block, return all candidates.
    if selected_candidates.len() <= max_dealings_per_block {
        return selected_candidates.into_iter().cloned().collect();
    }

    // Count the number of (completed) remote target IDs with no remaining capacity.
    let remote_target_ids_with_no_capacity = remaining_remote_target_capacity
        .values()
        .filter(|cap| **cap == 0)
        .count();
    // If the number of remote target IDs with no remaining capacity is less than the maximum
    // number of remote DKGs per interval, then we prioritize remote DKGs.
    let prioritize_remote = remote_target_ids_with_no_capacity < MAX_REMOTE_DKGS_PER_INTERVAL;

    // 1. Prioritize remote DKGs first, if requested, otherwise prioritize local DKGs.
    // 2. For remote targets, prioritize dealings for targets that are closer to their threshold.
    // 3. Use the target subnet as a tie-breaker.
    let (prioritized, _, _) =
        selected_candidates.select_nth_unstable_by_key(max_dealings_per_block, |msg| {
            match msg.content.dkg_id.target_subnet {
                NiDkgTargetSubnet::Local => (
                    prioritize_remote,
                    usize::MAX,
                    &msg.content.dkg_id.target_subnet,
                ),
                NiDkgTargetSubnet::Remote(target_id) => (
                    !prioritize_remote,
                    remaining_remote_target_capacity
                        .get(&target_id)
                        .copied()
                        .unwrap_or(usize::MAX),
                    &msg.content.dkg_id.target_subnet,
                ),
            }
        });

    prioritized.iter().map(|&msg| msg.clone()).collect()
}

/// Creates a summary payload for the given parent and registry_version.
///
/// We compute the summary from prev_summary as follows:
/// ```ignore
/// summary.current_transcript =
///   prev_summary.next_transcript.unwrap_or_else(
///      prev_summary.current_transcript
///   )
///
/// // compute transcript from the dealings in the past interval
/// summary.next_transcript = ...;
///
/// summary.configs.high.resharing_transcript =
///   summary.next_transcript.unwrap_or_else(
///      summary.current_transcript
///   )
/// // committee of resharing_transcript reshares to members of
/// // subnet according to proposed stable registry version
/// summary.configs.high = ...;
///
/// // members of subnet according to proposed stable registry
/// // version create low threshold transcript among them
/// summary.configs.low = ...;
/// ```
///
#[allow(clippy::too_many_arguments)]
pub(super) fn create_summary_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    last_summary: &DkgSummary,
    parent: &Block,
    registry_version: RegistryVersion,
    state_reader: &dyn StateReader<State = ReplicatedState>,
    validation_context: &ValidationContext,
    logger: ReplicaLogger,
    dkg_payload_metrics: Option<&DkgPayloadMetrics>,
) -> Result<DkgSummary, DkgPayloadCreationError> {
    let _timer = dkg_payload_metrics.payload_creation_timer("summary");

    let (mut all_dealings, completed_dkgs) = utils::get_dkg_dealings(pool_reader, parent);
    let mut next_transcripts = BTreeMap::new();
    // Try to create transcripts from the last round.
    for (dkg_id, config) in last_summary.configs.iter() {
        if dkg_id.target_subnet.is_remote() {
            // Skip remote DKGs
            continue;
        }
        let dealings = all_dealings.remove(dkg_id).unwrap_or_default();
        match NiDkgAlgorithm::create_transcript(crypto, config, dealings) {
            Ok(transcript) => {
                if next_transcripts
                    .insert(dkg_id.dkg_tag.clone(), transcript)
                    .is_some()
                {
                    panic!(
                        "last summary has multiple configs for tag {:?}",
                        dkg_id.dkg_tag
                    );
                }
            }
            Err(err) if err.is_reproducible() => {
                dkg_payload_metrics.payload_errors_inc("summary_transcript_reproducible_error");
                warn!(
                    logger,
                    "Failed to create transcript for dkg id {:?}: {:?}", dkg_id, err
                );
            }
            Err(err) => {
                dkg_payload_metrics.payload_errors_inc("summary_transcript_transient_error");
                return Err(DkgPayloadCreationError::DkgCreateTranscriptError(err));
            }
        };
    }

    let height = parent.height.increment();

    // Current transcripts come from next transcripts of the last_summary.
    let current_transcripts = as_next_transcripts(last_summary, &logger);

    let vet_key_ids = vetkd_key_ids_for_subnet(
        subnet_id,
        registry_client,
        validation_context.registry_version,
    )?;

    // If the config for the currently computed DKG intervals requires a transcript
    // resharing (currently for high-threshold DKG only), we are going to re-share
    // the next transcripts, as they are the newest ones.
    // If `next_transcripts` does not contain the required transcripts (due to
    // failed DKGs in the past interval) we reshare the current transcripts.
    let reshared_transcripts = tags_iter(&vet_key_ids)
        .filter_map(|tag| {
            let transcript = next_transcripts
                .get(&tag)
                .or_else(|| current_transcripts.get(&tag))
                .map(|transcript| (tag.clone(), transcript.clone()));

            if transcript.is_none() {
                warn!(
                    logger,
                    "Found tag {:?} in summary configs without any current or next transcripts",
                    tag
                );
            }

            transcript
        })
        .collect::<BTreeMap<_, _>>();

    let state = state_reader
        .get_state_at(validation_context.certified_height)
        .map_err(DkgPayloadCreationError::StateManagerError)?;

    let remote_dkg_attempts = get_updated_remote_dkg_attempts(
        last_summary,
        state.get_ref(),
        get_completed_target_ids(&completed_dkgs),
    );

    let interval_length = last_summary.next_interval_length;
    let next_interval_length = get_dkg_interval_length(
        registry_client,
        validation_context.registry_version,
        subnet_id,
    )?;

    // New configs are created using the new stable registry version proposed by this
    // block, which determines receivers of the dealings.
    let local_configs = get_configs_for_local_transcripts(
        subnet_id,
        get_node_list(
            subnet_id,
            registry_client,
            validation_context.registry_version,
        )?,
        height,
        reshared_transcripts,
        validation_context.registry_version,
        &vet_key_ids,
    )?;

    Ok(DkgSummary::new(
        local_configs,
        current_transcripts,
        next_transcripts,
        registry_version,
        interval_length,
        next_interval_length,
        height,
        remote_dkg_attempts,
    ))
}

/// Return the set of next transcripts for all tags. If for some tag
/// the next transcript is not available, the current transcript is used.
fn as_next_transcripts(
    summary: &DkgSummary,
    logger: &ReplicaLogger,
) -> BTreeMap<NiDkgTag, NiDkgTranscript> {
    let mut next_transcripts = summary.next_transcripts().clone();

    for (tag, transcript) in summary.current_transcripts().iter() {
        if !next_transcripts.contains_key(tag) {
            warn!(logger, "Reusing current transcript for tag {:?}", tag);
            next_transcripts.insert(tag.clone(), transcript.clone());
        }
    }

    next_transcripts
}

pub fn get_dkg_summary_from_cup_contents(
    cup_contents: CatchUpPackageContents,
    subnet_id: SubnetId,
    registry: &dyn RegistryClient,
    registry_version: RegistryVersion,
) -> Result<DkgSummary, String> {
    // If we're in a NNS subnet recovery case with failover nodes, we extract the registry of the
    // NNS we're recovering.
    let registry_version_of_original_registry = cup_contents
        .registry_store_uri
        .as_ref()
        .map(|v| RegistryVersion::from(v.registry_version));

    let mut transcripts: BTreeMap<NiDkgTag, NiDkgTranscript> = BTreeMap::new();

    transcripts.insert(
        NiDkgTag::LowThreshold,
        cup_contents
            .initial_ni_dkg_transcript_low_threshold
            .ok_or("Missing initial low-threshold DKG transcript".to_string())
            .map(|dkg_transcript_record| {
                initial_ni_dkg_transcript_from_registry_record(dkg_transcript_record).map_err(
                    |err| format!("Decoding initial low-threshold DKG transcript failed: {err}"),
                )
            })??,
    );
    transcripts.insert(
        NiDkgTag::HighThreshold,
        cup_contents
            .initial_ni_dkg_transcript_high_threshold
            .ok_or("Missing initial high-threshold DKG transcript".to_string())
            .map(|dkg_transcript_record| {
                initial_ni_dkg_transcript_from_registry_record(dkg_transcript_record).map_err(
                    |err| format!("Decoding initial high-threshold DKG transcript failed: {err}"),
                )
            })??,
    );

    // Get the transcripts for vetkeys from the `chain_key_initializations`
    for init in cup_contents.chain_key_initializations.into_iter() {
        let key_id = init
            .key_id
            .ok_or("Initialization without a key id".to_string())?;
        let init = init
            .initialization
            .ok_or("Empty initialization".to_string())?;
        // IDkg initializations are handled in a different place. This is to include NiDkgTranscripts into the Summary only
        let Initialization::TranscriptRecord(record) = init else {
            continue;
        };
        let key_id = NiDkgMasterPublicKeyId::try_from(key_id)
            .map_err(|err| format!("IDkg key combined with NiDkg initialization: {err}"))?;
        let transcript = initial_ni_dkg_transcript_from_registry_record(record).map_err(|err| {
            format!("Decoding high-threshold DKG for key-id {key_id} failed: {err}")
        })?;
        transcripts.insert(NiDkgTag::HighThresholdForKey(key_id), transcript);
    }

    // Extract vet key ids
    let vet_key_ids = vetkd_key_ids_for_subnet(subnet_id, registry, registry_version)
        .map_err(|err| format!("Failed to get vetKD key IDs: {err:?}"))?;

    // If we're in a NNS subnet recovery with failover nodes, we set the transcript versions to the
    // registry version of the recovered NNS, otherwise the oldest registry version used in a CUP is
    // computed incorrectly.
    if let Some(version) = registry_version_of_original_registry {
        for transcript in transcripts.values_mut() {
            transcript.registry_version = version;
        }
    }

    let committee = get_node_list(subnet_id, registry, registry_version)
        .map_err(|err| format!("Could not retrieve committee list: {err:?}"))?;

    let height = Height::from(cup_contents.height);
    let configs = get_configs_for_local_transcripts(
        subnet_id,
        committee,
        height,
        transcripts.clone(),
        // If we are in a NNS subnet recovery with failover nodes, we use the registry version of
        // the recovered NNS so that the DKG configs point to the correct registry version and new
        // dealings can be created in the first DKG interval.
        registry_version_of_original_registry.unwrap_or(registry_version),
        &vet_key_ids,
    )
    .map_err(|err| format!("Couldn't generate configs for the genesis summary: {err:?}"))?;

    // For the first 2 intervals we use the length value contained in the
    // genesis subnet record.
    let interval_length =
        get_dkg_interval_length(registry, registry_version, subnet_id).map_err(|err| {
            format!("Could not retrieve the interval length for the genesis summary: {err:?}")
        })?;
    let next_interval_length = interval_length;
    Ok(DkgSummary::new(
        configs,
        transcripts,
        BTreeMap::new(), // next transcripts
        // If we are in a NNS subnet recovery with failover nodes, we use the registry version of
        // the recovered NNS as a DKG summary version which is used as the CUP version.
        registry_version_of_original_registry.unwrap_or(registry_version),
        interval_length,
        next_interval_length,
        height,
        BTreeMap::new(), // remote_dkg_attempts
    ))
}

/// Creates DKG configs for the local subnet for the next DKG intervals.
pub(crate) fn get_configs_for_local_transcripts(
    subnet_id: SubnetId,
    node_ids: BTreeSet<NodeId>,
    start_block_height: Height,
    mut reshared_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
    registry_version: RegistryVersion,
    vet_key_ids: &[NiDkgMasterPublicKeyId],
) -> Result<Vec<NiDkgConfig>, DkgPayloadCreationError> {
    let mut new_configs = Vec::new();

    for tag in tags_iter(vet_key_ids) {
        let dkg_id = NiDkgId {
            start_block_height,
            dealer_subnet: subnet_id,
            dkg_tag: tag.clone(),
            target_subnet: NiDkgTargetSubnet::Local,
        };
        let (dealers, resharing_transcript) = match tag {
            NiDkgTag::LowThreshold => (node_ids.clone(), None),
            NiDkgTag::HighThreshold | NiDkgTag::HighThresholdForKey(_) => {
                let resharing_transcript = reshared_transcripts.remove(&tag);
                (
                    resharing_transcript
                        .as_ref()
                        .map(|transcript| transcript.committee.get().clone())
                        .unwrap_or_else(|| node_ids.clone()),
                    resharing_transcript,
                )
            }
        };

        let threshold =
            NumberOfNodes::from(tag.threshold_for_subnet_of_size(node_ids.len()) as u32);
        let new_config = match NiDkgConfig::new(NiDkgConfigData {
            dkg_id,
            max_corrupt_dealers: NumberOfNodes::from(get_faults_tolerated(dealers.len()) as u32),
            max_corrupt_receivers: NumberOfNodes::from(get_faults_tolerated(node_ids.len()) as u32),
            dealers,
            receivers: node_ids.clone(),
            threshold,
            registry_version,
            resharing_transcript,
        }) {
            Ok(config) => config,
            Err(err) => unreachable!("Failed to create a DKG config: {:?}", err),
        };
        new_configs.push(new_config);
    }

    Ok(new_configs)
}

fn get_dkg_interval_length(
    registry_client: &dyn RegistryClient,
    version: RegistryVersion,
    subnet_id: SubnetId,
) -> Result<Height, DkgPayloadCreationError> {
    registry_client
        .get_dkg_interval_length(subnet_id, version)
        .map_err(DkgPayloadCreationError::FailedToGetDkgIntervalSettingFromRegistry)?
        .ok_or_else(|| {
            panic!(
                "No subnet record found for registry version={version:?} and subnet_id={subnet_id:?}",
            )
        })
}

pub(crate) fn get_node_list(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
) -> Result<BTreeSet<NodeId>, DkgPayloadCreationError> {
    Ok(registry_client
        .get_node_ids_on_subnet(subnet_id, registry_version)
        .map_err(DkgPayloadCreationError::FailedToGetSubnetMemberListFromRegistry)?
        .unwrap_or_else(|| {
            panic!(
                "No subnet record found for registry version={registry_version:?} and subnet_id={subnet_id:?}",
            )
        })
        .into_iter()
        .collect())
}

/// Returns the set of remote target IDs for which at least one DKG instance
/// was completed.
fn get_completed_target_ids(completed: &BTreeSet<NiDkgId>) -> BTreeSet<NiDkgTargetId> {
    completed
        .iter()
        .filter_map(|dkg_id| {
            if let NiDkgTargetSubnet::Remote(target_id) = dkg_id.target_subnet {
                Some(target_id)
            } else {
                None
            }
        })
        .collect()
}

/// This function is called for each entry on the SubnetCallContext. It returns
/// either the created high and low configs for the entry or returns two errors
/// identified by the NiDkgId.
pub(crate) fn create_low_high_remote_dkg_configs(
    start_block_height: Height,
    dealer_subnet: SubnetId,
    target_subnet: NiDkgTargetId,
    dealers: BTreeSet<NodeId>,
    receivers: BTreeSet<NodeId>,
    registry_version: &RegistryVersion,
    logger: &ReplicaLogger,
) -> Result<(NiDkgConfig, NiDkgConfig), Vec<(NiDkgId, String)>> {
    let low_thr_dkg_id = NiDkgId {
        start_block_height,
        dealer_subnet,
        dkg_tag: NiDkgTag::LowThreshold,
        target_subnet: NiDkgTargetSubnet::Remote(target_subnet),
    };

    let high_thr_dkg_id = NiDkgId {
        start_block_height,
        dealer_subnet,
        dkg_tag: NiDkgTag::HighThreshold,
        target_subnet: NiDkgTargetSubnet::Remote(target_subnet),
    };

    let low_thr_config = create_remote_dkg_config(
        low_thr_dkg_id.clone(),
        dealers.clone(),
        receivers.clone(),
        registry_version,
        None,
    );
    let high_thr_config = create_remote_dkg_config(
        high_thr_dkg_id.clone(),
        dealers,
        receivers,
        registry_version,
        None,
    );

    let sibl_err = String::from("Failed to create the sibling config");
    match (low_thr_config, high_thr_config) {
        (Ok(config0), Ok(config1)) => Ok((config0, config1)),
        (Err(err0), Err(err1)) => {
            error!(logger, "Failed to create a remote DKG config {}", err0);
            error!(logger, "Failed to create a remote DKG config {}", err1);
            Err(vec![
                (low_thr_dkg_id, err0.to_string()),
                (high_thr_dkg_id, err1.to_string()),
            ])
        }
        (Ok(_), Err(err1)) => {
            error!(logger, "Failed to create a remote DKG config {}", err1);
            Err(vec![
                (low_thr_dkg_id, sibl_err),
                (high_thr_dkg_id, err1.to_string()),
            ])
        }
        (Err(err0), Ok(_)) => {
            error!(logger, "Failed to create a remote DKG config {}", err0);
            Err(vec![
                (low_thr_dkg_id, err0.to_string()),
                (high_thr_dkg_id, sibl_err),
            ])
        }
    }
}

pub(crate) fn create_remote_dkg_config(
    dkg_id: NiDkgId,
    dealers: BTreeSet<NodeId>,
    receivers: BTreeSet<NodeId>,
    registry_version: &RegistryVersion,
    resharing_transcript: Option<NiDkgTranscript>,
) -> Result<NiDkgConfig, NiDkgConfigValidationError> {
    NiDkgConfig::new(NiDkgConfigData {
        threshold: NumberOfNodes::from(
            dkg_id.dkg_tag.threshold_for_subnet_of_size(receivers.len()) as u32,
        ),
        dkg_id,
        max_corrupt_dealers: NumberOfNodes::from(get_faults_tolerated(dealers.len()) as u32),
        max_corrupt_receivers: NumberOfNodes::from(get_faults_tolerated(receivers.len()) as u32),
        dealers,
        receivers,
        registry_version: *registry_version,
        resharing_transcript,
    })
}

#[cfg(test)]
mod tests {
    use crate::tests::test_vet_key_config;
    use crate::{MAX_REMOTE_DKG_ATTEMPTS, REMOTE_DKG_REPEATED_FAILURE_ERROR};

    use super::{
        super::test_utils::{
            complement_state_manager_with_dkg_contexts, create_dealing, local_dkg_id,
            make_test_config, remote_dkg_id, remote_dkg_id_with_target,
        },
        *,
    };
    use ic_consensus_mocks::{
        Dependencies, dependencies_with_subnet_params,
        dependencies_with_subnet_records_with_raw_state_manager,
    };
    use ic_crypto_test_utils_ni_dkg::dummy_transcript_for_tests_with_params;
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types_private::{VetKdCurve, VetKdKeyId};
    use ic_registry_client_helpers::subnet::SubnetRegistry;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::{
        ReshareChainKeyContext, SetupInitialDkgContext, SubnetCallContext,
    };
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::{SubnetRecordBuilder, add_subnet_record};
    use ic_test_utilities_types::{
        ids::{node_test_id, subnet_test_id},
        messages::RequestBuilder,
    };
    use ic_types::consensus::dkg::RemoteDkgAttempts;
    use ic_types::{
        RegistryVersion,
        crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet},
        time::UNIX_EPOCH,
    };
    use std::collections::{BTreeMap, BTreeSet};

    // Tests creation of local configs.
    #[test]
    fn test_get_configs_for_local_transcripts() {
        let prev_committee: Vec<_> = (10..21).map(node_test_id).collect();

        let receivers: BTreeSet<_> = (3..8).map(node_test_id).collect();
        let start_block_height = Height::from(777);
        let subnet_id = subnet_test_id(123);
        let registry_version = RegistryVersion::from(888);

        let vet_key_ids = vec![
            NiDkgMasterPublicKeyId::VetKd(VetKdKeyId {
                curve: VetKdCurve::Bls12_381_G2,
                name: String::from("first_key"),
            }),
            NiDkgMasterPublicKeyId::VetKd(VetKdKeyId {
                curve: VetKdCurve::Bls12_381_G2,
                name: String::from("second_key"),
            }),
        ];

        let mut reshared_transcripts = BTreeMap::new();
        reshared_transcripts.insert(
            NiDkgTag::HighThreshold,
            dummy_transcript_for_tests_with_params(
                prev_committee.clone(),
                NiDkgTag::HighThreshold,
                NiDkgTag::HighThreshold.threshold_for_subnet_of_size(prev_committee.len()) as u32,
                888,
            ),
        );
        for key in &vet_key_ids {
            let tag = NiDkgTag::HighThresholdForKey(key.clone());

            reshared_transcripts.insert(
                tag.clone(),
                dummy_transcript_for_tests_with_params(
                    prev_committee.clone(),
                    tag.clone(),
                    tag.clone()
                        .threshold_for_subnet_of_size(prev_committee.len())
                        as u32,
                    888,
                ),
            );
        }

        // Tests the happy path.
        let configs = get_configs_for_local_transcripts(
            subnet_id,
            receivers.clone(),
            start_block_height,
            reshared_transcripts.clone(),
            registry_version,
            &vet_key_ids,
        )
        .unwrap_or_else(|err| panic!("Couldn't create configs: {err:?}"));

        // We produced exactly four configs (high, low and two vetkeys), and with expected ids.
        assert_eq!(configs.len(), 4);
        for (index, tag) in tags_iter(&vet_key_ids).enumerate() {
            let config = configs[index].clone();
            assert_eq!(
                config.dkg_id(),
                &NiDkgId {
                    start_block_height,
                    dealer_subnet: subnet_id,
                    dkg_tag: tag.clone(),
                    target_subnet: NiDkgTargetSubnet::Local,
                }
            );
            assert_eq!(
                config.receivers().get(),
                &receivers.clone().into_iter().collect::<BTreeSet<_>>()
            );
            assert_eq!(config.registry_version(), registry_version);
            assert_eq!(config.max_corrupt_receivers().get(), 1);

            assert_eq!(
                config.threshold().get().get(),
                match tag {
                    // 5 receivers => committee size is 4 => high threshold is  4 - f with f = 1
                    NiDkgTag::HighThreshold | NiDkgTag::HighThresholdForKey(_) => 3,
                    // low threshold is f + 1, with f same as for high threshold.
                    NiDkgTag::LowThreshold => 2,
                }
            );

            // When the threshold is high, we use the receivers from the reshared
            // transcript as dealers (nodes 10..12), and compute the threshold on that
            // subnet.
            assert_eq!(
                config.max_corrupt_dealers().get(),
                match tag {
                    NiDkgTag::HighThreshold | NiDkgTag::HighThresholdForKey(_) => 3,
                    NiDkgTag::LowThreshold => 1,
                }
            );

            // We use the committee of the reshared transcript as dealers for the high
            // threshold, or the current subnet members, for the low threshold.
            let expected_dealers = match tag {
                NiDkgTag::HighThreshold | NiDkgTag::HighThresholdForKey(_) => {
                    prev_committee.clone().into_iter().collect::<BTreeSet<_>>()
                }
                NiDkgTag::LowThreshold => receivers.clone().into_iter().collect::<BTreeSet<_>>(),
            };
            assert_eq!(config.dealers().get(), &expected_dealers);

            assert_eq!(
                config.resharing_transcript().as_ref(),
                match tag {
                    NiDkgTag::HighThreshold | NiDkgTag::HighThresholdForKey(_) =>
                        reshared_transcripts.get(&tag),
                    NiDkgTag::LowThreshold => None,
                }
            );
        }
    }

    #[test]
    fn test_remote_dkg_config_dealers_match_reshared_transcript_committee() {
        let transcript_committee: Vec<_> = (0..4).map(node_test_id).collect();
        let receivers: BTreeSet<_> = (4..8).map(node_test_id).collect();
        let start_block_height = Height::from(500);
        let dealer_subnet = subnet_test_id(1);
        let target_id = NiDkgTargetId::new([7_u8; 32]);
        let registry_version = RegistryVersion::from(777);

        let key_id = NiDkgMasterPublicKeyId::VetKd(VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: String::from("test_key"),
        });
        let tag = NiDkgTag::HighThresholdForKey(key_id.clone());

        let resharing_transcript = dummy_transcript_for_tests_with_params(
            transcript_committee.clone(),
            tag.clone(),
            tag.threshold_for_subnet_of_size(transcript_committee.len()) as u32,
            777,
        );

        let dkg_id = NiDkgId {
            start_block_height,
            dealer_subnet,
            dkg_tag: tag,
            target_subnet: NiDkgTargetSubnet::Remote(target_id),
        };
        let config = super::create_remote_dkg_config(
            dkg_id,
            resharing_transcript.committee.get().clone(),
            receivers,
            &registry_version,
            Some(resharing_transcript.clone()),
        )
        .expect("expected remote DKG config for resharing");

        assert_eq!(
            config.dealers().get(),
            resharing_transcript.committee.get(),
            "dealers must be the committee of the transcript being reshared"
        );
    }

    #[test]
    fn test_return_errors_for_repeatedly_failing_remote_dkg_requests() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            use ic_types::crypto::threshold_sig::ni_dkg::*;
            with_test_replica_logger(|logger| {
                let node_ids = vec![
                    node_test_id(0),
                    node_test_id(1),
                    node_test_id(2),
                    node_test_id(3),
                ];
                let dkg_interval_length = 19;
                let subnet_id = subnet_test_id(0);
                let vet_key_config = test_vet_key_config();
                let key_id = vet_key_config.key_configs[0].key_id.clone();
                let mut deps = dependencies_with_subnet_records_with_raw_state_manager(
                    pool_config,
                    subnet_id,
                    vec![(
                        10,
                        SubnetRecordBuilder::from(&node_ids)
                            .with_dkg_interval_length(dkg_interval_length)
                            .with_chain_key_config(test_vet_key_config())
                            .build(),
                    )],
                );
                let registry_version = deps.registry.get_latest_version();
                let setup_target = NiDkgTargetId::new([5_u8; 32]);
                let reshare_target = NiDkgTargetId::new([6_u8; 32]);

                let target_nodes: BTreeSet<_> =
                    vec![10, 11, 12].into_iter().map(node_test_id).collect();
                let contexts = vec![
                    SubnetCallContext::SetupInitialDKG(SetupInitialDkgContext {
                        request: RequestBuilder::new().build(),
                        nodes_in_target_subnet: target_nodes.clone(),
                        target_id: setup_target,
                        registry_version,
                        time: UNIX_EPOCH,
                    }),
                    SubnetCallContext::ReshareChainKey(ReshareChainKeyContext {
                        request: RequestBuilder::new().build(),
                        key_id,
                        nodes: target_nodes,
                        registry_version,
                        time: UNIX_EPOCH,
                        target_id: reshare_target,
                    }),
                ];
                complement_state_manager_with_dkg_contexts(
                    deps.state_manager.clone(),
                    contexts,
                    None,
                );

                let build_callback_map = |summary: &DkgSummary| {
                    let state = deps
                        .state_manager
                        .get_latest_certified_state()
                        .expect("latest certified state should exist");
                    build_callback_id_config_map(
                        subnet_id,
                        deps.registry.as_ref(),
                        state.get_ref(),
                        registry_version,
                        summary,
                        &logger,
                    )
                    .expect("callback map should be built")
                };

                for attempt in 1..=MAX_REMOTE_DKG_ATTEMPTS {
                    deps.pool
                        .advance_round_normal_operation_n(dkg_interval_length + 1);
                    let summary_block =
                        PoolReader::new(&deps.pool).get_highest_finalized_summary_block();
                    let dkg_summary = &summary_block.payload.as_ref().as_summary().dkg;
                    assert_eq!(
                        dkg_summary.remote_dkg_attempts.get(&setup_target),
                        Some(&RemoteDkgAttempts::from(attempt))
                    );
                    assert_eq!(
                        dkg_summary.remote_dkg_attempts.get(&reshare_target),
                        Some(&RemoteDkgAttempts::from(attempt))
                    );

                    let callback_map = build_callback_map(dkg_summary);
                    assert_eq!(callback_map.len(), 2);
                    if attempt < MAX_REMOTE_DKG_ATTEMPTS {
                        let total_configs: usize = callback_map
                            .values()
                            .map(|result| result.as_ref().map(|configs| configs.len()).unwrap_or(0))
                            .sum();
                        assert_eq!(total_configs, 3, "{callback_map:?}");
                    } else {
                        for result in callback_map.values() {
                            let errors = result.as_ref().expect_err(
                                "attempts above max should return repeated-failure errors",
                            );
                            assert!(
                                errors
                                    .iter()
                                    .all(|(_, err)| { err == REMOTE_DKG_REPEATED_FAILURE_ERROR })
                            );
                        }
                    }
                }

                // The first data block after the last summary should contain repeated-failure
                // errors for the setup DKG transcripts.
                deps.pool.advance_round_normal_operation();
                let data_block = deps.pool.get_cache().finalized_block();
                let dkg_data = data_block.payload.as_ref().as_data().dkg.clone();
                assert_eq!(dkg_data.messages.len(), 0);
                assert_eq!(dkg_data.transcripts_for_remote_subnets.len(), 2);
                assert_eq!(
                    dkg_data
                        .transcripts_for_remote_subnets
                        .iter()
                        .filter(|transcript| {
                            transcript.dkg_id.target_subnet
                                == NiDkgTargetSubnet::Remote(setup_target)
                                && transcript.transcript_result
                                    == Err(REMOTE_DKG_REPEATED_FAILURE_ERROR.to_string())
                        })
                        .count(),
                    2
                );

                // The second data block after the last summary should contain repeated-failure
                // errors for the reshare chain key transcript.
                deps.pool.advance_round_normal_operation();
                let data_block = deps.pool.get_cache().finalized_block();
                let dkg_data = data_block.payload.as_ref().as_data().dkg.clone();
                assert_eq!(dkg_data.messages.len(), 0);
                assert_eq!(dkg_data.transcripts_for_remote_subnets.len(), 1);
                assert_eq!(
                    dkg_data
                        .transcripts_for_remote_subnets
                        .iter()
                        .filter(|transcript| {
                            transcript.dkg_id.target_subnet
                                == NiDkgTargetSubnet::Remote(reshare_target)
                                && transcript.transcript_result
                                    == Err(REMOTE_DKG_REPEATED_FAILURE_ERROR.to_string())
                        })
                        .count(),
                    1
                );

                // The next block should not contain any more errors.
                deps.pool.advance_round_normal_operation();
                let data_block = deps.pool.get_cache().finalized_block();
                let dkg_data = &data_block.payload.as_ref().as_data().dkg;
                assert!(dkg_data.transcripts_for_remote_subnets.is_empty());

                // After one more full interval, both targets are marked completed (attempts = 0),
                // and callback map no longer contains configs.
                deps.pool
                    .advance_round_normal_operation_n(dkg_interval_length + 1);
                let summary_block =
                    PoolReader::new(&deps.pool).get_highest_finalized_summary_block();
                let dkg_summary = &summary_block.payload.as_ref().as_summary().dkg;
                assert_eq!(
                    dkg_summary.remote_dkg_attempts.get(&setup_target),
                    Some(&RemoteDkgAttempts::Completed)
                );
                assert_eq!(
                    dkg_summary.remote_dkg_attempts.get(&reshare_target),
                    Some(&RemoteDkgAttempts::Completed)
                );
                let callback_map = build_callback_map(dkg_summary);
                assert!(callback_map.is_empty(), "{callback_map:?}");

                // Remove remote DKG requests from the state.
                deps.state_manager.get_mut().checkpoint();
                complement_state_manager_with_dkg_contexts(
                    deps.state_manager.clone(),
                    vec![],
                    None,
                );

                // It should no longer appear in `remote_dkg_attempts` of the next summary.
                deps.pool
                    .advance_round_normal_operation_n(dkg_interval_length + 1);
                let summary_block =
                    PoolReader::new(&deps.pool).get_highest_finalized_summary_block();
                let dkg_summary = &summary_block.payload.as_ref().as_summary().dkg;
                assert!(dkg_summary.remote_dkg_attempts.is_empty());
            });
        });
    }

    /// Tests, which transcripts get reshared, when DKG succeeded or failed.
    #[test]
    fn test_transcript_resharing() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let nodes: Vec<_> = (7..14).map(node_test_id).collect();
            let dkg_interval_len = 3;
            let subnet_id = subnet_test_id(222);
            let initial_registry_version = 112;
            let Dependencies {
                crypto,
                registry,
                mut pool,
                state_manager,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_id,
                vec![(
                    initial_registry_version,
                    SubnetRecordBuilder::from(&nodes)
                        .with_dkg_interval_length(dkg_interval_len)
                        .with_chain_key_config(test_vet_key_config())
                        .build(),
                )],
            );
            let cup_contents = registry
                .get_cup_contents(subnet_id, registry.get_latest_version())
                .expect("Failed to retreive the DKG transcripts from registry");
            let mut genesis_summary = get_dkg_summary_from_cup_contents(
                cup_contents.value.expect("Missing CUP contents"),
                subnet_id,
                &*registry,
                cup_contents.version,
            )
            .expect("Failed to get DKG summary from CUP contents");

            // Let's ensure we have no summaries for the whole DKG interval.
            for _ in 0..dkg_interval_len {
                pool.advance_round_normal_operation();
                let block = pool.get_cache().finalized_block();
                assert!(!block.payload.as_ref().is_summary());
            }

            let latest_block = pool.get_cache().finalized_block();
            let create_summary_payload = |last_summary: &DkgSummary| {
                create_summary_payload(
                    subnet_test_id(222),
                    registry.as_ref(),
                    crypto.as_ref(),
                    &PoolReader::new(&pool),
                    &last_summary.clone(),
                    &latest_block,
                    RegistryVersion::from(112),
                    state_manager.as_ref(),
                    &ValidationContext {
                        registry_version: RegistryVersion::from(112),
                        certified_height: Height::from(3),
                        time: UNIX_EPOCH,
                    },
                    no_op_logger(),
                    None,
                )
                .unwrap()
            };

            // Test the regular case (Both DKGs succeeded)
            let next_summary = create_summary_payload(&genesis_summary);
            for conf in next_summary.configs.values() {
                let tag = &conf.dkg_id().dkg_tag;
                match tag {
                    NiDkgTag::HighThreshold | NiDkgTag::HighThresholdForKey(_) => assert_eq!(
                        next_summary.clone().next_transcript(tag).unwrap(),
                        &conf.resharing_transcript().clone().unwrap()
                    ),
                    NiDkgTag::LowThreshold => (),
                }
            }

            // Remove configs from `genesis_summary`. This emulates the
            // behaviour of DKG failing validations.
            // In this case, the `current_transcripts` are being reshared.
            genesis_summary.configs.clear();
            let next_summary = create_summary_payload(&genesis_summary);
            for conf in next_summary.configs.values() {
                let tag = &conf.dkg_id().dkg_tag;
                match tag {
                    NiDkgTag::HighThreshold | NiDkgTag::HighThresholdForKey(_) => assert_eq!(
                        next_summary.clone().current_transcript(tag).unwrap(),
                        &conf.resharing_transcript().clone().unwrap()
                    ),
                    NiDkgTag::LowThreshold => (),
                }
            }
        });
    }

    /// Creates a summary from registry and tests that all fields of the summary
    /// contain the expected contents.
    #[test]
    fn test_get_dkg_summary_from_cup_contents() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let nodes: Vec<_> = (7..14).map(node_test_id).collect();
            let initial_registry_version = 145;
            let dkg_interval_len = 66;
            let subnet_id = subnet_test_id(222);
            let Dependencies { registry, .. } = dependencies_with_subnet_params(
                pool_config,
                subnet_id,
                vec![(
                    initial_registry_version,
                    SubnetRecordBuilder::from(&nodes)
                        .with_dkg_interval_length(dkg_interval_len)
                        .with_chain_key_config(test_vet_key_config())
                        .build(),
                )],
            );

            let cup_contents = registry
                .get_cup_contents(subnet_id, registry.get_latest_version())
                .expect("Failed to retreive the DKG transcripts from registry");
            let summary = get_dkg_summary_from_cup_contents(
                cup_contents.value.expect("Missing CUP contents"),
                subnet_id,
                &*registry,
                cup_contents.version,
            )
            .expect("Failed to get DKG summary from CUP contents");

            let vet_key_ids =
                vetkd_key_ids_for_subnet(subnet_id, &*registry, summary.registry_version).unwrap();

            assert_eq!(
                summary.registry_version,
                RegistryVersion::from(initial_registry_version)
            );
            assert_eq!(summary.height, Height::from(0));
            assert_eq!(summary.interval_length, Height::from(dkg_interval_len));
            assert_eq!(summary.next_interval_length, Height::from(dkg_interval_len));
            assert_eq!(summary.configs.len(), 3);
            assert!(summary.next_transcript(&NiDkgTag::LowThreshold).is_none());
            assert!(summary.next_transcript(&NiDkgTag::HighThreshold).is_none());
            assert_eq!(vet_key_ids.len(), 1);
            for vet_key_id in &vet_key_ids {
                assert!(
                    summary
                        .next_transcript(&NiDkgTag::HighThresholdForKey(vet_key_id.clone()))
                        .is_none()
                );
            }

            for tag in tags_iter(&vet_key_ids) {
                let (id, conf) = summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == tag)
                    .unwrap();

                assert_eq!(
                    id,
                    &NiDkgId {
                        start_block_height: Height::from(0),
                        dealer_subnet: subnet_id,
                        dkg_tag: tag.clone(),
                        target_subnet: NiDkgTargetSubnet::Local,
                    }
                );

                assert_eq!(conf.dkg_id(), id);
                assert_eq!(
                    conf.registry_version(),
                    RegistryVersion::from(initial_registry_version)
                );
                assert_eq!(
                    conf.receivers().get(),
                    &nodes.clone().into_iter().collect::<BTreeSet<_>>()
                );
                assert_eq!(
                    conf.dealers().get(),
                    &nodes.clone().into_iter().collect::<BTreeSet<_>>()
                );
                assert_eq!(conf.max_corrupt_receivers().get(), 2);
                assert_eq!(conf.max_corrupt_dealers().get(), 2);
                assert_eq!(
                    conf.threshold().get().get(),
                    match tag {
                        NiDkgTag::LowThreshold => 3,
                        NiDkgTag::HighThreshold | NiDkgTag::HighThresholdForKey(_) => 5,
                    }
                );
            }
        });
    }

    #[test]
    /// In this test we check that all summary payloads are created at the expected
    /// heights and with the expected contents. Note, we do not test anything related
    /// to the presence or contents of transcripts, as this would require using a
    /// real CSP.
    fn test_create_regular_summaries() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let nodes: Vec<_> = (7..14).map(node_test_id).collect();
            let dkg_interval_len = 3;
            let subnet_id = subnet_test_id(222);
            let initial_registry_version = 112;
            let Dependencies {
                registry, mut pool, ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_id,
                vec![(
                    initial_registry_version,
                    SubnetRecordBuilder::from(&nodes)
                        .with_dkg_interval_length(dkg_interval_len)
                        .with_chain_key_config(test_vet_key_config())
                        .build(),
                )],
            );
            let cup_contents = registry
                .get_cup_contents(subnet_id, registry.get_latest_version())
                .expect("Failed to retreive the DKG transcripts from registry");
            let genesis_summary = get_dkg_summary_from_cup_contents(
                cup_contents.value.expect("Missing CUP contents"),
                subnet_id,
                &*registry,
                cup_contents.version,
            )
            .expect("Failed to get DKG summary from CUP contents");
            let block = pool.get_cache().finalized_block();
            // This first block is expected to contain the genesis summary.
            if block.payload.as_ref().is_summary() {
                assert_eq!(
                    block.payload.as_ref().as_summary().dkg,
                    genesis_summary,
                    "Unexpected genesis summary."
                );
            } else {
                panic!("Unexpected DKG payload.")
            };

            // Simulate 3 intervals
            for interval in 0..3 {
                // Let's ensure we have no summaries for the whole DKG interval.
                for _ in 0..dkg_interval_len {
                    pool.advance_round_normal_operation();
                    let block = pool.get_cache().finalized_block();
                    assert!(!block.payload.as_ref().is_summary());
                }

                // Advance one more time and get the summary block.
                pool.advance_round_normal_operation();
                let block = pool.get_cache().finalized_block();
                let dkg_summary = &block.payload.as_ref().as_summary().dkg;

                assert_eq!(
                    dkg_summary.registry_version,
                    RegistryVersion::from(initial_registry_version)
                );
                let expected_height = interval * (dkg_interval_len + 1) + dkg_interval_len + 1;
                assert_eq!(dkg_summary.height, Height::from(expected_height));
                assert_eq!(dkg_summary.interval_length, Height::from(dkg_interval_len));
                assert_eq!(
                    dkg_summary.next_interval_length,
                    Height::from(dkg_interval_len)
                );
                assert_eq!(dkg_summary.configs.len(), 3);

                let vet_key_ids =
                    vetkd_key_ids_for_subnet(subnet_id, &*registry, dkg_summary.registry_version)
                        .unwrap();
                assert_eq!(vet_key_ids.len(), 1);
                for tag in tags_iter(&vet_key_ids) {
                    let (id, conf) = dkg_summary
                        .configs
                        .iter()
                        .find(|(id, _)| id.dkg_tag == tag)
                        .unwrap();

                    assert_eq!(
                        id,
                        &NiDkgId {
                            start_block_height: Height::from(expected_height),
                            dealer_subnet: subnet_id,
                            dkg_tag: tag.clone(),
                            target_subnet: NiDkgTargetSubnet::Local,
                        }
                    );

                    assert_eq!(conf.dkg_id(), id);
                    assert_eq!(
                        conf.registry_version(),
                        RegistryVersion::from(initial_registry_version)
                    );
                    assert_eq!(
                        conf.receivers().get(),
                        &nodes.clone().into_iter().collect::<BTreeSet<_>>()
                    );
                    assert_eq!(
                        conf.dealers().get(),
                        &nodes.clone().into_iter().collect::<BTreeSet<_>>()
                    );
                    assert_eq!(conf.max_corrupt_receivers().get(), 2);
                    assert_eq!(conf.max_corrupt_dealers().get(), 2);
                    assert_eq!(
                        conf.threshold().get().get(),
                        match tag {
                            NiDkgTag::LowThreshold => 3,
                            NiDkgTag::HighThreshold | NiDkgTag::HighThresholdForKey(_) => 5,
                        }
                    );

                    // In later intervals we can also check that the resharing transcript matches
                    // the expected value.
                    if interval > 0 {
                        match tag {
                            NiDkgTag::HighThreshold | NiDkgTag::HighThresholdForKey(_) => {
                                assert_eq!(
                                    dkg_summary.clone().next_transcript(&tag).unwrap(),
                                    &conf.resharing_transcript().clone().unwrap()
                                );
                            }
                            _ => assert!(&conf.resharing_transcript().is_none()),
                        }
                    }
                }
            }
        });
    }

    /// Test the generation of vetkeys
    ///
    /// 1. Create a subnet with 4 nodes and a genesis summary
    /// 2. Add registry entry to add a vetkey
    /// 3. Check that a config ends up in the next summary
    /// 4. Check that the summary after that has a matching next transcript
    /// 5. CHeck that the summary after that has matching current and next transcripts
    #[test]
    fn test_vet_key_local_transcript_generation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            // We'll have a DKG summary inside every 5th block.
            let dkg_interval_length = 4;
            // Committee are nodes 0, 1, 2, 3.
            let committee = (0..4).map(node_test_id).collect::<Vec<_>>();
            let Dependencies {
                mut pool,
                registry_data_provider,
                registry,
                replica_config,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    5,
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(dkg_interval_length)
                        .build(),
                )],
            );

            // Get the latest summary block, which is the genesis block
            let cup = PoolReader::new(&pool).get_highest_catch_up_package();
            let dkg_block = cup.content.block.as_ref();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(5),
                "The latest available version was used for the summary block."
            );
            let summary = dkg_block.payload.as_ref().as_summary();
            let dkg_summary = &summary.dkg;

            // The genesis summary does not have vetkeys enabled
            let vet_key_ids = vetkd_key_ids_for_subnet(
                replica_config.subnet_id,
                &*registry,
                dkg_block.context.registry_version,
            )
            .unwrap();
            assert_eq!(vet_key_ids.len(), 0);

            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(5));
            assert_eq!(dkg_summary.height, Height::from(0));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(5)
            );

            // This summary does not contain a config for the vetkey yet
            assert_eq!(dkg_summary.configs.len(), 2);
            assert_eq!(dkg_summary.current_transcripts().len(), 2);

            // Since it is the genesis summary, it also has no next transcripts
            assert_eq!(dkg_summary.next_transcripts().len(), 0);
            for tag in tags_iter(&vet_key_ids) {
                // Check that every tag has a config in the summary
                let _ = dkg_summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == tag)
                    .unwrap();
                let _ = dkg_summary.current_transcript(&tag).unwrap();
            }

            // Add the vetkey to the registry
            pool.advance_round_normal_operation();
            add_subnet_record(
                &registry_data_provider,
                6,
                replica_config.subnet_id,
                SubnetRecordBuilder::from(&committee)
                    .with_dkg_interval_length(dkg_interval_length)
                    .with_chain_key_config(test_vet_key_config())
                    .build(),
            );
            registry.update_to_latest_version();

            pool.advance_round_normal_operation_n(dkg_interval_length);
            let cup = PoolReader::new(&pool).get_highest_catch_up_package();
            let dkg_block = cup.content.block.as_ref();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(6),
                "The newest registry version is used."
            );
            let summary = dkg_block.payload.as_ref().as_summary();
            let dkg_summary = &summary.dkg;

            // At this point the summary has a registry version with a vetkey
            let vet_key_ids = vetkd_key_ids_for_subnet(
                replica_config.subnet_id,
                &*registry,
                dkg_block.context.registry_version,
            )
            .unwrap();
            assert_eq!(vet_key_ids.len(), 1);

            // This membership registry version corresponds to the registry version from
            // the block context of the previous summary.
            assert_eq!(dkg_summary.configs.len(), 3);
            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(5));
            assert_eq!(dkg_summary.height, Height::from(5));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(5)
            );

            assert_eq!(dkg_summary.current_transcripts().len(), 2);
            assert_eq!(dkg_summary.next_transcripts().len(), 2);
            for tag in tags_iter(&vet_key_ids) {
                // Check that every tag has a config in the summary
                let _ = dkg_summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == tag)
                    .unwrap();
                let current_transcript = dkg_summary.current_transcript(&tag);
                let next_transcript = dkg_summary.next_transcript(&tag);

                match tag {
                    // Vetkeys should not have transcripts yet, since the configs where only added in
                    // this summary
                    NiDkgTag::HighThresholdForKey(_) => {
                        assert!(current_transcript.is_none() && next_transcript.is_none())
                    }
                    NiDkgTag::LowThreshold | NiDkgTag::HighThreshold => {
                        assert!(current_transcript.is_some() && next_transcript.is_some())
                    }
                };
            }

            pool.advance_round_normal_operation_n(dkg_interval_length + 1);
            let cup = PoolReader::new(&pool).get_highest_catch_up_package();
            let dkg_block = cup.content.block.as_ref();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(6),
                "The newest registry version is used."
            );
            let summary = dkg_block.payload.as_ref().as_summary();
            let dkg_summary = &summary.dkg;

            let vet_key_ids = vetkd_key_ids_for_subnet(
                replica_config.subnet_id,
                &*registry,
                dkg_block.context.registry_version,
            )
            .unwrap();
            assert_eq!(vet_key_ids.len(), 1);

            // This membership registry version corresponds to the registry version from
            // the block context of the previous summary.
            assert_eq!(dkg_summary.configs.len(), 3);
            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(6));
            assert_eq!(dkg_summary.height, Height::from(10));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(5)
            );

            assert_eq!(dkg_summary.current_transcripts().len(), 2);
            assert_eq!(dkg_summary.next_transcripts().len(), 3);
            for tag in tags_iter(&vet_key_ids) {
                // Check that every tag has a config in the summary
                let _ = dkg_summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == tag)
                    .unwrap();
                let current_transcript = dkg_summary.current_transcript(&tag);
                let next_transcript = dkg_summary.next_transcript(&tag);

                match tag {
                    // There should be a vetkey next transcript but not a current one
                    NiDkgTag::HighThresholdForKey(_) => {
                        assert!(current_transcript.is_none() && next_transcript.is_some())
                    }
                    NiDkgTag::LowThreshold | NiDkgTag::HighThreshold => {
                        assert!(current_transcript.is_some() && next_transcript.is_some())
                    }
                };
            }

            pool.advance_round_normal_operation_n(dkg_interval_length + 1);
            let cup = PoolReader::new(&pool).get_highest_catch_up_package();
            let dkg_block = cup.content.block.as_ref();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(6),
                "The newest registry version is used."
            );
            let summary = dkg_block.payload.as_ref().as_summary();
            let dkg_summary = &summary.dkg;

            let vet_key_ids = vetkd_key_ids_for_subnet(
                replica_config.subnet_id,
                &*registry,
                dkg_block.context.registry_version,
            )
            .unwrap();
            assert_eq!(vet_key_ids.len(), 1);

            // This membership registry version corresponds to the registry version from
            // the block context of the previous summary.
            assert_eq!(dkg_summary.configs.len(), 3);
            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(6));
            assert_eq!(dkg_summary.height, Height::from(15));
            // The oldest registry in use is no longer 5
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(6)
            );

            assert_eq!(dkg_summary.current_transcripts().len(), 3);
            assert_eq!(dkg_summary.next_transcripts().len(), 3);
            for tag in tags_iter(&vet_key_ids) {
                // Check that every tag has a config in the summary
                let _ = dkg_summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == tag)
                    .unwrap();
                let current_transcript = dkg_summary.current_transcript(&tag);
                let next_transcript = dkg_summary.next_transcript(&tag);

                // All tags have all transcripts now
                assert!(current_transcript.is_some() && next_transcript.is_some());
            }
        });
    }

    #[test]
    fn test_get_completed_target_ids() {
        let targets: Vec<_> = (1..=3).map(|i| NiDkgTargetId::new([i; 32])).collect();
        let tags = [NiDkgTag::LowThreshold, NiDkgTag::HighThreshold];

        let config_ids: Vec<_> = targets
            .iter()
            .flat_map(|t| {
                tags.iter().map(|tag| NiDkgId {
                    start_block_height: Height::from(1),
                    dealer_subnet: subnet_test_id(1),
                    dkg_tag: tag.clone(),
                    target_subnet: NiDkgTargetSubnet::Remote(*t),
                })
            })
            .collect();

        // target 0 has both tags completed, target 1 has only one tag completed,
        // target 2 is not completed.
        let completed: BTreeSet<_> = config_ids[..3].iter().cloned().collect();

        let result = get_completed_target_ids(&completed);
        assert_eq!(result, BTreeSet::from([targets[0], targets[1]]));
    }

    struct TestDkgPool {
        messages: Vec<Message>,
    }

    impl DkgPool for TestDkgPool {
        fn get_validated(&self) -> Box<dyn Iterator<Item = &Message> + '_> {
            Box::new(self.messages.iter())
        }
        fn get_unvalidated(&self) -> Box<dyn Iterator<Item = &Message> + '_> {
            unimplemented!()
        }
        fn get_current_start_height(&self) -> Height {
            unimplemented!()
        }
        fn validated_contains(&self, _msg: &Message) -> bool {
            unimplemented!()
        }
    }

    #[test]
    fn test_select_dealings_caps_at_collection_threshold() {
        // collection_threshold = max_corrupt_dealers + 1 = 2
        let id = local_dkg_id(NiDkgTag::LowThreshold);
        let configs: BTreeMap<_, _> = [(id.clone(), make_test_config(id.clone(), 1))].into();

        // Create 4 dealings for the same config, from different dealers.
        let pool = TestDkgPool {
            messages: (0..4).map(|i| create_dealing(i, id.clone())).collect(),
        };

        let configs: BTreeMap<&NiDkgId, &NiDkgConfig> = configs.iter().collect();
        let selected = select_dealings_for_payload(&configs, &HashSet::new(), &pool, 10);

        // Only collection_threshold (2) dealings should be included.
        assert_eq!(selected.len(), 2);
        for (i, msg) in selected.iter().enumerate() {
            assert_eq!(msg.content.dkg_id, id);
            assert_eq!(msg.signature.signer, node_test_id(i as u64));
        }
    }

    #[test]
    fn test_select_dealings_filters_duplicate_dealers() {
        let id = local_dkg_id(NiDkgTag::LowThreshold);
        let configs: BTreeMap<_, _> = [(id.clone(), make_test_config(id.clone(), 1))].into();
        let configs: BTreeMap<&NiDkgId, &NiDkgConfig> = configs.iter().collect();

        // Dealer 0 already on chain
        let dealers_from_chain: HashSet<_> = [(id.clone(), node_test_id(0))].into();

        // 4 more dealings in pool, including a dealing from dealer 0
        let pool = TestDkgPool {
            messages: (0..4).map(|i| create_dealing(i, id.clone())).collect(),
        };

        let selected = select_dealings_for_payload(&configs, &dealers_from_chain, &pool, 10);

        // Dealer 0's dealing should be filtered out, only dealer 1's remains.
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].signature.signer, node_test_id(1));
        assert_eq!(selected[0].content.dkg_id, id);
    }

    #[test]
    fn test_select_dealings_respects_max_dealings_per_block() {
        let local_id = local_dkg_id(NiDkgTag::LowThreshold);
        let remote_id = remote_dkg_id(NiDkgTag::LowThreshold);

        // Both configs have collection_threshold = 4
        let configs: BTreeMap<_, _> = [
            (local_id.clone(), make_test_config(local_id.clone(), 3)),
            (remote_id.clone(), make_test_config(remote_id.clone(), 3)),
        ]
        .into();
        let configs: BTreeMap<&NiDkgId, &NiDkgConfig> = configs.iter().collect();

        let pool = TestDkgPool {
            messages: (0..4)
                .map(|i| create_dealing(i, local_id.clone()))
                .chain((4..8).map(|i| create_dealing(i, remote_id.clone())))
                .collect(),
        };

        let selected = select_dealings_for_payload(&configs, &HashSet::new(), &pool, 3);

        assert_eq!(selected.len(), 3);
        // All 3 should be remote (prioritized), since remote has 4 available.
        for (i, msg) in selected.iter().enumerate() {
            assert_eq!(msg.content.dkg_id, remote_id);
            assert_eq!(msg.signature.signer, node_test_id(4 + i as u64));
        }
    }

    #[test]
    fn test_select_dealings_ignores_unknown_configs() {
        let known_id = local_dkg_id(NiDkgTag::LowThreshold);
        let unknown_id = local_dkg_id(NiDkgTag::HighThreshold);

        let configs: BTreeMap<_, _> =
            [(known_id.clone(), make_test_config(known_id.clone(), 1))].into();
        let configs: BTreeMap<&NiDkgId, &NiDkgConfig> = configs.iter().collect();

        let pool = TestDkgPool {
            messages: vec![
                create_dealing(0, unknown_id),
                create_dealing(1, known_id.clone()),
            ],
        };

        let selected = select_dealings_for_payload(&configs, &HashSet::new(), &pool, 10);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].content.dkg_id, known_id);
        assert_eq!(selected[0].signature.signer, node_test_id(1));
    }

    #[test]
    fn test_select_dealings_remote_priority_with_threshold_cap() {
        let local_id = local_dkg_id(NiDkgTag::LowThreshold);
        let remote_id = remote_dkg_id(NiDkgTag::LowThreshold);

        // collection_threshold = 2 for both
        let configs: BTreeMap<_, _> = [
            (local_id.clone(), make_test_config(local_id.clone(), 1)),
            (remote_id.clone(), make_test_config(remote_id.clone(), 1)),
        ]
        .into();
        let configs: BTreeMap<&NiDkgId, &NiDkgConfig> = configs.iter().collect();

        // 3 local dealings, 3 remote dealings
        let pool = TestDkgPool {
            messages: (0..3)
                .map(|i| create_dealing(i, local_id.clone()))
                .chain((3..6).map(|i| create_dealing(i, remote_id.clone())))
                .collect(),
        };

        let selected = select_dealings_for_payload(&configs, &HashSet::new(), &pool, 2);
        assert_eq!(selected.len(), 2);
        assert!(selected.iter().all(|msg| msg.content.dkg_id == remote_id));
        assert_eq!(
            BTreeSet::from_iter(selected.iter().map(|msg| msg.signature.signer)),
            BTreeSet::from_iter((3..5).map(node_test_id))
        );

        let selected = select_dealings_for_payload(&configs, &HashSet::new(), &pool, 10);

        // 2 remote + 2 local (both capped at collection_threshold)
        assert_eq!(selected.len(), 4);
        assert_eq!(
            BTreeSet::from_iter(
                selected
                    .iter()
                    .map(|msg| (msg.content.dkg_id.clone(), msg.signature.signer))
            ),
            BTreeSet::from_iter([
                (remote_id.clone(), node_test_id(3)),
                (remote_id.clone(), node_test_id(4)),
                (local_id.clone(), node_test_id(0)),
                (local_id.clone(), node_test_id(1))
            ])
        );
    }

    #[test]
    fn test_select_dealings_prioritizes_remote_target_with_lower_remaining_capacity() {
        let remote_low_remaining_id = remote_dkg_id_with_target(NiDkgTag::LowThreshold, [0_u8; 32]);
        let remote_high_remaining_id =
            remote_dkg_id_with_target(NiDkgTag::LowThreshold, [1_u8; 32]);

        // collection_threshold = 3 for both
        let configs: BTreeMap<_, _> = [
            (
                remote_low_remaining_id.clone(),
                make_test_config(remote_low_remaining_id.clone(), 2),
            ),
            (
                remote_high_remaining_id.clone(),
                make_test_config(remote_high_remaining_id.clone(), 2),
            ),
        ]
        .into();
        let configs: BTreeMap<&NiDkgId, &NiDkgConfig> = configs.iter().collect();

        // Some dealings already included on chain:
        // - remote_low_remaining has 2 on chain, so 1 remaining.
        // - remote_high_remaining has 1 on chain, so 2 remaining.
        let dealers_from_chain: HashSet<_> = [
            (remote_low_remaining_id.clone(), node_test_id(0)),
            (remote_low_remaining_id.clone(), node_test_id(1)),
            (remote_high_remaining_id.clone(), node_test_id(0)),
        ]
        .into();

        let pool = TestDkgPool {
            messages: vec![
                create_dealing(1, remote_high_remaining_id.clone()),
                create_dealing(2, remote_low_remaining_id.clone()),
            ],
        };

        let selected = select_dealings_for_payload(&configs, &dealers_from_chain, &pool, 1);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].content.dkg_id, remote_low_remaining_id);

        let selected = select_dealings_for_payload(&configs, &dealers_from_chain, &pool, 10);
        assert_eq!(selected.len(), 2);
        assert_eq!(
            BTreeSet::from_iter(selected.iter().map(|msg| msg.content.dkg_id.clone())),
            BTreeSet::from_iter([remote_low_remaining_id, remote_high_remaining_id])
        );
    }

    #[test]
    fn test_select_dealings_remote_priority_requires_completed_remote_below_interval_limit() {
        let local_id = local_dkg_id(NiDkgTag::LowThreshold);
        let remote_completed_id = remote_dkg_id_with_target(NiDkgTag::LowThreshold, [0_u8; 32]);
        let remote_active_id = remote_dkg_id_with_target(NiDkgTag::LowThreshold, [1_u8; 32]);

        // collection_threshold = 2 for all configs
        let configs: BTreeMap<_, _> = [
            (local_id.clone(), make_test_config(local_id.clone(), 1)),
            (
                remote_completed_id.clone(),
                make_test_config(remote_completed_id.clone(), 1),
            ),
            (
                remote_active_id.clone(),
                make_test_config(remote_active_id.clone(), 1),
            ),
        ]
        .into();
        let configs: BTreeMap<&NiDkgId, &NiDkgConfig> = configs.iter().collect();

        // remote_completed has no remaining capacity, so with
        // MAX_REMOTE_DKGS_PER_INTERVAL = 1 we should not prioritize remote.
        let dealers_from_chain: HashSet<_> = [
            (remote_completed_id.clone(), node_test_id(0)),
            (remote_completed_id.clone(), node_test_id(1)),
        ]
        .into();

        let pool = TestDkgPool {
            messages: vec![
                create_dealing(0, remote_active_id.clone()),
                create_dealing(1, remote_completed_id.clone()),
                create_dealing(2, local_id.clone()),
                create_dealing(3, local_id.clone()),
                create_dealing(4, local_id.clone()),
            ],
        };

        // With max_dealings_per_block = 1, we should prioritize local.
        let selected = select_dealings_for_payload(&configs, &dealers_from_chain, &pool, 1);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].content.dkg_id, local_id);

        // With max_dealings_per_block = 10, we should prioritize local (although it has higher remaining capacity).
        // We should also include remote, once local is capped at collection_threshold.
        let selected = select_dealings_for_payload(&configs, &dealers_from_chain, &pool, 10);
        assert_eq!(selected.len(), 3);
        assert_eq!(
            selected
                .iter()
                .filter(|msg| msg.content.dkg_id == local_id)
                .count(),
            2
        );
        assert_eq!(
            selected
                .iter()
                .filter(|msg| msg.content.dkg_id == remote_active_id)
                .count(),
            1
        );
    }

    #[test]
    fn test_select_dealings_uses_target_subnet_as_tie_breaker() {
        let remote_target_0 = remote_dkg_id_with_target(NiDkgTag::LowThreshold, [0_u8; 32]);
        let remote_target_1 = remote_dkg_id_with_target(NiDkgTag::LowThreshold, [1_u8; 32]);

        // collection_threshold = 2 for both, so remaining capacities tie.
        let configs: BTreeMap<_, _> = [
            (
                remote_target_0.clone(),
                make_test_config(remote_target_0.clone(), 1),
            ),
            (
                remote_target_1.clone(),
                make_test_config(remote_target_1.clone(), 1),
            ),
        ]
        .into();
        let configs: BTreeMap<&NiDkgId, &NiDkgConfig> = configs.iter().collect();

        let pool = TestDkgPool {
            messages: vec![
                create_dealing(0, remote_target_1.clone()),
                create_dealing(1, remote_target_0.clone()),
            ],
        };

        let selected = select_dealings_for_payload(&configs, &HashSet::new(), &pool, 1);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].content.dkg_id, remote_target_0);
    }

    #[test]
    fn test_select_dealings_completed_remote_is_counted_per_target_id() {
        let target_id = [7_u8; 32];
        let local_low_id = local_dkg_id(NiDkgTag::LowThreshold);
        let remote_low_id = remote_dkg_id_with_target(NiDkgTag::LowThreshold, target_id);
        let remote_high_id = remote_dkg_id_with_target(NiDkgTag::HighThreshold, target_id);

        // collection_threshold = 2 for all configs.
        let configs: BTreeMap<_, _> = [
            (
                local_low_id.clone(),
                make_test_config(local_low_id.clone(), 1),
            ),
            (
                remote_low_id.clone(),
                make_test_config(remote_low_id.clone(), 1),
            ),
            (
                remote_high_id.clone(),
                make_test_config(remote_high_id.clone(), 1),
            ),
        ]
        .into();
        let configs: BTreeMap<&NiDkgId, &NiDkgConfig> = configs.iter().collect();

        // remote_low is completed, remote_high still has remaining capacity.
        // Both remotes share one target ID, so that target should not count as "completed".
        let dealers_from_chain: HashSet<_> = [
            (remote_low_id.clone(), node_test_id(0)),
            (remote_low_id.clone(), node_test_id(1)),
            (remote_high_id.clone(), node_test_id(0)),
        ]
        .into();

        let pool = TestDkgPool {
            messages: vec![
                create_dealing(1, local_low_id.clone()),
                create_dealing(1, remote_high_id.clone()),
            ],
        };

        // With MAX_REMOTE_DKGS_PER_INTERVAL = 1 and no completed remote target IDs,
        // remote dealings should still be prioritized.
        let selected = select_dealings_for_payload(&configs, &dealers_from_chain, &pool, 1);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].content.dkg_id, remote_high_id);

        let selected = select_dealings_for_payload(&configs, &dealers_from_chain, &pool, 10);
        assert_eq!(selected.len(), 2);
        assert_eq!(
            BTreeSet::from_iter(selected.iter().map(|msg| msg.content.dkg_id.clone())),
            BTreeSet::from_iter([remote_high_id, local_low_id])
        );
    }

    #[test]
    fn test_select_dealings_returns_empty_when_preselection_finds_no_candidates() {
        let local_id = local_dkg_id(NiDkgTag::LowThreshold);

        // collection_threshold = 2
        let configs: BTreeMap<_, _> =
            [(local_id.clone(), make_test_config(local_id.clone(), 1))].into();
        let configs: BTreeMap<&NiDkgId, &NiDkgConfig> = configs.iter().collect();

        // Capacity for this config is already exhausted on chain.
        let dealers_from_chain: HashSet<_> = [
            (local_id.clone(), node_test_id(0)),
            (local_id.clone(), node_test_id(1)),
        ]
        .into();

        // Pool contains dealings, but all must be filtered out by pre-selection.
        let pool = TestDkgPool {
            messages: vec![
                create_dealing(2, local_id.clone()),
                create_dealing(3, local_id.clone()),
            ],
        };

        let selected = select_dealings_for_payload(&configs, &dealers_from_chain, &pool, 10);
        assert!(selected.is_empty());
    }
}
