use crate::{
    MAX_REMOTE_DKG_ATTEMPTS, MAX_REMOTE_DKGS_PER_INTERVAL, REMOTE_DKG_REPEATED_FAILURE_ERROR,
    utils::{self, tags_iter, vetkd_key_ids_for_subnet},
};
use ic_consensus_utils::{crypto::ConsensusCrypto, pool_reader::PoolReader};
use ic_interfaces::{crypto::ErrorReproducibility, dkg::DkgPool};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{ReplicaLogger, error, warn};
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
        dkg::{DkgDataPayload, DkgPayload, DkgPayloadCreationError, DkgSummary},
        get_faults_tolerated,
    },
    crypto::threshold_sig::ni_dkg::{
        NiDkgDealing, NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
        NiDkgTranscript,
        config::{NiDkgConfig, NiDkgConfigData, errors::NiDkgConfigValidationError},
        errors::create_transcript_error::DkgCreateTranscriptError,
    },
    messages::CallbackId,
};
use std::{
    collections::{BTreeMap, BTreeSet},
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
    state_manager: &dyn StateManager<State = ReplicatedState>,
    validation_context: &ValidationContext,
    logger: ReplicaLogger,
    max_dealings_per_block: usize,
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
            state_manager,
            validation_context,
            logger,
        )
        .map(DkgPayload::Summary)
    } else {
        // If the height is not a start height, create a payload with new dealings.
        create_data_payload(
            pool_reader,
            dkg_pool,
            parent,
            max_dealings_per_block,
            &last_summary_block,
            last_dkg_summary,
        )
        .map(DkgPayload::Data)
    }
}

fn create_data_payload(
    pool_reader: &PoolReader<'_>,
    dkg_pool: Arc<RwLock<dyn DkgPool>>,
    parent: &Block,
    max_dealings_per_block: usize,
    last_summary_block: &Block,
    last_dkg_summary: &DkgSummary,
) -> Result<DkgDataPayload, DkgPayloadCreationError> {
    // Get all dealer ids from the chain.
    let dealers_from_chain = utils::get_dealers_from_chain(pool_reader, parent);
    // Filter from the validated pool all dealings whose dealer has no dealing on
    // the chain yet.
    let new_validated_dealings = dkg_pool
        .read()
        .expect("Couldn't lock DKG pool for reading.")
        .get_validated()
        .filter(|msg| {
            // Make sure the message relates to one of the ongoing DKGs and it's from a unique
            // dealer.
            last_dkg_summary.configs.contains_key(&msg.content.dkg_id)
                && !dealers_from_chain.contains(&(msg.content.dkg_id.clone(), msg.signature.signer))
        })
        .take(max_dealings_per_block)
        .cloned()
        .collect();
    Ok(DkgDataPayload::new(
        last_summary_block.height,
        new_validated_dealings,
    ))
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
    state_manager: &dyn StateManager<State = ReplicatedState>,
    validation_context: &ValidationContext,
    logger: ReplicaLogger,
) -> Result<DkgSummary, DkgPayloadCreationError> {
    let all_dealings = utils::get_dkg_dealings(pool_reader, parent);
    let mut transcripts_for_remote_subnets = BTreeMap::new();
    let mut next_transcripts = BTreeMap::new();
    // Try to create transcripts from the last round.
    for (dkg_id, config) in last_summary.configs.iter() {
        match create_transcript(crypto, config, &all_dealings, &logger) {
            Ok(transcript) => {
                let previous_value_found = if dkg_id.target_subnet == NiDkgTargetSubnet::Local {
                    next_transcripts
                        .insert(dkg_id.dkg_tag.clone(), transcript)
                        .is_some()
                } else {
                    transcripts_for_remote_subnets
                        .insert(dkg_id.clone(), Ok(transcript))
                        .is_some()
                };
                if previous_value_found {
                    unreachable!(
                        "last summary has multiple configs for tag {:?}",
                        dkg_id.dkg_tag
                    );
                }
            }
            Err(err) if err.is_reproducible() => {
                warn!(
                    logger,
                    "Failed to create transcript for dkg id {:?}: {:?}", dkg_id, err
                );
            }
            Err(err) => {
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

    let previous_transcripts = last_summary
        .transcripts_for_remote_subnets
        .iter()
        .map(|(id, _, result)| (id.clone(), result.clone()))
        .collect();

    let (mut configs, transcripts_for_remote_subnets, initial_dkg_attempts) =
        compute_remote_dkg_data(
            subnet_id,
            height,
            registry_client,
            state_manager,
            validation_context,
            transcripts_for_remote_subnets,
            &previous_transcripts,
            &reshared_transcripts,
            &last_summary.initial_dkg_attempts,
            &logger,
        )?;

    let interval_length = last_summary.next_interval_length;
    let next_interval_length = get_dkg_interval_length(
        registry_client,
        validation_context.registry_version,
        subnet_id,
    )?;

    // New configs are created using the new stable registry version proposed by this
    // block, which determines receivers of the dealings.
    configs.append(&mut get_configs_for_local_transcripts(
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
    )?);

    Ok(DkgSummary::new(
        configs,
        current_transcripts,
        next_transcripts,
        transcripts_for_remote_subnets,
        registry_version,
        interval_length,
        next_interval_length,
        height,
        initial_dkg_attempts,
    ))
}

fn create_transcript(
    crypto: &dyn ConsensusCrypto,
    config: &NiDkgConfig,
    all_dealings: &BTreeMap<NiDkgId, BTreeMap<NodeId, NiDkgDealing>>,
    _logger: &ReplicaLogger,
) -> Result<NiDkgTranscript, DkgCreateTranscriptError> {
    let no_dealings = BTreeMap::new();
    let dealings = all_dealings.get(config.dkg_id()).unwrap_or(&no_dealings);

    ic_interfaces::crypto::NiDkgAlgorithm::create_transcript(crypto, config, dealings)
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

#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
fn compute_remote_dkg_data(
    subnet_id: SubnetId,
    height: Height,
    registry_client: &dyn RegistryClient,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    validation_context: &ValidationContext,
    mut new_transcripts: BTreeMap<NiDkgId, Result<NiDkgTranscript, String>>,
    previous_transcripts: &BTreeMap<NiDkgId, Result<NiDkgTranscript, String>>,
    reshared_transcripts: &BTreeMap<NiDkgTag, NiDkgTranscript>,
    previous_attempts: &BTreeMap<NiDkgTargetId, u32>,
    logger: &ReplicaLogger,
) -> Result<
    (
        Vec<NiDkgConfig>,
        Vec<(NiDkgId, CallbackId, Result<NiDkgTranscript, String>)>,
        BTreeMap<NiDkgTargetId, u32>,
    ),
    DkgPayloadCreationError,
> {
    let state = state_manager
        .get_state_at(validation_context.certified_height)
        .map_err(DkgPayloadCreationError::StateManagerError)?;
    let (context_configs, errors, valid_target_ids) = process_subnet_call_context(
        subnet_id,
        height,
        registry_client,
        state.get_ref(),
        validation_context,
        reshared_transcripts,
        logger,
    )?;

    let mut config_groups = Vec::new();
    // In this loop we go over all still open requests for DKGs for other subnets.
    // We check for both (high & low) configs if we have computed transcripts for
    // them. If we did, we move these transcripts into the new summary. If not,
    // we create a new configs group, consisting the remaining outstanding
    // transcripts (at most two).
    for low_high_threshold_configs in context_configs {
        let mut expected_configs = Vec::new();
        for config in low_high_threshold_configs {
            let dkg_id = config.dkg_id();
            // Check if we have a transcript in the previous summary for this config, and
            // if we do, move it to the new summary.
            if let Some((id, transcript)) = previous_transcripts
                .iter()
                .find(|(id, _)| eq_sans_height(id, dkg_id))
            {
                new_transcripts.insert(id.clone(), transcript.clone());
            }
            // If not, we check if we computed a transcript for this config in the last round. And
            // if not, we move the config into the new summary so that we try again in
            // the next round.
            else if !new_transcripts
                .iter()
                .any(|(id, _)| eq_sans_height(id, dkg_id))
            {
                expected_configs.push(config)
            }
        }

        // If some configs are added into the expected_configs in the end, add this
        // group of config(s) into the config_groups.
        if !expected_configs.is_empty() {
            config_groups.push(expected_configs);
        }
    }

    // Remove the data regarding old targets.
    let mut attempts = previous_attempts
        .clone()
        .into_iter()
        .filter(|(target_id, _)| valid_target_ids.contains(target_id))
        .collect::<BTreeMap<_, _>>();

    // Get the target ids that are attempted at least MAX_REMOTE_DKG_ATTEMPTS times.
    let failed_target_ids = attempts
        .iter()
        .filter_map(
            |(target_id, attempt_no)| match *attempt_no >= MAX_REMOTE_DKG_ATTEMPTS {
                true => Some(*target_id),
                false => None,
            },
        )
        .collect::<Vec<_>>();

    // Add errors into 'new_transcripts' for repeatedly failed configs and do not
    // attempt to create transcripts for them any more.
    config_groups.retain(|config_group| {
        let target = config_group
            .first()
            .map(|config| config.dkg_id().target_subnet);
        if let Some(NiDkgTargetSubnet::Remote(id)) = target
            && failed_target_ids.contains(&id)
        {
            for config in config_group.iter() {
                new_transcripts.insert(
                    config.dkg_id().clone(),
                    Err(REMOTE_DKG_REPEATED_FAILURE_ERROR.to_string()),
                );
            }
            return false;
        }
        true
    });

    // Retain not more than `MAX_REMOTE_DKGS_PER_INTERVAL` config groups, each
    // containing at most two configs: for high and low thresholds.
    let selected_config_groups: Vec<_> =
        config_groups[0..MAX_REMOTE_DKGS_PER_INTERVAL.min(config_groups.len())].to_vec();

    for config_group in selected_config_groups.iter() {
        let target = config_group
            .first()
            .map(|config| config.dkg_id().target_subnet);
        if let Some(NiDkgTargetSubnet::Remote(id)) = target {
            *attempts.entry(id).or_insert(0) += 1;
        }
    }

    let configs = selected_config_groups.into_iter().flatten().collect();

    // Add the errors returned during the config generation.
    for (dkg_id, err_str) in errors.into_iter() {
        new_transcripts.insert(dkg_id, Err(err_str));
    }

    let new_transcripts_vec =
        add_callback_ids_to_transcript_results(new_transcripts, state.get_ref(), logger);

    Ok((configs, new_transcripts_vec, attempts))
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
        Vec::new(),      // transcripts for other subnets
        // If we are in a NNS subnet recovery with failover nodes, we use the registry version of
        // the recovered NNS as a DKG summary version which is used as the CUP version.
        registry_version_of_original_registry.unwrap_or(registry_version),
        interval_length,
        next_interval_length,
        height,
        BTreeMap::new(), // initial_dkg_attempts
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

/// Reads the SubnetCallContext and attempts to create DKG configs for remote subnets for the next round
///
/// An Ok return value contains:
/// - configs grouped by subnet, either low and high threshold configs for `setup_initial_dkg` or
///   a high threshold for a vetkey for `reshare_chain_key`
/// - errors produced while generating the configs
#[allow(clippy::type_complexity)]
fn process_subnet_call_context(
    this_subnet_id: SubnetId,
    start_block_height: Height,
    registry_client: &dyn RegistryClient,
    state: &ReplicatedState,
    validation_context: &ValidationContext,
    reshared_transcripts: &BTreeMap<NiDkgTag, NiDkgTranscript>,
    logger: &ReplicaLogger,
) -> Result<
    (
        Vec<Vec<NiDkgConfig>>,
        Vec<(NiDkgId, String)>,
        Vec<NiDkgTargetId>,
    ),
    DkgPayloadCreationError,
> {
    let (init_dkg_configs, init_dkg_errors, init_dkg_valid_target_ids) =
        process_setup_initial_dkg_contexts(
            this_subnet_id,
            start_block_height,
            registry_client,
            state,
            validation_context,
            logger,
        )?;

    let (reshare_key_configs, reshare_key_errors, reshare_key_valid_target_ids) =
        process_reshare_chain_key_contexts(
            this_subnet_id,
            start_block_height,
            registry_client,
            state,
            validation_context,
            reshared_transcripts,
        )?;

    let dkg_configs = init_dkg_configs
        .into_iter()
        .chain(reshare_key_configs)
        .collect();
    let dkg_errors = init_dkg_errors
        .into_iter()
        .chain(reshare_key_errors)
        .collect();
    let dkg_valid_target_ids = init_dkg_valid_target_ids
        .into_iter()
        .chain(reshare_key_valid_target_ids)
        .collect();

    Ok((dkg_configs, dkg_errors, dkg_valid_target_ids))
}

#[allow(clippy::type_complexity)]
fn process_reshare_chain_key_contexts(
    this_subnet_id: SubnetId,
    start_block_height: Height,
    registry_client: &dyn RegistryClient,
    state: &ReplicatedState,
    validation_context: &ValidationContext,
    reshared_transcripts: &BTreeMap<NiDkgTag, NiDkgTranscript>,
) -> Result<
    (
        Vec<Vec<NiDkgConfig>>,
        Vec<(NiDkgId, String)>,
        Vec<NiDkgTargetId>,
    ),
    DkgPayloadCreationError,
> {
    let mut new_configs = Vec::new();
    let mut errors = Vec::new();
    let mut valid_target_ids = Vec::new();
    let contexts = &state
        .metadata
        .subnet_call_context_manager
        .reshare_chain_key_contexts;

    for (_callback_id, context) in contexts.iter() {
        // if we haven't reached the required registry version yet, skip this context
        if context.registry_version > validation_context.registry_version {
            continue;
        }

        // Only process NiDkgMasterPublicKeyId
        let Ok(key_id) = NiDkgMasterPublicKeyId::try_from(context.key_id.clone()) else {
            continue;
        };

        // Dealers must be in the same registry_version.
        let dealers = get_node_list(this_subnet_id, registry_client, context.registry_version)?;

        match create_remote_dkg_config_for_key_id(
            key_id,
            start_block_height,
            this_subnet_id,
            context.target_id,
            &dealers,
            &context.nodes,
            reshared_transcripts,
            &context.registry_version,
        ) {
            Ok(config) => {
                new_configs.push(vec![config]);
                valid_target_ids.push(context.target_id);
            }
            Err(err) => errors.push(*err),
        }
    }
    Ok((new_configs, errors, valid_target_ids))
}

#[allow(clippy::type_complexity)]
fn process_setup_initial_dkg_contexts(
    this_subnet_id: SubnetId,
    start_block_height: Height,
    registry_client: &dyn RegistryClient,
    state: &ReplicatedState,
    validation_context: &ValidationContext,
    logger: &ReplicaLogger,
) -> Result<
    (
        Vec<Vec<NiDkgConfig>>,
        Vec<(NiDkgId, String)>,
        Vec<NiDkgTargetId>,
    ),
    DkgPayloadCreationError,
> {
    let mut new_configs = Vec::new();
    let mut errors = Vec::new();
    let mut valid_target_ids = Vec::new();
    let contexts = &state
        .metadata
        .subnet_call_context_manager
        .setup_initial_dkg_contexts;
    for (_callback_id, context) in contexts.iter() {
        // if we haven't reached the required registry version yet, skip this context
        if context.registry_version > validation_context.registry_version {
            continue;
        }

        // Dealers must be in the same registry_version.
        let dealers = get_node_list(this_subnet_id, registry_client, context.registry_version)?;

        match create_low_high_remote_dkg_configs(
            start_block_height,
            this_subnet_id,
            context.target_id,
            &dealers,
            &context.nodes_in_target_subnet,
            &context.registry_version,
            logger,
        ) {
            Ok((config0, config1)) => {
                new_configs.push(vec![config0, config1]);
                valid_target_ids.push(context.target_id);
            }
            Err(mut err_vec) => errors.append(&mut err_vec),
        };
    }
    Ok((new_configs, errors, valid_target_ids))
}

fn get_node_list(
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

// Compares two DKG ids without considering the start block heights. This
// function is only used for DKGs for other subnets, as the start block height
// is not used to differentiate two DKGs for the same subnet.
fn eq_sans_height(dkg_id1: &NiDkgId, dkg_id2: &NiDkgId) -> bool {
    dkg_id1.dealer_subnet == dkg_id2.dealer_subnet
        && dkg_id1.dkg_tag == dkg_id2.dkg_tag
        && dkg_id1.target_subnet == dkg_id2.target_subnet
}

fn add_callback_ids_to_transcript_results(
    new_transcripts: BTreeMap<NiDkgId, Result<NiDkgTranscript, String>>,
    state: &ReplicatedState,
    log: &ReplicaLogger,
) -> Vec<(NiDkgId, CallbackId, Result<NiDkgTranscript, String>)> {
    // Build a map from target id to callback id
    let call_contexts = &state.metadata.subnet_call_context_manager;
    let callback_id_map = call_contexts
        .setup_initial_dkg_contexts
        .iter()
        .map(|(&callback_id, context)| (context.target_id, callback_id))
        .chain(
            call_contexts
                .reshare_chain_key_contexts
                .iter()
                .map(|(&callback_id, context)| (context.target_id, callback_id)),
        )
        .collect::<BTreeMap<NiDkgTargetId, CallbackId>>();

    new_transcripts
        .into_iter()
        .filter_map(|(id, result)| match id.target_subnet {
            NiDkgTargetSubnet::Local => None,
            NiDkgTargetSubnet::Remote(target_id) => match callback_id_map.get(&target_id) {
                Some(&callback_id) => Some((id, callback_id, result)),
                None => {
                    error!(
                        log,
                        "Unable to find callback id associated with remote dkg id {},\
                            this should not happen",
                        id
                    );
                    None
                }
            },
        })
        .collect()
}

/// This function is called on each entry on the SetupInitialDkgContext. It returns
/// either the created high and low configs for the entry or returns two errors
/// identified by the NiDkgId.
fn create_low_high_remote_dkg_configs(
    start_block_height: Height,
    dealer_subnet: SubnetId,
    target_subnet: NiDkgTargetId,
    dealers: &BTreeSet<NodeId>,
    receivers: &BTreeSet<NodeId>,
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
        dealers,
        receivers,
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

fn create_remote_dkg_config_for_key_id(
    key_id: NiDkgMasterPublicKeyId,
    start_block_height: Height,
    dealer_subnet: SubnetId,
    target_id: NiDkgTargetId,
    dealers: &BTreeSet<NodeId>,
    receivers: &BTreeSet<NodeId>,
    reshared_transcripts: &BTreeMap<NiDkgTag, NiDkgTranscript>,
    registry_version: &RegistryVersion,
) -> Result<NiDkgConfig, Box<(NiDkgId, String)>> {
    let dkg_id = NiDkgId {
        start_block_height,
        dealer_subnet,
        dkg_tag: NiDkgTag::HighThresholdForKey(key_id),
        target_subnet: NiDkgTargetSubnet::Remote(target_id),
    };

    // Find the resharing transcript corresponding to the remote dkg id
    let Some(resharing_transcript) = reshared_transcripts.get(&dkg_id.dkg_tag) else {
        let err = format!(
            "Failed to find resharing transcript for a remote dkg for tag {:?}",
            &dkg_id.dkg_tag
        );
        return Err(Box::new((dkg_id, err)));
    };

    create_remote_dkg_config(
        dkg_id.clone(),
        dealers,
        receivers,
        registry_version,
        Some(resharing_transcript.clone()),
    )
    .map_err(|err| Box::new((dkg_id, format!("{err:?}"))))
}

fn create_remote_dkg_config(
    dkg_id: NiDkgId,
    dealers: &BTreeSet<NodeId>,
    receivers: &BTreeSet<NodeId>,
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
        dealers: dealers.clone(),
        receivers: receivers.clone(),
        registry_version: *registry_version,
        resharing_transcript,
    })
}

#[cfg(test)]
mod tests {
    use crate::tests::test_vet_key_config;

    use super::{super::test_utils::complement_state_manager_with_setup_initial_dkg_request, *};
    use ic_consensus_mocks::{
        Dependencies, dependencies_with_subnet_params,
        dependencies_with_subnet_records_with_raw_state_manager,
    };
    use ic_crypto_test_utils_ni_dkg::dummy_transcript_for_tests_with_params;
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types_private::{VetKdCurve, VetKdKeyId};
    use ic_registry_client_helpers::subnet::SubnetRegistry;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::{SubnetRecordBuilder, add_subnet_record};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        RegistryVersion,
        crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
        time::UNIX_EPOCH,
    };
    use std::collections::BTreeSet;

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
    fn test_return_errors_for_repeatedly_failing_remote_dkg_requests() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            use ic_types::crypto::threshold_sig::ni_dkg::*;
            with_test_replica_logger(|logger| {
                let node_ids = vec![node_test_id(0), node_test_id(1)];
                let dkg_interval_length = 99;
                let subnet_id = subnet_test_id(0);
                let Dependencies {
                    registry,
                    state_manager,
                    ..
                } = dependencies_with_subnet_records_with_raw_state_manager(
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

                let target_id = NiDkgTargetId::new([0u8; 32]);
                // The first two times, the context will have a request for the given target and
                // not afterwards.
                complement_state_manager_with_setup_initial_dkg_request(
                    state_manager.clone(),
                    registry.get_latest_version(),
                    vec![10, 11, 12],
                    // XXX: This is a very brittle way to set up this test since
                    // it will cause issues if we access the state manager more
                    // than once in any call.
                    Some(2),
                    Some(target_id),
                );
                complement_state_manager_with_setup_initial_dkg_request(
                    state_manager.clone(),
                    registry.get_latest_version(),
                    vec![],
                    None,
                    None,
                );

                // Any validation_context
                let validation_context = ValidationContext {
                    registry_version: registry.get_latest_version(),
                    certified_height: Height::from(0),
                    time: ic_types::time::UNIX_EPOCH,
                };

                // STEP 1;
                // Call compute_remote_dkg_data for the first time with this target.
                let (configs, _, mut initial_dkg_attempts) = compute_remote_dkg_data(
                    subnet_id,
                    Height::from(0),
                    registry.as_ref(),
                    state_manager.as_ref(),
                    &validation_context,
                    BTreeMap::new(),
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    &logger,
                )
                .unwrap();

                // Two configs are created for this remote target.
                assert_eq!(
                    configs
                        .iter()
                        .filter(|config| config.dkg_id().target_subnet
                            == NiDkgTargetSubnet::Remote(target_id))
                        .count(),
                    2,
                    "{configs:?}"
                );

                // This is the first attempt to run DKG for this remote target.
                assert_eq!(initial_dkg_attempts.get(&target_id), Some(&1u32));

                // STEP 2:
                // Call compute_remote_dkg_data again, but this time with an indicator that we
                // have already attempted to run remote DKG for this target
                // MAX_REMOTE_DKG_ATTEMPTS times.
                initial_dkg_attempts.insert(target_id, MAX_REMOTE_DKG_ATTEMPTS);
                let (configs, transcripts_for_remote_subnets, initial_dkg_attempts) =
                    compute_remote_dkg_data(
                        subnet_id,
                        Height::from(0),
                        registry.as_ref(),
                        state_manager.as_ref(),
                        &validation_context,
                        BTreeMap::new(),
                        &BTreeMap::new(),
                        &BTreeMap::new(),
                        &initial_dkg_attempts,
                        &logger,
                    )
                    .unwrap();

                // No configs are created for this remote target any more.
                assert_eq!(
                    configs
                        .iter()
                        .filter(|config| config.dkg_id().target_subnet
                            == NiDkgTargetSubnet::Remote(target_id))
                        .count(),
                    0
                );

                // We rather respond with errors for this target.
                assert_eq!(
                    transcripts_for_remote_subnets
                        .iter()
                        .filter(|(dkg_id, _, result)| dkg_id.target_subnet
                            == NiDkgTargetSubnet::Remote(target_id)
                            && *result == Err(REMOTE_DKG_REPEATED_FAILURE_ERROR.to_string()))
                        .count(),
                    2
                );
                // The attempt counter is still kept and unchanged.
                assert_eq!(
                    initial_dkg_attempts.get(&target_id),
                    Some(&MAX_REMOTE_DKG_ATTEMPTS)
                );

                // STEP 3:
                // Call compute_remote_dkg_data the last time, with an empty call context.
                // (As arranged in the initialization of the state manager...)
                let (configs, transcripts_for_remote_subnets, initial_dkg_attempts) =
                    compute_remote_dkg_data(
                        subnet_id,
                        Height::from(0),
                        registry.as_ref(),
                        state_manager.as_ref(),
                        &validation_context,
                        BTreeMap::new(),
                        &BTreeMap::new(),
                        &BTreeMap::new(),
                        &initial_dkg_attempts,
                        &logger,
                    )
                    .unwrap();

                // No configs are created for this remote target any more.
                assert_eq!(configs.len(), 0);
                // No transcripts or errors are returned for this target.
                assert_eq!(transcripts_for_remote_subnets.len(), 0);
                // The corresponding entry is removed from the counter.
                assert_eq!(initial_dkg_attempts.len(), 0);
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
                )
                .unwrap()
            };

            // Test the regular case (Both DKGs succeeded)
            let next_summary = create_summary_payload(&genesis_summary);
            for (_, conf) in next_summary.configs.iter() {
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
            for (_, conf) in next_summary.configs.iter() {
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
}
