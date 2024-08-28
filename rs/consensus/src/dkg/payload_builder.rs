use super::{
    utils, MAX_REMOTE_DKGS_PER_INTERVAL, MAX_REMOTE_DKG_ATTEMPTS,
    REMOTE_DKG_REPEATED_FAILURE_ERROR, TAGS,
};
use ic_consensus_utils::{crypto::ConsensusCrypto, pool_reader::PoolReader};
use ic_interfaces::{crypto::ErrorReproducibility, dkg::DkgPool};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{StateManager, StateManagerError};
use ic_logger::{error, warn, ReplicaLogger};
use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
use ic_registry_client_helpers::{
    crypto::{initial_ni_dkg_transcript_from_registry_record, DkgTranscripts},
    subnet::SubnetRegistry,
};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::ValidationContext,
    consensus::{dkg, dkg::Summary, get_faults_tolerated, Block},
    crypto::{
        threshold_sig::ni_dkg::{
            config::{errors::NiDkgConfigValidationError, NiDkgConfig, NiDkgConfigData},
            errors::create_transcript_error::DkgCreateTranscriptError,
            NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet, NiDkgTranscript,
        },
        CryptoError,
    },
    messages::CallbackId,
    registry::RegistryClientError,
    Height, NodeId, NumberOfNodes, RegistryVersion, SubnetId,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
    time::Duration,
};

/// Errors which could occur when creating a Dkg payload.
#[allow(missing_docs)]
#[derive(Debug, PartialEq)]
pub enum PayloadCreationError {
    CryptoError(CryptoError),
    StateManagerError(StateManagerError),
    DkgCreateTranscriptError(DkgCreateTranscriptError),
    FailedToGetDkgIntervalSettingFromRegistry(RegistryClientError),
    FailedToGetSubnetMemberListFromRegistry(RegistryClientError),
    MissingDkgStartBlock,
}

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
) -> Result<dkg::Payload, PayloadCreationError> {
    let height = parent.height.increment();
    // Get the last summary from the chain.
    let last_summary_block = pool_reader
        .dkg_summary_block(parent)
        .ok_or(PayloadCreationError::MissingDkgStartBlock)?;
    let last_dkg_summary = &last_summary_block.payload.as_ref().as_summary().dkg;

    if last_dkg_summary.get_next_start_height() == height {
        // Since `height` corresponds to the start of a new DKG interval, we create a
        // new summary.
        return create_summary_payload(
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
        .map(dkg::Payload::Summary);
    }

    // If the height is not a start height, create a payload with new dealings.

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
                && !dealers_from_chain.contains(&(msg.content.dkg_id, msg.signature.signer))
        })
        .take(max_dealings_per_block)
        .cloned()
        .collect();
    Ok(dkg::Payload::Dealings(dkg::Dealings::new(
        last_summary_block.height,
        new_validated_dealings,
    )))
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
    last_summary: &Summary,
    parent: &Block,
    registry_version: RegistryVersion,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    validation_context: &ValidationContext,
    logger: ReplicaLogger,
) -> Result<dkg::Summary, PayloadCreationError> {
    let all_dealings = utils::get_dkg_dealings(pool_reader, parent);
    let mut transcripts_for_new_subnets = BTreeMap::new();
    let mut next_transcripts = BTreeMap::new();
    // Try to create transcripts from the last round.
    for (dkg_id, config) in last_summary.configs.iter() {
        match create_transcript(crypto, config, &all_dealings, &logger) {
            Ok(transcript) => {
                let previous_value_found = if dkg_id.target_subnet == NiDkgTargetSubnet::Local {
                    next_transcripts
                        .insert(dkg_id.dkg_tag, transcript)
                        .is_some()
                } else {
                    transcripts_for_new_subnets
                        .insert(*dkg_id, Ok(transcript))
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
                return Err(PayloadCreationError::DkgCreateTranscriptError(err));
            }
        };
    }

    let height = parent.height.increment();

    let (mut configs, transcripts_for_new_subnets, initial_dkg_attempts) = compute_remote_dkg_data(
        subnet_id,
        height,
        registry_client,
        state_manager,
        validation_context,
        transcripts_for_new_subnets,
        &last_summary
            .transcripts_for_new_subnets_with_callback_ids
            .iter()
            .map(|(id, _, result)| (*id, result.clone()))
            .collect(),
        &last_summary.initial_dkg_attempts,
        &logger,
    )?;

    let interval_length = last_summary.next_interval_length;
    let next_interval_length = get_dkg_interval_length(
        registry_client,
        validation_context.registry_version,
        subnet_id,
    )?;
    // Current transcripts come from next transcripts of the last_summary.
    let current_transcripts = last_summary.clone().into_next_transcripts();

    // If the config for the currently computed DKG intervals requires a transcript
    // resharing (currently for high-threshold DKG only), we are going to re-share
    // the next transcripts, as they are the newest ones.
    // If `next_transcripts` does not contain the required transcripts (due to
    // failed DKGs in the past interval) we reshare the current transcripts.
    let reshared_transcripts = if next_transcripts.contains_key(&NiDkgTag::LowThreshold)
        && next_transcripts.contains_key(&NiDkgTag::HighThreshold)
    {
        &next_transcripts
    } else {
        &current_transcripts
    };

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
    )?);

    Ok(Summary::new(
        configs,
        current_transcripts,
        next_transcripts,
        transcripts_for_new_subnets,
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
    let dealings = all_dealings.get(&config.dkg_id()).unwrap_or(&no_dealings);

    ic_interfaces::crypto::NiDkgAlgorithm::create_transcript(crypto, config, dealings)
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
    previous_attempts: &BTreeMap<NiDkgTargetId, u32>,
    logger: &ReplicaLogger,
) -> Result<
    (
        Vec<NiDkgConfig>,
        Vec<(NiDkgId, CallbackId, Result<NiDkgTranscript, String>)>,
        BTreeMap<NiDkgTargetId, u32>,
    ),
    PayloadCreationError,
> {
    let state = state_manager
        .get_state_at(validation_context.certified_height)
        .map_err(PayloadCreationError::StateManagerError)?;
    let (context_configs, errors, valid_target_ids) = process_subnet_call_context(
        subnet_id,
        height,
        registry_client,
        state.get_ref(),
        validation_context,
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
                .find(|(id, _)| eq_sans_height(id, &dkg_id))
            {
                new_transcripts.insert(*id, transcript.clone());
            }
            // If not, we check if we computed a transcript for this config in the last round. And
            // if not, we move the config into the new summary so that we try again in
            // the next round.
            else if !new_transcripts
                .iter()
                .any(|(id, _)| eq_sans_height(id, &dkg_id))
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
    //
    // TODO: use drain_filter once it's stable.
    config_groups.retain(|config_group| {
        let target = config_group
            .first()
            .map(|config| config.dkg_id().target_subnet);
        if let Some(NiDkgTargetSubnet::Remote(id)) = target {
            if failed_target_ids.contains(&id) {
                for config in config_group.iter() {
                    new_transcripts.insert(
                        config.dkg_id(),
                        Err(REMOTE_DKG_REPEATED_FAILURE_ERROR.to_string()),
                    );
                }
                return false;
            }
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

pub(super) fn get_dkg_summary_from_cup_contents(
    cup_contents: CatchUpPackageContents,
    subnet_id: SubnetId,
    registry: &dyn RegistryClient,
    registry_version: RegistryVersion,
) -> Summary {
    // If we're in a NNS subnet recovery case with failover nodes, we extract the registry of the
    // NNS we're recovering.
    let registry_version_of_original_registry = cup_contents
        .registry_store_uri
        .as_ref()
        .map(|v| RegistryVersion::from(v.registry_version));
    let mut transcripts = DkgTranscripts {
        low_threshold: cup_contents
            .initial_ni_dkg_transcript_low_threshold
            .map(|dkg_transcript_record| {
                initial_ni_dkg_transcript_from_registry_record(dkg_transcript_record)
                    .expect("Decoding initial low-threshold DKG transcript failed.")
            })
            .expect("Missing initial low-threshold DKG transcript"),
        high_threshold: cup_contents
            .initial_ni_dkg_transcript_high_threshold
            .map(|dkg_transcript_record| {
                initial_ni_dkg_transcript_from_registry_record(dkg_transcript_record)
                    .expect("Decoding initial high-threshold DKG transcript failed.")
            })
            .expect("Missing initial high-threshold DKG transcript"),
    };

    // If we're in a NNS subnet recovery with failover nodes, we set the transcript versions to the
    // registry version of the recovered NNS, otherwise the oldest registry version used in a CUP is
    // computed incorrectly.
    if let Some(version) = registry_version_of_original_registry {
        transcripts.low_threshold.registry_version = version;
        transcripts.high_threshold.registry_version = version;
    }

    let transcripts = vec![
        (NiDkgTag::LowThreshold, transcripts.low_threshold),
        (NiDkgTag::HighThreshold, transcripts.high_threshold),
    ]
    .into_iter()
    .collect();

    let committee = get_node_list(subnet_id, registry, registry_version)
        .expect("Could not retrieve committee list");

    let height = Height::from(cup_contents.height);
    let configs = get_configs_for_local_transcripts(
        subnet_id,
        committee,
        height,
        &transcripts,
        // If we are in a NNS subnet recovery with failover nodes, we use the registry version of
        // the recovered NNS so that the DKG configs point to the correct registry version and new
        // dealings can be created in the first DKG interval.
        registry_version_of_original_registry.unwrap_or(registry_version),
    )
    .expect("Couldn't generate configs for the genesis summary");
    // For the first 2 intervals we use the length value contained in the
    // genesis subnet record.
    let interval_length = get_dkg_interval_length(registry, registry_version, subnet_id)
        .expect("Could not retrieve the interval length for the genesis summary.");
    let next_interval_length = interval_length;
    Summary::new(
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
    )
}

/// Creates DKG configs for the local subnet for the next DKG intervals.
pub(crate) fn get_configs_for_local_transcripts(
    subnet_id: SubnetId,
    node_ids: BTreeSet<NodeId>,
    start_block_height: Height,
    reshared_transcripts: &BTreeMap<NiDkgTag, NiDkgTranscript>,
    registry_version: RegistryVersion,
) -> Result<Vec<NiDkgConfig>, PayloadCreationError> {
    let mut new_configs = Vec::new();
    for tag in TAGS.iter() {
        let dkg_id = NiDkgId {
            start_block_height,
            dealer_subnet: subnet_id,
            dkg_tag: *tag,
            target_subnet: NiDkgTargetSubnet::Local,
        };
        let (dealers, resharing_transcript) = match tag {
            NiDkgTag::LowThreshold => (node_ids.clone(), None),
            NiDkgTag::HighThreshold => {
                let resharing_transcript = reshared_transcripts.get(&NiDkgTag::HighThreshold);
                (
                    resharing_transcript
                        .map(|transcript| transcript.committee.get().clone())
                        .unwrap_or_else(|| node_ids.clone()),
                    resharing_transcript.cloned(),
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
) -> Result<Height, PayloadCreationError> {
    registry_client
        .get_dkg_interval_length(subnet_id, version)
        .map_err(PayloadCreationError::FailedToGetDkgIntervalSettingFromRegistry)?
        .ok_or_else(|| {
            panic!(
                "No subnet record found for registry version={:?} and subnet_id={:?}",
                version, subnet_id,
            )
        })
}

// Reads the SubnetCallContext and attempts to create DKG configs for new
// subnets for the next round. An Ok return value contains:
// * configs grouped by subnet (low and high threshold configs per subnet)
// * errors produced while generating the configs.
#[allow(clippy::type_complexity)]
fn process_subnet_call_context(
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
    PayloadCreationError,
> {
    let mut new_configs = Vec::new();
    let mut errors = Vec::new();
    let mut valid_target_ids = Vec::new();
    let contexts = &state
        .metadata
        .subnet_call_context_manager
        .setup_initial_dkg_contexts;
    for (_callback_id, context) in contexts.iter() {
        use ic_replicated_state::metadata_state::subnet_call_context_manager::SetupInitialDkgContext;

        let SetupInitialDkgContext {
            request: _,
            nodes_in_target_subnet,
            target_id,
            registry_version,
            time: _,
        } = context;

        // if we haven't reached the required registry version yet, skip this context
        if registry_version > &validation_context.registry_version {
            continue;
        }

        // Dealers must be in the same registry_version.
        let dealers = get_node_list(this_subnet_id, registry_client, *registry_version)?;

        match create_remote_dkg_configs(
            start_block_height,
            this_subnet_id,
            NiDkgTargetSubnet::Remote(*target_id),
            &dealers,
            nodes_in_target_subnet,
            registry_version,
            logger,
        ) {
            Ok((config0, config1)) => {
                new_configs.push(vec![config0, config1]);
                valid_target_ids.push(*target_id);
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
) -> Result<BTreeSet<NodeId>, PayloadCreationError> {
    Ok(registry_client
        .get_node_ids_on_subnet(subnet_id, registry_version)
        .map_err(PayloadCreationError::FailedToGetSubnetMemberListFromRegistry)?
        .unwrap_or_else(|| {
            panic!(
                "No subnet record found for registry version={:?} and subnet_id={:?}",
                registry_version, subnet_id,
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
    let setup_initial_dkg_contexts = &state
        .metadata
        .subnet_call_context_manager
        .setup_initial_dkg_contexts;

    new_transcripts
        .into_iter()
        .filter_map(|(id, result)| {
            if let Some(callback_id) = setup_initial_dkg_contexts
                .iter()
                .filter_map(|(callback_id, context)| {
                    if NiDkgTargetSubnet::Remote(context.target_id) == id.target_subnet {
                        Some(*callback_id)
                    } else {
                        None
                    }
                })
                .last()
            {
                Some((id, callback_id, result))
            } else {
                error!(
                    log,
                    "Unable to find callback id associated with remote dkg id {}, this should not happen",
                    id
                );
                None
            }
        })
        .collect()
}

// This function is called for each entry on the SubnetCallContext. It returns
// either the created high and low configs for the entry or returns two errors
// identified by the NiDkgId.
fn create_remote_dkg_configs(
    start_block_height: Height,
    dealer_subnet: SubnetId,
    target_subnet: NiDkgTargetSubnet,
    dealers: &BTreeSet<NodeId>,
    receivers: &BTreeSet<NodeId>,
    registry_version: &RegistryVersion,
    logger: &ReplicaLogger,
) -> Result<(NiDkgConfig, NiDkgConfig), Vec<(NiDkgId, String)>> {
    let low_thr_dkg_id = NiDkgId {
        start_block_height,
        dealer_subnet,
        dkg_tag: NiDkgTag::LowThreshold,
        target_subnet,
    };

    let high_thr_dkg_id = NiDkgId {
        start_block_height,
        dealer_subnet,
        dkg_tag: NiDkgTag::HighThreshold,
        target_subnet,
    };

    let low_thr_config =
        do_create_remote_dkg_config(&low_thr_dkg_id, dealers, receivers, registry_version);
    let high_thr_config =
        do_create_remote_dkg_config(&high_thr_dkg_id, dealers, receivers, registry_version);
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

fn do_create_remote_dkg_config(
    dkg_id: &NiDkgId,
    dealers: &BTreeSet<NodeId>,
    receivers: &BTreeSet<NodeId>,
    registry_version: &RegistryVersion,
) -> Result<NiDkgConfig, NiDkgConfigValidationError> {
    NiDkgConfig::new(NiDkgConfigData {
        dkg_id: *dkg_id,
        max_corrupt_dealers: NumberOfNodes::from(get_faults_tolerated(dealers.len()) as u32),
        max_corrupt_receivers: NumberOfNodes::from(get_faults_tolerated(receivers.len()) as u32),
        dealers: dealers.clone(),
        receivers: receivers.clone(),
        threshold: NumberOfNodes::from(
            dkg_id.dkg_tag.threshold_for_subnet_of_size(receivers.len()) as u32,
        ),
        registry_version: *registry_version,
        resharing_transcript: None,
    })
}

/// Generates the summary for the genesis block.
pub fn make_genesis_summary(
    registry: &dyn RegistryClient,
    subnet_id: SubnetId,
    registry_version_to_put_in_summary: Option<RegistryVersion>,
) -> Summary {
    let max_backoff = Duration::from_secs(32);
    let mut backoff = Duration::from_secs(1);
    loop {
        match registry.get_cup_contents(subnet_id, registry.get_latest_version()) {
            // Here the `registry_version` corresponds to the registry version at which the
            // initial CUP contents were inserted.
            Ok(versioned_record) => {
                let registry_version = versioned_record.version;
                let summary_registry_version =
                    registry_version_to_put_in_summary.unwrap_or(registry_version);
                let cup_contents = versioned_record.value.expect("Missing CUP contents");
                return get_dkg_summary_from_cup_contents(
                    cup_contents,
                    subnet_id,
                    registry,
                    summary_registry_version,
                );
            }
            _ => {
                if backoff > max_backoff {
                    panic!("Retrieving the Dkg transcripts from registry timed out.")
                }
                std::thread::sleep(backoff);
                backoff *= 2;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_utils::complement_state_manager_with_remote_dkg_requests, *};
    use ic_consensus_mocks::{
        dependencies_with_subnet_params, dependencies_with_subnet_records_with_raw_state_manager,
        Dependencies,
    };
    use ic_crypto_test_utils_ni_dkg::dummy_transcript_for_tests_with_params;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
        time::UNIX_EPOCH,
        RegistryVersion,
    };
    use std::collections::BTreeSet;

    // Tests creation of local configs.
    #[test]
    fn test_get_configs_for_local_transcripts() {
        let prev_committee: Vec<_> = (10..21).map(node_test_id).collect();
        let reshared_transcript = Some(dummy_transcript_for_tests_with_params(
            prev_committee.clone(),
            NiDkgTag::HighThreshold,
            NiDkgTag::HighThreshold.threshold_for_subnet_of_size(prev_committee.len()) as u32,
            888,
        ));
        let receivers: BTreeSet<_> = (3..8).map(node_test_id).collect();
        let start_block_height = Height::from(777);
        let subnet_id = subnet_test_id(123);
        let registry_version = RegistryVersion::from(888);

        // Tests the happy path.
        let configs = get_configs_for_local_transcripts(
            subnet_id,
            receivers.clone(),
            start_block_height,
            &vec![(
                NiDkgTag::HighThreshold,
                reshared_transcript.clone().unwrap(),
            )]
            .into_iter()
            .collect(),
            registry_version,
        )
        .unwrap_or_else(|err| panic!("Couldn't create configs: {:?}", err));

        // We produced exactly two configs, and with expected ids.
        assert_eq!(configs.len(), 2);
        for (index, tag) in TAGS.iter().enumerate() {
            let config = configs[index].clone();
            assert_eq!(
                config.dkg_id(),
                NiDkgId {
                    start_block_height,
                    dealer_subnet: subnet_id,
                    dkg_tag: *tag,
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
                    NiDkgTag::HighThreshold => 3,
                    // low threshold is f + 1, with f same as for high threshold.
                    _ => 2,
                }
            );

            // When the threshold is high, we use the receivers from the reshared
            // transcript as dealers (nodes 10..12), and compute the threshold on that
            // subnet.
            assert_eq!(
                config.max_corrupt_dealers().get(),
                match tag {
                    NiDkgTag::HighThreshold => 3,
                    _ => 1,
                }
            );

            // We use the committee of the reshared transcript as dealers for the high
            // threshold, or the current subnet members, for the low threshold.
            let expected_dealers = match tag {
                NiDkgTag::HighThreshold => {
                    prev_committee.clone().into_iter().collect::<BTreeSet<_>>()
                }
                _ => receivers.clone().into_iter().collect::<BTreeSet<_>>(),
            };
            assert_eq!(config.dealers().get(), &expected_dealers);

            assert_eq!(
                config.resharing_transcript(),
                match tag {
                    NiDkgTag::HighThreshold => &reshared_transcript,
                    _ => &None,
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
                            .build(),
                    )],
                );

                let target_id = NiDkgTargetId::new([0u8; 32]);
                // The first two times, the context will have a request for the given target and
                // not afterwards.
                complement_state_manager_with_remote_dkg_requests(
                    state_manager.clone(),
                    registry.get_latest_version(),
                    vec![10, 11, 12],
                    // XXX: This is a very brittle way to set up this test since
                    // it will cause issues if we access the state manager more
                    // than once in any call.
                    Some(2),
                    Some(target_id),
                );
                complement_state_manager_with_remote_dkg_requests(
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
                    "{:?}",
                    configs
                );

                // This is the first attempt to run DKG for this remote target.
                assert_eq!(initial_dkg_attempts.get(&target_id), Some(&1u32));

                // STEP 2:
                // Call compute_remote_dkg_data again, but this time with an indicator that we
                // have already attempted to run remote DKG for this target
                // MAX_REMOTE_DKG_ATTEMPTS times.
                initial_dkg_attempts.insert(target_id, MAX_REMOTE_DKG_ATTEMPTS);
                let (configs, transcripts_for_new_subnets, initial_dkg_attempts) =
                    compute_remote_dkg_data(
                        subnet_id,
                        Height::from(0),
                        registry.as_ref(),
                        state_manager.as_ref(),
                        &validation_context,
                        BTreeMap::new(),
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
                    transcripts_for_new_subnets
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
                let (configs, transcripts_for_new_subnets, initial_dkg_attempts) =
                    compute_remote_dkg_data(
                        subnet_id,
                        Height::from(0),
                        registry.as_ref(),
                        state_manager.as_ref(),
                        &validation_context,
                        BTreeMap::new(),
                        &BTreeMap::new(),
                        &initial_dkg_attempts,
                        &logger,
                    )
                    .unwrap();

                // No configs are created for this remote target any more.
                assert_eq!(configs.len(), 0);
                // No transcripts or errors are returned for this target.
                assert_eq!(transcripts_for_new_subnets.len(), 0);
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
                        .build(),
                )],
            );
            let mut genesis_summary = make_genesis_summary(&*registry, subnet_id, None);

            // Let's ensure we have no summaries for the whole DKG interval.
            for _ in 0..dkg_interval_len {
                pool.advance_round_normal_operation();
                let block = pool.get_cache().finalized_block();
                assert!(!block.payload.as_ref().is_summary());
            }

            let latest_block = pool.get_cache().finalized_block();
            let create_summary_payload = |last_summary: &Summary| {
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
                if conf.dkg_id().dkg_tag == NiDkgTag::HighThreshold {
                    assert_eq!(
                        next_summary
                            .clone()
                            .next_transcript(&NiDkgTag::HighThreshold)
                            .unwrap(),
                        &conf.resharing_transcript().clone().unwrap()
                    )
                }
            }

            // Remove configs from `genesis_summary`. This emulates the
            // behaviour of DKG failing validations.
            // In this case, the `current_transcripts` are being reshared.
            genesis_summary.configs.clear();
            let next_summary = create_summary_payload(&genesis_summary);
            for (_, conf) in next_summary.configs.iter() {
                if conf.dkg_id().dkg_tag == NiDkgTag::HighThreshold {
                    assert_eq!(
                        next_summary
                            .clone()
                            .current_transcript(&NiDkgTag::HighThreshold),
                        &conf.resharing_transcript().clone().unwrap()
                    )
                }
            }
        });
    }

    // Creates a summary from registry and tests that all fields of the summary
    // contain the expected contents.
    #[test]
    fn test_make_genesis_summary() {
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
                        .build(),
                )],
            );

            let summary = make_genesis_summary(&*registry, subnet_id, None);

            assert_eq!(
                summary.registry_version,
                RegistryVersion::from(initial_registry_version)
            );
            assert_eq!(summary.height, Height::from(0));
            assert_eq!(summary.interval_length, Height::from(dkg_interval_len));
            assert_eq!(summary.next_interval_length, Height::from(dkg_interval_len));
            assert!(summary.next_transcript(&NiDkgTag::LowThreshold).is_none());
            assert!(summary.next_transcript(&NiDkgTag::HighThreshold).is_none());

            for tag in TAGS.iter() {
                let (id, conf) = summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == *tag)
                    .unwrap();

                assert_eq!(
                    id,
                    &NiDkgId {
                        start_block_height: Height::from(0),
                        dealer_subnet: subnet_id,
                        dkg_tag: *tag,
                        target_subnet: NiDkgTargetSubnet::Local,
                    }
                );

                assert_eq!(&conf.dkg_id(), id);
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
                    match *tag {
                        NiDkgTag::LowThreshold => 3,
                        NiDkgTag::HighThreshold => 5,
                    }
                );
            }
        });
    }

    #[test]
    // In this test we check that all summary payloads are created at the expected
    // heights and with the expected contents. Note, we do not test anything related
    // to the presence or contents of transcripts, as this would require using a
    // real CSP.
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
                        .build(),
                )],
            );
            let genesis_summary = make_genesis_summary(&*registry, subnet_id, None);
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

                for tag in TAGS.iter() {
                    let (id, conf) = dkg_summary
                        .configs
                        .iter()
                        .find(|(id, _)| id.dkg_tag == *tag)
                        .unwrap();

                    assert_eq!(
                        id,
                        &NiDkgId {
                            start_block_height: Height::from(expected_height),
                            dealer_subnet: subnet_id,
                            dkg_tag: *tag,
                            target_subnet: NiDkgTargetSubnet::Local,
                        }
                    );

                    assert_eq!(&conf.dkg_id(), id);
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
                        match *tag {
                            NiDkgTag::LowThreshold => 3,
                            NiDkgTag::HighThreshold => 5,
                        }
                    );

                    // In later intervals we can also check that the resharing transcript matches
                    // the expected value.
                    if interval > 0 {
                        if tag == &NiDkgTag::HighThreshold {
                            assert_eq!(
                                dkg_summary
                                    .clone()
                                    .next_transcript(&NiDkgTag::HighThreshold)
                                    .unwrap(),
                                &conf.resharing_transcript().clone().unwrap()
                            );
                        } else {
                            assert!(&conf.resharing_transcript().is_none());
                        }
                    }
                }
            }
        });
    }
}
