//! This module defines an embedding of the dkg algorithm provided by the crypto
//! component into the consensus algorithm that is implemented within this
//! crate.

use crate::consensus::{crypto::ConsensusCrypto, pool_reader::PoolReader};
use ic_crypto::crypto_hash;
use ic_interfaces::{
    consensus_pool::ConsensusPoolCache,
    dkg::{ChangeAction, ChangeSet, Dkg, DkgGossip, DkgPool},
    registry::RegistryClient,
    state_manager::{StateManager, StateManagerError},
    validation::{ValidationError, ValidationResult},
};
use ic_logger::{error, warn, ReplicaLogger};
use ic_metrics::buckets::{decimal_buckets, linear_buckets};
use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
use ic_registry_client::helper::{
    crypto::{initial_ni_dkg_transcript_from_registry_record, DkgTranscripts},
    subnet::SubnetRegistry,
};
use ic_replicated_state::ReplicatedState;
use ic_types::batch::ValidationContext;
use ic_types::consensus::get_faults_tolerated;
use ic_types::{
    artifact::{DkgMessageAttribute, DkgMessageId, Priority, PriorityFn},
    consensus::{
        dkg,
        dkg::{DealingContent, Message, Summary},
        Block, BlockPayload, CatchUpContent, CatchUpPackage, HashedBlock, HashedRandomBeacon,
        Payload, RandomBeaconContent, Rank, ThresholdSignature,
    },
    crypto::{
        threshold_sig::ni_dkg::{
            config::{errors::NiDkgConfigValidationError, NiDkgConfig, NiDkgConfigData},
            errors::{
                create_transcript_error::DkgCreateTranscriptError,
                verify_dealing_error::DkgVerifyDealingError,
            },
            NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetSubnet, NiDkgTranscript,
        },
        CryptoError, Signed,
    },
    registry::RegistryClientError,
    Height, NodeId, NumberOfNodes, RegistryVersion, SubnetId, Time,
};

use ic_types::crypto::{CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash};
use phantom_newtype::Id;
use prometheus::{Histogram, IntCounterVec};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

// The maximal number of DKGs for other subnets we want to run in one interval.
const MAX_REMOTE_DKGS_PER_INTERVAL: usize = 1;

// Currently we assume that we run DKGs for all of these tags.
const TAGS: [NiDkgTag; 2] = [NiDkgTag::LowThreshold, NiDkgTag::HighThreshold];

/// Transient Dkg message validation errors.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum PermanentError {
    CryptoError(CryptoError),
    DkgCreateTranscriptError(DkgCreateTranscriptError),
    DkgVerifyDealingError(DkgVerifyDealingError),
    MismatchedDkgSummary(dkg::Summary, dkg::Summary),
    MissingDkgConfigForDealing,
    LastSummaryHasMultipleConfigsForSameTag,
    DkgStartHeightDoesNotMatchParentBlock,
    DkgSummaryAtNonStartHeight(Height),
    DkgDealingAtStartHeight(Height),
    MissingRegistryVersion(Height),
    InvalidDealer(NodeId),
    DealerAlreadyDealt(NodeId),
    FailedToCreateDkgConfig(NiDkgConfigValidationError),
}

/// Permanent Dkg message validation errors.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum TransientError {
    /// Crypto related errors.
    CryptoError(CryptoError),
    StateManagerError(StateManagerError),
    DkgCreateTranscriptError(DkgCreateTranscriptError),
    DkgVerifyDealingError(DkgVerifyDealingError),
    FailedToGetDkgIntervalSettingFromRegistry(RegistryClientError),
    FailedToGetSubnetMemberListFromRegistry(RegistryClientError),
    MissingDkgStartBlock,
}

/// Dkg errors.
pub type DkgMessageValidationError = ValidationError<PermanentError, TransientError>;

impl From<DkgCreateTranscriptError> for PermanentError {
    fn from(err: DkgCreateTranscriptError) -> Self {
        PermanentError::DkgCreateTranscriptError(err)
    }
}

impl From<DkgCreateTranscriptError> for TransientError {
    fn from(err: DkgCreateTranscriptError) -> Self {
        TransientError::DkgCreateTranscriptError(err)
    }
}

impl From<DkgVerifyDealingError> for PermanentError {
    fn from(err: DkgVerifyDealingError) -> Self {
        PermanentError::DkgVerifyDealingError(err)
    }
}

impl From<DkgVerifyDealingError> for TransientError {
    fn from(err: DkgVerifyDealingError) -> Self {
        TransientError::DkgVerifyDealingError(err)
    }
}

impl From<CryptoError> for PermanentError {
    fn from(err: CryptoError) -> Self {
        PermanentError::CryptoError(err)
    }
}

impl From<CryptoError> for TransientError {
    fn from(err: CryptoError) -> Self {
        TransientError::CryptoError(err)
    }
}

impl From<PermanentError> for DkgMessageValidationError {
    fn from(err: PermanentError) -> Self {
        ValidationError::Permanent(err)
    }
}

impl From<TransientError> for DkgMessageValidationError {
    fn from(err: TransientError) -> Self {
        ValidationError::Transient(err)
    }
}

struct Metrics {
    pub on_state_change_duration: Histogram,
    pub on_state_change_processed: Histogram,
}

/// `DkgImpl` is responsible for holding DKG dependencies and for responding to
/// changes in the consensus and DKG pool.
pub struct DkgImpl {
    node_id: NodeId,
    crypto: Arc<dyn ConsensusCrypto>,
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    logger: ReplicaLogger,
    metrics: Metrics,
}

/// `DkgGossipImpl` is a placeholder for gossip related DKG interfaces.
pub struct DkgGossipImpl {}

impl DkgImpl {
    /// Build a new DKG component
    pub fn new(
        node_id: NodeId,
        crypto: Arc<dyn ConsensusCrypto>,
        consensus_cache: Arc<dyn ConsensusPoolCache>,
        metrics_registry: ic_metrics::MetricsRegistry,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            crypto,
            consensus_cache,
            node_id,
            logger,
            metrics: Metrics {
                on_state_change_duration: metrics_registry.histogram(
                    "consensus_dkg_on_state_change_duration_seconds",
                    "The time it took to execute on_state_change(), in seconds",
                    // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                    // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                    decimal_buckets(-4, 2),
                ),
                on_state_change_processed: metrics_registry.histogram(
                    "consensus_dkg_on_state_change_processed",
                    "Number of entries processed by on_state_change()",
                    // 0 - 100
                    linear_buckets(0.0, 1.0, 100),
                ),
            },
        }
    }

    // Create a dealing for the given DKG config if necessary. That is, if this
    // replica is a dealer for the config and hasn't yet created a dealing, it will
    // return a change action to add a dealing.
    fn create_dealing(&self, dkg_pool: &dyn DkgPool, config: &NiDkgConfig) -> Option<ChangeAction> {
        // Do not produce any dealings if the dealers list does not contain the id of
        // the current replica, or the current replica has already produced dealings.
        if !config.dealers().get().contains(&self.node_id)
            || contains_dkg_messages(dkg_pool, config, self.node_id)
        {
            return None;
        }

        let content =
            match ic_interfaces::crypto::NiDkgAlgorithm::create_dealing(&*self.crypto, config) {
                Ok(dealing) => DealingContent::new(dealing, config.dkg_id()),
                Err(err) => {
                    error!(self.logger, "Couldn't create a DKG dealing: {:?}", err);
                    return None;
                }
            };

        match self
            .crypto
            .sign(&content, self.node_id, config.registry_version())
        {
            Ok(signature) => Some(ChangeAction::AddToValidated(Signed { signature, content })),
            Err(err) => {
                error!(self.logger, "Couldn't sign a DKG dealing: {:?}", err);
                None
            }
        }
    }

    // Validates the DKG messages against the provided config. If multiple messages
    // are found for the same dealer, we deduplicate them and — if multiple messages
    // remain — we invalidate all of them, because the dealer is considered as
    // faulty or malicious. If only one message remains, we validate it.
    //
    // Invalidates the message if:
    // - no DKG config among onging DKGs was found,
    // - the dealer is not on the list of dealers wrt. DKG config,
    // - the validated DKG pool already contains a dealing from this dealer,
    // - the dealing signature is invalid,
    // - the dealing is invalid.
    //
    // We skip the validation if an error occurs during the signature or dealing
    // verification.
    fn validate_dealings(
        &self,
        dkg_pool: &dyn DkgPool,
        configs: &BTreeMap<NiDkgId, NiDkgConfig>,
        dkg_start_height: Height,
        messages: Vec<&Message>,
    ) -> ChangeSet {
        // Deduplicate all messages.
        let unique_messages = &messages
            .iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        // Look at the remaining messages after the deduplication.
        let message = match unique_messages.as_slice() {
            [] => return ChangeSet::new(),
            // If there exactly one message remained, we validate it.
            [message] => message,
            // Otherwise, this dealer must have produced multiple distinguishable
            // dealings, so we discard all of them as invalid.
            _ => {
                return messages
                    .iter()
                    .map(|invalid_message| {
                        get_handle_invalid_change_action(
                            invalid_message,
                            format!(
                                "The replica with Id={:?} produced multiple dealings.",
                                &invalid_message.signature.signer
                            ),
                        )
                    })
                    .collect()
            }
        };

        let message_dkg_id = message.content.dkg_id;

        // If the dealing refers to a DKG interval starting at a different height,
        // we skip it.
        if message_dkg_id.start_block_height != dkg_start_height {
            return ChangeSet::new();
        }

        // If the dealing refers a config which is not among the ongoing DKGs,
        // we reject it.
        let config = match configs.get(&message_dkg_id) {
            Some(config) => config,
            None => {
                return get_handle_invalid_change_action(
                    message,
                    format!(
                        "No DKG configuration for Id={:?} was found.",
                        message_dkg_id
                    ),
                )
                .into()
            }
        };

        let dealer_id = &message.signature.signer;

        // If the validated pool already contains this exact message, we skip it.
        if dkg_pool.get_validated().any(|item| item.eq(&message)) {
            return ChangeSet::new();
        }

        // If the dealing comes from a non-dealer, reject it.
        if !config.dealers().get().contains(&dealer_id) {
            return get_handle_invalid_change_action(
                message,
                format!("Replica with Id={:?} is not a dealer.", dealer_id),
            )
            .into();
        }

        // If there exists another validated dealing from this dealer and DKG id, reject
        // it.
        if contains_dkg_messages(dkg_pool, config, *dealer_id) {
            return get_handle_invalid_change_action(
                message,
                format!(
                    "A dealing from replica with Id={:?} is already validated.",
                    dealer_id
                ),
            )
            .into();
        }

        // Verify the signature and reject if it's invalid, or skip, if there was an
        // error.
        match self
            .crypto
            .verify(message, config.registry_version())
            .map_err(DkgMessageValidationError::from)
        {
            Ok(()) => (),
            Err(ValidationError::Permanent(err)) => {
                return get_handle_invalid_change_action(
                    message,
                    format!("Invalid signature: {:?}", err),
                )
                .into()
            }
            Err(ValidationError::Transient(err)) => {
                error!(
                    self.logger,
                    "Couldn't verify the signature of a DKG dealing: {:?}", err
                );
                return ChangeSet::new();
            }
        }

        // Verify the dealing and move to validated if it was successful,
        // reject, if it was rejected, or skip, if there was an error.
        match ic_interfaces::crypto::NiDkgAlgorithm::verify_dealing(
            &*self.crypto,
            &config,
            *dealer_id,
            &message.content.dealing,
        )
        .map_err(DkgMessageValidationError::from)
        {
            Ok(()) => ChangeAction::MoveToValidated((**message).clone()).into(),
            Err(ValidationError::Permanent(err)) => get_handle_invalid_change_action(
                message,
                format!("Dealing verification failed: {:?}", err),
            )
            .into(),
            Err(ValidationError::Transient(err)) => {
                error!(self.logger, "Couldn't verify a DKG dealing: {:?}", err);
                ChangeSet::new()
            }
        }
    }
}

fn get_dealers_from_chain(
    pool_reader: &PoolReader<'_>,
    block: &Block,
) -> HashMap<NiDkgId, HashSet<NodeId>> {
    get_dkg_dealings(pool_reader, &block)
        .into_iter()
        .map(|(dkg_id, dealings)| (dkg_id, dealings.into_iter().map(|(key, _)| key).collect()))
        .collect()
}

fn contains_dkg_messages(dkg_pool: &dyn DkgPool, config: &NiDkgConfig, replica_id: NodeId) -> bool {
    dkg_pool.get_validated().any(|message| {
        message.content.dkg_id == config.dkg_id() && message.signature.signer == replica_id
    })
}

fn get_handle_invalid_change_action<T: AsRef<str>>(message: &Message, reason: T) -> ChangeAction {
    ChangeAction::HandleInvalid(ic_crypto::crypto_hash(message), reason.as_ref().to_string())
}

/// Validates the DKG payload. The parent block is expected to be a valid block.
#[allow(clippy::too_many_arguments)]
pub fn validate_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    dkg_pool: &dyn DkgPool,
    parent: Block,
    payload: &BlockPayload,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    validation_context: &ValidationContext,
    metrics: &IntCounterVec,
) -> ValidationResult<DkgMessageValidationError> {
    let last_summary_block = pool_reader
        .dkg_summary_block(&parent)
        // We expect the parent to be valid, so there will be _always_ a DKG start block on the
        // chain.
        .expect("No DKG start block found for the parent block.");
    let last_summary = BlockPayload::from(last_summary_block.payload).into_summary();

    let current_height = parent.height.increment();
    let is_dkg_start_height = last_summary.get_next_start_height() == current_height;

    if payload.is_summary() {
        if !is_dkg_start_height {
            return Err(PermanentError::DkgSummaryAtNonStartHeight(current_height).into());
        }
        let registry_version = pool_reader
            .registry_version(current_height)
            .expect("Couldn't get the registry version.");
        let expected_summary = create_summary_payload(
            subnet_id,
            registry_client,
            crypto,
            pool_reader,
            last_summary,
            &parent,
            registry_version,
            state_manager,
            validation_context,
            ic_logger::replica_logger::no_op_logger(),
        )?;
        let expected_payload = expected_summary.into();
        if payload != &expected_payload {
            return Err(PermanentError::MismatchedDkgSummary(
                expected_payload.as_summary().clone(),
                payload.as_summary().clone(),
            )
            .into());
        }
        Ok(())
    } else {
        if is_dkg_start_height {
            return Err(PermanentError::DkgDealingAtStartHeight(current_height).into());
        }
        validate_dealings_payload(
            crypto,
            pool_reader,
            dkg_pool,
            &last_summary,
            payload.dkg_interval_start_height(),
            &payload.as_dealings().messages,
            &parent,
            metrics,
        )
    }
}

/// Creates the DKG payload for a new block proposal with the given parent. If
/// the new height corresponds to a new DKG start interval, creates a summary,
/// otherwise it creates a payload containing new dealing for the
/// current interval.
#[allow(clippy::too_many_arguments)]
pub fn create_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    dkg_pool: Arc<RwLock<dyn DkgPool>>,
    parent: Block,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    validation_context: &ValidationContext,
    logger: ReplicaLogger,
    max_dealings_per_block: usize,
    dealing_age_threshold_ms: u64,
) -> Result<dkg::Payload, TransientError> {
    let height = parent.height.increment();
    // Get the last summary from the chain.
    let last_summary_block = pool_reader
        .dkg_summary_block(&parent)
        .ok_or_else(|| TransientError::MissingDkgStartBlock)?;
    let last_summary = BlockPayload::from(last_summary_block.payload).into_summary();

    if last_summary.get_next_start_height() == height {
        // Since `height` corresponds to the start of a new DKG interval, we create a
        // new summary.
        return create_summary_payload(
            subnet_id,
            registry_client,
            &*crypto,
            pool_reader,
            last_summary,
            &parent,
            last_summary_block.context.registry_version,
            state_manager,
            validation_context,
            logger,
        )
        .map(dkg::Payload::Summary);
    }

    // If the height is not a start height, create a payload with new dealings.

    // Get all dealer ids from the chain.
    let dealers_from_chain = get_dealers_from_chain(pool_reader, &parent);
    let age_threshold = Duration::from_millis(dealing_age_threshold_ms);
    // Filter from the validated pool all dealings whose dealer has no dealing on
    // the chain yet.
    let new_validated_dealings = dkg_pool
        .read()
        .expect("Couldn't lock DKG pool for reading.")
        .get_validated_older_than(age_threshold)
        .filter(|msg| {
            // Make sure the message relates to one of the ongoing DKGs.
            last_summary.configs.contains_key(&msg.content.dkg_id) &&
                    // The message is from a unique dealer.
                    match dealers_from_chain.get(&msg.content.dkg_id) {
                        // If no list of dealers for the given DKG id was found, this must be the
                        // first dealer for this DKG id and we need the dealing.
                        None => true,
                        // If we have a list of dealers for the given DKG Id, make sure the
                        // new dealer is not on this list.
                        Some(dealers) => !dealers.contains(&msg.signature.signer)
                    }
        })
        .take(max_dealings_per_block)
        .cloned()
        .collect();
    Ok(dkg::Payload::Dealings(dkg::Dealings::new(
        last_summary_block.height,
        new_validated_dealings,
    )))
}

/* Creates a summary payload for the given parent and registry_version.
 *
 * We compute the summary from prev_summary as follows:
 * summary.current_transcript =
 *   prev_summary.next_transcript.unwrap_or_else(
 *      prev_summary.current_transcript
 *   )
 * // compute transcript from the dealings in the past interval
 * summary.next_transcript =  ...;
 * summary.configs.resharing_transcript = summary.current_transcript
 */
#[allow(clippy::too_many_arguments)]
fn create_summary_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    last_summary: Summary,
    parent: &Block,
    registry_version: RegistryVersion,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    validation_context: &ValidationContext,
    logger: ReplicaLogger,
) -> Result<dkg::Summary, TransientError> {
    let all_dealings = get_dkg_dealings(pool_reader, parent);
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
            Err(DkgMessageValidationError::Permanent(err)) => {
                warn!(
                    logger,
                    "Failed to create transcript for dkg id {:?}: {:?}", dkg_id, err
                );
            }
            Err(DkgMessageValidationError::Transient(err)) => {
                return Err(err);
            }
        };
    }

    let height = parent.height.increment();
    let mut config_groups = Vec::new();

    // In this loop we go over all still open requests for DKGs for other subnets.
    // We check for both (high & low) configs if we have computed transcripts for
    // them. If we did, we move these transcripts into the new summary. If not,
    // we create a new configs group, consisting the remaining outstanding
    // transcripts (at most two).
    for low_high_threshold_configs in get_configs_for_new_subnets(
        subnet_id,
        height,
        registry_client,
        state_manager,
        validation_context,
    )? {
        let mut expected_configs = Vec::new();
        for config in low_high_threshold_configs {
            let dkg_id = config.dkg_id();
            // Check if we have a transcript in the previous summary for this config, and
            // if we do, move it to the new summary.
            if let Some((id, transcript)) = last_summary
                .transcripts_for_new_subnets()
                .iter()
                .find(|(id, _)| eq_sans_height(id, &dkg_id))
            {
                transcripts_for_new_subnets.insert(*id, transcript.clone());
            }
            // If not, we check if we computed a transcript for this config in the last round. And
            // if not, we move the config into the new summary so that we try again in
            // the next round.
            else if !transcripts_for_new_subnets
                .iter()
                .any(|(id, _)| eq_sans_height(id, &dkg_id))
            {
                expected_configs.push(config)
            }
        }
        config_groups.push(expected_configs);
    }

    // Retain not more than `MAX_REMOTE_DKGS_PER_INTERVAL` config groups, each
    // containing at most two configs: for high and low thresholds.
    let mut configs: Vec<_> = config_groups
        [0..MAX_REMOTE_DKGS_PER_INTERVAL.min(config_groups.len())]
        .to_vec()
        .into_iter()
        .flatten()
        .collect();

    let interval_length = last_summary.next_interval_length;
    let next_interval_length =
        get_dkg_interval_length(registry_client, registry_version, subnet_id)?;
    // Current transcripts come from next transcripts of the last_summary.
    let current_transcripts = last_summary.into_next_transcripts();
    // If the config for the currently computed DKG intervals requires a transcript
    // resharing (currently for high-threshold DKG only), we are going to re-share
    // the _current_ transcripts, as they are the newest ones, which are finalized.
    let reshared_transcripts = &current_transcripts;

    configs.append(&mut get_configs_for_local_transcripts(
        subnet_id,
        get_node_list(subnet_id, registry_client, registry_version)?,
        height,
        reshared_transcripts,
        registry_version,
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
    ))
}

// Compares two DKG ids without considering the start block heights. This
// function is only used for DKGs for other subnets, as the start block height
// is not used to differentiate two DKGs for the same subnet.
fn eq_sans_height(dkg_id1: &NiDkgId, dkg_id2: &NiDkgId) -> bool {
    dkg_id1.dealer_subnet == dkg_id2.dealer_subnet
        && dkg_id1.dkg_tag == dkg_id2.dkg_tag
        && dkg_id1.target_subnet == dkg_id2.target_subnet
}

fn create_transcript(
    crypto: &dyn ConsensusCrypto,
    config: &NiDkgConfig,
    all_dealings: &BTreeMap<NiDkgId, BTreeMap<NodeId, NiDkgDealing>>,
    _logger: &ReplicaLogger,
) -> Result<NiDkgTranscript, DkgMessageValidationError> {
    let no_dealings = BTreeMap::new();
    let dealings = all_dealings.get(&config.dkg_id()).unwrap_or(&no_dealings);
    let transcript =
        ic_interfaces::crypto::NiDkgAlgorithm::create_transcript(crypto, &config, dealings)?;
    Ok(transcript)
}

fn get_dkg_interval_length(
    registry_client: &dyn RegistryClient,
    version: RegistryVersion,
    subnet_id: SubnetId,
) -> Result<Height, TransientError> {
    registry_client
        .get_dkg_interval_length(subnet_id, version)
        .map_err(TransientError::FailedToGetDkgIntervalSettingFromRegistry)?
        .ok_or_else(|| {
            panic!(
                "No subnet record found for registry version={:?} and subnet_id={:?}",
                version, subnet_id,
            )
        })
}

// Validates the payload containing dealings.
#[allow(clippy::too_many_arguments)]
fn validate_dealings_payload(
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    dkg_pool: &dyn DkgPool,
    last_summary: &Summary,
    start_height: Height,
    messages: &[Message],
    parent: &Block,
    metrics: &IntCounterVec,
) -> ValidationResult<DkgMessageValidationError> {
    let valid_start_height = parent.payload.as_ref().dkg_interval_start_height();
    if start_height != valid_start_height {
        return Err(PermanentError::DkgStartHeightDoesNotMatchParentBlock.into());
    }

    // Get a list of all dealers, who created a dealing already, indexed by DKG id.
    let dealers_from_chain = get_dealers_from_chain(pool_reader, &parent);

    // Check that all messages have a valid DKG config from the summary and the
    // dealer is valid, then verify each dealing.
    for (message, config) in messages
        .iter()
        .map(|m| (m, last_summary.configs.get(&m.content.dkg_id)))
    {
        metrics.with_label_values(&["total"]).inc();
        // Skip the rest if already present in DKG pool
        if dkg_pool.validated_contains(message) {
            metrics.with_label_values(&["dkg_pool_hit"]).inc();
            continue;
        }

        match config {
            None => {
                return Err(PermanentError::MissingDkgConfigForDealing.into());
            }
            Some(config) => {
                let dealer_id = message.signature.signer;
                // If the dealer is not in the set of dealers, reject.
                if !config.dealers().get().contains(&dealer_id) {
                    return Err(PermanentError::InvalidDealer(dealer_id).into());
                }

                // If the dealer created a dealing already, reject.
                if dealers_from_chain
                    .get(&config.dkg_id())
                    .map(|dealers| dealers.contains(&dealer_id))
                    .unwrap_or(false)
                {
                    return Err(PermanentError::DealerAlreadyDealt(dealer_id).into());
                }

                // Verify the signature.
                crypto.verify(message, last_summary.registry_version)?;

                // Verify the dealing.
                ic_interfaces::crypto::NiDkgAlgorithm::verify_dealing(
                    crypto,
                    &config,
                    message.signature.signer,
                    &message.content.dealing,
                )?;
            }
        }
    }
    Ok(())
}

fn get_node_list(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
) -> Result<BTreeSet<NodeId>, TransientError> {
    Ok(registry_client
        .get_node_ids_on_subnet(subnet_id, registry_version)
        .map_err(TransientError::FailedToGetSubnetMemberListFromRegistry)?
        .unwrap_or_else(|| {
            panic!(
                "No subnet record found for registry version={:?} and subnet_id={:?}",
                registry_version, subnet_id,
            )
        })
        .into_iter()
        .collect())
}

/// Creates DKG configs for the local subnet for the next DKG intervals.
pub fn get_configs_for_local_transcripts(
    subnet_id: SubnetId,
    node_ids: BTreeSet<NodeId>,
    start_block_height: Height,
    reshared_transcripts: &BTreeMap<NiDkgTag, NiDkgTranscript>,
    registry_version: RegistryVersion,
) -> Result<Vec<NiDkgConfig>, TransientError> {
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

// Creates DKG configs for new subnets for the next round. Returns configs
// grouped by the subnet (two configs per subnet: for low and high thresholds).
fn get_configs_for_new_subnets(
    this_subnet_id: SubnetId,
    start_block_height: Height,
    registry_client: &dyn RegistryClient,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    validation_context: &ValidationContext,
) -> Result<Vec<Vec<NiDkgConfig>>, TransientError> {
    let mut new_configs = Vec::new();
    let state = state_manager
        .get_state_at(validation_context.certified_height)
        .map_err(TransientError::StateManagerError)?;
    let contexts = &state
        .get_ref()
        .metadata
        .subnet_call_context_manager
        .contexts;
    for (_callback_id, context) in contexts.iter() {
        use ic_replicated_state::metadata_state::SubnetCallContext;

        let SubnetCallContext::SetupInitialDKGContext {
            request: _,
            nodes_in_target_subnet,
            target_id,
            registry_version,
        } = context;

        // if we haven't reached the required registry version yet, skip this context
        if registry_version > &validation_context.registry_version {
            continue;
        }

        let dealers = get_node_list(this_subnet_id, registry_client, *registry_version)?;

        let low_and_high_threshold_configs = TAGS
            .iter()
            .map(|tag| {
                let dkg_id = NiDkgId {
                    start_block_height,
                    dealer_subnet: this_subnet_id,
                    dkg_tag: *tag,
                    target_subnet: NiDkgTargetSubnet::Remote(*target_id),
                };
                match NiDkgConfig::new(NiDkgConfigData {
                    dkg_id,
                    max_corrupt_dealers: NumberOfNodes::from(
                        get_faults_tolerated(dealers.len()) as u32
                    ),
                    max_corrupt_receivers: NumberOfNodes::from(get_faults_tolerated(
                        nodes_in_target_subnet.len(),
                    ) as u32),
                    dealers: dealers.clone(),
                    receivers: nodes_in_target_subnet.clone(),
                    threshold: NumberOfNodes::from(
                        tag.threshold_for_subnet_of_size(nodes_in_target_subnet.len()) as u32,
                    ),
                    registry_version: *registry_version,
                    resharing_transcript: None,
                }) {
                    Ok(config) => config,
                    Err(err) => unreachable!("Failed to create a DKG config: {:?}", err),
                }
            })
            .collect();
        new_configs.push(low_and_high_threshold_configs);
    }
    Ok(new_configs)
}

// Starts with the given block and creates a nested mapping from the DKG Id to
// the node Id to the dealing. This function panics if multiple dealings
// from one dealer are discovered, hence, we assume a valid block chain.
fn get_dkg_dealings(
    pool_reader: &PoolReader<'_>,
    block: &Block,
) -> BTreeMap<NiDkgId, BTreeMap<NodeId, NiDkgDealing>> {
    pool_reader
        .chain_iterator(block.clone())
        .take_while(|block| !block.payload.is_summary())
        .fold(Default::default(), |mut acc, block| {
            BlockPayload::from(block.payload)
                .into_dealings()
                .messages
                .into_iter()
                .for_each(|msg| {
                    let collected_dealings = acc.entry(msg.content.dkg_id).or_default();
                    assert!(
                        collected_dealings
                            .insert(msg.signature.signer, msg.content.dealing)
                            .is_none(),
                        "Dealings from the same dealers discovered."
                    );
                });
            acc
        })
}

impl Dkg for DkgImpl {
    fn on_state_change(&self, dkg_pool: &dyn DkgPool) -> ChangeSet {
        // This timer will make an entry in the metrics histogram automatically, when
        // it's dropped.
        let _timer = self.metrics.on_state_change_duration.start_timer();
        let dkg_summary_block = self.consensus_cache.summary_block();
        let dkg_summary = dkg_summary_block.payload.as_ref().as_summary();
        let start_height = dkg_summary_block.height;

        if start_height > dkg_pool.get_current_start_height() {
            return ChangeAction::Purge(start_height).into();
        }

        let change_set: ChangeSet = dkg_summary
            .configs
            .par_iter()
            .filter_map(|(_id, config)| self.create_dealing(dkg_pool, config))
            .collect();
        if !change_set.is_empty() {
            return change_set;
        }

        let mut processed = 0;
        let dealings: Vec<Vec<&Message>> = dkg_pool
            .get_unvalidated()
            // Group all unvalidated dealings by dealer.
            .fold(BTreeMap::new(), |mut map, dealing| {
                let key = (dealing.signature.signer, dealing.content.dkg_id);
                let dealings = map.entry(key).or_insert_with(Vec::new);
                dealings.push(dealing);
                processed += 1;
                map
            })
            // Get the dealings sorted by dealers
            .values()
            .cloned()
            .collect();

        let changeset = dealings
            .par_iter()
            .map(|dealings| {
                self.validate_dealings(
                    dkg_pool,
                    &dkg_summary.configs,
                    start_height,
                    dealings.to_vec(),
                )
            })
            .collect::<Vec<ChangeSet>>()
            .into_iter()
            .flatten()
            .collect::<ChangeSet>();

        self.metrics
            .on_state_change_processed
            .observe(processed as f64);
        changeset
    }
}

impl DkgGossip for DkgGossipImpl {
    fn get_priority_function(
        &self,
        dkg_pool: &dyn DkgPool,
    ) -> PriorityFn<DkgMessageId, DkgMessageAttribute> {
        let start_height = dkg_pool.get_current_start_height();
        Box::new(move |_id, attribute| {
            use std::cmp::Ordering;
            match attribute.interval_start_height.cmp(&start_height) {
                Ordering::Equal => Priority::Fetch,
                Ordering::Greater => Priority::Later,
                Ordering::Less => Priority::Drop,
            }
        })
    }
}

/// Generates the summary for the genesis block.
pub fn make_genesis_summary(
    registry: &dyn RegistryClient,
    subnet_id: SubnetId,
    registry_version_to_put_in_summary: Option<RegistryVersion>,
) -> ic_types::consensus::dkg::Summary {
    let max_backoff = Duration::from_secs(32);
    let mut backoff = Duration::from_secs(1);
    loop {
        match registry.get_cup_contents(subnet_id, registry.get_latest_version()) {
            // Here the `registry_version` corresponds to the registry version at which the
            // initial CUP contents were inserted.
            Ok(versioned_record) => {
                let registry_version = versioned_record.version;
                let summary_registry_version =
                    registry_version_to_put_in_summary.unwrap_or_else(|| registry_version);
                let cup_contents = versioned_record.value.expect("Missing CUP contents");
                let cup_height = Height::new(cup_contents.height);

                let transcripts = get_dkg_transcripts_from_cup_contents(cup_contents);
                let transcripts = vec![
                    (NiDkgTag::LowThreshold, transcripts.low_threshold),
                    (NiDkgTag::HighThreshold, transcripts.high_threshold),
                ]
                .into_iter()
                .collect();

                let committee = get_node_list(subnet_id, registry, registry_version)
                    .expect("Could not retrieve committee list");

                let configs = get_configs_for_local_transcripts(
                    subnet_id,
                    committee,
                    cup_height,
                    &transcripts,
                    registry_version,
                )
                .expect("Couldn't generate configs for the genesis summary");
                // For the first 2 intervals we use the length value contained in the
                // genesis subnet record.
                let interval_length =
                    get_dkg_interval_length(registry, registry_version, subnet_id)
                        .expect("Could not retieve the interval length for the genesis summary.");
                let next_interval_length = interval_length;
                return Summary::new(
                    configs,
                    transcripts,
                    BTreeMap::new(), // next transcripts
                    BTreeMap::new(), // transcripts for other subnets
                    summary_registry_version,
                    interval_length,
                    next_interval_length,
                    cup_height,
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

fn get_dkg_transcripts_from_cup_contents(cup_contents: CatchUpPackageContents) -> DkgTranscripts {
    DkgTranscripts {
        low_threshold: cup_contents
            .initial_ni_dkg_transcript_low_threshold
            .map(initial_ni_dkg_transcript_from_registry_record)
            .expect("Missing initial low-threshold DKG transcript"),
        high_threshold: cup_contents
            .initial_ni_dkg_transcript_high_threshold
            .map(initial_ni_dkg_transcript_from_registry_record)
            .expect("Missing initial high-threshold DKG transcript"),
    }
}

/// Construcs a genesis/recovery CUP from the CUP contents associated with the
/// given subnet
pub fn make_registry_cup(
    registry: &dyn RegistryClient,
    subnet_id: SubnetId,
) -> Option<CatchUpPackage> {
    match registry.get_cup_contents(subnet_id, registry.get_latest_version()) {
        Ok(versioned_record) => {
            let cup_contents = versioned_record.value.expect("Missing CUP contents");
            let registry_version = if let Some(registry_info) = cup_contents.registry_store_uri {
                RegistryVersion::from(registry_info.registry_version)
            } else {
                versioned_record.version
            };
            let dkg_summary = make_genesis_summary(registry, subnet_id, Some(registry_version));
            let cup_height = Height::new(cup_contents.height);

            let low_dkg_id = dkg_summary
                .current_transcript(&NiDkgTag::LowThreshold)
                .dkg_id;
            let high_dkg_id = dkg_summary
                .current_transcript(&NiDkgTag::HighThreshold)
                .dkg_id;
            let block = Block::new(
                Id::from(CryptoHash(Vec::new())),
                Payload::new(crypto_hash, dkg_summary.into()),
                cup_height,
                Rank(0),
                ValidationContext {
                    certified_height: cup_height,
                    registry_version,
                    time: Time::from_nanos_since_unix_epoch(cup_contents.time),
                },
            );
            let random_beacon = Signed {
                content: RandomBeaconContent::new(cup_height, Id::from(CryptoHash(Vec::new()))),
                signature: ThresholdSignature {
                    signer: low_dkg_id,
                    signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
                },
            };
            Some(CatchUpPackage {
                content: CatchUpContent::new(
                    HashedBlock::new(crypto_hash, block),
                    HashedRandomBeacon::new(crypto_hash, random_beacon),
                    Id::from(CryptoHash(cup_contents.state_hash)),
                ),
                signature: ThresholdSignature {
                    signer: high_dkg_id,
                    signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
                },
            })
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::mocks::{
        dependencies, dependencies_with_subnet_params,
        dependencies_with_subnet_records_with_raw_state_manager, Dependencies,
    };
    use ic_artifact_pool::dkg_pool::DkgPoolImpl;
    use ic_interfaces::{
        artifact_pool::UnvalidatedArtifact, consensus_pool::ConsensusPool, dkg::MutableDkgPool,
    };
    use ic_metrics::MetricsRegistry;
    use ic_replicated_state::metadata_state::SubnetCallContext;
    use ic_test_utilities::{
        crypto::CryptoReturningOk,
        registry::{add_subnet_record, SubnetRecordBuilder},
        state_manager::RefMockStateManager,
        types::ids::{node_test_id, subnet_test_id},
        types::messages::RequestBuilder,
        with_test_replica_logger,
    };
    use ic_types::{
        crypto::threshold_sig::ni_dkg::{
            NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
        },
        time::UNIX_EPOCH,
        RegistryVersion,
    };
    use std::collections::BTreeSet;

    #[test]
    // In this test we test the creation of dealing payloads.
    fn test_create_dealings_payload() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let nodes: Vec<_> = (0..3).map(node_test_id).collect();
                let dkg_interval_len = 30;
                let subnet_id = subnet_test_id(222);
                let initial_registry_version = 112;
                let Dependencies {
                    crypto,
                    mut pool,
                    dkg_pool,
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

                // Now we instantiate the DKG component for node Id = 1, who is a dealer.
                let replica_1 = node_test_id(1);
                let dkg = DkgImpl::new(
                    replica_1,
                    crypto.clone(),
                    pool.get_cache(),
                    MetricsRegistry::new(),
                    logger.clone(),
                );

                // Creates two dealings for both thresholds and add them to the pool.
                let change_set = dkg.on_state_change(&*dkg_pool.read().unwrap());
                assert_eq!(change_set.len(), 2);
                dkg_pool.write().unwrap().apply_changes(change_set);

                // Advance the consensus pool for one round and make sure both dealings made it
                // into the block.
                pool.advance_round_normal_operation();
                let block = pool.get_cache().finalized_block();
                let dealings = BlockPayload::from(block.payload).into_dealings();
                if dealings.start_height != Height::from(0) {
                    panic!(
                        "Expected start height in dealings {:?}, but found {:?}",
                        Height::from(0),
                        dealings.start_height
                    )
                }
                assert_eq!(dealings.messages.len(), 2);
                for tag in &TAGS {
                    assert!(dealings.messages.iter().any(
                        |m| m.signature.signer == replica_1 && m.content.dkg_id.dkg_tag == *tag
                    ));
                }

                // Now make sure, the dealing from the same dealer will not be included in a new
                // block anymore.
                pool.advance_round_normal_operation();
                let block = pool.get_cache().finalized_block();
                let dealings = BlockPayload::from(block.payload).into_dealings();
                assert_eq!(dealings.messages.len(), 0);

                // Now we empty the dkg pool, add new dealings from this dealer and make sure
                // they are still not included.
                assert_eq!(dkg_pool.read().unwrap().get_validated().count(), 2);
                dkg_pool
                    .write()
                    .unwrap()
                    .apply_changes(vec![ChangeAction::Purge(block.height)]);
                // Check that the dkg pool is really empty.
                assert_eq!(dkg_pool.read().unwrap().get_validated().count(), 0);
                // Create new dealings; this works, because we cleaned the pool before.
                let change_set = dkg.on_state_change(&*dkg_pool.read().unwrap());
                assert_eq!(change_set.len(), 2);
                dkg_pool.write().unwrap().apply_changes(change_set);
                // Make sure the new dealings are in the pool.
                assert_eq!(dkg_pool.read().unwrap().get_validated().count(), 2);
                // Advance the pool and make sure the dealing are not included.
                pool.advance_round_normal_operation();
                let block = pool.get_cache().finalized_block();
                let dealings = BlockPayload::from(block.payload).into_dealings();
                assert_eq!(dealings.messages.len(), 0);

                // Create another dealer and add his dealings into the unvalidated pool of
                // replica 1.
                let replica_2 = node_test_id(2);
                let dkg_2 = DkgImpl::new(
                    replica_2,
                    crypto,
                    pool.get_cache(),
                    MetricsRegistry::new(),
                    logger,
                );
                let dkg_pool_2 = DkgPoolImpl::new(MetricsRegistry::new());
                match &dkg_2.on_state_change(&dkg_pool_2).as_slice() {
                    &[ChangeAction::AddToValidated(message), ChangeAction::AddToValidated(message2)] =>
                    {
                        dkg_pool.write().unwrap().insert(UnvalidatedArtifact {
                            message: message.clone(),
                            peer_id: replica_1,
                            timestamp: UNIX_EPOCH,
                        });
                        dkg_pool.write().unwrap().insert(UnvalidatedArtifact {
                            message: message2.clone(),
                            peer_id: replica_1,
                            timestamp: UNIX_EPOCH,
                        });
                    }
                    val => panic!("Unexpected change set: {:?}", val),
                };

                // Now we validate these dealings on replica 1 and move them to the validated
                // pool.
                let change_set = dkg.on_state_change(&*dkg_pool.read().unwrap());
                match &change_set.as_slice() {
                    &[ChangeAction::MoveToValidated(_), ChangeAction::MoveToValidated(_)] => {}
                    val => panic!("Unexpected change set: {:?}", val),
                };
                dkg_pool.write().unwrap().apply_changes(change_set);
                assert_eq!(dkg_pool.read().unwrap().get_validated().count(), 4);

                // Now we create a new block and make sure, the dealings made into the payload.
                pool.advance_round_normal_operation();
                let block = pool.get_cache().finalized_block();
                let dealings = BlockPayload::from(block.payload).into_dealings();
                if dealings.start_height != Height::from(0) {
                    panic!(
                        "Expected start height in dealings {:?}, but found {:?}",
                        Height::from(0),
                        dealings.start_height
                    )
                }
                assert_eq!(dealings.messages.len(), 2);
                for tag in &TAGS {
                    assert!(dealings.messages.iter().any(
                        |m| m.signature.signer == replica_2 && m.content.dkg_id.dkg_tag == *tag
                    ));
                }
            });
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
            match BlockPayload::from(block.payload) {
                BlockPayload::Summary(summary) => {
                    assert_eq!(summary, genesis_summary, "Unexpected genesis summary.");
                }
                _ => panic!("Unexpected DKG payload."),
            };

            let mut prev_summary: Option<Summary> = None;

            // Simulate 3 intervals
            for interval in 0..3 {
                // Let's ensure we have no summaries for the whole DKG interval.
                for _ in 0..dkg_interval_len {
                    pool.advance_round_normal_operation();
                    let block = pool.get_cache().finalized_block();
                    assert!(!BlockPayload::from(block.payload).is_summary());
                }

                // Advance one more time and get the summary block.
                pool.advance_round_normal_operation();
                let summary =
                    BlockPayload::from(pool.get_cache().finalized_block().payload).into_summary();

                assert_eq!(
                    summary.registry_version,
                    RegistryVersion::from(initial_registry_version)
                );
                let expected_height = interval * (dkg_interval_len + 1) + dkg_interval_len + 1;
                assert_eq!(summary.height, Height::from(expected_height));
                assert_eq!(summary.interval_length, Height::from(dkg_interval_len));
                assert_eq!(summary.next_interval_length, Height::from(dkg_interval_len));

                for tag in TAGS.iter() {
                    let (id, conf) = summary
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
                                prev_summary
                                    .clone()
                                    .unwrap()
                                    .next_transcript(&NiDkgTag::HighThreshold)
                                    .unwrap(),
                                &conf.resharing_transcript().clone().unwrap()
                            );
                        } else {
                            assert!(&conf.resharing_transcript().is_none());
                        }
                    }
                }
                prev_summary = Some(summary);
            }
        });
    }

    // Tests creation of local configs.
    #[test]
    fn test_get_configs_for_local_transcripts() {
        let prev_committee: Vec<_> = (10..21).map(node_test_id).collect();
        let reshared_transcript = Some(NiDkgTranscript::dummy_transcript_for_tests_with_params(
            prev_committee.clone(),
            NiDkgTag::HighThreshold,
            NiDkgTag::HighThreshold.threshold_for_subnet_of_size(prev_committee.len()) as u32,
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
    fn test_create_dealing_works() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let Dependencies {
                    mut pool, crypto, ..
                } = dependencies(pool_config.clone(), 2);
                let mut dkg_pool = DkgPoolImpl::new(MetricsRegistry::new());
                // Let's check that replica 3, who's not a dealer, does not produce dealings.
                let dkg = DkgImpl::new(
                    node_test_id(3),
                    crypto.clone(),
                    pool.get_cache(),
                    MetricsRegistry::new(),
                    logger.clone(),
                );
                assert!(dkg.on_state_change(&dkg_pool).is_empty());

                // Now we instantiate the DKG component for node Id = 1, who is a dealer.
                let dkg = DkgImpl::new(
                    node_test_id(1),
                    crypto,
                    pool.get_cache(),
                    MetricsRegistry::new(),
                    logger,
                );

                // Make sure the replica creates two dealings for both thresholds.
                let change_set = dkg.on_state_change(&dkg_pool);
                match &change_set.as_slice() {
                    &[ChangeAction::AddToValidated(_), ChangeAction::AddToValidated(_)] => {}
                    val => panic!("Unexpected change set: {:?}", val),
                };

                // Apply the changes and make sure, we do not produce any dealings anymore.
                dkg_pool.apply_changes(change_set);
                assert!(dkg.on_state_change(&dkg_pool).is_empty());

                // Mimic consensus progress and make sure we still do not
                // generate new dealings because the DKG summary didn't change.
                pool.advance_round_normal_operation_n(5);
                assert!(dkg.on_state_change(&dkg_pool).is_empty());

                // Skip till the new DKG summary and make sure we generate dealings
                // again.
                let default_interval_length = 60;
                pool.advance_round_normal_operation_n(default_interval_length);
                // First we expect a new purge.
                let change_set = dkg.on_state_change(&dkg_pool);
                match &change_set.as_slice() {
                    &[ChangeAction::Purge(purge_height)]
                        if *purge_height == Height::from(default_interval_length) => {}
                    val => panic!("Unexpected change set: {:?}", val),
                };
                dkg_pool.apply_changes(change_set);
                // And then we validate...
                let change_set = dkg.on_state_change(&dkg_pool);
                match &change_set.as_slice() {
                    &[ChangeAction::AddToValidated(_), ChangeAction::AddToValidated(_)] => {}
                    val => panic!("Unexpected change set: {:?}", val),
                };
                // Just check again, we do not reproduce a dealing once changes are applied.
                dkg_pool.apply_changes(change_set);
                assert!(dkg.on_state_change(&dkg_pool).is_empty());
            });
        });
    }

    fn complement_state_manager_with_remote_dkg_requests(
        state_manager: Arc<RefMockStateManager>,
        registry_version: RegistryVersion,
        node_ids: Vec<u64>,
        times: Option<usize>,
        target: Option<NiDkgTargetId>,
    ) {
        let mut state = ic_test_utilities::state::get_initial_state(0, 0);

        // Add the context into state_manager.
        let nodes_in_target_subnet = node_ids.into_iter().map(node_test_id).collect();

        if let Some(target_id) = target {
            state.metadata.subnet_call_context_manager.push(
                SubnetCallContext::SetupInitialDKGContext {
                    request: RequestBuilder::new().build(),
                    nodes_in_target_subnet,
                    target_id,
                    registry_version,
                },
            );
        }

        let mut mock = state_manager.get_mut();
        let expectation = mock.expect_get_state_at().return_const(Ok(
            ic_interfaces::state_manager::Labeled::new(Height::new(0), Arc::new(state)),
        ));
        if let Some(times) = times {
            expectation.times(times);
        }
    }

    #[test]
    fn test_create_dealing_works_for_remote_dkg() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            use ic_types::crypto::threshold_sig::ni_dkg::*;
            with_test_replica_logger(|logger| {
                let node_ids = vec![node_test_id(0), node_test_id(1)];
                let dkg_interval_length = 99;
                let subnet_id = subnet_test_id(0);
                let Dependencies {
                    mut pool,
                    crypto,
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
                complement_state_manager_with_remote_dkg_requests(
                    state_manager,
                    registry.get_latest_version(),
                    vec![10, 11, 12],
                    None,
                    Some(target_id),
                );

                // Now we instantiate the DKG component for node Id = 1, who is a dealer.
                let dkg = DkgImpl::new(
                    node_test_id(1),
                    crypto,
                    pool.get_cache(),
                    MetricsRegistry::new(),
                    logger,
                );

                // We did not advance the consensus pool yet. The configs for remote transcripts
                // are not added to a summary block yet. That's why we see two dealings for
                // local thresholds.
                let mut dkg_pool = DkgPoolImpl::new(MetricsRegistry::new());
                let change_set = dkg.on_state_change(&dkg_pool);
                match &change_set.as_slice() {
                    &[ChangeAction::AddToValidated(a), ChangeAction::AddToValidated(b)] => {
                        assert_eq!(a.content.dkg_id.target_subnet, NiDkgTargetSubnet::Local);
                        assert_eq!(b.content.dkg_id.target_subnet, NiDkgTargetSubnet::Local);
                    }
                    val => panic!("Unexpected change set: {:?}", val),
                };

                // Apply the changes and make sure, we do not produce any dealings anymore.
                dkg_pool.apply_changes(change_set);
                assert!(dkg.on_state_change(&dkg_pool).is_empty());

                // Advance _past_ the new summary to make sure the configs for remote
                // transcripts are added into the summary.
                pool.advance_round_normal_operation_n(dkg_interval_length + 1);

                // First we expect a new purge.
                let change_set = dkg.on_state_change(&dkg_pool);
                match &change_set.as_slice() {
                    &[ChangeAction::Purge(purge_height)]
                        if *purge_height == Height::from(dkg_interval_length + 1) => {}
                    val => panic!("Unexpected change set: {:?}", val),
                };
                dkg_pool.apply_changes(change_set);

                // And then we validate two local and two remote dealings.
                let change_set = dkg.on_state_change(&dkg_pool);
                match &change_set.as_slice() {
                    &[ChangeAction::AddToValidated(a), ChangeAction::AddToValidated(b), ChangeAction::AddToValidated(c), ChangeAction::AddToValidated(d)] =>
                    {
                        assert_eq!(
                            [a, b, c, d]
                                .iter()
                                .filter(|msg| msg.content.dkg_id.target_subnet
                                    == NiDkgTargetSubnet::Remote(target_id))
                                .count(),
                            2
                        );
                        assert_eq!(
                            [a, b, c, d]
                                .iter()
                                .filter(|msg| msg.content.dkg_id.target_subnet
                                    == NiDkgTargetSubnet::Local)
                                .count(),
                            2
                        );
                    }
                    val => panic!("Unexpected change set: {:?}", val),
                };
                // Just check again, we do not reproduce a dealing once changes are applied.
                dkg_pool.apply_changes(change_set);
                assert!(dkg.on_state_change(&dkg_pool).is_empty());
            });
        });
    }

    fn run_validation_test(f: &dyn Fn(DkgPoolImpl, DkgPoolImpl, DkgImpl, DkgImpl, NodeId)) {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config_1| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config_2| {
                let crypto = Arc::new(CryptoReturningOk::default());
                let node_id_1 = node_test_id(1);
                // This is not a dealer!
                let node_id_2 = node_test_id(0);
                let consensus_pool_1 = dependencies(pool_config_1, 2).pool;
                let consensus_pool_2 = dependencies(pool_config_2, 2).pool;
                let dkg_pool_1 = DkgPoolImpl::new(MetricsRegistry::new());
                let dkg_pool_2 = DkgPoolImpl::new(MetricsRegistry::new());

                with_test_replica_logger(|logger| {
                    // We instantiate the DKG component for node Id = 1 nd Id = 2.
                    let dkg_1 = DkgImpl::new(
                        node_id_1,
                        crypto.clone(),
                        consensus_pool_1.get_cache(),
                        MetricsRegistry::new(),
                        logger.clone(),
                    );
                    let dkg_2 = DkgImpl::new(
                        node_id_2,
                        crypto,
                        consensus_pool_2.get_cache(),
                        MetricsRegistry::new(),
                        logger,
                    );
                    f(dkg_pool_1, dkg_pool_2, dkg_1, dkg_2, node_id_1);
                });
            });
        });
    }

    // Makes sure we do not validate dealing, if an identical one exists in the
    // validated section.
    #[test]
    fn test_validate_dealing_works_1() {
        run_validation_test(&|dkg_pool_1: DkgPoolImpl,
                              mut dkg_pool_2: DkgPoolImpl,
                              dkg_1: DkgImpl,
                              dkg_2: DkgImpl,
                              node_id_1| {
            // Make sure the replica 1 creates two dealings, which we insert as unvalidated
            // message into the pool of replica 2 and save one of them for later.
            let valid_dealing_message = {
                match &dkg_1.on_state_change(&dkg_pool_1).as_slice() {
                    &[ChangeAction::AddToValidated(message), ChangeAction::AddToValidated(message2)] =>
                    {
                        dkg_pool_2.insert(UnvalidatedArtifact {
                            message: message.clone(),
                            peer_id: node_id_1,
                            timestamp: UNIX_EPOCH,
                        });
                        dkg_pool_2.insert(UnvalidatedArtifact {
                            message: message2.clone(),
                            peer_id: node_id_1,
                            timestamp: UNIX_EPOCH,
                        });
                        message.clone()
                    }
                    val => panic!("Unexpected change set: {:?}", val),
                }
            };

            // Let replica 2 create its dealings for L/H thresholds.
            let change_set = dkg_2.on_state_change(&dkg_pool_2);
            match &change_set.as_slice() {
                &[ChangeAction::AddToValidated(_), ChangeAction::AddToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            dkg_pool_2.apply_changes(change_set);

            // Make sure both dealings from replica 1 is successfully validated and apply
            // the changes.
            let change_set = dkg_2.on_state_change(&dkg_pool_2);
            match &change_set.as_slice() {
                &[ChangeAction::MoveToValidated(_), ChangeAction::MoveToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            dkg_pool_2.apply_changes(change_set);

            // Now we try to add another identical dealing from replica 1.
            dkg_pool_2.insert(UnvalidatedArtifact {
                message: valid_dealing_message,
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            // This dealing is identical to the one in the validated section, so we just
            // ignore it.
            assert!(dkg_2.on_state_change(&dkg_pool_2).is_empty());
        });
    }

    // Tests different attempts to add an invalid dealing: using the wrong dkg_id,
    // wrong height or just another dealing, while one valid one from this
    // dealer already exists.
    #[test]
    fn test_validate_dealing_works_2() {
        run_validation_test(&|dkg_pool_1: DkgPoolImpl,
                              mut dkg_pool_2: DkgPoolImpl,
                              dkg_1: DkgImpl,
                              dkg_2: DkgImpl,
                              node_id_1| {
            // Make sure the replica 1 creates two dealings, which we insert as unvalidated
            // messages into the pool of replica 2 and save one of them for later.
            let valid_dealing_message = {
                match &dkg_1.on_state_change(&dkg_pool_1).as_slice() {
                    &[ChangeAction::AddToValidated(message), ChangeAction::AddToValidated(message2)] =>
                    {
                        dkg_pool_2.insert(UnvalidatedArtifact {
                            message: message2.clone(),
                            peer_id: node_id_1,
                            timestamp: UNIX_EPOCH,
                        });
                        dkg_pool_2.insert(UnvalidatedArtifact {
                            message: message.clone(),
                            peer_id: node_id_1,
                            timestamp: UNIX_EPOCH,
                        });
                        message.clone()
                    }
                    val => panic!("Unexpected change set: {:?}", val),
                }
            };

            // Let replica 2 create its dealings for L/H thresholds.
            let change_set = dkg_2.on_state_change(&dkg_pool_2);
            match &change_set.as_slice() {
                &[ChangeAction::AddToValidated(_), ChangeAction::AddToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            dkg_pool_2.apply_changes(change_set);

            // Make sure both dealings from replica 1 is successfully validated and apply
            // the changes.
            let change_set = dkg_2.on_state_change(&dkg_pool_2);
            match &change_set.as_slice() {
                &[ChangeAction::MoveToValidated(_), ChangeAction::MoveToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            dkg_pool_2.apply_changes(change_set);

            // Now we try to add a different dealing but still from replica 1.
            let mut invalid_dealing_message = valid_dealing_message.clone();
            invalid_dealing_message.content.dealing = NiDkgDealing::dummy_dealing_for_tests(1);
            dkg_pool_2.insert(UnvalidatedArtifact {
                message: invalid_dealing_message,
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            // We expect that this dealing will be invalidated, since we have a valid one
            // from that dealer already.
            let change_set = dkg_2.on_state_change(&dkg_pool_2);
            match &change_set.as_slice() {
                &[ChangeAction::HandleInvalid(_, reason)] => {
                    assert_eq!(
                        reason,
                        &format!(
                            "A dealing from replica with Id={:?} is already validated.",
                            node_id_1
                        )
                    );
                }
                val => panic!("Unexpected change set: {:?}", val),
            };
            dkg_pool_2.apply_changes(change_set);

            // Now we create a message with an unknown Dkg id and verify
            // that it gets rejected.
            let mut invalid_dkg_id = valid_dealing_message.content.dkg_id;
            invalid_dkg_id.dealer_subnet = subnet_test_id(444);
            let mut invalid_dealing_message = valid_dealing_message.clone();
            invalid_dealing_message.content.dkg_id = invalid_dkg_id;

            dkg_pool_2.insert(UnvalidatedArtifact {
                message: invalid_dealing_message.clone(),
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            let change_set = dkg_2.on_state_change(&dkg_pool_2);
            match &change_set.as_slice() {
                &[ChangeAction::HandleInvalid(_, reason)] => {
                    assert_eq!(
                        reason,
                        &format!(
                            "No DKG configuration for Id={:?} was found.",
                            invalid_dealing_message.content.dkg_id
                        )
                    );
                }
                val => panic!("Unexpected change set: {:?}", val),
            };
            dkg_pool_2.apply_changes(change_set);

            // Now we create a message from a non-dealer and verify it gets marked as
            // invalid.
            let mut invalid_dealing_message = valid_dealing_message.clone();
            invalid_dealing_message.signature.signer = node_test_id(101);

            dkg_pool_2.insert(UnvalidatedArtifact {
                message: invalid_dealing_message.clone(),
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            let change_set = dkg_2.on_state_change(&dkg_pool_2);
            match &change_set.as_slice() {
                &[ChangeAction::HandleInvalid(_, reason)] => {
                    assert_eq!(
                        reason,
                        &format!(
                            "Replica with Id={:?} is not a dealer.",
                            invalid_dealing_message.signature.signer
                        )
                    );
                }
                val => panic!("Unexpected change set: {:?}", val),
            };
            dkg_pool_2.apply_changes(change_set);

            // Now we create a message, which refers a DKG interval above our finalized
            // height and make sure we skip it.
            let dkg_id_from_future = NiDkgId {
                start_block_height: ic_types::Height::from(1000),
                dealer_subnet: valid_dealing_message.content.dkg_id.dealer_subnet,
                dkg_tag: valid_dealing_message.content.dkg_id.dkg_tag,
                target_subnet: NiDkgTargetSubnet::Local,
            };
            let mut dealing_message_from_future = valid_dealing_message;
            dealing_message_from_future.content.dkg_id = dkg_id_from_future;

            dkg_pool_2.insert(UnvalidatedArtifact {
                message: dealing_message_from_future,
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            assert!(dkg_2.on_state_change(&dkg_pool_2).is_empty());
        });
    }

    // Creates two distiguishable dealings from one dealer and makes sure they both
    // get invalidated.
    #[test]
    fn test_validate_dealing_works_3() {
        run_validation_test(&|dkg_pool_1: DkgPoolImpl,
                              mut dkg_pool_2: DkgPoolImpl,
                              dkg_1: DkgImpl,
                              dkg_2: DkgImpl,
                              node_id_1| {
            // Make sure the replica 1 creates dealing for H/L thresholds, which we insert
            // as unvalidated messages into the pool of replica 2 and save one of them
            // for later.
            let valid_dealing_message = {
                match &dkg_1.on_state_change(&dkg_pool_1).as_slice() {
                    &[ChangeAction::AddToValidated(message), ChangeAction::AddToValidated(message2)] =>
                    {
                        dkg_pool_2.insert(UnvalidatedArtifact {
                            message: message.clone(),
                            peer_id: node_id_1,
                            timestamp: UNIX_EPOCH,
                        });
                        dkg_pool_2.insert(UnvalidatedArtifact {
                            message: message2.clone(),
                            peer_id: node_id_1,
                            timestamp: UNIX_EPOCH,
                        });
                        message.clone()
                    }
                    val => panic!("Unexpected change set: {:?}", val),
                }
            };

            // Now we try to add a different dealing but still from replica 1.
            let mut dealing_message_2 = valid_dealing_message;
            dealing_message_2.content.dealing = NiDkgDealing::dummy_dealing_for_tests(1);
            dkg_pool_2.insert(UnvalidatedArtifact {
                message: dealing_message_2,
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            // Let replica 2 create dealings for L/H thresholds.
            let change_set = dkg_2.on_state_change(&dkg_pool_2);
            match &change_set.as_slice() {
                &[ChangeAction::AddToValidated(_), ChangeAction::AddToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            dkg_pool_2.apply_changes(change_set);

            // Make sure we validate one dealing, and handle another two as invalid.
            let change_set = dkg_2.on_state_change(&dkg_pool_2);
            match &change_set.as_slice() {
                &[ChangeAction::HandleInvalid(_, reason1), ChangeAction::HandleInvalid(_, reason2), ChangeAction::MoveToValidated(_)] =>
                {
                    let expected_reason = format!(
                        "The replica with Id={} produced multiple dealings.",
                        node_id_1
                    );
                    assert_eq!(*reason1, expected_reason);
                    assert_eq!(*reason2, expected_reason);
                }
                val => panic!("Unexpected change set: {:?}", val),
            };
        });
    }

    // Creates two dealings for both thresholds and make sure they get validated.
    #[test]
    fn test_validate_dealing_works_4() {
        run_validation_test(&|dkg_pool_1: DkgPoolImpl,
                              mut dkg_pool_2: DkgPoolImpl,
                              dkg_1: DkgImpl,
                              dkg_2: DkgImpl,
                              node_id_1| {
            // Make sure the replica 1 creates two dealings for L/H thresholds, which we
            // insert as unvalidated messages into the pool of replica 2.
            match &dkg_1.on_state_change(&dkg_pool_1).as_slice() {
                &[ChangeAction::AddToValidated(message), ChangeAction::AddToValidated(message2)] => {
                    dkg_pool_2.insert(UnvalidatedArtifact {
                        message: message.clone(),
                        peer_id: node_id_1,
                        timestamp: UNIX_EPOCH,
                    });
                    dkg_pool_2.insert(UnvalidatedArtifact {
                        message: message2.clone(),
                        peer_id: node_id_1,
                        timestamp: UNIX_EPOCH,
                    });
                }
                val => panic!("Unexpected change set: {:?}", val),
            }

            // Make sure the replica produces its dealings.
            let change_set = dkg_2.on_state_change(&dkg_pool_2);
            match &change_set.as_slice() {
                &[ChangeAction::AddToValidated(_), ChangeAction::AddToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            dkg_pool_2.apply_changes(change_set);

            // Make sure we validate both dealings from replica 1
            let change_set = dkg_2.on_state_change(&dkg_pool_2);
            match &change_set.as_slice() {
                &[ChangeAction::MoveToValidated(_), ChangeAction::MoveToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
        });
    }

    #[test]
    fn test_validate_dealing_works_for_remote_dkg() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config_1| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config_2| {
                use ic_types::crypto::threshold_sig::ni_dkg::*;
                with_test_replica_logger(|logger| {
                    let node_ids = vec![node_test_id(0), node_test_id(1)];
                    let dkg_interval_length = 99;
                    let subnet_id = subnet_test_id(0);

                    // Set pool_1 and pool_2
                    let dependencies_1 = dependencies_with_subnet_records_with_raw_state_manager(
                        pool_config_1,
                        subnet_id,
                        vec![(
                            10,
                            SubnetRecordBuilder::from(&node_ids)
                                .with_dkg_interval_length(dkg_interval_length)
                                .build(),
                        )],
                    );
                    let dependencies_2 = dependencies_with_subnet_records_with_raw_state_manager(
                        pool_config_2,
                        subnet_id,
                        vec![(
                            10,
                            SubnetRecordBuilder::from(&node_ids)
                                .with_dkg_interval_length(dkg_interval_length)
                                .build(),
                        )],
                    );

                    // Return an empty call context when we create the first summary,
                    // so that we later test the case where remote dealing has a different
                    // height than the local dealings.
                    let target_id = NiDkgTargetId::new([0u8; 32]);
                    [&dependencies_1, &dependencies_2]
                        .iter()
                        .for_each(|dependencies| {
                            complement_state_manager_with_remote_dkg_requests(
                                dependencies.state_manager.clone(),
                                dependencies.registry.get_latest_version(),
                                vec![],
                                Some(1),
                                None,
                            );

                            complement_state_manager_with_remote_dkg_requests(
                                dependencies.state_manager.clone(),
                                dependencies.registry.get_latest_version(),
                                vec![10, 11, 12],
                                None,
                                Some(target_id),
                            );
                        });

                    let crypto_1 = dependencies_1.crypto.clone();
                    let crypto_2 = dependencies_2.crypto.clone();
                    let mut pool_1 = dependencies_1.pool;
                    let mut pool_2 = dependencies_2.pool;

                    // Verify that the first summary block contains only two local configs.
                    pool_1.advance_round_normal_operation_n(dkg_interval_length + 1);
                    pool_2.advance_round_normal_operation_n(dkg_interval_length + 1);
                    let block: Block = PoolReader::new(&pool_1).get_highest_summary_block();
                    if let BlockPayload::Summary(summary) = block.payload.as_ref() {
                        assert_eq!(summary.configs.len(), 2);
                        for (dkg_id, _) in summary.configs.iter() {
                            assert_eq!(dkg_id.target_subnet, NiDkgTargetSubnet::Local);
                        }
                    } else {
                        panic!(
                            "block at height {} is not a summary block",
                            block.height.get()
                        );
                    }

                    // Advance _past_ the next summary to make sure the configs for remote
                    // transcripts are added into the summary. Verify that the second summary
                    // block contains only two local and two remote configs.
                    pool_1.advance_round_normal_operation_n(dkg_interval_length + 1);
                    pool_2.advance_round_normal_operation_n(dkg_interval_length + 1);
                    let block: Block = PoolReader::new(&pool_1).get_highest_summary_block();
                    if let BlockPayload::Summary(summary) = block.payload.as_ref() {
                        assert_eq!(summary.configs.len(), 4);
                    } else {
                        panic!(
                            "block at height {} is not a summary block",
                            block.height.get()
                        );
                    }

                    // Now we instantiate the DKG components. Node Id = 1 is a dealer.
                    let dkg_1 = DkgImpl::new(
                        node_test_id(1),
                        crypto_1,
                        pool_1.get_cache(),
                        MetricsRegistry::new(),
                        logger.clone(),
                    );
                    let dkg_2 = DkgImpl::new(
                        node_test_id(2),
                        crypto_2,
                        pool_2.get_cache(),
                        MetricsRegistry::new(),
                        logger,
                    );
                    let mut dkg_pool_1 = DkgPoolImpl::new(MetricsRegistry::new());
                    let mut dkg_pool_2 = DkgPoolImpl::new(MetricsRegistry::new());

                    // First we expect a new purge.
                    let change_set = dkg_1.on_state_change(&dkg_pool_1);
                    match &change_set.as_slice() {
                        &[ChangeAction::Purge(purge_height)]
                            if *purge_height == Height::from(2 * (dkg_interval_length + 1)) => {}
                        val => panic!("Unexpected change set: {:?}", val),
                    };
                    dkg_pool_1.apply_changes(change_set);

                    // The last summary contains two local and two remote configs.
                    // dkg.on_state_change should create 4 dealings for those
                    // configs.
                    let change_set = dkg_1.on_state_change(&dkg_pool_1);
                    match &change_set.as_slice() {
                        &[ChangeAction::AddToValidated(a), ChangeAction::AddToValidated(b), ChangeAction::AddToValidated(c), ChangeAction::AddToValidated(d)] =>
                        {
                            assert_eq!(
                                [a, b, c, d]
                                    .iter()
                                    .filter(|msg| msg.content.dkg_id.target_subnet
                                        == NiDkgTargetSubnet::Remote(target_id))
                                    .count(),
                                2
                            );
                            assert_eq!(
                                [a, b, c, d]
                                    .iter()
                                    .filter(|msg| msg.content.dkg_id.target_subnet
                                        == NiDkgTargetSubnet::Local)
                                    .count(),
                                2
                            );
                        }
                        val => panic!("Unexpected change set: {:?}", val),
                    };

                    // Add the dealings in the above changeset into dkg_pool_2.
                    for change in change_set.into_iter() {
                        if let ChangeAction::AddToValidated(message) = change {
                            dkg_pool_2.insert(UnvalidatedArtifact {
                                message,
                                peer_id: node_test_id(1),
                                timestamp: ic_test_utilities::mock_time(),
                            });
                        }
                    }

                    assert_eq!(dkg_pool_2.get_unvalidated().count(), 4);

                    // First we expect a new purge from dkg_2 as well.
                    let change_set = dkg_2.on_state_change(&dkg_pool_2);
                    match &change_set.as_slice() {
                        &[ChangeAction::Purge(purge_height)]
                            if *purge_height == Height::from(2 * (dkg_interval_length + 1)) => {}
                        val => panic!("Unexpected change set: {:?}", val),
                    };
                    dkg_pool_2.apply_changes(change_set);

                    assert_eq!(dkg_pool_2.get_unvalidated().count(), 4);

                    // The pool contains two local and two remote dealings.
                    // dkg.on_state_change should move these 4 dealings
                    // into the validated pool.
                    let change_set = dkg_2.on_state_change(&dkg_pool_2);
                    match &change_set.as_slice() {
                        &[ChangeAction::MoveToValidated(a), ChangeAction::MoveToValidated(b), ChangeAction::MoveToValidated(c), ChangeAction::MoveToValidated(d)] =>
                        {
                            assert_eq!(
                                [a, b, c, d]
                                    .iter()
                                    .filter(|msg| msg.content.dkg_id.target_subnet
                                        == NiDkgTargetSubnet::Remote(target_id))
                                    .count(),
                                2
                            );
                            assert_eq!(
                                [a, b, c, d]
                                    .iter()
                                    .filter(|msg| msg.content.dkg_id.target_subnet
                                        == NiDkgTargetSubnet::Local)
                                    .count(),
                                2
                            );
                        }
                        val => panic!("Unexpected change set: {:?}", val),
                    };
                });
            });
        });
    }

    #[test]
    fn test_dkg_payload_has_transcripts_for_new_subnets() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let node_ids = vec![node_test_id(0), node_test_id(1)];
            let dkg_interval_length = 99;
            let subnet_id = subnet_test_id(0);
            let Dependencies {
                mut pool,
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
            complement_state_manager_with_remote_dkg_requests(
                state_manager,
                registry.get_latest_version(),
                vec![10, 11, 12],
                None,
                Some(target_id),
            );

            // Verify that the next summary block contains the configs and no transcripts.
            pool.advance_round_normal_operation_n(dkg_interval_length + 1);
            let block: Block = pool
                .validated()
                .block_proposal()
                .get_highest()
                .unwrap()
                .content
                .into_inner();
            if block.payload.as_ref().is_summary() {
                let summary = block.payload.as_ref().as_summary();
                assert_eq!(summary.configs.len(), 4);
                assert_eq!(
                    summary
                        .configs
                        .keys()
                        .filter(|id| id.target_subnet == NiDkgTargetSubnet::Remote(target_id))
                        .count(),
                    2
                );
                assert!(summary.transcripts_for_new_subnets().is_empty());
            } else {
                assert!(
                    false,
                    "block at height {} is not a summary block",
                    block.height.get()
                );
            }

            // Verify that the next summary block contains the transcripts and not the
            // configs.
            pool.advance_round_normal_operation_n(dkg_interval_length + 1);
            let block: Block = pool
                .validated()
                .block_proposal()
                .get_highest()
                .unwrap()
                .content
                .into_inner();
            if block.payload.as_ref().is_summary() {
                let summary = block.payload.as_ref().as_summary();
                assert_eq!(summary.configs.len(), 2);
                assert_eq!(
                    summary
                        .configs
                        .keys()
                        .filter(|id| id.target_subnet == NiDkgTargetSubnet::Remote(target_id))
                        .count(),
                    0
                );
                assert_eq!(
                    summary
                        .transcripts_for_new_subnets()
                        .keys()
                        .filter(|id| id.target_subnet == NiDkgTargetSubnet::Remote(target_id))
                        .count(),
                    2
                );
            } else {
                assert!(
                    false,
                    "block at height {} is not a summary block",
                    block.height.get()
                );
            }
        })
    }

    /*
     * Test bases on the following example (assumption: every DKG succeeds).
     *
     * Registry:
     *  - Version 6: Members {A B C D E}
     *  - Version 10: Members {A B C D}
     *
     *
     * Block 0:
     *   block.context.registry_version = 5
     *   summary.registry_version = 1
     *   summary.current_transcript is 0
     *   summary.next_transcript is None
     *   summary.configs: Compute DKG 1, which reshares transcript 0, and based
     *                    on registry version 1
     *
     *
     * Block 5:
     *   block.context.registry_version = 6
     *   summary.registry_version = 5
     *   summary.current_transcript is 0
     *   summary.next_transcript is 1
     *   summary.configs: Compute DKG 2,  which reshares transcript 0, and based
     *                    on registry version 5
     *
     * // here, somewhere node E is removed from subnet
     *
     * Block 10:
     *   block.context.registry_version = 10
     *   summary.registry_version = 6
     *   summary.current_transcript is 1
     *   summary.next_transcript = 2
     *   summary.configs: Compute DKG 3,  which reshares transcript 1, and based
     *                    on registry version 6
     *
     * Block 15:
     *   block.context.registry_version = 14
     *   summary.registry_version = 10
     *   summary.current_transcript is 2
     *   summary.next_transcript is 3
     *   summary.configs: Compute DKG 4, which reshares transcript 2, and based
     *                    on registry version 10 (this is the first DKG that no
     *                    longer includes E)
     *
     * Block 20:
     *   block.context.registry_version = 16
     *   summary.registry_version = 14
     *   summary.current_transcript is 3
     *   summary.next_transcript is 4
     *   summary.configs: Compute DKG 5, which reshares transcript 3, and based
     *                    on registry version 14
     *
     * Block 25: (this is the first time that node E is no longer needed)
     *   block.context.registry_version = 20
     *   summary.registry_version = 16
     *   summary.current_transcript is 4
     *   summary.next_transcript is 5
     *   summary.configs: Compute DKG 6, which reshares transcript 4, and based
     *                    on registry version 16
     *
     * Block 30:
     *   block.context.registry_version = 22
     *   summary.registry_version = 20
     *   summary.current_transcript is 5
     *   summary.next_transcript is 6
     *   summary.configs: Compute DKG 7, which reshares transcript 5, and based
     *                    on registry version 20
     *
     *
     */
    #[test]
    fn test_create_summary_registry_versions() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            // We'll have a DKG summary inside every 5th block.
            let dkg_interval_length = 4;
            // Original committee are nodes 0, 1, 2, 3.
            let committee1 = (0..4).map(node_test_id).collect::<Vec<_>>();
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
                    SubnetRecordBuilder::from(&committee1)
                        .with_dkg_interval_length(dkg_interval_length)
                        .build(),
                )],
            );

            // Get the latest summary block, which is the genesis block
            let dkg_block = PoolReader::new(&pool).get_highest_summary_block();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(5),
                "The latest available version was used for the summary block."
            );
            let summary = BlockPayload::from(dkg_block.payload).into_summary();
            assert_eq!(summary.registry_version, RegistryVersion::from(5));
            assert_eq!(summary.height, Height::from(0));
            for tag in TAGS.iter() {
                let current_transcript = summary.current_transcript(tag);
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(0)
                );
                assert_eq!(
                    current_transcript.committee.get(),
                    &committee1.clone().into_iter().collect::<BTreeSet<_>>()
                );
                // The genesis summary cannot have next transcripts, instead we'll reuse in
                // round 1 the active transcripts from round 0.
                assert!(summary.next_transcript(tag).is_none());
            }

            // Advance for one round and update the registry to version 6 with new
            // memebership (nodes 3, 4, 5, 6, 7).
            pool.advance_round_normal_operation();
            let committee2 = (3..8).map(node_test_id).collect::<Vec<_>>();
            add_subnet_record(
                &registry_data_provider,
                6,
                replica_config.subnet_id,
                SubnetRecordBuilder::from(&committee2)
                    .with_dkg_interval_length(dkg_interval_length)
                    .build(),
            );
            registry.update_to_latest_version();

            // Skip till the next DKG summary and make sure the new summary block contains
            // correct data.
            pool.advance_round_normal_operation_n(dkg_interval_length);
            let dkg_block = PoolReader::new(&pool).get_highest_summary_block();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(6),
                "The newest registry version is used."
            );
            let summary = BlockPayload::from(dkg_block.payload).into_summary();
            // This registry version corresponds to the registry version from the block
            // context of the previous summary.
            assert_eq!(summary.registry_version, RegistryVersion::from(5));
            assert_eq!(summary.height, Height::from(5));
            for tag in TAGS.iter() {
                // We reused the transcript.
                let current_transcript = summary.current_transcript(tag);
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(0)
                );
                let (_, conf) = summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == *tag)
                    .unwrap();
                assert_eq!(
                    conf.receivers().get(),
                    &committee1.clone().into_iter().collect::<BTreeSet<_>>()
                );
            }

            // Advance for one round and update the registry to version 10 with new
            // memebership (nodes 3, 4, 5, 6).
            pool.advance_round_normal_operation();
            let committee3 = (3..7).map(node_test_id).collect::<Vec<_>>();
            add_subnet_record(
                &registry_data_provider,
                10,
                replica_config.subnet_id,
                SubnetRecordBuilder::from(&committee3)
                    .with_dkg_interval_length(dkg_interval_length)
                    .build(),
            );
            registry.update_to_latest_version();

            // Skip till the next DKG summary and make sure the new summary block contains
            // correct data.
            pool.advance_round_normal_operation_n(dkg_interval_length);
            let dkg_block = PoolReader::new(&pool).get_highest_summary_block();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(10),
                "The newest registry version is used."
            );
            let summary = BlockPayload::from(dkg_block.payload).into_summary();
            // This registry version corresponds to the registry version from the block
            // context of the previous summary.
            assert_eq!(summary.registry_version, RegistryVersion::from(6));
            assert_eq!(summary.height, Height::from(10));
            for tag in TAGS.iter() {
                let (_, conf) = summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == *tag)
                    .unwrap();
                assert_eq!(
                    conf.receivers().get(),
                    &committee2.clone().into_iter().collect::<BTreeSet<_>>()
                );
                let current_transcript = summary.current_transcript(tag);
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(0)
                );
                let next_transcript = summary.next_transcript(tag).unwrap();
                // The DKG id start height refers to height 0, where we started computing this
                // DKG.
                assert_eq!(next_transcript.dkg_id.start_block_height, Height::from(5));
            }

            // Skip till the next DKG round
            pool.advance_round_normal_operation_n(dkg_interval_length + 1);
            let dkg_block = PoolReader::new(&pool).get_highest_summary_block();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(10),
                "The latest registry version is used."
            );
            let summary = BlockPayload::from(dkg_block.payload).into_summary();
            // This registry version corresponds to the registry version from the block
            // context of the previous summary.
            assert_eq!(summary.registry_version, RegistryVersion::from(10));
            assert_eq!(summary.height, Height::from(15));
            for tag in TAGS.iter() {
                let (_, conf) = summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == *tag)
                    .unwrap();
                assert_eq!(
                    conf.receivers().get(),
                    &committee3.clone().into_iter().collect::<BTreeSet<_>>()
                );
                let current_transcript = summary.current_transcript(tag);
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(5)
                );
                let next_transcript = summary.next_transcript(tag).unwrap();
                assert_eq!(next_transcript.dkg_id.start_block_height, Height::from(10));
            }
        });
    }
}
