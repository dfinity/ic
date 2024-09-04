//! This module defines an embedding of the dkg algorithm provided by the crypto
//! component into the consensus algorithm that is implemented within this
//! crate.

use crate::{
    consensus::{check_protocol_version, dkg_key_manager::DkgKeyManager},
    idkg::{
        make_bootstrap_summary,
        payload_builder::make_bootstrap_summary_with_initial_dealings,
        utils::{get_chain_key_config_if_enabled, inspect_chain_key_initializations},
    },
};
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_interfaces::{
    consensus_pool::ConsensusPoolCache,
    crypto::ErrorReproducibility,
    dkg::{ChangeAction, ChangeSet, DkgPool},
    p2p::consensus::{Bouncer, BouncerFactory, BouncerValue, ChangeSetProducer},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, info, warn, ReplicaLogger};
use ic_metrics::buckets::{decimal_buckets, linear_buckets};
use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{
    batch::ValidationContext,
    consensus::{
        dkg::{DealingContent, DkgMessageId, Message},
        idkg, Block, BlockPayload, CatchUpContent, CatchUpPackage, HashedBlock, HashedRandomBeacon,
        Payload, RandomBeaconContent, Rank, SummaryPayload,
    },
    crypto::{
        crypto_hash,
        threshold_sig::ni_dkg::{config::NiDkgConfig, NiDkgId, NiDkgTag, NiDkgTargetSubnet},
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, Signed,
    },
    signature::ThresholdSignature,
    Height, NodeId, RegistryVersion, SubnetId, Time,
};
pub(crate) use payload_validator::{DkgPayloadValidationFailure, InvalidDkgPayloadReason};
use phantom_newtype::Id;
use prometheus::Histogram;
use rayon::prelude::*;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

pub(crate) mod payload_builder;
pub(crate) mod payload_validator;
#[cfg(test)]
mod test_utils;
mod utils;

pub use payload_builder::{create_payload, make_genesis_summary, PayloadCreationError};

// The maximal number of DKGs for other subnets we want to run in one interval.
const MAX_REMOTE_DKGS_PER_INTERVAL: usize = 1;

// The maximum number of intervals during which an initial DKG request is
// attempted.
const MAX_REMOTE_DKG_ATTEMPTS: u32 = 5;

// Generic error string for failed remote DKG requests.
const REMOTE_DKG_REPEATED_FAILURE_ERROR: &str = "Attempts to run this DKG repeatedly failed";

// Currently we assume that we run DKGs for all of these tags.
const TAGS: [NiDkgTag; 2] = [NiDkgTag::LowThreshold, NiDkgTag::HighThreshold];

struct Metrics {
    on_state_change_duration: Histogram,
    on_state_change_processed: Histogram,
}

/// `DkgImpl` is responsible for holding DKG dependencies and for responding to
/// changes in the consensus and DKG pool.
pub struct DkgImpl {
    node_id: NodeId,
    crypto: Arc<dyn ConsensusCrypto>,
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    dkg_key_manager: Arc<Mutex<DkgKeyManager>>,
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
        dkg_key_manager: Arc<Mutex<DkgKeyManager>>,
        metrics_registry: ic_metrics::MetricsRegistry,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            crypto,
            consensus_cache,
            node_id,
            dkg_key_manager,
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

        // If the transcript is being loaded at the moment, we return early.
        // The transcript will be available at a later point in time.
        if let Some(transcript) = config.resharing_transcript() {
            if !self
                .dkg_key_manager
                .lock()
                .unwrap()
                .is_transcript_loaded(&transcript.dkg_id)
            {
                return None;
            }
        }

        let content =
            match ic_interfaces::crypto::NiDkgAlgorithm::create_dealing(&*self.crypto, config) {
                Ok(dealing) => DealingContent::new(dealing, config.dkg_id()),
                Err(err) => {
                    match config.dkg_id().target_subnet {
                        NiDkgTargetSubnet::Local => error!(
                            self.logger,
                            "Couldn't create a DKG dealing at height {:?}: {:?}",
                            config.dkg_id().start_block_height,
                            err
                        ),
                        // NOTE: In rare cases, we might hit this case.
                        NiDkgTargetSubnet::Remote(_) => info!(
                            self.logger,
                            "Waiting for Remote DKG dealing at height {:?}: {:?}",
                            config.dkg_id().start_block_height,
                            err
                        ),
                    };
                    return None;
                }
            };

        match self
            .crypto
            .sign(&content, self.node_id, config.registry_version())
        {
            Ok(signature) => Some(ChangeAction::AddToValidated(Signed { content, signature })),
            Err(err) => {
                error!(self.logger, "Couldn't sign a DKG dealing: {:?}", err);
                None
            }
        }
    }

    // Validates the DKG messages against the provided config.
    //
    // Invalidates the message if:
    // - no DKG config among onging DKGs was found,
    // - the dealer is not on the list of dealers wrt. DKG config,
    // - the dealing signature is invalid,
    // - the dealing is invalid.
    //
    // We simply remove the message from the pool if we already have a dealing
    // from the dealer of the the message, because it is possible for honest
    // dealers to provide multiple, non-identical dealings in certain
    // situations. We skip the validation if an error occurs during the
    // signature or dealing verification.
    fn validate_dealings_for_dealer(
        &self,
        dkg_pool: &dyn DkgPool,
        configs: &BTreeMap<NiDkgId, NiDkgConfig>,
        dkg_start_height: Height,
        messages: Vec<&Message>,
    ) -> ChangeSet {
        // Because dealing generation is not entirely deterministic, it is
        // actually possible to receive multiple dealings from an honest dealer.
        // As such, we simply try validating the first message in the list, and
        // get a result for that message. Other messages will be dealt with by
        // subsequent calls to this function.
        let message = if let Some(message) = messages.first() {
            message
        } else {
            return ChangeSet::new();
        };

        if check_protocol_version(&message.content.version).is_err() {
            return ChangeSet::from(ChangeAction::RemoveFromUnvalidated((*message).clone()));
        }

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
        if dkg_pool.get_validated().any(|item| item.eq(message)) {
            return ChangeSet::new();
        }

        // If the dealing comes from a non-dealer, reject it.
        if !config.dealers().get().contains(dealer_id) {
            return get_handle_invalid_change_action(
                message,
                format!("Replica with Id={:?} is not a dealer.", dealer_id),
            )
            .into();
        }

        // If we already have a dealing from this dealer, we simply remove the
        // message from the pool. Multiple distinguishable valid dealings can be
        // created by an honest node because dkg dealings are not deterministic,
        // and in the case of a restart it is possible it might forget that it
        // has already sent out a dealing. See
        // https://dfinity.atlassian.net/browse/CON-534 for more details.
        if contains_dkg_messages(dkg_pool, config, *dealer_id) {
            return ChangeSet::from(ChangeAction::RemoveFromUnvalidated((*message).clone()));
        }

        // Verify the signature and reject if it's invalid, or skip, if there was an error.
        match self.crypto.verify(message, config.registry_version()) {
            Ok(()) => (),
            Err(err) if err.is_reproducible() => {
                return get_handle_invalid_change_action(
                    message,
                    format!("Invalid signature: {}", err),
                )
                .into()
            }
            Err(err) => {
                error!(
                    self.logger,
                    "Couldn't verify the signature of a DKG dealing: {}", err
                );

                return ChangeSet::new();
            }
        }

        // Verify the dealing and move to validated if it was successful,
        // reject, if it was rejected, or skip, if there was an error.
        match ic_interfaces::crypto::NiDkgAlgorithm::verify_dealing(
            &*self.crypto,
            config,
            *dealer_id,
            &message.content.dealing,
        ) {
            Ok(()) => ChangeAction::MoveToValidated((*message).clone()).into(),
            Err(err) if err.is_reproducible() => get_handle_invalid_change_action(
                message,
                format!("Dealing verification failed: {}", err),
            )
            .into(),
            Err(err) => {
                error!(self.logger, "Couldn't verify a DKG dealing: {}", err);

                ChangeSet::new()
            }
        }
    }
}

fn contains_dkg_messages(dkg_pool: &dyn DkgPool, config: &NiDkgConfig, replica_id: NodeId) -> bool {
    dkg_pool.get_validated().any(|message| {
        message.content.dkg_id == config.dkg_id() && message.signature.signer == replica_id
    })
}

fn get_handle_invalid_change_action<T: AsRef<str>>(message: &Message, reason: T) -> ChangeAction {
    ChangeAction::HandleInvalid(DkgMessageId::from(message), reason.as_ref().to_string())
}

impl<T: DkgPool> ChangeSetProducer<T> for DkgImpl {
    type ChangeSet = ChangeSet;

    fn on_state_change(&self, dkg_pool: &T) -> ChangeSet {
        // This timer will make an entry in the metrics histogram automatically, when
        // it's dropped.
        let _timer = self.metrics.on_state_change_duration.start_timer();
        let dkg_summary_block = self.consensus_cache.summary_block();
        let dkg_summary = &dkg_summary_block.payload.as_ref().as_summary().dkg;
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
                let dealings: &mut Vec<_> = map.entry(key).or_default();
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
                self.validate_dealings_for_dealer(
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

// The NiDKG component does not implement custom `get_filter` function
// because it doesn't require artifact retransmission. Nodes participating
// in NiDKG would create artifacts depending on their own consensus state.
// If a node happens to disconnect, it would send out dealings based on
// its previous state after it reconnects, regardless of whether it has sent
// them before.
impl<Pool: DkgPool> BouncerFactory<DkgMessageId, Pool> for DkgGossipImpl {
    fn new_bouncer(&self, dkg_pool: &Pool) -> Bouncer<DkgMessageId> {
        let start_height = dkg_pool.get_current_start_height();
        Box::new(move |id| {
            use std::cmp::Ordering;
            match id.height.cmp(&start_height) {
                Ordering::Equal => BouncerValue::Wants,
                Ordering::Greater => BouncerValue::MaybeWantsLater,
                Ordering::Less => BouncerValue::Unwanted,
            }
        })
    }

    fn refresh_period(&self) -> std::time::Duration {
        std::time::Duration::from_secs(3)
    }
}

/// Constructs a genesis/recovery CUP from the CUP contents associated with the
/// given subnet
pub fn make_registry_cup(
    registry: &dyn RegistryClient,
    subnet_id: SubnetId,
    logger: &ReplicaLogger,
) -> Option<CatchUpPackage> {
    let versioned_record = match registry.get_cup_contents(subnet_id, registry.get_latest_version())
    {
        Ok(versioned_record) => versioned_record,
        Err(e) => {
            warn!(
                logger,
                "Failed to retrieve versioned record from the registry {:?}", e,
            );
            return None;
        }
    };

    let cup_contents = versioned_record.value.expect("Missing CUP contents");
    make_registry_cup_from_cup_contents(
        registry,
        subnet_id,
        cup_contents,
        versioned_record.version,
        logger,
    )
}

/// Constructs a genesis/recovery CUP from the CUP contents associated with the
/// given subnet from the provided CUP contents
pub fn make_registry_cup_from_cup_contents(
    registry: &dyn RegistryClient,
    subnet_id: SubnetId,
    cup_contents: CatchUpPackageContents,
    registry_version: RegistryVersion,
    logger: &ReplicaLogger,
) -> Option<CatchUpPackage> {
    let replica_version = match registry.get_replica_version(subnet_id, registry_version) {
        Ok(Some(replica_version)) => replica_version,
        err => {
            warn!(
                logger,
                "Failed to retrieve subnet replica version at registry version {:?}: {:?}",
                registry_version,
                err
            );
            return None;
        }
    };
    let dkg_summary = payload_builder::get_dkg_summary_from_cup_contents(
        cup_contents.clone(),
        subnet_id,
        registry,
        registry_version,
    );
    let cup_height = Height::new(cup_contents.height);

    let idkg_summary = match bootstrap_idkg_summary(
        &cup_contents,
        subnet_id,
        registry_version,
        registry,
        logger,
    ) {
        Ok(summary) => summary,
        Err(err) => {
            warn!(
                logger,
                "Failed constructing IDKG summary block from CUP contents: {}", err
            );

            None
        }
    };

    let low_dkg_id = dkg_summary
        .current_transcript(&NiDkgTag::LowThreshold)
        .dkg_id;
    let high_dkg_id = dkg_summary
        .current_transcript(&NiDkgTag::HighThreshold)
        .dkg_id;

    // In a NNS subnet recovery case the block validation context needs to reference a registry
    // version of the NNS to be recovered. Otherwise the validation context points to a registry
    // version without the NNS subnet record.
    let block_registry_version = cup_contents
        .registry_store_uri
        .as_ref()
        .map(|v| RegistryVersion::from(v.registry_version))
        .unwrap_or(registry_version);
    let block = Block {
        version: replica_version.clone(),
        parent: Id::from(CryptoHash(Vec::new())),
        payload: Payload::new(
            crypto_hash,
            BlockPayload::Summary(SummaryPayload {
                dkg: dkg_summary,
                idkg: idkg_summary,
            }),
        ),
        height: cup_height,
        rank: Rank(0),
        context: ValidationContext {
            certified_height: cup_height,
            registry_version: block_registry_version,
            time: Time::from_nanos_since_unix_epoch(cup_contents.time),
        },
    };
    let random_beacon = Signed {
        content: RandomBeaconContent {
            version: replica_version,
            height: cup_height,
            parent: Id::from(CryptoHash(Vec::new())),
        },
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
            /* oldest_registry_version_in_use_by_replicated_state */ None,
        ),
        signature: ThresholdSignature {
            signer: high_dkg_id,
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    })
}

fn bootstrap_idkg_summary_from_cup_contents(
    cup_contents: &CatchUpPackageContents,
    subnet_id: SubnetId,
    logger: &ReplicaLogger,
) -> Result<idkg::Summary, String> {
    let initial_dealings = inspect_chain_key_initializations(
        &cup_contents.ecdsa_initializations,
        &cup_contents.chain_key_initializations,
    )?;
    if initial_dealings.is_empty() {
        return Ok(None);
    };

    make_bootstrap_summary_with_initial_dealings(
        subnet_id,
        Height::new(cup_contents.height),
        initial_dealings,
        logger,
    )
    .map_err(|err| format!("Failed to create IDKG summary block: {:?}", err))
}

fn bootstrap_idkg_summary(
    cup_contents: &CatchUpPackageContents,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    registry_client: &dyn RegistryClient,
    logger: &ReplicaLogger,
) -> Result<idkg::Summary, String> {
    if let Some(summary) =
        bootstrap_idkg_summary_from_cup_contents(cup_contents, subnet_id, logger)?
    {
        return Ok(Some(summary));
    }

    match get_chain_key_config_if_enabled(subnet_id, registry_version, registry_client)
        .map_err(|err| format!("Failed getting the chain key config: {:?}", err))?
    {
        Some(chain_key_config) => Ok(make_bootstrap_summary(
            subnet_id,
            chain_key_config
                .key_configs
                .iter()
                .map(|key_config| key_config.key_id.clone())
                .collect(),
            Height::new(cup_contents.height),
        )),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::{test_utils::complement_state_manager_with_remote_dkg_requests, *};
    use ic_artifact_pool::dkg_pool::DkgPoolImpl;
    use ic_consensus_mocks::{
        dependencies, dependencies_with_subnet_params,
        dependencies_with_subnet_records_with_raw_state_manager, Dependencies,
    };
    use ic_consensus_utils::pool_reader::PoolReader;
    use ic_crypto_test_utils_ni_dkg::dummy_initial_dkg_transcript;
    use ic_interfaces::{
        consensus_pool::ConsensusPool,
        p2p::consensus::{MutablePool, UnvalidatedArtifact},
    };
    use ic_interfaces_registry::RegistryVersionedRecord;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, SubnetRecord};
    use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
    use ic_test_utilities::crypto::CryptoReturningOk;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::{add_subnet_record, SubnetRecordBuilder};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        consensus::HasVersion,
        crypto::threshold_sig::ni_dkg::{
            NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
        },
        registry::RegistryClientError,
        time::UNIX_EPOCH,
        PrincipalId, RegistryVersion, ReplicaVersion,
    };
    use std::{collections::BTreeSet, convert::TryFrom};

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
                let dkg_key_manager =
                    new_dkg_key_manager(crypto.clone(), logger.clone(), &PoolReader::new(&pool));
                let dkg = DkgImpl::new(
                    replica_1,
                    crypto.clone(),
                    pool.get_cache(),
                    dkg_key_manager.clone(),
                    MetricsRegistry::new(),
                    logger.clone(),
                );

                // Creates two dealings for both thresholds and add them to the pool.
                sync_dkg_key_manager(&dkg_key_manager, &pool);
                let change_set = dkg.on_state_change(&*dkg_pool.read().unwrap());
                assert_eq!(change_set.len(), 2);
                dkg_pool.write().unwrap().apply_changes(change_set);

                // Advance the consensus pool for one round and make sure both dealings made it
                // into the block.
                pool.advance_round_normal_operation();
                let block = pool.get_cache().finalized_block();
                let dealings = &block.payload.as_ref().as_data().dealings;
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
                let dealings = &block.payload.as_ref().as_data().dealings;
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
                let dealings = &block.payload.as_ref().as_data().dealings;
                assert_eq!(dealings.messages.len(), 0);

                // Create another dealer and add his dealings into the unvalidated pool of
                // replica 1.
                let replica_2 = node_test_id(2);
                let dkg_key_manager_2 =
                    new_dkg_key_manager(crypto.clone(), logger.clone(), &PoolReader::new(&pool));
                let dkg_2 = DkgImpl::new(
                    replica_2,
                    crypto,
                    pool.get_cache(),
                    dkg_key_manager_2.clone(),
                    MetricsRegistry::new(),
                    logger.clone(),
                );
                let dkg_pool_2 = DkgPoolImpl::new(MetricsRegistry::new(), logger);
                sync_dkg_key_manager(&dkg_key_manager_2, &pool);
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
                let dealings = &block.payload.as_ref().as_data().dealings;
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
    fn test_create_dealing_works() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let Dependencies {
                    mut pool, crypto, ..
                } = dependencies(pool_config.clone(), 2);
                let mut dkg_pool = DkgPoolImpl::new(MetricsRegistry::new(), logger.clone());
                // Let's check that replica 3, who's not a dealer, does not produce dealings.
                let dkg_key_manager =
                    new_dkg_key_manager(crypto.clone(), logger.clone(), &PoolReader::new(&pool));
                let dkg = DkgImpl::new(
                    node_test_id(3),
                    crypto.clone(),
                    pool.get_cache(),
                    dkg_key_manager,
                    MetricsRegistry::new(),
                    logger.clone(),
                );
                assert!(dkg.on_state_change(&dkg_pool).is_empty());

                // Now we instantiate the DKG component for node Id = 1, who is a dealer.
                let dkg_key_manager =
                    new_dkg_key_manager(crypto.clone(), logger.clone(), &PoolReader::new(&pool));
                let dkg = DkgImpl::new(
                    node_test_id(1),
                    crypto,
                    pool.get_cache(),
                    dkg_key_manager.clone(),
                    MetricsRegistry::new(),
                    logger,
                );

                // Make sure the replica creates two dealings for both thresholds.
                sync_dkg_key_manager(&dkg_key_manager, &pool);
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
                let dkg_key_manager =
                    new_dkg_key_manager(crypto.clone(), logger.clone(), &PoolReader::new(&pool));
                let dkg = DkgImpl::new(
                    node_test_id(1),
                    crypto,
                    pool.get_cache(),
                    dkg_key_manager.clone(),
                    MetricsRegistry::new(),
                    logger.clone(),
                );

                // We did not advance the consensus pool yet. The configs for remote transcripts
                // are not added to a summary block yet. That's why we see two dealings for
                // local thresholds.
                let mut dkg_pool = DkgPoolImpl::new(MetricsRegistry::new(), logger);
                sync_dkg_key_manager(&dkg_key_manager, &pool);
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

    #[test]
    fn test_config_generation_failures_are_added_to_the_summary() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            use ic_types::crypto::threshold_sig::ni_dkg::*;
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
                vec![], // an erroneous request with no nodes.
                None,
                Some(target_id),
            );

            // Advance _past_ the new summary to make sure the replicas attempt to create
            // the configs for remote transcripts.
            pool.advance_round_normal_operation_n(dkg_interval_length + 1);

            // Verify that the first summary block contains only two local configs and the
            // two errors for the remote DKG request.
            let block: Block = PoolReader::new(&pool).get_highest_summary_block();
            if let BlockPayload::Summary(summary) = block.payload.as_ref() {
                assert_eq!(
                    summary.dkg.configs.len(),
                    2,
                    "Configs: {:?}",
                    summary.dkg.configs
                );
                for (dkg_id, _) in summary.dkg.configs.iter() {
                    assert_eq!(dkg_id.target_subnet, NiDkgTargetSubnet::Local);
                }
                assert_eq!(
                    summary
                        .dkg
                        .transcripts_for_new_subnets_with_callback_ids
                        .len(),
                    2
                );
                for (dkg_id, _, result) in summary
                    .dkg
                    .transcripts_for_new_subnets_with_callback_ids
                    .iter()
                {
                    assert_eq!(dkg_id.target_subnet, NiDkgTargetSubnet::Remote(target_id));
                    assert!(result.is_err());
                }
            } else {
                panic!(
                    "block at height {} is not a summary block",
                    block.height.get()
                );
            }
        });
    }

    /// These components are used for the validation tests.
    struct ValidationTestComponents {
        dkg: DkgImpl,
        dkg_pool: DkgPoolImpl,
        dkg_key_manager: Arc<Mutex<DkgKeyManager>>,
        pool: TestConsensusPool,
    }

    impl ValidationTestComponents {
        fn sync_key_manager(&self) {
            sync_dkg_key_manager(&self.dkg_key_manager, &self.pool);
        }
    }

    fn run_validation_test(f: &dyn Fn(ValidationTestComponents, ValidationTestComponents, NodeId)) {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config_1| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config_2| {
                let crypto = Arc::new(CryptoReturningOk::default());
                let node_id_1 = node_test_id(1);
                // This is not a dealer!
                let node_id_2 = node_test_id(0);
                let consensus_pool_1 = dependencies(pool_config_1, 2).pool;
                let consensus_pool_2 = dependencies(pool_config_2, 2).pool;

                with_test_replica_logger(|logger| {
                    let dkg_pool_1 = DkgPoolImpl::new(MetricsRegistry::new(), logger.clone());
                    let dkg_pool_2 = DkgPoolImpl::new(MetricsRegistry::new(), logger.clone());

                    // We instantiate the DKG component for node Id = 1 and Id = 2.
                    let dkg_key_manager_1 = new_dkg_key_manager(
                        crypto.clone(),
                        logger.clone(),
                        &PoolReader::new(&consensus_pool_1),
                    );
                    let dkg_1 = DkgImpl::new(
                        node_id_1,
                        crypto.clone(),
                        consensus_pool_1.get_cache(),
                        dkg_key_manager_1.clone(),
                        MetricsRegistry::new(),
                        logger.clone(),
                    );

                    let dkg_key_manager_2 = new_dkg_key_manager(
                        crypto.clone(),
                        logger.clone(),
                        &PoolReader::new(&consensus_pool_2),
                    );
                    let dkg_2 = DkgImpl::new(
                        node_id_2,
                        crypto.clone(),
                        consensus_pool_2.get_cache(),
                        dkg_key_manager_2.clone(),
                        MetricsRegistry::new(),
                        logger,
                    );
                    f(
                        ValidationTestComponents {
                            dkg: dkg_1,
                            dkg_pool: dkg_pool_1,
                            dkg_key_manager: dkg_key_manager_1,
                            pool: consensus_pool_1,
                        },
                        ValidationTestComponents {
                            dkg: dkg_2,
                            dkg_pool: dkg_pool_2,
                            dkg_key_manager: dkg_key_manager_2,
                            pool: consensus_pool_2,
                        },
                        node_id_1,
                    );
                });
            });
        });
    }

    // Makes sure we do not validate dealing, if an identical one exists in the
    // validated section.
    #[test]
    fn test_validate_dealing_works_1() {
        run_validation_test(&|node_1: ValidationTestComponents,
                              mut node_2: ValidationTestComponents,
                              node_id_1| {
            // Make sure the replica 1 creates two dealings, which we insert as unvalidated
            // message into the pool of replica 2 and save one of them for later.
            let valid_dealing_message = {
                node_1.sync_key_manager();
                match &node_1.dkg.on_state_change(&node_1.dkg_pool).as_slice() {
                    &[ChangeAction::AddToValidated(message), ChangeAction::AddToValidated(message2)] =>
                    {
                        node_2.dkg_pool.insert(UnvalidatedArtifact {
                            message: message.clone(),
                            peer_id: node_id_1,
                            timestamp: UNIX_EPOCH,
                        });
                        node_2.dkg_pool.insert(UnvalidatedArtifact {
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
            node_2.sync_key_manager();
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[ChangeAction::AddToValidated(_), ChangeAction::AddToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply_changes(change_set);

            // Make sure both dealings from replica 1 is successfully validated and apply
            // the changes.
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[ChangeAction::MoveToValidated(_), ChangeAction::MoveToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply_changes(change_set);

            // Now we try to add another identical dealing from replica 1.
            node_2.dkg_pool.insert(UnvalidatedArtifact {
                message: valid_dealing_message,
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            // This dealing is identical to the one in the validated section, so we just
            // ignore it.
            assert!(node_2.dkg.on_state_change(&node_2.dkg_pool).is_empty());
        });
    }

    // Tests different attempts to add an invalid dealing: using the wrong dkg_id,
    // wrong height or just another dealing, while one valid one from this
    // dealer already exists.
    #[test]
    fn test_validate_dealing_works_2() {
        run_validation_test(&|node_1: ValidationTestComponents,
                              mut node_2: ValidationTestComponents,
                              node_id_1| {
            // Make sure the replica 1 creates two dealings, which we insert as unvalidated
            // messages into the pool of replica 2 and save one of them for later.
            let valid_dealing_message = {
                node_1.sync_key_manager();
                match &node_1.dkg.on_state_change(&node_1.dkg_pool).as_slice() {
                    &[ChangeAction::AddToValidated(message), ChangeAction::AddToValidated(message2)] =>
                    {
                        node_2.dkg_pool.insert(UnvalidatedArtifact {
                            message: message2.clone(),
                            peer_id: node_id_1,
                            timestamp: UNIX_EPOCH,
                        });
                        node_2.dkg_pool.insert(UnvalidatedArtifact {
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
            node_2.sync_key_manager();
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[ChangeAction::AddToValidated(_), ChangeAction::AddToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply_changes(change_set);

            // Make sure both dealings from replica 1 is successfully validated and apply
            // the changes.
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[ChangeAction::MoveToValidated(_), ChangeAction::MoveToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply_changes(change_set);

            // Now we try to add a different dealing but still from replica 1.
            let mut invalid_dealing_message = valid_dealing_message.clone();
            invalid_dealing_message.content.dealing = NiDkgDealing::dummy_dealing_for_tests(1);
            node_2.dkg_pool.insert(UnvalidatedArtifact {
                message: invalid_dealing_message,
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            // We expect that this dealing will be invalidated, since we have a valid one
            // from that dealer already.
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[ChangeAction::RemoveFromUnvalidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply_changes(change_set);

            // Now we create a message with an unknown Dkg id and verify
            // that it gets rejected.
            let mut invalid_dkg_id = valid_dealing_message.content.dkg_id;
            invalid_dkg_id.dealer_subnet = subnet_test_id(444);
            let mut invalid_dealing_message = valid_dealing_message.clone();
            invalid_dealing_message.content.dkg_id = invalid_dkg_id;

            node_2.dkg_pool.insert(UnvalidatedArtifact {
                message: invalid_dealing_message.clone(),
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
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
            node_2.dkg_pool.apply_changes(change_set);

            // Now we create a message from a non-dealer and verify it gets marked as
            // invalid.
            let mut invalid_dealing_message = valid_dealing_message.clone();
            invalid_dealing_message.signature.signer = node_test_id(101);

            node_2.dkg_pool.insert(UnvalidatedArtifact {
                message: invalid_dealing_message.clone(),
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
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
            node_2.dkg_pool.apply_changes(change_set);

            // Now we create a message with a wrong replica version and verify
            // that it gets rejected.
            let mut invalid_dealing_message = valid_dealing_message.clone();
            invalid_dealing_message.content.version =
                ReplicaVersion::try_from("invalid_version").unwrap();

            node_2.dkg_pool.insert(UnvalidatedArtifact {
                message: invalid_dealing_message.clone(),
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[ChangeAction::RemoveFromUnvalidated(m)] => {
                    assert_eq!(*m, invalid_dealing_message);
                }
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply_changes(change_set);

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

            node_2.dkg_pool.insert(UnvalidatedArtifact {
                message: dealing_message_from_future,
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            assert!(node_2.dkg.on_state_change(&node_2.dkg_pool).is_empty());
        });
    }

    // Creates two distiguishable dealings from one dealer and makes sure that
    // one is still accepted
    #[test]
    fn test_validate_dealing_works_3() {
        run_validation_test(&|node_1: ValidationTestComponents,
                              mut node_2: ValidationTestComponents,
                              node_id_1| {
            // Make sure the replica 1 creates dealing for H/L thresholds, which we insert
            // as unvalidated messages into the pool of replica 2 and save one of them
            // for later.
            let valid_dealing_message = {
                node_1.sync_key_manager();
                match &node_1.dkg.on_state_change(&node_1.dkg_pool).as_slice() {
                    &[ChangeAction::AddToValidated(message), ChangeAction::AddToValidated(message2)] =>
                    {
                        node_2.dkg_pool.insert(UnvalidatedArtifact {
                            message: message.clone(),
                            peer_id: node_id_1,
                            timestamp: UNIX_EPOCH,
                        });
                        node_2.dkg_pool.insert(UnvalidatedArtifact {
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
            node_2.dkg_pool.insert(UnvalidatedArtifact {
                message: dealing_message_2,
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            // Let replica 2 create dealings for L/H thresholds.
            node_2.sync_key_manager();
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[ChangeAction::AddToValidated(_), ChangeAction::AddToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply_changes(change_set);

            // Make sure we validate one dealing, and handle another two as invalid.
            node_2.sync_key_manager();
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[ChangeAction::MoveToValidated(_), ChangeAction::MoveToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
        });
    }

    // Creates two dealings for both thresholds and make sure they get validated.
    #[test]
    fn test_validate_dealing_works_4() {
        run_validation_test(&|node_1: ValidationTestComponents,
                              mut node_2: ValidationTestComponents,
                              node_id_1| {
            // Make sure the replica 1 creates two dealings for L/H thresholds, which we
            // insert as unvalidated messages into the pool of replica 2.
            node_1.sync_key_manager();
            match &node_1.dkg.on_state_change(&node_1.dkg_pool).as_slice() {
                &[ChangeAction::AddToValidated(message), ChangeAction::AddToValidated(message2)] => {
                    node_2.dkg_pool.insert(UnvalidatedArtifact {
                        message: message.clone(),
                        peer_id: node_id_1,
                        timestamp: UNIX_EPOCH,
                    });
                    node_2.dkg_pool.insert(UnvalidatedArtifact {
                        message: message2.clone(),
                        peer_id: node_id_1,
                        timestamp: UNIX_EPOCH,
                    });
                }
                val => panic!("Unexpected change set: {:?}", val),
            }

            // Make sure the replica produces its dealings.
            node_2.sync_key_manager();
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[ChangeAction::AddToValidated(_), ChangeAction::AddToValidated(_)] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply_changes(change_set);

            // Make sure we validate both dealings from replica 1
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
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
                        assert_eq!(summary.dkg.configs.len(), 2);
                        for (dkg_id, _) in summary.dkg.configs.iter() {
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
                        assert_eq!(summary.dkg.configs.len(), 4);
                    } else {
                        panic!(
                            "block at height {} is not a summary block",
                            block.height.get()
                        );
                    }

                    // Now we instantiate the DKG components. Node Id = 1 is a dealer.
                    let dgk_key_manager_1 = new_dkg_key_manager(
                        crypto_1.clone(),
                        logger.clone(),
                        &PoolReader::new(&pool_1),
                    );
                    let dkg_1 = DkgImpl::new(
                        node_test_id(1),
                        crypto_1,
                        pool_1.get_cache(),
                        dgk_key_manager_1.clone(),
                        MetricsRegistry::new(),
                        logger.clone(),
                    );

                    let dkg_2 = DkgImpl::new(
                        node_test_id(2),
                        crypto_2.clone(),
                        pool_2.get_cache(),
                        new_dkg_key_manager(crypto_2, logger.clone(), &PoolReader::new(&pool_2)),
                        MetricsRegistry::new(),
                        logger.clone(),
                    );
                    let mut dkg_pool_1 = DkgPoolImpl::new(MetricsRegistry::new(), logger.clone());
                    let mut dkg_pool_2 = DkgPoolImpl::new(MetricsRegistry::new(), logger);

                    // First we expect a new purge.
                    let change_set = dkg_1.on_state_change(&dkg_pool_1);
                    match &change_set.as_slice() {
                        &[ChangeAction::Purge(purge_height)]
                            if *purge_height == Height::from(2 * (dkg_interval_length + 1)) => {}
                        val => panic!("Unexpected change set: {:?}", val),
                    };
                    dkg_pool_1.apply_changes(change_set);
                    sync_dkg_key_manager(&dgk_key_manager_1, &pool_1);

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
                                timestamp: ic_types::time::UNIX_EPOCH,
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
                let dkg_summary = &block.payload.as_ref().as_summary().dkg;
                assert_eq!(dkg_summary.configs.len(), 4);
                assert_eq!(
                    dkg_summary
                        .configs
                        .keys()
                        .filter(|id| id.target_subnet == NiDkgTargetSubnet::Remote(target_id))
                        .count(),
                    2
                );
                assert!(dkg_summary
                    .transcripts_for_new_subnets_with_callback_ids
                    .is_empty());
            } else {
                panic!(
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
                let dkg_summary = &block.payload.as_ref().as_summary().dkg;
                assert_eq!(dkg_summary.configs.len(), 2);
                assert_eq!(
                    dkg_summary
                        .configs
                        .keys()
                        .filter(|id| id.target_subnet == NiDkgTargetSubnet::Remote(target_id))
                        .count(),
                    0
                );
                assert_eq!(
                    dkg_summary
                        .transcripts_for_new_subnets_with_callback_ids
                        .iter()
                        .filter(
                            |(id, _, _)| id.target_subnet == NiDkgTargetSubnet::Remote(target_id)
                        )
                        .count(),
                    2
                );
            } else {
                panic!(
                    "block at height {} is not a summary block",
                    block.height.get()
                );
            }
        })
    }

    /*
     * Test bases on the following example (assumption: every DKG succeeds).
     * DKG interval = 4
     *
     * Version 5: Members {0, 1, 2, 3}
     *
     * Block 0:
     *   - created by registry
     *   block.context.registry_version = 5
     *   summary.registry_version = 5
     *   summary.current_transcript is 0
     *   summary.next_transcript is None
     *   summary.configs: Compute DKG 1: committee 5 reshares transcript 0 to
     *                    committee 5, committee 5 creates low threshold transcript
     *
     * Version 6: Members {3, 4, 5, 6, 7}
     *
     * Block 5:
     *   - created by committee 5
     *   block.context.registry_version = 6
     *   summary.registry_version = 5
     *   summary.current_transcript is 0 (re-used)
     *   summary.next_transcript is 1
     *   summary.configs: Compute DKG 2: committee 5 reshares transcript 1 to
     *                    committee 6, committee 6 creates low threshold transcript
     *
     * Version 10: Members {3, 4, 5, 6}
     *
     * Block 10:
     *   - proposed, notarized, finalized by committee 6
     *   - beacon, tape, certification, cup by committee 5
     *   block.context.registry_version = 10
     *   summary.registry_version = 6
     *   summary.current_transcript is 1
     *   summary.next_transcript = 2
     *   summary.configs: Compute DKG 3: committee 6 reshares transcript 2 to
     *                    committee 10, committee 10 creates low threshold transcript
     *
     * Block 15:
     *   - proposed, notarized, finalized by committee 10
     *   - beacon, tape, certification, cup by committee 6
     *   block.context.registry_version = 10
     *   summary.registry_version = 10
     *   summary.current_transcript is 2, meaning nodes {0, 1, 2} can leave
     *   summary.next_transcript is 3
     *   summary.configs: Compute DKG 4: committee 10 reshares transcript 3 to
     *                    committee 10, committee 10 creates low threshold transcript
     *
     * Block 20:
     *   - created by committee 10
     *   block.context.registry_version = 10
     *   summary.registry_version = 10
     *   summary.current_transcript is 3, meaning node {7} can leave
     *   summary.next_transcript is 4
     *   summary.configs: Compute DKG 5: committee 10 reshares transcript 4 to
     *                    committee 10, committee 10 creates low threshold transcript
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
            let cup = PoolReader::new(&pool).get_highest_catch_up_package();
            let dkg_block = cup.content.block.as_ref();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(5),
                "The latest available version was used for the summary block."
            );
            let summary = dkg_block.payload.as_ref().as_summary();
            let dkg_summary = &summary.dkg;
            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(5));
            assert_eq!(dkg_summary.height, Height::from(0));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(5)
            );
            for tag in TAGS.iter() {
                let current_transcript = dkg_summary.current_transcript(tag);
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(0)
                );
                assert_eq!(
                    current_transcript.committee.get(),
                    &committee1.clone().into_iter().collect::<BTreeSet<_>>()
                );
                assert_eq!(
                    current_transcript.registry_version,
                    RegistryVersion::from(5)
                );
                // The genesis summary cannot have next transcripts, instead we'll reuse in
                // round 1 the active transcripts from round 0.
                assert!(dkg_summary.next_transcript(tag).is_none());
            }

            // Advance for one round and update the registry to version 6 with new
            // membership (nodes 3, 4, 5, 6, 7).
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
            let cup = PoolReader::new(&pool).get_highest_catch_up_package();
            let dkg_block = cup.content.block.as_ref();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(6),
                "The newest registry version is used."
            );
            let summary = dkg_block.payload.as_ref().as_summary();
            let dkg_summary = &summary.dkg;
            // This membership registry version corresponds to the registry version from
            // the block context of the previous summary.
            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(5));
            assert_eq!(dkg_summary.height, Height::from(5));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(5)
            );
            for tag in TAGS.iter() {
                // We reused the transcript.
                let current_transcript = dkg_summary.current_transcript(tag);
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(0)
                );
                // New configs are created for the new context registry version,
                // which will be the new membership version in the next interval.
                let (_, conf) = dkg_summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == *tag)
                    .unwrap();
                assert_eq!(conf.registry_version(), RegistryVersion::from(6));
                assert_eq!(
                    conf.receivers().get(),
                    &committee2.clone().into_iter().collect::<BTreeSet<_>>()
                );
            }

            // Advance for one round and update the registry to version 10 with new
            // membership (nodes 3, 4, 5, 6).
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
            let cup = PoolReader::new(&pool).get_highest_catch_up_package();
            let dkg_block = cup.content.block.as_ref();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(10),
                "The newest registry version is used."
            );
            let summary = dkg_block.payload.as_ref().as_summary();
            let dkg_summary = &summary.dkg;
            // This membership registry version corresponds to the registry version from
            // the block context of the previous summary.
            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(6));
            assert_eq!(dkg_summary.height, Height::from(10));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(5)
            );
            for tag in TAGS.iter() {
                let (_, conf) = dkg_summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == *tag)
                    .unwrap();
                assert_eq!(
                    conf.receivers().get(),
                    &committee3.clone().into_iter().collect::<BTreeSet<_>>()
                );
                let current_transcript = dkg_summary.current_transcript(tag);
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(0)
                );
                let next_transcript = dkg_summary.next_transcript(tag).unwrap();
                // The DKG id start height refers to height 5, where we started computing this
                // DKG.
                assert_eq!(next_transcript.dkg_id.start_block_height, Height::from(5));
            }

            // Skip till the next DKG round
            pool.advance_round_normal_operation_n(dkg_interval_length + 1);
            let cup = PoolReader::new(&pool).get_highest_catch_up_package();
            let dkg_block = cup.content.block.as_ref();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(10),
                "The latest registry version is used."
            );
            let summary = dkg_block.payload.as_ref().as_summary();
            let dkg_summary = &summary.dkg;
            // This membership registry version corresponds to the registry version from
            // the block context of the previous summary.
            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(10));
            assert_eq!(dkg_summary.height, Height::from(15));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(6)
            );
            for tag in TAGS.iter() {
                let (_, conf) = dkg_summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == *tag)
                    .unwrap();
                assert_eq!(
                    conf.receivers().get(),
                    &committee3.clone().into_iter().collect::<BTreeSet<_>>()
                );
                let current_transcript = dkg_summary.current_transcript(tag);
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(5)
                );
                let next_transcript = dkg_summary.next_transcript(tag).unwrap();
                assert_eq!(next_transcript.dkg_id.start_block_height, Height::from(10));
            }

            // Skip till the next DKG round
            pool.advance_round_normal_operation_n(dkg_interval_length + 1);
            let cup = PoolReader::new(&pool).get_highest_catch_up_package();
            let dkg_block = cup.content.block.as_ref();
            assert_eq!(
                dkg_block.context.registry_version,
                RegistryVersion::from(10),
                "The latest registry version is used."
            );
            let summary = dkg_block.payload.as_ref().as_summary();
            let dkg_summary = &summary.dkg;
            // This membership registry version corresponds to the registry version from
            // the block context of the previous summary.
            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(10));
            assert_eq!(dkg_summary.height, Height::from(20));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(10)
            );
            for tag in TAGS.iter() {
                let (_, conf) = dkg_summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == *tag)
                    .unwrap();
                assert_eq!(
                    conf.receivers().get(),
                    &committee3.clone().into_iter().collect::<BTreeSet<_>>()
                );
                let current_transcript = dkg_summary.current_transcript(tag);
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(10)
                );
                let next_transcript = dkg_summary.next_transcript(tag).unwrap();
                assert_eq!(next_transcript.dkg_id.start_block_height, Height::from(15));
            }
        });
    }

    /// `RegistryClient` implementation that allows to provide a custom function
    /// to provide a `get_versioned_value`.
    struct MockRegistryClient<F>
    where
        F: Fn(&str, RegistryVersion) -> Option<Vec<u8>>,
    {
        latest_registry_version: RegistryVersion,
        get_versioned_value_fun: F,
    }

    impl<F> MockRegistryClient<F>
    where
        F: Fn(&str, RegistryVersion) -> Option<Vec<u8>>,
    {
        fn new(latest_registry_version: RegistryVersion, get_versioned_value_fun: F) -> Self {
            Self {
                latest_registry_version,
                get_versioned_value_fun,
            }
        }
    }

    impl<F> RegistryClient for MockRegistryClient<F>
    where
        F: Fn(&str, RegistryVersion) -> Option<Vec<u8>> + Send + Sync,
    {
        fn get_versioned_value(
            &self,
            key: &str,
            version: RegistryVersion,
        ) -> ic_interfaces_registry::RegistryClientVersionedResult<Vec<u8>> {
            let value = (self.get_versioned_value_fun)(key, version);
            Ok(RegistryVersionedRecord {
                key: key.to_string(),
                version,
                value,
            })
        }

        // Not needed for this test
        fn get_key_family(
            &self,
            _: &str,
            _: RegistryVersion,
        ) -> Result<Vec<String>, RegistryClientError> {
            Ok(vec![])
        }

        fn get_latest_version(&self) -> RegistryVersion {
            self.latest_registry_version
        }

        // Not needed for this test
        fn get_version_timestamp(&self, _: RegistryVersion) -> Option<Time> {
            None
        }
    }

    #[test]
    fn test_make_registry_cup() {
        let registry_client = MockRegistryClient::new(RegistryVersion::from(12345), |key, _| {
            use prost::Message;
            if key.starts_with("catch_up_package_contents_") {
                // Build a dummy cup
                let committee = vec![NodeId::from(PrincipalId::new_node_test_id(0))];
                let cup =
                    CatchUpPackageContents {
                        initial_ni_dkg_transcript_low_threshold: Some(
                            dummy_initial_dkg_transcript(committee.clone(), NiDkgTag::LowThreshold),
                        ),
                        initial_ni_dkg_transcript_high_threshold: Some(
                            dummy_initial_dkg_transcript(committee, NiDkgTag::HighThreshold),
                        ),
                        height: 54321,
                        time: 1,
                        state_hash: vec![1, 2, 3, 4, 5],
                        registry_store_uri: None,
                        ecdsa_initializations: vec![],
                        chain_key_initializations: vec![],
                    };

                // Encode the cup to protobuf
                let mut value = Vec::with_capacity(cup.encoded_len());
                cup.encode(&mut value).unwrap();
                Some(value)
            } else if key.starts_with("subnet_record_") {
                // Build a dummy subnet record. The only value used from this are the
                // `membership` and `dkg_interval_length` fields.
                let subnet_record = SubnetRecord {
                    membership: vec![PrincipalId::new_subnet_test_id(1).to_vec()],
                    dkg_interval_length: 99,
                    replica_version_id: "TestID".to_string(),
                    ..SubnetRecord::default()
                };

                // Encode the `SubnetRecord` to protobuf
                let mut value = Vec::with_capacity(subnet_record.encoded_len());
                subnet_record.encode(&mut value).unwrap();
                Some(value)
            } else {
                None
            }
        });
        let result =
            make_registry_cup(&registry_client, subnet_test_id(0), &no_op_logger()).unwrap();

        assert_eq!(
            result.content.state_hash.get_ref(),
            &CryptoHash(vec![1, 2, 3, 4, 5])
        );
        assert_eq!(
            result.content.block.get_value().context.registry_version,
            RegistryVersion::from(12345)
        );
        assert_eq!(
            result.content.block.get_value().context.certified_height,
            Height::from(54321)
        );
        assert_eq!(
            result.content.version(),
            &ReplicaVersion::try_from("TestID").unwrap()
        );
        assert_eq!(result.signature.signer.dealer_subnet, subnet_test_id(0));
    }

    fn new_dkg_key_manager(
        crypto: Arc<dyn ConsensusCrypto>,
        logger: ReplicaLogger,
        pool_reader: &PoolReader<'_>,
    ) -> Arc<Mutex<DkgKeyManager>> {
        Arc::new(Mutex::new(DkgKeyManager::new(
            MetricsRegistry::new(),
            crypto,
            logger,
            pool_reader,
        )))
    }

    // Since the `DkgKeyManager` component is not running, we need to allow it to
    // make progress occasionally.
    //
    // This function calls on_state_change and sync, to allow the transcripts to be
    // loaded.
    fn sync_dkg_key_manager(mngr: &Arc<Mutex<DkgKeyManager>>, pool: &TestConsensusPool) {
        let mut mngr = mngr.lock().unwrap();

        mngr.on_state_change(&PoolReader::new(pool));
        mngr.sync();
    }
}
