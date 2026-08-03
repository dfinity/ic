//! This module defines an embedding of the dkg algorithm provided by the crypto
//! component into the consensus algorithm that is implemented within this
//! crate.

use ic_consensus_utils::{bouncer_metrics::BouncerMetrics, crypto::ConsensusCrypto};
use ic_interfaces::{
    consensus_pool::ConsensusPoolCache,
    dkg::{ChangeAction, DkgPayloadValidationError, DkgPool, Mutations},
    p2p::consensus::{Bouncer, BouncerFactory, BouncerValue, PoolMutationsProducer},
    validation::ValidationResult,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{ReplicaLogger, error, info};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    Height, NodeId, ReplicaVersion, SubnetId,
    consensus::dkg::{DealingContent, DkgMessageId, InvalidDkgPayloadReason, Message},
    crypto::{
        Signed,
        threshold_sig::ni_dkg::{NiDkgId, NiDkgTargetSubnet, config::NiDkgConfig},
    },
};
use rayon::prelude::*;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

pub mod dkg_key_manager;
pub mod metrics;
pub mod payload_builder;
pub mod payload_validator;
pub(crate) mod remote;

use crate::remote::{build_callback_id_config_map, merge_configs};
pub use crate::utils::get_vetkey_public_keys;
use metrics::DkgClientMetrics;

#[cfg(test)]
mod test_utils;
mod utils;

pub use dkg_key_manager::DkgKeyManager;
pub use payload_builder::{create_payload, get_dkg_summary_from_cup_contents};

/// The maximal number of DKGs for other subnets we want to run in one interval.
const MAX_REMOTE_DKGS_PER_INTERVAL: usize = 1;

/// The maximum number of remote DKG transcripts we want to include in a data payload.
/// Note that responses for `SetupInitialDKG` requests contain two transcripts.
const MAX_REMOTE_TRANSCRIPTS_PER_PAYLOAD: usize = 2;

/// The maximum number of intervals during which an initial DKG request is
/// attempted.
const MAX_REMOTE_DKG_ATTEMPTS: u32 = 5;

/// Generic error string for failed remote DKG requests.
const REMOTE_DKG_REPEATED_FAILURE_ERROR: &str = "Attempts to run this DKG repeatedly failed";

/// `DkgImpl` is responsible for holding DKG dependencies and for responding to
/// changes in the consensus and DKG pool.
pub struct DkgImpl {
    node_id: NodeId,
    subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    crypto: Arc<dyn ConsensusCrypto>,
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    dkg_key_manager: Arc<Mutex<DkgKeyManager>>,
    logger: ReplicaLogger,
    metrics: DkgClientMetrics,
}

impl DkgImpl {
    /// Build a new DKG component
    pub fn new(
        node_id: NodeId,
        subnet_id: SubnetId,
        registry_client: Arc<dyn RegistryClient>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        crypto: Arc<dyn ConsensusCrypto>,
        consensus_cache: Arc<dyn ConsensusPoolCache>,
        dkg_key_manager: Arc<Mutex<DkgKeyManager>>,
        metrics_registry: ic_metrics::MetricsRegistry,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            subnet_id,
            registry_client,
            state_reader,
            crypto,
            consensus_cache,
            dkg_key_manager,
            logger,
            metrics: DkgClientMetrics::new(metrics_registry),
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
        if let Some(transcript) = config.resharing_transcript()
            && !self
                .dkg_key_manager
                .lock()
                .unwrap()
                .is_transcript_loaded(&transcript.dkg_id)
        {
            return None;
        }

        let content =
            match ic_interfaces::crypto::NiDkgAlgorithm::create_dealing(&*self.crypto, config) {
                Ok(dealing) => DealingContent::new(dealing, config.dkg_id().clone()),
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
        configs: &BTreeMap<&NiDkgId, &NiDkgConfig>,
        dkg_start_height: Height,
        messages: &[&Message],
    ) -> Mutations {
        // Because dealing generation is not entirely deterministic, it is
        // actually possible to receive multiple dealings from an honest dealer.
        // As such, we simply try validating the first message in the list, and
        // get a result for that message. Other messages will be dealt with by
        // subsequent calls to this function.
        let message = if let Some(message) = messages.first() {
            message
        } else {
            return Mutations::new();
        };

        if message.content.version != ReplicaVersion::default() {
            return Mutations::from(ChangeAction::RemoveFromUnvalidated((*message).clone()));
        }

        let message_dkg_id = &message.content.dkg_id;

        // If the dealing refers to a DKG interval starting at a different height,
        // we skip it.
        if message_dkg_id.start_block_height != dkg_start_height {
            return Mutations::new();
        }

        // If the dealing refers a config which is not among the ongoing DKGs,
        // we reject it, unless it is a remote DKG, in which case we defer it
        // until the request appears in the state, or the dealing is purged.
        let config = match configs.get(message_dkg_id) {
            Some(config) => config,
            None if message_dkg_id.target_subnet.is_remote() => {
                return Mutations::new();
            }
            None => {
                return get_handle_invalid_change_action(
                    message,
                    format!("No DKG configuration for Id={message_dkg_id:?} was found."),
                )
                .into();
            }
        };

        let dealer_id = &message.signature.signer;

        // If the validated pool already contains this exact message, we skip it.
        if dkg_pool.get_validated().any(|item| item.eq(message)) {
            return Mutations::new();
        }

        // If we already have a dealing from this dealer, we simply remove the
        // message from the pool. Multiple distinguishable valid dealings can be
        // created by an honest node because dkg dealings are not deterministic,
        // and in the case of a restart it is possible it might forget that it
        // has already sent out a dealing. See
        // https://dfinity.atlassian.net/browse/CON-534 for more details.
        if contains_dkg_messages(dkg_pool, config, *dealer_id) {
            return Mutations::from(ChangeAction::RemoveFromUnvalidated((*message).clone()));
        }

        // Verify the dealing and move to validated if it was successful,
        // reject, if it was rejected, or skip, if there was an error.
        match crypto_validate_dealing(&*self.crypto, config, message) {
            Ok(()) => ChangeAction::MoveToValidated((*message).clone()).into(),
            Err(DkgPayloadValidationError::InvalidArtifact(err)) => {
                get_handle_invalid_change_action(
                    message,
                    format!("Dealing verification failed: {err:?}"),
                )
                .into()
            }
            Err(DkgPayloadValidationError::ValidationFailed(err)) => {
                error!(
                    self.logger,
                    "Couldn't verify a DKG dealing from the pool: {:?}", err
                );
                Mutations::new()
            }
        }
    }
}

/// Validate the signature and dealing of the given message against its config
#[allow(clippy::result_large_err)]
pub(crate) fn crypto_validate_dealing(
    crypto: &dyn ConsensusCrypto,
    config: &NiDkgConfig,
    message: &Message,
) -> ValidationResult<DkgPayloadValidationError> {
    let dealer = message.signature.signer;
    if !config.dealers().get().contains(&dealer) {
        return Err(InvalidDkgPayloadReason::InvalidDealer(dealer).into());
    }
    crypto.verify(message, config.registry_version())?;
    ic_interfaces::crypto::NiDkgAlgorithm::verify_dealing(
        crypto,
        config,
        dealer,
        &message.content.dealing,
    )?;
    Ok(())
}

fn contains_dkg_messages(dkg_pool: &dyn DkgPool, config: &NiDkgConfig, replica_id: NodeId) -> bool {
    dkg_pool.get_validated().any(|message| {
        &message.content.dkg_id == config.dkg_id() && message.signature.signer == replica_id
    })
}

fn get_handle_invalid_change_action<T: AsRef<str>>(message: &Message, reason: T) -> ChangeAction {
    ChangeAction::HandleInvalid(DkgMessageId::from(message), reason.as_ref().to_string())
}

impl<T: DkgPool> PoolMutationsProducer<T> for DkgImpl {
    type Mutations = Mutations;

    fn on_state_change(&self, dkg_pool: &T) -> Mutations {
        // This timer will make an entry in the metrics histogram automatically, when
        // it's dropped.
        let _timer = self.metrics.on_state_change_duration.start_timer();
        let dkg_summary_block = self.consensus_cache.summary_block();
        let dkg_summary = &dkg_summary_block.payload.as_ref().as_summary().dkg;
        let start_height = dkg_summary_block.height;

        if start_height > dkg_pool.get_current_start_height() {
            return ChangeAction::Purge(start_height).into();
        }

        // Consider NiDKG configs from the latest state and summary block.
        let remote_config_results = self
            .state_reader
            .get_latest_certified_state()
            .and_then(|state| {
                build_callback_id_config_map(
                    self.subnet_id,
                    self.registry_client.as_ref(),
                    state.get_ref(),
                    self.registry_client.get_latest_version(),
                    dkg_summary,
                    &self.logger,
                )
                .inspect_err(|err| {
                    error!(
                        every_n_seconds => 15,
                        self.logger,
                        "Error building callback id config map: {err:?}"
                    )
                })
                .ok()
            })
            .unwrap_or_default();
        let configs = merge_configs(&dkg_summary.configs, &remote_config_results);

        let change_set: Mutations = configs
            .par_iter()
            .filter_map(|(_id, config)| self.create_dealing(dkg_pool, config))
            .collect();
        if !change_set.is_empty() {
            return change_set;
        }

        let mut processed = 0;
        let dealings: Vec<Vec<&Message>> = dkg_pool
            .get_unvalidated()
            // Group all unvalidated dealings by (dealer, DKG ID).
            .fold(BTreeMap::new(), |mut map, dealing| {
                let key = (dealing.signature.signer, dealing.content.dkg_id.clone());
                let dealings: &mut Vec<_> = map.entry(key).or_default();
                dealings.push(dealing);
                processed += 1;
                map
            })
            // Get the dealings sorted by (dealer, DKG ID)
            .into_values()
            .collect();

        let changeset = dealings
            .par_iter()
            .map(|dealings| {
                self.validate_dealings_for_dealer(dkg_pool, &configs, start_height, dealings)
            })
            .collect::<Vec<Mutations>>()
            .into_iter()
            .flatten()
            .collect::<Mutations>();

        self.metrics
            .on_state_change_processed
            .observe(processed as f64);
        changeset
    }
}

/// `DkgBouncer` is a placeholder for gossip related DKG interfaces.
pub struct DkgBouncer {
    metrics: BouncerMetrics,
}

impl DkgBouncer {
    /// Creates a new bouncer.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            metrics: BouncerMetrics::new(metrics_registry, "dkg_pool"),
        }
    }
}

// The NiDKG component does not implement custom `get_filter` function
// because it doesn't require artifact retransmission. Nodes participating
// in NiDKG would create artifacts depending on their own consensus state.
// If a node happens to disconnect, it would send out dealings based on
// its previous state after it reconnects, regardless of whether it has sent
// them before.
impl<Pool: DkgPool> BouncerFactory<DkgMessageId, Pool> for DkgBouncer {
    fn new_bouncer(&self, dkg_pool: &Pool) -> Bouncer<DkgMessageId> {
        let _timer = self.metrics.update_duration.start_timer();

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        complement_state_manager_with_dkg_contexts,
        complement_state_manager_with_setup_initial_dkg_request, create_dealing,
        extract_dkg_configs_from_highest_block, make_reshare_chain_key_context,
        make_setup_initial_dkg_context,
    };
    use core::panic;
    use ic_artifact_pool::dkg_pool::DkgPoolImpl;
    use ic_consensus_mocks::{
        Dependencies, dependencies, dependencies_with_subnet_params,
        dependencies_with_subnet_records_with_raw_state_manager,
    };
    use ic_consensus_utils::pool_reader::PoolReader;
    use ic_crypto_test_utils_crypto_returning_ok::CryptoReturningOk;
    use ic_crypto_test_utils_ni_dkg::dummy_dealing;
    use ic_interfaces::{
        consensus_pool::ConsensusPool,
        p2p::consensus::{BouncerFactory, BouncerValue, MutablePool, UnvalidatedArtifact},
    };
    use ic_interfaces_mocks::crypto::MockCrypto;
    use ic_interfaces_registry::RegistryClient;
    use ic_interfaces_state_manager::{Labeled, StateReader};
    use ic_logger::no_op_logger;
    use ic_management_canister_types_private::{MasterPublicKeyId, VetKdCurve, VetKdKeyId};
    use ic_metrics::MetricsRegistry;
    use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
    use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
    use ic_test_utilities_consensus::fake::{FakeContentSigner, FromParent};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::{SubnetRecordBuilder, add_subnet_record};
    use ic_test_utilities_state::get_initial_state;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        RegistryVersion, ReplicaVersion,
        batch::ValidationContext,
        consensus::{
            Block, BlockPayload, BlockProposal, DataPayload, HasHeight, Payload,
            dkg::{DkgDataPayload, RemoteDkgAttempts, RemoteTranscriptResult},
        },
        crypto::{
            AlgorithmId, CryptoHash,
            error::MalformedPublicKeyError,
            threshold_sig::ni_dkg::{
                NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
                errors::create_transcript_error::DkgCreateTranscriptError,
            },
        },
        time::UNIX_EPOCH,
    };
    use payload_validator::validate_payload;
    use std::{collections::BTreeSet, convert::TryFrom};
    use test_utils::{extract_dealings_from_highest_block, extract_remote_dkgs_from_highest_block};
    use utils::{tags_iter, vetkd_key_ids_for_subnet};

    #[test]
    fn test_dkg_bouncer() {
        with_test_replica_logger(|logger| {
            let mut dkg_pool = DkgPoolImpl::new(MetricsRegistry::new(), logger, Height::from(500));
            let bouncer_factory = DkgBouncer::new(&MetricsRegistry::new());
            let bouncer = bouncer_factory.new_bouncer(&dkg_pool);

            let height_500_id = DkgMessageId {
                hash: CryptoHash(vec![0]).into(),
                height: Height::from(500),
            };
            let height_1000_id = DkgMessageId {
                hash: CryptoHash(vec![1]).into(),
                height: Height::from(1000),
            };
            assert_eq!(bouncer(&height_500_id), BouncerValue::Wants);
            assert_eq!(bouncer(&height_1000_id), BouncerValue::MaybeWantsLater);

            dkg_pool.apply(vec![ChangeAction::Purge(Height::from(1000))]);
            let bouncer = bouncer_factory.new_bouncer(&dkg_pool);

            assert_eq!(bouncer(&height_1000_id), BouncerValue::Wants);
            assert_eq!(bouncer(&height_500_id), BouncerValue::Unwanted);
        });
    }

    #[test]
    // In this test we test the creation of dealing payloads.
    fn test_create_dealings_payload() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let nodes: Vec<_> = (0..4).map(node_test_id).collect();
                let dkg_interval_len = 30;
                let subnet_id = subnet_test_id(222);
                let initial_registry_version = 112;
                let vet_key_ids = vec![NiDkgMasterPublicKeyId::VetKd(test_vet_key())];
                let Dependencies {
                    crypto,
                    mut pool,
                    dkg_pool,
                    registry,
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
                state_manager
                    .get_mut()
                    .expect_get_latest_certified_state()
                    .return_const(Some(Labeled::new(
                        Height::new(0),
                        Arc::new(get_initial_state(0, 0)),
                    )));

                // Now we instantiate the DKG component for node Id = 1, who is a dealer.
                let replica_1 = node_test_id(1);
                let dkg_key_manager =
                    new_dkg_key_manager(crypto.clone(), logger.clone(), &PoolReader::new(&pool));
                let dkg = DkgImpl::new(
                    replica_1,
                    subnet_id,
                    registry.clone(),
                    state_manager.clone(),
                    crypto.clone(),
                    pool.get_cache(),
                    dkg_key_manager.clone(),
                    MetricsRegistry::new(),
                    logger.clone(),
                );

                // Creates dealings for both thresholds and vet key and add them to the pool.
                sync_dkg_key_manager(&dkg_key_manager, &pool);
                let change_set = dkg.on_state_change(&*dkg_pool.read().unwrap());
                assert_eq!(change_set.len(), 3);
                dkg_pool.write().unwrap().apply(change_set);

                // Advance the consensus pool for one round and make sure all dealings made it
                // into the block.
                pool.advance_round_normal_operation();
                let block = pool.get_cache().finalized_block();
                let dealings = &block.payload.as_ref().as_data().dkg;
                if dealings.start_height != Height::from(0) {
                    panic!(
                        "Expected start height in dealings {:?}, but found {:?}",
                        Height::from(0),
                        dealings.start_height
                    )
                }
                assert_eq!(dealings.messages.len(), 3);
                for tag in tags_iter(&vet_key_ids) {
                    assert!(dealings.messages.iter().any(
                        |m| m.signature.signer == replica_1 && m.content.dkg_id.dkg_tag == tag
                    ));
                }

                // Now make sure, the dealing from the same dealer will not be included in a new
                // block anymore.
                pool.advance_round_normal_operation();
                let block = pool.get_cache().finalized_block();
                let dealings = &block.payload.as_ref().as_data().dkg;
                assert_eq!(dealings.messages.len(), 0);

                // Now we empty the dkg pool, add new dealings from this dealer and make sure
                // they are still not included.
                assert_eq!(dkg_pool.read().unwrap().get_validated().count(), 3);
                dkg_pool
                    .write()
                    .unwrap()
                    .apply(vec![ChangeAction::Purge(block.height)]);
                // Check that the dkg pool is really empty.
                assert_eq!(dkg_pool.read().unwrap().get_validated().count(), 0);
                // Create new dealings; this works, because we cleaned the pool before.
                let change_set = dkg.on_state_change(&*dkg_pool.read().unwrap());
                assert_eq!(change_set.len(), 3);
                dkg_pool.write().unwrap().apply(change_set);
                // Make sure the new dealings are in the pool.
                assert_eq!(dkg_pool.read().unwrap().get_validated().count(), 3);
                // Advance the pool and make sure the dealing are not included.
                pool.advance_round_normal_operation();
                let block = pool.get_cache().finalized_block();
                let dealings = &block.payload.as_ref().as_data().dkg;
                assert_eq!(dealings.messages.len(), 0);

                // Create another dealer and add his dealings into the unvalidated pool of
                // replica 1.
                let replica_2 = node_test_id(2);
                let dkg_key_manager_2 =
                    new_dkg_key_manager(crypto.clone(), logger.clone(), &PoolReader::new(&pool));
                let dkg_2 = DkgImpl::new(
                    replica_2,
                    subnet_id,
                    registry,
                    state_manager,
                    crypto,
                    pool.get_cache(),
                    dkg_key_manager_2.clone(),
                    MetricsRegistry::new(),
                    logger.clone(),
                );
                let start_height = dkg_pool.read().unwrap().get_current_start_height();
                let dkg_pool_2 = DkgPoolImpl::new(MetricsRegistry::new(), logger, start_height);
                sync_dkg_key_manager(&dkg_key_manager_2, &pool);
                let change_set = dkg_2.on_state_change(&dkg_pool_2);
                assert_eq!(change_set.len(), 3);
                for action in change_set {
                    match action {
                        ChangeAction::AddToValidated(message) => {
                            dkg_pool.write().unwrap().insert(UnvalidatedArtifact {
                                message: message.clone(),
                                peer_id: replica_1,
                                timestamp: UNIX_EPOCH,
                            })
                        }
                        action => panic!("Unexpected action {:?} in changeset", action),
                    }
                }

                // Now we validate these dealings on replica 1 and move them to the validated
                // pool.
                let change_set = dkg.on_state_change(&*dkg_pool.read().unwrap());
                match &change_set.as_slice() {
                    &[
                        ChangeAction::MoveToValidated(_),
                        ChangeAction::MoveToValidated(_),
                        ChangeAction::MoveToValidated(_),
                    ] => {}
                    val => panic!("Unexpected change set: {:?}", val),
                };
                dkg_pool.write().unwrap().apply(change_set);
                assert_eq!(dkg_pool.read().unwrap().get_validated().count(), 6);

                // Now we create a new block and make sure, the dealings made into the payload.
                pool.advance_round_normal_operation();
                let block = pool.get_cache().finalized_block();
                let dealings = &block.payload.as_ref().as_data().dkg;
                if dealings.start_height != Height::from(0) {
                    panic!(
                        "Expected start height in dealings {:?}, but found {:?}",
                        Height::from(0),
                        dealings.start_height
                    )
                }
                assert_eq!(dealings.messages.len(), 3);
                for tag in tags_iter(&vet_key_ids) {
                    assert!(dealings.messages.iter().any(
                        |m| m.signature.signer == replica_2 && m.content.dkg_id.dkg_tag == tag
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
                    mut pool,
                    crypto,
                    registry,
                    state_manager,
                    replica_config,
                    ..
                } = dependencies(pool_config.clone(), 2);
                state_manager
                    .get_mut()
                    .expect_get_latest_certified_state()
                    .return_const(Some(Labeled::new(
                        Height::new(0),
                        Arc::new(get_initial_state(0, 0)),
                    )));
                let mut dkg_pool =
                    DkgPoolImpl::new(MetricsRegistry::new(), logger.clone(), Height::from(0));
                // Let's check that replica 3, who's not a dealer, does not produce dealings.
                let dkg_key_manager =
                    new_dkg_key_manager(crypto.clone(), logger.clone(), &PoolReader::new(&pool));
                let dkg = DkgImpl::new(
                    node_test_id(3),
                    replica_config.subnet_id,
                    registry.clone(),
                    state_manager.clone(),
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
                    replica_config.subnet_id,
                    registry,
                    state_manager,
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
                    &[
                        ChangeAction::AddToValidated(_),
                        ChangeAction::AddToValidated(_),
                    ] => {}
                    val => panic!("Unexpected change set: {:?}", val),
                };

                // Apply the changes and make sure, we do not produce any dealings anymore.
                dkg_pool.apply(change_set);
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
                dkg_pool.apply(change_set);
                // And then we validate...
                let change_set = dkg.on_state_change(&dkg_pool);
                match &change_set.as_slice() {
                    &[
                        ChangeAction::AddToValidated(_),
                        ChangeAction::AddToValidated(_),
                    ] => {}
                    val => panic!("Unexpected change set: {:?}", val),
                };
                // Just check again, we do not reproduce a dealing once changes are applied.
                dkg_pool.apply(change_set);
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
                    dkg_pool,
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

                let target_id = NiDkgTargetId::new([0_u8; 32]);
                complement_state_manager_with_setup_initial_dkg_request(
                    state_manager.clone(),
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
                    subnet_id,
                    registry.clone(),
                    state_manager.clone(),
                    crypto,
                    pool.get_cache(),
                    dkg_key_manager.clone(),
                    MetricsRegistry::new(),
                    logger.clone(),
                );

                // We will create dealings for remote requests immediately, even if we haven't
                // reached a summary block yet.
                sync_dkg_key_manager(&dkg_key_manager, &pool);
                let change_set = dkg.on_state_change(&*dkg_pool.read().unwrap());
                match &change_set.as_slice() {
                    &[
                        ChangeAction::AddToValidated(a),
                        ChangeAction::AddToValidated(b),
                        ChangeAction::AddToValidated(c),
                        ChangeAction::AddToValidated(d),
                    ] => {
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
                                .filter(|msg| msg.content.dkg_id.target_subnet.is_local())
                                .count(),
                            2
                        );
                    }
                    val => panic!("Unexpected change set: {:?}", val),
                };
                // Just check again, we do not reproduce a dealing once changes are applied.
                dkg_pool.write().unwrap().apply(change_set);
                assert!(dkg.on_state_change(&*dkg_pool.read().unwrap()).is_empty());

                // Dealings should be included in a block.
                pool.advance_round_normal_operation();
                let dealings = extract_dealings_from_highest_block(&pool);
                assert_eq!(dealings.len(), 4);
                let remote_dealings = dealings
                    .iter()
                    .filter(|d| {
                        d.content.dkg_id.target_subnet == NiDkgTargetSubnet::Remote(target_id)
                    })
                    .count();
                assert_eq!(remote_dealings, 2);

                // Once enough remote dealings are available on chain, they are turned into
                // remote transcripts in the data payload.
                pool.advance_round_normal_operation();
                let remote_transcripts = extract_remote_dkgs_from_highest_block(&pool);
                assert_eq!(remote_transcripts.len(), 2);
                let mut tags = BTreeSet::new();
                for transcript in &remote_transcripts {
                    assert_eq!(
                        transcript.dkg_id.target_subnet,
                        NiDkgTargetSubnet::Remote(target_id)
                    );
                    assert!(transcript.transcript_result.is_ok());
                    assert!(tags.insert(transcript.dkg_id.dkg_tag.clone()));
                }
                assert_eq!(
                    tags,
                    BTreeSet::from([NiDkgTag::LowThreshold, NiDkgTag::HighThreshold])
                );

                // After the next summary, remote transcripts are finalized and we should not
                // attempt to create remote dealings again.
                pool.advance_round_normal_operation_n(dkg_interval_length);
                let latest_summary = PoolReader::new(&pool).get_highest_finalized_summary_block();
                assert_eq!(
                    latest_summary
                        .payload
                        .as_ref()
                        .as_summary()
                        .dkg
                        .remote_dkg_attempts
                        .get(&target_id),
                    Some(&RemoteDkgAttempts::Completed),
                    "Expected remote_dkg_attempts[{target_id:?}] to be Completed"
                );
                let change_set = dkg.on_state_change(&*dkg_pool.read().unwrap());
                match &change_set.as_slice() {
                    &[ChangeAction::Purge(purge_height)] if *purge_height == Height::from(100) => {}
                    val => panic!("Unexpected change set: {:?}", val),
                };
                dkg_pool.write().unwrap().apply(change_set);

                let change_set = dkg.on_state_change(&*dkg_pool.read().unwrap());
                let remote_dealings = change_set
                    .iter()
                    .filter(|change|
                        matches!(
                            change,
                            ChangeAction::AddToValidated(message)
                            if message.content.dkg_id.target_subnet == NiDkgTargetSubnet::Remote(target_id)
                        )
                    )
                    .count();
                assert_eq!(
                    remote_dealings, 0,
                    "Unexpected remote dealings: {change_set:?}"
                );

                // The same should hold also for the next summary.
                pool.advance_round_normal_operation_n(dkg_interval_length);
                let latest_summary = PoolReader::new(&pool).get_highest_finalized_summary_block();
                let dkg_summary = &latest_summary.payload.as_ref().as_summary().dkg;
                let remote_dkg_attempts = &dkg_summary.remote_dkg_attempts;
                assert_eq!(
                    remote_dkg_attempts.get(&target_id),
                    Some(&RemoteDkgAttempts::Completed)
                );
                assert_eq!(remote_dkg_attempts.len(), 1);
            });
        });
    }

    #[test]
    fn test_config_generation_failures_are_added_to_data_blocks() {
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

            let target_id = NiDkgTargetId::new([0_u8; 32]);
            complement_state_manager_with_setup_initial_dkg_request(
                state_manager,
                registry.get_latest_version(),
                vec![], // an erroneous request with no nodes.
                None,
                Some(target_id),
            );

            // Advance one round
            pool.advance_round_normal_operation();
            // Verify that the latest block contains errors for both requests
            let block: Block = PoolReader::new(&pool).get_finalized_tip();
            if let BlockPayload::Data(data) = block.payload.as_ref() {
                assert_eq!(data.dkg.transcripts_for_remote_subnets.len(), 2);
                let mut tags = BTreeSet::new();
                for dkg in data.dkg.transcripts_for_remote_subnets.iter() {
                    assert_eq!(
                        dkg.dkg_id.target_subnet,
                        NiDkgTargetSubnet::Remote(target_id)
                    );
                    assert!(dkg.transcript_result.is_err());
                    assert!(tags.insert(dkg.dkg_id.dkg_tag.clone()));
                }
                assert_eq!(
                    tags,
                    BTreeSet::from([NiDkgTag::LowThreshold, NiDkgTag::HighThreshold])
                );
            } else {
                panic!("block at height {} is not a data block", block.height.get());
            }

            // Advance one more round
            pool.advance_round_normal_operation();
            // Verify that the replicas don't include errors a second time
            let block: Block = PoolReader::new(&pool).get_finalized_tip();
            if let BlockPayload::Data(data) = block.payload.as_ref() {
                assert!(data.dkg.transcripts_for_remote_subnets.is_empty());
            } else {
                panic!("block at height {} is not a data block", block.height.get());
            }

            // Advance _past_ the new summary to make sure the replicas don't attempt to create
            // the configs for remote transcripts.
            pool.advance_round_normal_operation_n(dkg_interval_length + 1);

            // Verify that the first summary block contains only two local configs
            let block: Block = PoolReader::new(&pool).get_highest_finalized_summary_block();
            if let BlockPayload::Summary(summary) = block.payload.as_ref() {
                assert_eq!(
                    summary.dkg.configs.len(),
                    2,
                    "Configs: {:?}",
                    summary.dkg.configs
                );
                for dkg_id in summary.dkg.configs.keys() {
                    assert_eq!(dkg_id.target_subnet, NiDkgTargetSubnet::Local);
                }
                assert_eq!(summary.dkg.transcripts_for_remote_subnets.len(), 0);
                // Verify that the remote_dkg_attempts are set to `Completed`.
                assert_eq!(
                    summary.dkg.remote_dkg_attempts.get(&target_id),
                    Some(&RemoteDkgAttempts::Completed),
                );
                assert_eq!(summary.dkg.remote_dkg_attempts.len(), 1);
            } else {
                panic!(
                    "block at height {} is not a summary block",
                    block.height.get()
                );
            }

            // Advance one more round
            pool.advance_round_normal_operation();
            // Verify that the replicas don't include errors a second time
            let block: Block = PoolReader::new(&pool).get_finalized_tip();
            if let BlockPayload::Data(data) = block.payload.as_ref() {
                assert!(data.dkg.transcripts_for_remote_subnets.is_empty());
            } else {
                panic!("block at height {} is not a data block", block.height.get());
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
                let Dependencies {
                    pool: consensus_pool_1,
                    registry: registry_1,
                    state_manager: state_manager_1,
                    replica_config: replica_config_1,
                    ..
                } = dependencies(pool_config_1, 2);
                let Dependencies {
                    pool: consensus_pool_2,
                    registry: registry_2,
                    state_manager: state_manager_2,
                    replica_config: replica_config_2,
                    ..
                } = dependencies(pool_config_2, 2);
                for state_manager in [&state_manager_1, &state_manager_2] {
                    state_manager
                        .get_mut()
                        .expect_get_latest_certified_state()
                        .return_const(Some(Labeled::new(
                            Height::new(0),
                            Arc::new(get_initial_state(0, 0)),
                        )));
                }

                with_test_replica_logger(|logger| {
                    let dkg_pool_1 =
                        DkgPoolImpl::new(MetricsRegistry::new(), logger.clone(), Height::from(0));
                    let dkg_pool_2 =
                        DkgPoolImpl::new(MetricsRegistry::new(), logger.clone(), Height::from(0));

                    // We instantiate the DKG component for node Id = 1 and Id = 2.
                    let dkg_key_manager_1 = new_dkg_key_manager(
                        crypto.clone(),
                        logger.clone(),
                        &PoolReader::new(&consensus_pool_1),
                    );
                    let dkg_1 = DkgImpl::new(
                        node_id_1,
                        replica_config_1.subnet_id,
                        registry_1,
                        state_manager_1,
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
                        replica_config_2.subnet_id,
                        registry_2,
                        state_manager_2,
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
                    &[
                        ChangeAction::AddToValidated(message),
                        ChangeAction::AddToValidated(message2),
                    ] => {
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
                &[
                    ChangeAction::AddToValidated(_),
                    ChangeAction::AddToValidated(_),
                ] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply(change_set);

            // Make sure both dealings from replica 1 is successfully validated and apply
            // the changes.
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[
                    ChangeAction::MoveToValidated(_),
                    ChangeAction::MoveToValidated(_),
                ] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply(change_set);

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
                    &[
                        ChangeAction::AddToValidated(message),
                        ChangeAction::AddToValidated(message2),
                    ] => {
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
                &[
                    ChangeAction::AddToValidated(_),
                    ChangeAction::AddToValidated(_),
                ] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply(change_set);

            // Make sure both dealings from replica 1 is successfully validated and apply
            // the changes.
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[
                    ChangeAction::MoveToValidated(_),
                    ChangeAction::MoveToValidated(_),
                ] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply(change_set);

            // Now we try to add a different dealing but still from replica 1.
            let mut invalid_dealing_message = valid_dealing_message.clone();
            invalid_dealing_message.content.dealing = dummy_dealing(1);
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
            node_2.dkg_pool.apply(change_set);

            // Now we create a message with an unknown Dkg id and verify
            // that it gets rejected.
            let mut invalid_dkg_id = valid_dealing_message.content.dkg_id.clone();
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
            node_2.dkg_pool.apply(change_set);

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
                            "Dealing verification failed: InvalidDealer({:?})",
                            invalid_dealing_message.signature.signer
                        )
                    );
                }
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply(change_set);

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
            node_2.dkg_pool.apply(change_set);

            // Now we create a message, which refers a DKG interval above our finalized
            // height and make sure we skip it.
            let dkg_id_from_future = NiDkgId {
                start_block_height: ic_types::Height::from(1000),
                dealer_subnet: valid_dealing_message.content.dkg_id.dealer_subnet,
                dkg_tag: valid_dealing_message.content.dkg_id.dkg_tag.clone(),
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
                    &[
                        ChangeAction::AddToValidated(message),
                        ChangeAction::AddToValidated(message2),
                    ] => {
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
            dealing_message_2.content.dealing = dummy_dealing(1);
            node_2.dkg_pool.insert(UnvalidatedArtifact {
                message: dealing_message_2,
                peer_id: node_id_1,
                timestamp: UNIX_EPOCH,
            });

            // Let replica 2 create dealings for L/H thresholds.
            node_2.sync_key_manager();
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[
                    ChangeAction::AddToValidated(_),
                    ChangeAction::AddToValidated(_),
                ] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply(change_set);

            // Make sure we validate one dealing, and handle another two as invalid.
            node_2.sync_key_manager();
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[
                    ChangeAction::MoveToValidated(_),
                    ChangeAction::MoveToValidated(_),
                ] => {}
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
                &[
                    ChangeAction::AddToValidated(message),
                    ChangeAction::AddToValidated(message2),
                ] => {
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
                &[
                    ChangeAction::AddToValidated(_),
                    ChangeAction::AddToValidated(_),
                ] => {}
                val => panic!("Unexpected change set: {:?}", val),
            };
            node_2.dkg_pool.apply(change_set);

            // Make sure we validate both dealings from replica 1
            let change_set = node_2.dkg.on_state_change(&node_2.dkg_pool);
            match &change_set.as_slice() {
                &[
                    ChangeAction::MoveToValidated(_),
                    ChangeAction::MoveToValidated(_),
                ] => {}
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
                    let target_id = NiDkgTargetId::new([0_u8; 32]);
                    [&dependencies_1, &dependencies_2]
                        .iter()
                        .for_each(|dependencies| {
                            complement_state_manager_with_setup_initial_dkg_request(
                                dependencies.state_manager.clone(),
                                dependencies.registry.get_latest_version(),
                                vec![10, 11, 12],
                                None,
                                Some(target_id),
                            );
                        });

                    let crypto_1 = dependencies_1.crypto.clone();
                    let crypto_2 = dependencies_2.crypto.clone();
                    let registry_1 = dependencies_1.registry.clone();
                    let registry_2 = dependencies_2.registry.clone();
                    let state_manager_1 = dependencies_1.state_manager.clone();
                    let state_manager_2 = dependencies_2.state_manager.clone();
                    let subnet_id_1 = dependencies_1.replica_config.subnet_id;
                    let subnet_id_2 = dependencies_2.replica_config.subnet_id;
                    let mut pool_1 = dependencies_1.pool;
                    let mut pool_2 = dependencies_2.pool;

                    // Verify that the first summary block contains only two local configs.
                    pool_1.advance_round_normal_operation_n(dkg_interval_length + 1);
                    pool_2.advance_round_normal_operation_n(dkg_interval_length + 1);
                    let block: Block =
                        PoolReader::new(&pool_1).get_highest_finalized_summary_block();
                    if let BlockPayload::Summary(summary) = block.payload.as_ref() {
                        assert_eq!(summary.dkg.configs.len(), 2);
                        for dkg_id in summary.dkg.configs.keys() {
                            assert_eq!(dkg_id.target_subnet, NiDkgTargetSubnet::Local);
                        }
                    } else {
                        panic!(
                            "block at height {} is not a summary block",
                            block.height.get()
                        );
                    }

                    // Advance _past_ the next summary to make sure no configs for remote
                    // transcripts are added into the summary. Verify that the second summary
                    // block contains only two local configs.
                    pool_1.advance_round_normal_operation_n(dkg_interval_length + 1);
                    pool_2.advance_round_normal_operation_n(dkg_interval_length + 1);
                    let block: Block =
                        PoolReader::new(&pool_1).get_highest_finalized_summary_block();
                    if let BlockPayload::Summary(summary) = block.payload.as_ref() {
                        assert_eq!(summary.dkg.configs.len(), 2);
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
                        subnet_id_1,
                        registry_1,
                        state_manager_1,
                        crypto_1,
                        pool_1.get_cache(),
                        dgk_key_manager_1.clone(),
                        MetricsRegistry::new(),
                        logger.clone(),
                    );

                    let dkg_2 = DkgImpl::new(
                        node_test_id(2),
                        subnet_id_2,
                        registry_2,
                        state_manager_2,
                        crypto_2.clone(),
                        pool_2.get_cache(),
                        new_dkg_key_manager(crypto_2, logger.clone(), &PoolReader::new(&pool_2)),
                        MetricsRegistry::new(),
                        logger.clone(),
                    );
                    let start_height = pool_1.get_cache().summary_block().height;
                    let dkg_pool_1 =
                        DkgPoolImpl::new(MetricsRegistry::new(), logger.clone(), start_height);
                    let mut dkg_pool_2 =
                        DkgPoolImpl::new(MetricsRegistry::new(), logger, start_height);

                    // The last summary contains two local configs, but the state contains an initial DKG context.
                    // dkg.on_state_change should create 4 dealings for all 4 resulting configs.
                    sync_dkg_key_manager(&dgk_key_manager_1, &pool_1);
                    let change_set = dkg_1.on_state_change(&dkg_pool_1);
                    match &change_set.as_slice() {
                        &[
                            ChangeAction::AddToValidated(a),
                            ChangeAction::AddToValidated(b),
                            ChangeAction::AddToValidated(c),
                            ChangeAction::AddToValidated(d),
                        ] => {
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
                                    .filter(|msg| msg.content.dkg_id.target_subnet.is_local())
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

                    // The pool contains two local and two remote dealings.
                    // dkg.on_state_change should move these 4 dealings
                    // into the validated pool.
                    let change_set = dkg_2.on_state_change(&dkg_pool_2);
                    match &change_set.as_slice() {
                        &[
                            ChangeAction::MoveToValidated(a),
                            ChangeAction::MoveToValidated(b),
                            ChangeAction::MoveToValidated(c),
                            ChangeAction::MoveToValidated(d),
                        ] => {
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
                                    .filter(|msg| msg.content.dkg_id.target_subnet.is_local())
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

    const REMOTE_DKG_INTERVAL: u64 = 99;

    /// Common setup for remote transcript tests using `setup_initial_dkg`.
    /// Advances to the first summary block and returns the deps, target id,
    /// and the two remote DKG ids (low + high threshold).
    fn setup_initial_dkg_test(
        pool_config: ic_config::artifact_pool::ArtifactPoolConfig,
    ) -> (Dependencies, NiDkgTargetId, Vec<NiDkgId>) {
        let node_ids = (1..8).map(node_test_id).collect::<Vec<_>>();

        let mut deps = dependencies_with_subnet_records_with_raw_state_manager(
            pool_config,
            subnet_test_id(0),
            vec![(
                10,
                SubnetRecordBuilder::from(&node_ids)
                    .with_dkg_interval_length(REMOTE_DKG_INTERVAL)
                    .build(),
            )],
        );

        let target_id = NiDkgTargetId::new([0_u8; 32]);
        complement_state_manager_with_setup_initial_dkg_request(
            deps.state_manager.clone(),
            deps.registry.get_latest_version(),
            vec![10, 11, 12, 13],
            None,
            Some(target_id),
        );

        deps.pool
            .advance_round_normal_operation_n(REMOTE_DKG_INTERVAL + 1);

        // Verify that the highest summary block has no remote DKG configs and
        // does not contain remote transcripts.
        let summary_configs = extract_dkg_configs_from_highest_block(&deps.pool);
        assert_eq!(summary_configs.len(), 2);
        assert_eq!(
            summary_configs
                .keys()
                .filter(|id| id.target_subnet == NiDkgTargetSubnet::Remote(target_id))
                .count(),
            0
        );
        assert_eq!(extract_remote_dkgs_from_highest_block(&deps.pool).len(), 0);
        let remote_dkg_ids = vec![
            NiDkgId {
                start_block_height: Height::from(REMOTE_DKG_INTERVAL + 1),
                dealer_subnet: deps.replica_config.subnet_id,
                dkg_tag: NiDkgTag::LowThreshold,
                target_subnet: NiDkgTargetSubnet::Remote(target_id),
            },
            NiDkgId {
                start_block_height: Height::from(REMOTE_DKG_INTERVAL + 1),
                dealer_subnet: deps.replica_config.subnet_id,
                dkg_tag: NiDkgTag::HighThreshold,
                target_subnet: NiDkgTargetSubnet::Remote(target_id),
            },
        ];

        (deps, target_id, remote_dkg_ids)
    }

    /// Add 3 dealings per config to the DKG pool, advancing the consensus
    /// pool one round after each config.
    fn add_dealings_for_configs(deps: &mut Dependencies, dkg_ids: &[NiDkgId]) {
        for dkg_id in dkg_ids {
            let dealings = (0..3)
                .map(|i| ChangeAction::AddToValidated(create_dealing(i, dkg_id.clone())))
                .collect::<Vec<_>>();
            deps.dkg_pool.write().unwrap().apply(dealings);
            deps.pool.advance_round_normal_operation();
        }
    }

    /// Assert that the highest block's payload passes DKG validation.
    fn assert_highest_block_validates(deps: &Dependencies) {
        let block: Block = deps
            .pool
            .validated()
            .block_proposal()
            .get_highest()
            .unwrap()
            .content
            .into_inner();
        let pool_reader = PoolReader::new(&deps.pool);
        let height = block.height().decrement();
        let parent = pool_reader
            .get_notarized_block(&block.parent, height)
            .map(|block| block.into_inner())
            .unwrap();

        assert!(
            validate_payload(
                subnet_test_id(0),
                deps.registry.as_ref(),
                deps.crypto.as_ref(),
                &pool_reader,
                &*deps.dkg_pool.read().unwrap(),
                parent,
                block.payload.as_ref(),
                deps.state_manager.as_ref(),
                &block.context,
                &MetricsRegistry::new().int_counter_vec(
                    "consensus_dkg_validator",
                    "DKG validator counter",
                    &["type"],
                ),
                &no_op_logger(),
            )
            .is_ok()
        );
    }

    /// Advance through a full DKG interval and verify that no remote
    /// transcripts or dealings appear in any block.
    fn assert_no_remote_transcript_duplicates(pool: &mut TestConsensusPool, interval_length: u64) {
        for _ in 0..interval_length + 1 {
            pool.advance_round_normal_operation();
            assert_eq!(extract_dealings_from_highest_block(pool).len(), 0);
            assert_eq!(extract_remote_dkgs_from_highest_block(pool).len(), 0);
        }
    }

    fn make_setup_initial_dkg_ids_with_height(
        target_id: NiDkgTargetId,
        start_block_height: Height,
    ) -> Vec<NiDkgId> {
        vec![
            NiDkgId {
                start_block_height,
                dealer_subnet: subnet_test_id(0),
                dkg_tag: NiDkgTag::LowThreshold,
                target_subnet: NiDkgTargetSubnet::Remote(target_id),
            },
            NiDkgId {
                start_block_height,
                dealer_subnet: subnet_test_id(0),
                dkg_tag: NiDkgTag::HighThreshold,
                target_subnet: NiDkgTargetSubnet::Remote(target_id),
            },
        ]
    }

    fn make_setup_initial_dkg_ids(target_id: NiDkgTargetId) -> Vec<NiDkgId> {
        make_setup_initial_dkg_ids_with_height(target_id, Height::from(0))
    }

    fn make_reshare_chain_key_id(target_id: NiDkgTargetId) -> NiDkgId {
        NiDkgId {
            start_block_height: Height::from(0),
            dealer_subnet: subnet_test_id(0),
            dkg_tag: NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(test_vet_key())),
            target_subnet: NiDkgTargetSubnet::Remote(target_id),
        }
    }

    #[test]
    fn test_setup_initial_dkg_remote_transcripts() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let (mut deps, target_id, remote_dkg_ids) = setup_initial_dkg_test(pool_config);

            // Add dealings for first config only; not enough for both transcripts
            let dealings = (0..3)
                .map(|i| ChangeAction::AddToValidated(create_dealing(i, remote_dkg_ids[0].clone())))
                .collect::<Vec<_>>();
            deps.dkg_pool.write().unwrap().apply(dealings);
            deps.pool.advance_round_normal_operation();
            // f + 1 dealings for high or low remote threshold DKG
            assert_eq!(extract_dealings_from_highest_block(&deps.pool).len(), 3);
            assert_eq!(extract_remote_dkgs_from_highest_block(&deps.pool).len(), 0);

            // No new dealings; building remote transcripts fails (need both high and low)
            deps.pool.advance_round_normal_operation();
            assert_eq!(extract_dealings_from_highest_block(&deps.pool).len(), 0);
            assert_eq!(extract_remote_dkgs_from_highest_block(&deps.pool).len(), 0);

            // Add dealings for second config
            let dealings = (0..3)
                .map(|i| ChangeAction::AddToValidated(create_dealing(i, remote_dkg_ids[1].clone())))
                .collect::<Vec<_>>();
            deps.dkg_pool.write().unwrap().apply(dealings);
            deps.pool.advance_round_normal_operation();
            // f + 1 dealings for low or high remote threshold DKG
            assert_eq!(extract_dealings_from_highest_block(&deps.pool).len(), 3);
            assert_eq!(extract_remote_dkgs_from_highest_block(&deps.pool).len(), 0);

            // Now sufficient dealings are on chain; remote transcripts should appear
            deps.pool.advance_round_normal_operation();
            assert_eq!(extract_dealings_from_highest_block(&deps.pool).len(), 0);
            let remote_dkgs = extract_remote_dkgs_from_highest_block(&deps.pool);
            assert_eq!(remote_dkgs.len(), 2);
            for transcript in &remote_dkgs {
                assert_eq!(
                    transcript.dkg_id.target_subnet,
                    NiDkgTargetSubnet::Remote(target_id)
                );
                assert!(transcript.transcript_result.is_ok());
            }
            assert!(
                remote_dkgs
                    .iter()
                    .any(|t| t.dkg_id.dkg_tag == NiDkgTag::HighThreshold)
            );
            assert!(
                remote_dkgs
                    .iter()
                    .any(|t| t.dkg_id.dkg_tag == NiDkgTag::LowThreshold)
            );

            assert_highest_block_validates(&deps);

            // Also validate with empty transcripts_for_remote_subnets (including
            // the remote transcripts is only an optimization, so validation must
            // still pass).
            let block: Block = deps
                .pool
                .validated()
                .block_proposal()
                .get_highest()
                .unwrap()
                .content
                .into_inner();
            let pool_reader = PoolReader::new(&deps.pool);
            let height = block.height().decrement();
            let parent = pool_reader
                .get_notarized_block(&block.parent, height)
                .map(|block| block.into_inner())
                .unwrap();
            let payload_without_remote = match block.payload.as_ref() {
                BlockPayload::Data(data) => {
                    let dkg_without_remote =
                        DkgDataPayload::new(data.dkg.start_height, data.dkg.messages.clone());
                    BlockPayload::Data(DataPayload {
                        batch: data.batch.clone(),
                        dkg: dkg_without_remote,
                        idkg: data.idkg.clone(),
                    })
                }
                _ => panic!("expected data block"),
            };
            assert!(
                validate_payload(
                    subnet_test_id(0),
                    deps.registry.as_ref(),
                    deps.crypto.as_ref(),
                    &pool_reader,
                    &*deps.dkg_pool.read().unwrap(),
                    parent,
                    &payload_without_remote,
                    deps.state_manager.as_ref(),
                    &block.context,
                    &MetricsRegistry::new().int_counter_vec(
                        "consensus_dkg_validator",
                        "DKG validator counter",
                        &["type"],
                    ),
                    &no_op_logger(),
                )
                .is_ok()
            );

            // Verify that no more transcripts are created in later blocks.
            assert_no_remote_transcript_duplicates(&mut deps.pool, REMOTE_DKG_INTERVAL);
        });
    }

    #[test]
    fn test_remote_transcripts_with_reproducible_crypto_error() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let (mut deps, target_id, remote_dkg_ids) = setup_initial_dkg_test(pool_config);

            add_dealings_for_configs(&mut deps, &remote_dkg_ids);

            let mut mock_crypto = MockCrypto::new();
            mock_crypto
                .expect_ni_dkg_create_transcript()
                .returning(|_config, _dealings| {
                    Err(
                        DkgCreateTranscriptError::MalformedResharingTranscriptInConfig(
                            MalformedPublicKeyError {
                                algorithm: AlgorithmId::Groth20_Bls12_381,
                                key_bytes: None,
                                internal_error: "test error".to_string(),
                            },
                        ),
                    )
                });

            let parent = deps.pool.get_cache().finalized_block();

            // Scope the pool borrow so we can mutate the pool afterwards
            let payload_with_errors = {
                let pool_reader = PoolReader::new(&deps.pool);
                let last_summary_block = pool_reader.dkg_summary_block(&parent).unwrap();
                let last_summary = &last_summary_block.payload.as_ref().as_summary().dkg;
                let validation_context = ValidationContext {
                    registry_version: deps.registry.get_latest_version(),
                    certified_height: Height::from(0),
                    time: UNIX_EPOCH,
                };
                let state = deps
                    .state_manager
                    .get_state_at(validation_context.certified_height)
                    .unwrap();
                let callback_id_map = remote::build_callback_id_config_map(
                    subnet_test_id(0),
                    deps.registry.as_ref(),
                    state.get_ref(),
                    validation_context.registry_version,
                    last_summary,
                    &no_op_logger(),
                )
                .unwrap();
                let remote_transcripts = payload_builder::create_remote_transcripts(
                    &pool_reader,
                    &mock_crypto,
                    &parent,
                    callback_id_map,
                    &no_op_logger(),
                    None,
                )
                .unwrap();

                assert_eq!(remote_transcripts.len(), 2);
                for transcript in &remote_transcripts {
                    assert_eq!(
                        transcript.dkg_id.target_subnet,
                        NiDkgTargetSubnet::Remote(target_id)
                    );
                    let error_msg = transcript.transcript_result.as_ref().unwrap_err();
                    assert!(
                        error_msg.contains("test error"),
                        "Error message should contain the original error, got: {error_msg}"
                    );
                }

                let payload = BlockPayload::Data(DataPayload {
                    batch: ic_types::batch::BatchPayload::default(),
                    dkg: DkgDataPayload::new_with_remote_dkg_transcripts(
                        last_summary_block.height,
                        vec![],
                        remote_transcripts,
                    ),
                    idkg: Default::default(),
                });

                assert!(
                    validate_payload(
                        subnet_test_id(0),
                        deps.registry.as_ref(),
                        &mock_crypto,
                        &pool_reader,
                        &*deps.dkg_pool.read().unwrap(),
                        parent.clone(),
                        &payload,
                        deps.state_manager.as_ref(),
                        &validation_context,
                        &MetricsRegistry::new().int_counter_vec(
                            "consensus_dkg_validator",
                            "DKG validator counter",
                            &["type"],
                        ),
                        &no_op_logger(),
                    )
                    .is_ok(),
                    "Payload with reproducible crypto errors should validate successfully"
                );

                payload
            };

            // Insert the payload with errors into the pool as part of a new block.
            let mut block = Block::from_parent(&parent);
            block.payload = Payload::new(ic_types::crypto::crypto_hash, payload_with_errors);
            let proposal = BlockProposal::fake(block, node_test_id(0));
            deps.pool.advance_round_with_block(&proposal);

            // Verify that no more transcripts are created in later blocks.
            assert_no_remote_transcript_duplicates(&mut deps.pool, REMOTE_DKG_INTERVAL);
        });
    }

    #[test]
    fn test_remote_dealing_validation_is_deferred_until_context_exists() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let node_ids = vec![node_test_id(0), node_test_id(1)];
                let dkg_interval_length = 99;
                let subnet_id = subnet_test_id(0);
                let target_id = NiDkgTargetId::new([9_u8; 32]);

                let mut deps = dependencies_with_subnet_records_with_raw_state_manager(
                    pool_config,
                    subnet_id,
                    vec![(
                        10,
                        SubnetRecordBuilder::from(&node_ids)
                            .with_dkg_interval_length(dkg_interval_length)
                            .build(),
                    )],
                );

                // Start without context so remote dealing validation is deferred.
                complement_state_manager_with_dkg_contexts(
                    deps.state_manager.clone(),
                    vec![],
                    None,
                );
                deps.pool
                    .advance_round_normal_operation_n(dkg_interval_length + 1);

                // Non-dealer receiver: validates incoming dealings but does not create its own.
                let receiver_key_manager = new_dkg_key_manager(
                    deps.crypto.clone(),
                    logger.clone(),
                    &PoolReader::new(&deps.pool),
                );
                let receiver_dkg = DkgImpl::new(
                    node_test_id(2),
                    deps.replica_config.subnet_id,
                    deps.registry.clone(),
                    deps.state_manager.clone(),
                    deps.crypto.clone(),
                    deps.pool.get_cache(),
                    receiver_key_manager.clone(),
                    MetricsRegistry::new(),
                    logger,
                );

                let start_height = deps.pool.get_cache().summary_block().height;
                let mut dkg_pool =
                    DkgPoolImpl::new(MetricsRegistry::new(), no_op_logger(), start_height);
                let remote_dkg_id = NiDkgId {
                    start_block_height: start_height,
                    dealer_subnet: subnet_id,
                    dkg_tag: NiDkgTag::LowThreshold,
                    target_subnet: NiDkgTargetSubnet::Remote(target_id),
                };
                let remote_message = create_dealing(1, remote_dkg_id);
                let other_target_id = NiDkgTargetId::new([10_u8; 32]);
                let deferred_remote_dkg_id = NiDkgId {
                    start_block_height: start_height,
                    dealer_subnet: subnet_id,
                    dkg_tag: NiDkgTag::LowThreshold,
                    target_subnet: NiDkgTargetSubnet::Remote(other_target_id),
                };
                let deferred_remote_message = create_dealing(42, deferred_remote_dkg_id);
                dkg_pool.insert(UnvalidatedArtifact {
                    message: remote_message.clone(),
                    peer_id: node_test_id(1),
                    timestamp: ic_types::time::UNIX_EPOCH,
                });
                dkg_pool.insert(UnvalidatedArtifact {
                    message: deferred_remote_message,
                    peer_id: node_test_id(42),
                    timestamp: ic_types::time::UNIX_EPOCH,
                });

                assert!(
                    receiver_dkg.on_state_change(&dkg_pool).is_empty(),
                    "dealing should be deferred while context is missing",
                );
                assert_eq!(dkg_pool.get_unvalidated().count(), 2);

                // Add context back: deferred dealing should now be validated.
                deps.state_manager.get_mut().checkpoint();
                complement_state_manager_with_setup_initial_dkg_request(
                    deps.state_manager.clone(),
                    deps.registry.get_latest_version(),
                    vec![10, 11, 12],
                    None,
                    Some(target_id),
                );
                let change_set = receiver_dkg.on_state_change(&dkg_pool);
                match &change_set.as_slice() {
                    &[ChangeAction::MoveToValidated(message)] => {
                        assert_eq!(message.content.dkg_id, remote_message.content.dkg_id);
                        assert_eq!(
                            message.content.dkg_id.target_subnet,
                            NiDkgTargetSubnet::Remote(target_id)
                        );
                    }
                    val => panic!("Unexpected change set: {:?}", val),
                }
                dkg_pool.apply(change_set);
                assert_eq!(dkg_pool.get_validated().count(), 1);
                assert_eq!(dkg_pool.get_unvalidated().count(), 1);

                // Once the summary/start height advances, deferred unvalidated and old validated
                // dealings should be purged.
                deps.pool
                    .advance_round_normal_operation_n(dkg_interval_length + 1);
                let change_set = receiver_dkg.on_state_change(&dkg_pool);
                match &change_set.as_slice() {
                    &[ChangeAction::Purge(purge_height)] if *purge_height > start_height => {}
                    val => panic!("Expected purge after summary advance, got {:?}", val),
                }
                dkg_pool.apply(change_set);
                assert_eq!(dkg_pool.get_unvalidated().count(), 0);
                assert_eq!(dkg_pool.get_validated().count(), 0);
            });
        });
    }

    #[test]
    fn test_reshare_chain_key_remote_transcripts() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let node_ids = (1..5).map(node_test_id).collect::<Vec<_>>();
            let key_id = VetKdKeyId {
                curve: VetKdCurve::Bls12_381_G2,
                name: String::from("some_vetkey"),
            };
            let target_id = NiDkgTargetId::new([0_u8; 32]);

            let mut deps = dependencies_with_subnet_records_with_raw_state_manager(
                pool_config,
                subnet_test_id(0),
                vec![(
                    10,
                    SubnetRecordBuilder::from(&node_ids)
                        .with_dkg_interval_length(REMOTE_DKG_INTERVAL)
                        .with_chain_key_config(ChainKeyConfig {
                            key_configs: vec![KeyConfig {
                                key_id: MasterPublicKeyId::VetKd(key_id.clone()),
                                pre_signatures_to_create_in_advance: None,
                                max_queue_size: 20,
                            }],
                            signature_request_timeout_ns: None,
                            idkg_key_rotation_period_ms: None,
                            max_parallel_pre_signature_transcripts_in_creation: None,
                        })
                        .build(),
                )],
            );

            // No contexts at the beginning
            complement_state_manager_with_dkg_contexts(deps.state_manager.clone(), vec![], None);

            // Advance until the first vetkd transcript is created
            deps.pool
                .advance_round_normal_operation_n(REMOTE_DKG_INTERVAL + 3);

            // Latest summary should contain only local configs.
            let summary_block = PoolReader::new(&deps.pool).get_highest_finalized_summary_block();
            let summary = &summary_block.payload.as_ref().as_summary().dkg;
            assert_eq!(
                summary
                    .configs
                    .keys()
                    .filter(|id| id.target_subnet.is_remote())
                    .count(),
                0
            );

            let contexts = vec![make_reshare_chain_key_context(
                deps.registry.get_latest_version(),
                key_id.clone(),
                vec![10, 11, 12, 13],
                target_id,
            )];
            deps.state_manager.get_mut().checkpoint();
            complement_state_manager_with_dkg_contexts(deps.state_manager.clone(), contexts, None);

            let remote_dkg_ids = vec![NiDkgId {
                start_block_height: Height::from(REMOTE_DKG_INTERVAL + 1),
                dealer_subnet: subnet_test_id(0),
                dkg_tag: NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(
                    key_id.clone(),
                )),
                target_subnet: NiDkgTargetSubnet::Remote(target_id),
            }];

            add_dealings_for_configs(&mut deps, &remote_dkg_ids);
            // 2f + 1 dealings for high threshold VetKD resharing
            assert_eq!(extract_dealings_from_highest_block(&deps.pool).len(), 3);
            assert_eq!(extract_remote_dkgs_from_highest_block(&deps.pool).len(), 0);

            // Now sufficient dealings are in the pool; remote transcript should appear
            deps.pool.advance_round_normal_operation();
            assert_eq!(extract_dealings_from_highest_block(&deps.pool).len(), 0);
            let remote_dkgs = extract_remote_dkgs_from_highest_block(&deps.pool);
            assert_eq!(remote_dkgs.len(), 1);
            let transcript = &remote_dkgs[0];
            assert_eq!(
                transcript.dkg_id.target_subnet,
                NiDkgTargetSubnet::Remote(target_id)
            );
            assert!(transcript.transcript_result.is_ok());
            assert_eq!(
                transcript.dkg_id.dkg_tag,
                NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(key_id))
            );

            // Verify that the highest block validates.
            assert_highest_block_validates(&deps);

            // Verify that no more transcripts are created in later blocks.
            assert_no_remote_transcript_duplicates(&mut deps.pool, REMOTE_DKG_INTERVAL);
        });
    }

    /// Tests that when the state has a SetupInitialDKG context (needing 2
    /// transcripts), a ReshareChainKey context (needing 1 transcript), and an
    /// additional SetupInitialDKG context (lowest target_id) with insufficient
    /// dealings for one of its configs:
    /// - The first setup target is skipped (insufficient dealings).
    /// - The remaining two contexts compete for MAX_REMOTE_TRANSCRIPTS_PER_PAYLOAD
    ///   (= 2), and only the first context's transcripts are included.
    #[test]
    fn test_remote_transcripts_respects_max() {
        for (setup_first, desc) in [
            (true, "SetupInitialDKG first"),
            (false, "ReshareChainKey first"),
        ] {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                let node_ids = (0..4).map(node_test_id).collect::<Vec<_>>();
                let key_id = test_vet_key();
                // This context always comes first but will be
                // skipped because one of its two configs lacks dealings.
                let skipped_target_id = NiDkgTargetId::new([0_u8; 32]);
                let setup_target_id = NiDkgTargetId::new([1_u8; 32]);
                let reshare_target_id = NiDkgTargetId::new([2_u8; 32]);

                let mut deps = dependencies_with_subnet_records_with_raw_state_manager(
                    pool_config,
                    subnet_test_id(0),
                    vec![(
                        10,
                        SubnetRecordBuilder::from(&node_ids)
                            .with_dkg_interval_length(REMOTE_DKG_INTERVAL)
                            .with_chain_key_config(ChainKeyConfig {
                                key_configs: vec![KeyConfig {
                                    key_id: MasterPublicKeyId::VetKd(key_id.clone()),
                                    pre_signatures_to_create_in_advance: None,
                                    max_queue_size: 20,
                                }],
                                signature_request_timeout_ns: None,
                                idkg_key_rotation_period_ms: None,
                                max_parallel_pre_signature_transcripts_in_creation: None,
                            })
                            .build(),
                    )],
                );

                let registry_version = deps.registry.get_latest_version();
                let mut contexts = vec![
                    make_setup_initial_dkg_context(
                        registry_version,
                        vec![10, 11, 12, 13],
                        skipped_target_id,
                    ),
                    make_setup_initial_dkg_context(
                        registry_version,
                        vec![10, 11, 12, 13],
                        setup_target_id,
                    ),
                    make_reshare_chain_key_context(
                        registry_version,
                        key_id.clone(),
                        vec![10, 11, 12, 13],
                        reshare_target_id,
                    ),
                ];
                if !setup_first {
                    contexts.swap(1, 2);
                }
                complement_state_manager_with_dkg_contexts(
                    deps.state_manager.clone(),
                    contexts,
                    None,
                );
                let skipped_remote_dkg_ids = make_setup_initial_dkg_ids(skipped_target_id);
                let setup_remote_dkg_ids = make_setup_initial_dkg_ids(setup_target_id);
                let reshare_dkg_id = make_reshare_chain_key_id(reshare_target_id);

                // get the latest finalized summary block
                let summary_block =
                    PoolReader::new(&deps.pool).get_highest_finalized_summary_block();
                // it should not have any remote configs
                let summary = &summary_block.payload.as_ref().as_summary().dkg;
                let remote_dkg_ids_count = summary
                    .configs
                    .keys()
                    .filter(|id| id.target_subnet.is_remote())
                    .count();
                assert_eq!(remote_dkg_ids_count, 0);

                // Add dealings for only ONE of the skipped target's two configs
                // (insufficient), all setup target configs, and the reshare config.
                let dkg_ids_with_dealings: Vec<&NiDkgId> =
                    std::iter::once(&skipped_remote_dkg_ids[0])
                        .chain(setup_remote_dkg_ids.iter())
                        .chain(std::iter::once(&reshare_dkg_id))
                        .collect();
                for dkg_id in &dkg_ids_with_dealings {
                    let dealings: Vec<_> = (1..5)
                        .map(|i| ChangeAction::AddToValidated(create_dealing(i, (*dkg_id).clone())))
                        .collect();
                    deps.dkg_pool.write().unwrap().apply(dealings);
                }
                deps.pool.advance_round_normal_operation();

                assert_eq!(
                    extract_dealings_from_highest_block(&deps.pool).len(),
                    9, // 3 * (f + 1) setup, plus 2f + 1 reshare, where f = 1
                    "[{desc}] 9 dealings should be in the block"
                );
                assert_eq!(
                    extract_remote_dkgs_from_highest_block(&deps.pool).len(),
                    0,
                    "[{desc}] no remote transcripts yet"
                );

                let check = |expect_setup_initial_dkg, remote_dkgs: Vec<RemoteTranscriptResult>| {
                    if expect_setup_initial_dkg {
                        assert_eq!(
                            remote_dkgs.len(),
                            2,
                            "[{desc}] Expected 2 SetupInitialDKG transcripts, got {}",
                            remote_dkgs.len()
                        );
                        let mut tags = BTreeSet::new();
                        for transcript in &remote_dkgs {
                            assert_eq!(
                                transcript.dkg_id.target_subnet,
                                NiDkgTargetSubnet::Remote(setup_target_id),
                                "[{desc}] transcript should be for SetupInitialDKG target id"
                            );
                            assert!(transcript.transcript_result.is_ok(), "[{desc}]");
                            assert!(tags.insert(transcript.dkg_id.dkg_tag.clone()));
                        }
                        assert_eq!(
                            tags,
                            BTreeSet::from([NiDkgTag::LowThreshold, NiDkgTag::HighThreshold]),
                        );
                    } else {
                        // Reshare comes first: 1 reshare transcript; setup's 2 exceed the limit.
                        assert_eq!(
                            remote_dkgs.len(),
                            1,
                            "[{desc}] Expected 1 ReshareChainKey transcript, got {}",
                            remote_dkgs.len()
                        );
                        let transcript = &remote_dkgs[0];
                        assert_eq!(
                            transcript.dkg_id.target_subnet,
                            NiDkgTargetSubnet::Remote(reshare_target_id),
                            "[{desc}] transcript should be for ReshareChainKey target id"
                        );
                        assert!(transcript.transcript_result.is_ok(), "[{desc}]");
                        assert_eq!(
                            transcript.dkg_id.dkg_tag,
                            NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(
                                key_id.clone()
                            ))
                        );
                    }
                };

                // The skipped target is skipped (insufficient dealings for its
                // second config). The remaining setup and reshare targets compete
                // for MAX_REMOTE_TRANSCRIPTS_PER_PAYLOAD.
                deps.pool.advance_round_normal_operation();
                assert_highest_block_validates(&deps);
                assert_eq!(extract_dealings_from_highest_block(&deps.pool).len(), 0);
                let remote_dkgs = extract_remote_dkgs_from_highest_block(&deps.pool);
                check(setup_first, remote_dkgs);

                // Now transcripts for the opposite request should appear
                deps.pool.advance_round_normal_operation();
                assert_highest_block_validates(&deps);
                assert_eq!(extract_dealings_from_highest_block(&deps.pool).len(), 0);
                let remote_dkgs = extract_remote_dkgs_from_highest_block(&deps.pool);
                check(!setup_first, remote_dkgs);
            });
        }
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
                        .with_chain_key_config(test_vet_key_config())
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

            let vet_key_ids = vetkd_key_ids_for_subnet(
                replica_config.subnet_id,
                &*registry,
                dkg_summary.registry_version,
            )
            .unwrap();

            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(5));
            assert_eq!(dkg_summary.height, Height::from(0));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(5)
            );

            assert_eq!(vet_key_ids.len(), 1);
            for tag in tags_iter(&vet_key_ids) {
                let current_transcript = dkg_summary.current_transcript(&tag).unwrap();
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
                assert!(dkg_summary.next_transcript(&tag).is_none());
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
                    .with_chain_key_config(test_vet_key_config())
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

            let vet_key_ids = vetkd_key_ids_for_subnet(
                replica_config.subnet_id,
                &*registry,
                dkg_summary.registry_version,
            )
            .unwrap();

            // This membership registry version corresponds to the registry version from
            // the block context of the previous summary.
            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(5));
            assert_eq!(dkg_summary.height, Height::from(5));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(5)
            );

            assert_eq!(vet_key_ids.len(), 1);
            for tag in tags_iter(&vet_key_ids) {
                // We reused the transcript.
                let current_transcript = dkg_summary.current_transcript(&tag).unwrap();
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(0)
                );
                // New configs are created for the new context registry version,
                // which will be the new membership version in the next interval.
                let (_, conf) = dkg_summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == tag)
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
                    .with_chain_key_config(test_vet_key_config())
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

            let vet_key_ids = vetkd_key_ids_for_subnet(
                replica_config.subnet_id,
                &*registry,
                dkg_summary.registry_version,
            )
            .unwrap();

            // This membership registry version corresponds to the registry version from
            // the block context of the previous summary.
            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(6));
            assert_eq!(dkg_summary.height, Height::from(10));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(5)
            );

            assert_eq!(vet_key_ids.len(), 1);
            for tag in tags_iter(&vet_key_ids) {
                let (_, conf) = dkg_summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == tag)
                    .unwrap();
                assert_eq!(
                    conf.receivers().get(),
                    &committee3.clone().into_iter().collect::<BTreeSet<_>>()
                );
                let current_transcript = dkg_summary.current_transcript(&tag).unwrap();
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(0)
                );
                let next_transcript = dkg_summary.next_transcript(&tag).unwrap();
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

            let vet_key_ids = vetkd_key_ids_for_subnet(
                replica_config.subnet_id,
                &*registry,
                dkg_summary.registry_version,
            )
            .unwrap();

            // This membership registry version corresponds to the registry version from
            // the block context of the previous summary.
            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(10));
            assert_eq!(dkg_summary.height, Height::from(15));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(6)
            );

            assert_eq!(vet_key_ids.len(), 1);
            for tag in tags_iter(&vet_key_ids) {
                let (_, conf) = dkg_summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == tag)
                    .unwrap();
                assert_eq!(
                    conf.receivers().get(),
                    &committee3.clone().into_iter().collect::<BTreeSet<_>>()
                );
                let current_transcript = dkg_summary.current_transcript(&tag).unwrap();
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(5)
                );
                let next_transcript = dkg_summary.next_transcript(&tag).unwrap();
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

            let vet_key_ids = vetkd_key_ids_for_subnet(
                replica_config.subnet_id,
                &*registry,
                dkg_summary.registry_version,
            )
            .unwrap();

            // This membership registry version corresponds to the registry version from
            // the block context of the previous summary.
            assert_eq!(dkg_summary.registry_version, RegistryVersion::from(10));
            assert_eq!(dkg_summary.height, Height::from(20));
            assert_eq!(
                cup.get_oldest_registry_version_in_use(),
                RegistryVersion::from(10)
            );

            assert_eq!(vet_key_ids.len(), 1);
            for tag in tags_iter(&vet_key_ids) {
                let (_, conf) = dkg_summary
                    .configs
                    .iter()
                    .find(|(id, _)| id.dkg_tag == tag)
                    .unwrap();
                assert_eq!(
                    conf.receivers().get(),
                    &committee3.clone().into_iter().collect::<BTreeSet<_>>()
                );
                let current_transcript = dkg_summary.current_transcript(&tag).unwrap();
                assert_eq!(
                    current_transcript.dkg_id.start_block_height,
                    Height::from(10)
                );
                let next_transcript = dkg_summary.next_transcript(&tag).unwrap();
                assert_eq!(next_transcript.dkg_id.start_block_height, Height::from(15));
            }
        });
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

    /// Get a test [`ChainKeyConfig`] containing a single vet key configuration
    pub(super) fn test_vet_key_config() -> ChainKeyConfig {
        ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: MasterPublicKeyId::VetKd(test_vet_key()),
                pre_signatures_to_create_in_advance: None,
                max_queue_size: 20,
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        }
    }

    fn test_vet_key() -> VetKdKeyId {
        VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: String::from("vet_kd_key"),
        }
    }
}
