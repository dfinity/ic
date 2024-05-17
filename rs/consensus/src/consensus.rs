//! This module encapsulates all components required for establishing of a
//! distributed consensus.

pub mod batch_delivery;
pub(crate) mod block_maker;
pub mod bounds;
mod catchup_package_maker;
pub mod dkg_key_manager;
mod finalizer;
pub mod malicious_consensus;
pub(crate) mod metrics;
mod notary;
mod payload;
pub mod payload_builder;
mod priority;
mod purger;
mod random_beacon_maker;
mod random_tape_maker;
mod share_aggregator;
mod status;
pub mod validator;

#[cfg(all(test, feature = "proptest"))]
mod proptests;

use crate::consensus::{
    block_maker::BlockMaker, catchup_package_maker::CatchUpPackageMaker,
    dkg_key_manager::DkgKeyManager, finalizer::Finalizer, metrics::ConsensusMetrics,
    notary::Notary, payload_builder::PayloadBuilderImpl, priority::get_priority_function,
    purger::Purger, random_beacon_maker::RandomBeaconMaker, random_tape_maker::RandomTapeMaker,
    share_aggregator::ShareAggregator, validator::Validator,
};
use ic_consensus_utils::{
    crypto::ConsensusCrypto, get_notarization_delay_settings, membership::Membership,
    pool_reader::PoolReader, RoundRobin,
};
use ic_interfaces::{
    batch_payload::BatchPayloadBuilder,
    consensus_pool::{ChangeAction, ChangeSet, ConsensusPool, ValidatedConsensusArtifact},
    dkg::DkgPool,
    ecdsa::EcdsaPool,
    ingress_manager::IngressSelector,
    messaging::{MessageRouting, XNetPayloadBuilder},
    p2p::consensus::{ChangeSetProducer, PriorityFnAndFilterProducer},
    self_validating_payload::SelfValidatingPayloadBuilder,
    time_source::TimeSource,
};
use ic_interfaces_registry::{RegistryClient, POLLING_PERIOD};
use ic_interfaces_state_manager::StateManager;
use ic_logger::{debug, error, info, trace, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::{ConsensusMessageId, PriorityFn},
    artifact_kind::ConsensusArtifact,
    consensus::ConsensusMessageHashable,
    malicious_flags::MaliciousFlags,
    replica_config::ReplicaConfig,
    replica_version::ReplicaVersion,
    Time,
};
pub use metrics::ValidatorMetrics;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use strum_macros::AsRefStr;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, AsRefStr)]
#[strum(serialize_all = "snake_case")]
enum ConsensusSubcomponent {
    Notary,
    Finalizer,
    RandomBeaconMaker,
    RandomTapeMaker,
    BlockMaker,
    CatchUpPackageMaker,
    Validator,
    Aggregator,
    Purger,
}

/// When purging consensus or certification artifacts, we always keep a
/// minimum chain length below the catch-up height.
pub(crate) const MINIMUM_CHAIN_LENGTH: u64 = 50;

/// Describe expected version and artifact version when there is a mismatch.
#[derive(Debug)]
pub(crate) struct ReplicaVersionMismatch {}

/// The function checks if the version of the given artifact matches the default
/// protocol version and returns an error if it does not.
pub(crate) fn check_protocol_version(
    version: &ReplicaVersion,
) -> Result<(), ReplicaVersionMismatch> {
    let expected_version = ReplicaVersion::default();
    if version != &expected_version {
        Err(ReplicaVersionMismatch {})
    } else {
        Ok(())
    }
}

/// [ConsensusImpl] holds all consensus subcomponents, and implements the
/// Consensus trait by calling each subcomponent in round-robin manner.
pub struct ConsensusImpl {
    /// Notary
    pub notary: Notary,
    /// Finalizer
    pub finalizer: Finalizer,
    random_beacon_maker: RandomBeaconMaker,
    random_tape_maker: RandomTapeMaker,
    /// Blockmaker
    pub block_maker: BlockMaker,
    catch_up_package_maker: CatchUpPackageMaker,
    validator: Validator,
    aggregator: ShareAggregator,
    purger: Purger,
    metrics: ConsensusMetrics,
    time_source: Arc<dyn TimeSource>,
    registry_client: Arc<dyn RegistryClient>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    dkg_key_manager: Arc<Mutex<DkgKeyManager>>,
    last_invoked: RefCell<BTreeMap<ConsensusSubcomponent, Time>>,
    schedule: RoundRobin,
    replica_config: ReplicaConfig,
    #[cfg_attr(not(feature = "malicious_code"), allow(dead_code))]
    malicious_flags: MaliciousFlags,
    /// Logger
    pub log: ReplicaLogger,
}

impl ConsensusImpl {
    /// Create a new [ConsensusImpl] along with all subcomponents it manages.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        replica_config: ReplicaConfig,
        registry_client: Arc<dyn RegistryClient>,
        membership: Arc<Membership>,
        crypto: Arc<dyn ConsensusCrypto>,
        ingress_selector: Arc<dyn IngressSelector>,
        xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
        self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
        canister_http_payload_builder: Arc<dyn BatchPayloadBuilder>,
        query_stats_payload_builder: Arc<dyn BatchPayloadBuilder>,
        dkg_pool: Arc<RwLock<dyn DkgPool>>,
        ecdsa_pool: Arc<RwLock<dyn EcdsaPool>>,
        dkg_key_manager: Arc<Mutex<DkgKeyManager>>,
        message_routing: Arc<dyn MessageRouting>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        time_source: Arc<dyn TimeSource>,
        stable_registry_version_age: Duration,
        malicious_flags: MaliciousFlags,
        metrics_registry: MetricsRegistry,
        logger: ReplicaLogger,
    ) -> Self {
        let payload_builder = Arc::new(PayloadBuilderImpl::new(
            replica_config.subnet_id,
            replica_config.node_id,
            registry_client.clone(),
            ingress_selector.clone(),
            xnet_payload_builder,
            self_validating_payload_builder,
            canister_http_payload_builder,
            query_stats_payload_builder,
            metrics_registry.clone(),
            logger.clone(),
        ));

        let current_time = time_source.get_relative_time();
        let mut last_invoked: BTreeMap<ConsensusSubcomponent, Time> = BTreeMap::new();
        last_invoked.insert(ConsensusSubcomponent::Notary, current_time);
        last_invoked.insert(ConsensusSubcomponent::Finalizer, current_time);
        last_invoked.insert(ConsensusSubcomponent::RandomBeaconMaker, current_time);
        last_invoked.insert(ConsensusSubcomponent::RandomTapeMaker, current_time);
        last_invoked.insert(ConsensusSubcomponent::BlockMaker, current_time);
        last_invoked.insert(ConsensusSubcomponent::CatchUpPackageMaker, current_time);
        last_invoked.insert(ConsensusSubcomponent::Validator, current_time);
        last_invoked.insert(ConsensusSubcomponent::Aggregator, current_time);
        last_invoked.insert(ConsensusSubcomponent::Purger, current_time);

        ConsensusImpl {
            dkg_key_manager,
            notary: Notary::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config.clone(),
                membership.clone(),
                crypto.clone(),
                state_manager.clone(),
                metrics_registry.clone(),
                logger.clone(),
            ),
            finalizer: Finalizer::new(
                replica_config.clone(),
                registry_client.clone(),
                membership.clone(),
                crypto.clone(),
                message_routing.clone(),
                ingress_selector.clone(),
                logger.clone(),
                metrics_registry.clone(),
            ),
            random_beacon_maker: RandomBeaconMaker::new(
                replica_config.clone(),
                membership.clone(),
                crypto.clone(),
                logger.clone(),
            ),
            random_tape_maker: RandomTapeMaker::new(
                replica_config.clone(),
                membership.clone(),
                crypto.clone(),
                message_routing.clone(),
                logger.clone(),
            ),
            catch_up_package_maker: CatchUpPackageMaker::new(
                replica_config.clone(),
                membership.clone(),
                crypto.clone(),
                state_manager.clone(),
                message_routing.clone(),
                logger.clone(),
            ),
            block_maker: BlockMaker::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config.clone(),
                Arc::clone(&registry_client),
                membership.clone(),
                crypto.clone(),
                payload_builder.clone(),
                dkg_pool.clone(),
                ecdsa_pool.clone(),
                state_manager.clone(),
                stable_registry_version_age,
                metrics_registry.clone(),
                logger.clone(),
            ),
            validator: Validator::new(
                replica_config.clone(),
                membership.clone(),
                Arc::clone(&registry_client),
                crypto.clone(),
                payload_builder,
                state_manager.clone(),
                message_routing.clone(),
                dkg_pool,
                logger.clone(),
                ValidatorMetrics::new(metrics_registry.clone()),
                Arc::clone(&time_source),
                Some(ingress_selector.clone()),
            ),
            aggregator: ShareAggregator::new(
                membership,
                message_routing.clone(),
                crypto.clone(),
                logger.clone(),
            ),
            purger: Purger::new(
                replica_config.clone(),
                state_manager.clone(),
                message_routing,
                registry_client.clone(),
                logger.clone(),
                metrics_registry.clone(),
            ),
            metrics: ConsensusMetrics::new(metrics_registry),
            log: logger,
            time_source,
            registry_client,
            state_manager,
            malicious_flags,
            replica_config,
            last_invoked: RefCell::new(last_invoked),
            schedule: RoundRobin::default(),
        }
    }

    /// Call the given sub-component's `on_state_change` function, mark the
    /// time it takes to complete, increment its invocation counter, and mark
    /// the size of the [`ChangeSet`] result.
    fn call_with_metrics<F>(
        &self,
        sub_component: ConsensusSubcomponent,
        on_state_change: F,
    ) -> ChangeSet
    where
        F: FnOnce() -> ChangeSet,
    {
        self.last_invoked
            .borrow_mut()
            .insert(sub_component, self.time_source.get_relative_time());
        let name = sub_component.as_ref();
        let timer = self
            .metrics
            .on_state_change_duration
            .with_label_values(&[name])
            .start_timer();

        let change_set = on_state_change();

        timer.observe_duration();

        self.metrics
            .on_state_change_invocations
            .with_label_values(&[name])
            .inc();

        self.metrics
            .on_state_change_change_set_size
            .with_label_values(&[name])
            .observe(change_set.len() as f64);

        change_set
    }

    /// check whether the subnet should halt because the subnet record in the
    /// latest registry version instructs the subnet to halt
    pub fn should_halt_by_subnet_record(&self) -> bool {
        let version = self.registry_client.get_latest_version();
        match self
            .registry_client
            .get_is_halted(self.replica_config.subnet_id, version)
        {
            Ok(None) => {
                panic!(
                    "No subnet record found for registry version={:?} and subnet_id={:?}",
                    version, self.replica_config.subnet_id,
                );
            }
            Err(err) => {
                error!(
                    self.log,
                    "Could not retrieve whether the subnet is halted from the registry: {:?}", err
                );
                false
            }
            Ok(Some(is_halted)) => is_halted,
        }
    }

    /// Checks, whether DKG transcripts for this replica are available
    fn dkgs_available(&self, pool_reader: &PoolReader) -> bool {
        // Get last summary
        let summary_block = pool_reader.get_highest_summary_block();
        let block_payload = summary_block.payload.as_ref().as_summary();

        // Get transcripts from summary
        let transcripts = block_payload.dkg.current_transcripts();

        // Check that this replica is listed as a receiver for every transcript type
        transcripts
            .iter()
            .map(|(_, transcript)| {
                transcript
                    .committee
                    .get()
                    .iter()
                    .any(|id| *id == self.replica_config.node_id)
            })
            .reduce(|a, b| a && b)
            .unwrap_or(false)
    }
}

impl<T: ConsensusPool> ChangeSetProducer<T> for ConsensusImpl {
    type ChangeSet = ChangeSet;
    /// Invoke `on_state_change` on each subcomponent in order.
    /// Return the first non-empty [ChangeSet] as returned by a subcomponent.
    /// Otherwise return an empty [ChangeSet] if all subcomponents return
    /// empty.
    ///
    /// There are two decisions that [ConsensusImpl] makes:
    ///
    /// 1. It must return immediately if one of the subcomponent returns a
    /// non-empty [ChangeSet]. It is important that a [ChangeSet] is fully
    /// applied to the pool or timer before another subcomponent uses
    /// them, because each subcomponent expects to see full state in order to
    /// make correct decisions on what to do next.
    ///
    /// 2. The order in which subcomponents are called also matters. At the
    /// moment it is important to call finalizer first, because otherwise
    /// we'll just keep producing notarized blocks indefinitely without
    /// finalizing anything, due to the above decision of having to return
    /// early.
    /// Additionally, we call the purger after every function that may increment
    /// the finalized or CUP height (currently aggregation & validation), as
    /// these heights determine which artifacts we can purge. This reduces the
    /// number of excess artifacts, which allows us to maintain a stricter bound
    /// on the memory consumption of our advertised validated pool.
    /// The order of the rest subcomponents decides whom is given
    /// a priority, but it should not affect liveness or correctness.
    fn on_state_change(&self, pool: &T) -> ChangeSet {
        let pool_reader = PoolReader::new(pool);
        trace!(self.log, "on_state_change");

        // Load new transcripts, remove outdated keys.
        self.dkg_key_manager
            .lock()
            .unwrap()
            .on_state_change(&pool_reader);

        // Consensus halts if instructed by the registry
        if self.should_halt_by_subnet_record() {
            info!(
                every_n_seconds => 5,
                self.log,
                "consensus is halted by instructions of the subnet record in the registry"
            );
            return ChangeSet::new();
        }

        // Log some information about the state of consensus
        // This is useful for testing purposes
        debug!(
            every_n_seconds => 5,
            self.log,
            "Consensus finalized height: {}, state available: {}, DKG key material available: {}",
            pool_reader.get_finalized_height(),
            pool_reader.get_finalized_tip().context.certified_height
                <= self.state_manager.latest_certified_height(),
            self.dkgs_available(&pool_reader)
        );

        let time_now = self.time_source.get_relative_time();
        let finalize = || {
            self.call_with_metrics(ConsensusSubcomponent::Finalizer, || {
                add_all_to_validated(time_now, self.finalizer.on_state_change(&pool_reader))
            })
        };
        let make_catch_up_package = || {
            self.call_with_metrics(ConsensusSubcomponent::CatchUpPackageMaker, || {
                add_to_validated(
                    time_now,
                    self.catch_up_package_maker.on_state_change(&pool_reader),
                )
            })
        };
        let aggregate = || {
            self.call_with_metrics(ConsensusSubcomponent::Aggregator, || {
                add_all_to_validated(time_now, self.aggregator.on_state_change(&pool_reader))
            })
        };
        let notarize = || {
            self.call_with_metrics(ConsensusSubcomponent::Notary, || {
                add_all_to_validated(time_now, self.notary.on_state_change(&pool_reader))
            })
        };
        let make_random_beacon = || {
            self.call_with_metrics(ConsensusSubcomponent::RandomBeaconMaker, || {
                add_to_validated(
                    time_now,
                    self.random_beacon_maker.on_state_change(&pool_reader),
                )
            })
        };
        let make_random_tape = || {
            self.call_with_metrics(ConsensusSubcomponent::RandomTapeMaker, || {
                add_all_to_validated(
                    time_now,
                    self.random_tape_maker.on_state_change(&pool_reader),
                )
            })
        };
        let make_block = || {
            self.call_with_metrics(ConsensusSubcomponent::BlockMaker, || {
                add_to_validated(time_now, self.block_maker.on_state_change(&pool_reader))
            })
        };
        let validate = || {
            self.call_with_metrics(ConsensusSubcomponent::Validator, || {
                self.validator.on_state_change(&pool_reader)
            })
        };
        let purge = || {
            self.call_with_metrics(ConsensusSubcomponent::Purger, || {
                self.purger.on_state_change(&pool_reader)
            })
        };

        let calls: [&'_ dyn Fn() -> ChangeSet; 10] = [
            &finalize,
            &make_catch_up_package,
            &aggregate,
            &purge,
            &notarize,
            &make_random_beacon,
            &make_random_tape,
            &make_block,
            &validate,
            &purge,
        ];

        let changeset = self.schedule.call_next(&calls);

        if let Some(settings) = get_notarization_delay_settings(
            &self.log,
            &*self.registry_client,
            self.replica_config.subnet_id,
            self.registry_client.get_latest_version(),
        ) {
            let unit_delay = settings.unit_delay;
            let current_time = self.time_source.get_relative_time();
            for (component, last_invoked_time) in self.last_invoked.borrow().iter() {
                let time_since_last_invoked =
                    current_time.saturating_duration_since(*last_invoked_time);
                let component_name = component.as_ref();
                self.metrics
                    .time_since_last_invoked
                    .with_label_values(&[component_name])
                    .set(time_since_last_invoked.as_secs_f64());

                // Log starvation
                if time_since_last_invoked > unit_delay {
                    self.metrics
                        .starvation_counter
                        .with_label_values(&[component_name])
                        .inc();

                    warn!(
                        every_n_seconds => 5,
                        self.log,
                        "starvation detected: {:?} has not been invoked for {:?}",
                        component,
                        time_since_last_invoked
                    );
                }
            }
        }

        #[cfg(feature = "malicious_code")]
        if self.malicious_flags.is_consensus_malicious() {
            crate::consensus::malicious_consensus::maliciously_alter_changeset(
                &pool_reader,
                changeset,
                &self.malicious_flags,
                &self.block_maker,
                &self.finalizer,
                &self.notary,
                &self.log,
                self.time_source.get_relative_time(),
            )
        } else {
            changeset
        }

        #[cfg(not(feature = "malicious_code"))]
        changeset
    }
}

pub(crate) fn add_all_to_validated<T: ConsensusMessageHashable>(
    timestamp: Time,
    messages: Vec<T>,
) -> ChangeSet {
    messages
        .into_iter()
        .map(|msg| {
            ChangeAction::AddToValidated(ValidatedConsensusArtifact {
                msg: msg.into_message(),
                timestamp,
            })
        })
        .collect()
}

fn add_to_validated<T: ConsensusMessageHashable>(timestamp: Time, msg: Option<T>) -> ChangeSet {
    msg.map(|msg| {
        ChangeAction::AddToValidated(ValidatedConsensusArtifact {
            msg: msg.into_message(),
            timestamp,
        })
        .into()
    })
    .unwrap_or_default()
}

/// Implement Consensus Gossip interface.
pub struct ConsensusGossipImpl {
    message_routing: Arc<dyn MessageRouting>,
}

impl ConsensusGossipImpl {
    /// Create a new [ConsensusGossipImpl].
    pub fn new(message_routing: Arc<dyn MessageRouting>) -> Self {
        ConsensusGossipImpl { message_routing }
    }
}

impl<Pool: ConsensusPool> PriorityFnAndFilterProducer<ConsensusArtifact, Pool>
    for ConsensusGossipImpl
{
    /// Return a priority function that matches the given consensus pool.
    fn get_priority_function(&self, pool: &Pool) -> PriorityFn<ConsensusMessageId, ()> {
        get_priority_function(pool, self.message_routing.expected_batch_height())
    }
}

#[allow(clippy::too_many_arguments)]
/// Setup consensus component, and return two objects satisfying the Consensus
/// and ConsensusGossip interfaces respectively.
pub fn setup(
    replica_config: ReplicaConfig,
    registry_client: Arc<dyn RegistryClient>,
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
    ingress_selector: Arc<dyn IngressSelector>,
    xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
    self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
    canister_http_payload_builder: Arc<dyn BatchPayloadBuilder>,
    query_stats_payload_builder: Arc<dyn BatchPayloadBuilder>,
    dkg_pool: Arc<RwLock<dyn DkgPool>>,
    ecdsa_pool: Arc<RwLock<dyn EcdsaPool>>,
    dkg_key_manager: Arc<Mutex<DkgKeyManager>>,
    message_routing: Arc<dyn MessageRouting>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    time_source: Arc<dyn TimeSource>,
    malicious_flags: MaliciousFlags,
    metrics_registry: MetricsRegistry,
    logger: ReplicaLogger,
    registry_poll_delay_duration_ms: u64,
) -> (ConsensusImpl, ConsensusGossipImpl) {
    // Currently, the orchestrator polls the registry every
    // `registry_poll_delay_duration_ms` and writes new updates into the
    // registry local store. The registry client polls the local store
    // for updates every `registry::POLLING_PERIOD`. These two polls are completely
    // async, so that every replica sees a new registry version at any time
    // between >0 and the sum of both polling intervals. To accommodate for that,
    // we use this sum as the minimal age of a registry version we consider as
    // stable.

    let stable_registry_version_age =
        POLLING_PERIOD + Duration::from_millis(registry_poll_delay_duration_ms);
    (
        ConsensusImpl::new(
            replica_config,
            registry_client,
            membership,
            crypto,
            ingress_selector,
            xnet_payload_builder,
            self_validating_payload_builder,
            canister_http_payload_builder,
            query_stats_payload_builder,
            dkg_pool,
            ecdsa_pool,
            dkg_key_manager,
            message_routing.clone(),
            state_manager,
            time_source,
            stable_registry_version_age,
            malicious_flags,
            metrics_registry,
            logger,
        ),
        ConsensusGossipImpl::new(message_routing),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_config::artifact_pool::ArtifactPoolConfig;
    use ic_consensus_mocks::{dependencies_with_subnet_params, Dependencies};
    use ic_https_outcalls_consensus::test_utils::FakeCanisterHttpPayloadBuilder;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::subnet::v1::SubnetRecord;
    use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
    use ic_test_utilities::{
        ingress_selector::FakeIngressSelector, message_routing::FakeMessageRouting,
        self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
        xnet_payload_builder::FakeXNetPayloadBuilder,
    };
    use ic_test_utilities_consensus::batch::MockBatchPayloadBuilder;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_time::FastForwardTimeSource;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{crypto::CryptoHash, CryptoHashOfState, Height, SubnetId};
    use std::{sync::Arc, time::Duration};

    fn set_up_consensus_with_subnet_record(
        record: SubnetRecord,
        pool_config: ArtifactPoolConfig,
    ) -> (ConsensusImpl, TestConsensusPool, Arc<FastForwardTimeSource>) {
        set_up_consensus_with_subnet_record_and_subnet_id(record, pool_config, subnet_test_id(0))
    }

    fn set_up_consensus_with_subnet_record_and_subnet_id(
        record: SubnetRecord,
        pool_config: ArtifactPoolConfig,
        subnet_id: SubnetId,
    ) -> (ConsensusImpl, TestConsensusPool, Arc<FastForwardTimeSource>) {
        let Dependencies {
            pool,
            membership,
            registry,
            crypto,
            time_source,
            replica_config,
            state_manager,
            dkg_pool,
            ecdsa_pool,
            ..
        } = dependencies_with_subnet_params(pool_config, subnet_id, vec![(1, record)]);
        state_manager
            .get_mut()
            .expect_latest_certified_height()
            .return_const(Height::from(0));
        state_manager
            .get_mut()
            .expect_latest_state_height()
            .return_const(Height::from(0));
        state_manager
            .get_mut()
            .expect_get_state_hash_at()
            .return_const(Ok(CryptoHashOfState::from(CryptoHash(Vec::new()))));

        let metrics_registry = MetricsRegistry::new();

        let consensus_impl = ConsensusImpl::new(
            replica_config,
            registry,
            membership,
            crypto.clone(),
            Arc::new(FakeIngressSelector::new()),
            Arc::new(FakeXNetPayloadBuilder::new()),
            Arc::new(FakeSelfValidatingPayloadBuilder::new()),
            Arc::new(FakeCanisterHttpPayloadBuilder::new()),
            Arc::new(MockBatchPayloadBuilder::new().expect_noop()),
            dkg_pool,
            ecdsa_pool,
            Arc::new(Mutex::new(DkgKeyManager::new(
                metrics_registry.clone(),
                crypto,
                no_op_logger(),
                &PoolReader::new(&pool),
            ))),
            Arc::new(FakeMessageRouting::new()),
            state_manager,
            time_source.clone(),
            Duration::from_secs(0),
            MaliciousFlags::default(),
            metrics_registry,
            no_op_logger(),
        );
        (consensus_impl, pool, time_source)
    }

    #[test]
    fn test_halt_subnet_via_registry() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let committee: Vec<_> = (0..4).map(node_test_id).collect();
            let interval_length = 99;

            // ensure that a consensus implementation with a subnet record with is_halted =
            // false returns changes
            let (consensus_impl, pool, _) = set_up_consensus_with_subnet_record(
                SubnetRecordBuilder::from(&committee)
                    .with_dkg_interval_length(interval_length)
                    .with_is_halted(false)
                    .build(),
                pool_config.clone(),
            );

            assert!(!consensus_impl.on_state_change(&pool).is_empty());

            // ensure that an consensus_impl with a subnet record with is_halted =
            // true returns no changes
            let (consensus_impl, pool, _) = set_up_consensus_with_subnet_record(
                SubnetRecordBuilder::from(&committee)
                    .with_dkg_interval_length(interval_length)
                    .with_is_halted(true)
                    .build(),
                pool_config,
            );
            assert!(consensus_impl.on_state_change(&pool).is_empty());
        })
    }
}
