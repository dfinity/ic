//! This module encapsulates all components required for establishing of a
//! distributed consensus.

pub mod batch_delivery;
mod block_maker;
mod catchup_package_maker;
pub(crate) mod crypto;
pub mod dkg_key_manager;
mod finalizer;
mod malicious_consensus;
pub(crate) mod membership;
pub(crate) mod metrics;
mod notary;
pub mod payload_builder;
pub mod pool_reader;
mod prelude;
mod priority;
mod purger;
mod random_beacon_maker;
mod random_tape_maker;
mod share_aggregator;
pub mod utils;
mod validator;

pub use batch_delivery::generate_responses_to_subnet_calls;
pub use crypto::ConsensusCrypto;
pub use membership::Membership;

#[cfg(test)]
pub(crate) mod mocks;

use crate::consensus::{
    block_maker::BlockMaker,
    catchup_package_maker::CatchUpPackageMaker,
    dkg_key_manager::DkgKeyManager,
    finalizer::Finalizer,
    metrics::{ConsensusGossipMetrics, ConsensusMetrics, ValidatorMetrics},
    notary::Notary,
    payload_builder::PayloadBuilderImpl,
    pool_reader::PoolReader,
    prelude::*,
    priority::get_priority_function,
    purger::Purger,
    random_beacon_maker::RandomBeaconMaker,
    random_tape_maker::RandomTapeMaker,
    share_aggregator::ShareAggregator,
    utils::{get_notarization_delay_settings, is_root_subnet, RoundRobin},
    validator::Validator,
};
use ic_config::consensus::ConsensusConfig;
use ic_interfaces::{
    consensus::{Consensus, ConsensusGossip},
    consensus_pool::ConsensusPool,
    dkg::DkgPool,
    ingress_manager::IngressSelector,
    ingress_pool::IngressPoolSelect,
    messaging::{MessageRouting, XNetPayloadBuilder},
    registry::{self, LocalStoreCertifiedTimeReader, RegistryClient},
    self_validating_payload::SelfValidatingPayloadBuilder,
    state_manager::StateManager,
    time_source::TimeSource,
};
use ic_logger::{error, info, trace, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::{ConsensusMessageFilter, ConsensusMessageId, PriorityFn},
    malicious_flags::MaliciousFlags,
    replica_config::ReplicaConfig,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use std::{cell::RefCell, sync::Mutex};
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

/// The maximum duration that we allow the registry to be outdated. If a
/// subnet has not managed to get a certified statement from the
/// registry for longer than this, the subnet should halt.
pub const HALT_AFTER_REGISTRY_UNREACHABLE: Duration = Duration::from_secs(60 * 60);

/// ConsensusImpl holds all consensus subcomponents, and implements the
/// Consensus trait by calling each subcomponent in round-robin manner.
pub struct ConsensusImpl {
    notary: Notary,
    finalizer: Finalizer,
    random_beacon_maker: RandomBeaconMaker,
    random_tape_maker: RandomTapeMaker,
    block_maker: BlockMaker,
    catch_up_package_maker: CatchUpPackageMaker,
    validator: Validator,
    aggregator: ShareAggregator,
    purger: Purger,
    metrics: ConsensusMetrics,
    time_source: Arc<dyn TimeSource>,
    registry_client: Arc<dyn RegistryClient>,
    dkg_key_manager: Arc<Mutex<DkgKeyManager>>,
    last_invoked: RefCell<BTreeMap<ConsensusSubcomponent, Time>>,
    schedule: RoundRobin,
    subnet_id: SubnetId,
    #[allow(dead_code)]
    malicious_flags: MaliciousFlags,
    log: ReplicaLogger,
    config: ConsensusConfig,
    local_store_time_reader: Option<Arc<dyn LocalStoreCertifiedTimeReader>>,
}

impl ConsensusImpl {
    /// Create a new ConsensusImpl along with all subcomponents it manages.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        replica_config: ReplicaConfig,
        consensus_config: ConsensusConfig,
        registry_client: Arc<dyn RegistryClient>,
        membership: Arc<Membership>,
        crypto: Arc<dyn ConsensusCrypto>,
        ingress_selector: Arc<dyn IngressSelector>,
        xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
        self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
        dkg_pool: Arc<RwLock<dyn DkgPool>>,
        dkg_key_manager: Arc<Mutex<DkgKeyManager>>,
        message_routing: Arc<dyn MessageRouting>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        time_source: Arc<dyn TimeSource>,
        stable_registry_version_age: Duration,
        malicious_flags: MaliciousFlags,
        metrics_registry: MetricsRegistry,
        logger: ReplicaLogger,
        local_store_time_reader: Option<Arc<dyn LocalStoreCertifiedTimeReader>>,
    ) -> Self {
        let payload_builder = Arc::new(PayloadBuilderImpl::new(
            ingress_selector.clone(),
            xnet_payload_builder,
            self_validating_payload_builder,
            metrics_registry.clone(),
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
                ingress_selector,
                state_manager.clone(),
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
            ),
            aggregator: ShareAggregator::new(
                membership,
                message_routing.clone(),
                crypto.clone(),
                logger.clone(),
            ),
            purger: Purger::new(
                state_manager,
                message_routing,
                logger.clone(),
                metrics_registry.clone(),
            ),
            metrics: ConsensusMetrics::new(metrics_registry),
            log: logger,
            time_source,
            registry_client,
            malicious_flags,
            subnet_id: replica_config.subnet_id,
            last_invoked: RefCell::new(last_invoked),
            schedule: RoundRobin::default(),
            config: consensus_config,
            local_store_time_reader,
        }
    }

    /// Call the given sub-component's `on_state_change` function, mark the
    /// time it takes to complete, increment its invocation counter, and mark
    /// the size of the `ChangeSet` result.
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

    /// check whether the subnet should halt because it has not reached
    /// the registry in a long time
    pub fn check_registry_outdated(&self) -> Result<(), String> {
        if let Some(reader) = &self.local_store_time_reader {
            let registry_time = reader.read_certified_time();
            let current_time = self.time_source.get_relative_time();
            if registry_time + HALT_AFTER_REGISTRY_UNREACHABLE < current_time {
                return Err(format!(
                    "registry time: {:?}, current_time: {:?}",
                    registry_time, current_time
                ));
            }
        }
        Ok(())
    }

    /// check whether the subnet should halt because the subnet record in the
    /// latest registry version instructs the subnet to halt
    pub fn should_halt_by_subnet_record(&self) -> bool {
        let version = self.registry_client.get_latest_version();
        match self.registry_client.get_is_halted(self.subnet_id, version) {
            Ok(None) => {
                panic!(
                    "No subnet record found for registry version={:?} and subnet_id={:?}",
                    version, self.subnet_id,
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
}

impl Consensus for ConsensusImpl {
    /// Invoke `on_state_change` on each subcomponent in order.
    /// Return the first non-empty [ChangeSet] as returned by a subcomponent.
    /// Otherwise return an empty [ChangeSet] if all subcomponents return
    /// empty.
    ///
    /// There are two decisions that ConsensusImpl makes:
    ///
    /// 1. It must return immediately if one of the subcomponent returns a
    /// non-empty [ChangeSet]. It is important that a [ChangeSet] is fully
    /// applied to the pool or timer before another subcomponent uses
    /// them, because each subcomponent expects to see full state in order to
    /// make correct decisions on what to do next.
    ///
    /// 2. The order in which subcomponents are called also matters. At the
    /// moment it is important to call finalizer first, because otherwise
    /// we'll just keep producing notarized blocks indefintely without
    /// finalizing anything, due to the above decision of having to return
    /// early. The order of the rest subcomponents decides whom is given
    /// a priority, but it should not affect liveness or correctness.
    fn on_state_change(
        &self,
        pool: &dyn ConsensusPool,
        ingress_pool: &dyn IngressPoolSelect,
    ) -> ChangeSet {
        let pool_reader = PoolReader::new(pool);
        trace!(self.log, "on_state_change");

        // Load new transcripts, remove outdated keys.
        self.dkg_key_manager
            .lock()
            .unwrap()
            .on_state_change(&pool_reader);

        // For non-root subnets, we must halt if our registry is outdated
        if let Ok(false) = is_root_subnet(
            self.registry_client.as_ref(),
            self.subnet_id,
            self.registry_client.get_latest_version(),
        ) {
            if let Err(e) = self.check_registry_outdated() {
                info!(
                    every_n_seconds => 5,
                    self.log,
                    "consensus is halted due to outdated registry. {:?}", e
                );
                return ChangeSet::new();
            }
        }

        // Consensus halts if instructed by the registry
        if self.should_halt_by_subnet_record() {
            info!(
                every_n_seconds => 5,
                self.log,
                "consensus is halted by instructions of the subnet record in the registry"
            );
            return ChangeSet::new();
        }

        let finalize = || {
            self.call_with_metrics(ConsensusSubcomponent::Finalizer, || {
                add_all_to_validated(self.finalizer.on_state_change(&pool_reader))
            })
        };
        let make_catch_up_package = || {
            self.call_with_metrics(ConsensusSubcomponent::CatchUpPackageMaker, || {
                add_to_validated(self.catch_up_package_maker.on_state_change(&pool_reader))
            })
        };
        let aggregate = || {
            self.call_with_metrics(ConsensusSubcomponent::Aggregator, || {
                add_all_to_validated(self.aggregator.on_state_change(&pool_reader))
            })
        };
        let notarize = || {
            self.call_with_metrics(ConsensusSubcomponent::Notary, || {
                add_all_to_validated(self.notary.on_state_change(&pool_reader))
            })
        };
        let make_random_beacon = || {
            self.call_with_metrics(ConsensusSubcomponent::RandomBeaconMaker, || {
                add_to_validated(self.random_beacon_maker.on_state_change(&pool_reader))
            })
        };
        let make_random_tape = || {
            self.call_with_metrics(ConsensusSubcomponent::RandomTapeMaker, || {
                add_all_to_validated(self.random_tape_maker.on_state_change(&pool_reader))
            })
        };
        let make_block = || {
            self.call_with_metrics(ConsensusSubcomponent::BlockMaker, || {
                add_to_validated(self.block_maker.on_state_change(&pool_reader, ingress_pool))
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
        let calls: [&'_ dyn Fn() -> ChangeSet; 9] = [
            &finalize,
            &make_catch_up_package,
            &purge,
            &aggregate,
            &notarize,
            &make_random_beacon,
            &make_random_tape,
            &make_block,
            &validate,
        ];

        let changeset = self.schedule.call_next(&calls);

        if let Some(settings) = get_notarization_delay_settings(
            &self.log,
            &*self.registry_client,
            self.subnet_id,
            self.registry_client.get_latest_version(),
        ) {
            let unit_delay = settings.unit_delay;
            let current_time = self.time_source.get_relative_time();
            for (component, last_invoked_time) in self.last_invoked.borrow().iter() {
                let time_since_last_invoked = current_time - *last_invoked_time;
                let component_name = component.as_ref();
                self.metrics
                    .time_since_last_invoked
                    .with_label_values(&[component_name])
                    .set(time_since_last_invoked.as_secs_f64());

                // Log starvation if configured
                if self.config.detect_starvation() && time_since_last_invoked > unit_delay {
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
                ingress_pool,
                changeset,
                &self.malicious_flags,
                &self.block_maker,
                &self.finalizer,
                &self.notary,
                &self.log,
            )
        } else {
            changeset
        }

        #[cfg(not(feature = "malicious_code"))]
        changeset
    }
}

pub(crate) fn add_all_to_validated<T: ConsensusMessageHashable>(messages: Vec<T>) -> ChangeSet {
    messages
        .into_iter()
        .map(|msg| ChangeAction::AddToValidated(msg.into_message()))
        .collect()
}

fn add_to_validated<T: ConsensusMessageHashable>(msg: Option<T>) -> ChangeSet {
    msg.map(|msg| ChangeAction::AddToValidated(msg.into_message()).into())
        .unwrap_or_default()
}

/// Implement Consensus Gossip interface.
pub struct ConsensusGossipImpl {
    message_routing: Arc<dyn MessageRouting>,
    metrics: ConsensusGossipMetrics,
}

impl ConsensusGossipImpl {
    /// Create a new ConsensusGossipImpl.
    pub fn new(
        message_routing: Arc<dyn MessageRouting>,
        metrics_registry: MetricsRegistry,
    ) -> Self {
        ConsensusGossipImpl {
            message_routing,
            metrics: ConsensusGossipMetrics::new(metrics_registry),
        }
    }
}

impl ConsensusGossip for ConsensusGossipImpl {
    /// Return a priority function that matches the given consensus pool.
    fn get_priority_function(
        &self,
        pool: &dyn ConsensusPool,
    ) -> PriorityFn<ConsensusMessageId, ConsensusMessageAttribute> {
        get_priority_function(
            pool,
            self.message_routing.expected_batch_height(),
            &self.metrics,
        )
    }

    /// Return a filter that represents what artifacts are needed above the
    /// filter height.
    fn get_filter(&self) -> ConsensusMessageFilter {
        let expected_batch_height = self.message_routing.expected_batch_height();
        assert!(
            expected_batch_height > Height::from(0),
            "Expected batch height must be 1 more higher"
        );
        ConsensusMessageFilter {
            height: expected_batch_height.decrement(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// Setup consensus component, and return two objects satisfying the Consensus
/// and ConsensusGossip interfaces respectively.
pub fn setup(
    replica_config: ReplicaConfig,
    consensus_config: ConsensusConfig,
    registry_client: Arc<dyn RegistryClient>,
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
    ingress_selector: Arc<dyn IngressSelector>,
    xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
    self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
    dkg_pool: Arc<RwLock<dyn DkgPool>>,
    dkg_key_manager: Arc<Mutex<DkgKeyManager>>,
    message_routing: Arc<dyn MessageRouting>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    time_source: Arc<dyn TimeSource>,
    malicious_flags: MaliciousFlags,
    metrics_registry: MetricsRegistry,
    logger: ReplicaLogger,
    local_store_time_reader: Option<Arc<dyn LocalStoreCertifiedTimeReader>>,
    registry_poll_delay_duration_ms: u64,
) -> (ConsensusImpl, ConsensusGossipImpl) {
    // Currently, the nodemanager polls the registry every
    // `registry_poll_delay_duration_ms` and writes new updates into the
    // registry local store. The registry client polls the local store
    // for updates every `registry::POLLING_PERIOD`. These two polls are completelly
    // async, so that every replica sees a new registry version at any time
    // between >0 and the sum of both polling intervals. To accomodate for that,
    // we use this sum as the minimal age of a registry version we consider as
    // stable.

    let stable_registry_version_age =
        registry::POLLING_PERIOD + Duration::from_millis(registry_poll_delay_duration_ms);
    (
        ConsensusImpl::new(
            replica_config,
            consensus_config,
            registry_client,
            membership,
            crypto,
            ingress_selector,
            xnet_payload_builder,
            self_validating_payload_builder,
            dkg_pool,
            dkg_key_manager,
            message_routing.clone(),
            state_manager,
            time_source,
            stable_registry_version_age,
            malicious_flags,
            metrics_registry.clone(),
            logger,
            local_store_time_reader,
        ),
        ConsensusGossipImpl::new(message_routing, metrics_registry),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::mocks::{dependencies_with_subnet_params, Dependencies};
    use ic_config::artifact_pool::ArtifactPoolConfig;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::subnet::v1::SubnetRecord;
    use ic_registry_subnet_type::SubnetType;
    use ic_test_artifact_pool::ingress_pool::TestIngressPool;
    use ic_test_utilities::{
        ingress_selector::FakeIngressSelector,
        message_routing::FakeMessageRouting,
        registry::{FakeLocalStoreCertifiedTimeReader, SubnetRecordBuilder},
        self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
        types::ids::{node_test_id, subnet_test_id},
        xnet_payload_builder::FakeXNetPayloadBuilder,
        FastForwardTimeSource,
    };
    use std::borrow::Borrow;
    use std::sync::Arc;
    use std::time::Duration;

    fn set_up_consensus_with_subnet_record(
        record: SubnetRecord,
        pool_config: ArtifactPoolConfig,
    ) -> (
        ConsensusImpl,
        Box<dyn ConsensusPool>,
        Arc<FastForwardTimeSource>,
    ) {
        let subnet_id = subnet_test_id(0);
        let Dependencies {
            pool,
            membership,
            registry,
            crypto,
            time_source,
            replica_config,
            state_manager,
            dkg_pool,
            ..
        } = dependencies_with_subnet_params(pool_config, subnet_id, vec![(1, record)]);
        state_manager
            .get_mut()
            .expect_latest_certified_height()
            .return_const(Height::from(0));
        state_manager
            .get_mut()
            .expect_get_state_hash_at()
            .return_const(Ok(CryptoHashOfState::from(CryptoHash(Vec::new()))));

        let metrics_registry = MetricsRegistry::new();

        let consensus_impl = ConsensusImpl::new(
            replica_config,
            ConsensusConfig::default(),
            registry,
            membership,
            crypto.clone(),
            Arc::new(FakeIngressSelector::new()),
            Arc::new(FakeXNetPayloadBuilder::new()),
            Arc::new(FakeSelfValidatingPayloadBuilder::new()),
            dkg_pool,
            Arc::new(Mutex::new(DkgKeyManager::new(
                metrics_registry.clone(),
                crypto,
                no_op_logger(),
            ))),
            Arc::new(FakeMessageRouting::new()),
            state_manager,
            time_source.clone(),
            Duration::from_secs(0),
            MaliciousFlags::default(),
            metrics_registry,
            no_op_logger(),
            Some(Arc::new(FakeLocalStoreCertifiedTimeReader::new(
                time_source.clone(),
            ))),
        );
        (consensus_impl, Box::new(pool), time_source)
    }

    #[test]
    fn test_halt_subnet_via_registry() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let committee: Vec<_> = (0..4).map(node_test_id).collect();
            let interval_length = 99;
            let ingress_pool = TestIngressPool::new(pool_config.clone());

            // ensure that a consensus implementation with a subnet record with is_halted =
            // false returns changes
            let (consensus_impl, pool, _) = set_up_consensus_with_subnet_record(
                SubnetRecordBuilder::from(&committee)
                    .with_dkg_interval_length(interval_length)
                    .with_is_halted(false)
                    .build(),
                pool_config.clone(),
            );

            assert!(!consensus_impl
                .on_state_change(pool.borrow(), &ingress_pool)
                .is_empty());

            // ensure that an consensus_impl with a subnet record with is_halted =
            // true returns no changes
            let (consensus_impl, pool, _) = set_up_consensus_with_subnet_record(
                SubnetRecordBuilder::from(&committee)
                    .with_dkg_interval_length(interval_length)
                    .with_is_halted(true)
                    .build(),
                pool_config,
            );
            assert!(consensus_impl
                .on_state_change(pool.borrow(), &ingress_pool)
                .is_empty());
        })
    }

    #[test]
    fn test_halt_subnet_when_registry_outdated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let committee: Vec<_> = (0..4).map(node_test_id).collect();
            let interval_length = 99;
            let ingress_pool = TestIngressPool::new(pool_config.clone());

            // ensure that an consensus_impl with a subnet record with is_halted = false
            // returns changes
            let (mut consensus_impl, pool, consensus_time_source) =
                set_up_consensus_with_subnet_record(
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(interval_length)
                        .build(),
                    pool_config,
                );

            // when the consensus time source and the registry time are equal, consensus
            // should not be halted.
            let registry_time_source = FastForwardTimeSource::new();
            consensus_impl.local_store_time_reader = Some(Arc::new(
                FakeLocalStoreCertifiedTimeReader::new(registry_time_source.clone()),
            ));
            registry_time_source
                .set_time(consensus_impl.time_source.get_relative_time())
                .unwrap();
            assert!(!consensus_impl
                .on_state_change(pool.borrow(), &ingress_pool)
                .is_empty());

            // advance the consensus time such that it's `HALT_AFTER_REGISTRY_UNREACHABLE`
            // ahead of the registry time. Consensus should not be halted yet.
            let new_time =
                consensus_time_source.get_relative_time() + HALT_AFTER_REGISTRY_UNREACHABLE;
            consensus_time_source.set_time(new_time).unwrap();
            assert!(!consensus_impl
                .on_state_change(pool.borrow(), &ingress_pool)
                .is_empty());

            // advance the consensus time another second, such that it's more than
            // `HALT_AFTER_REGISTRY_UNREACHABLE` ahead of the registry time. Consensus
            // should now be stalled.
            let new_time = consensus_time_source.get_relative_time() + Duration::from_secs(1);
            consensus_time_source.set_time(new_time).unwrap();
            assert!(consensus_impl
                .on_state_change(pool.borrow(), &ingress_pool)
                .is_empty());

            // if we advance the registry time such that it's <=
            // `HALT_AFTER_REGISTRY_UNREACHABLE` behind the consensus time,
            // consensus should no longer be halted.
            registry_time_source.set_time(new_time).unwrap();
            assert!(!consensus_impl
                .on_state_change(pool.borrow(), &ingress_pool)
                .is_empty());
        })
    }

    #[test]
    fn test_root_subnet_does_not_halt_when_registry_outdated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let committee: Vec<_> = (0..4).map(node_test_id).collect();
            let interval_length = 99;
            let ingress_pool = TestIngressPool::new(pool_config.clone());

            // ensure that an consensus_impl with a subnet record with is_halted = false
            // returns changes
            let (mut consensus_impl, pool, consensus_time_source) =
                set_up_consensus_with_subnet_record(
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(interval_length)
                        .with_subnet_type(SubnetType::System)
                        .build(),
                    pool_config,
                );

            // when the consensus time source and the registry time are equal, consensus
            // should not be halted.
            let registry_time_source = FastForwardTimeSource::new();
            consensus_impl.local_store_time_reader = Some(Arc::new(
                FakeLocalStoreCertifiedTimeReader::new(registry_time_source.clone()),
            ));
            registry_time_source
                .set_time(consensus_impl.time_source.get_relative_time())
                .unwrap();
            // advance the consensus time such that it's more than
            // `HALT_AFTER_REGISTRY_UNREACHABLE` ahead of the registry time. Consensus
            // should not be halted as the root subnet should be excluded from the
            // halt-by-outdated-registry check
            let new_time = consensus_time_source.get_relative_time()
                + HALT_AFTER_REGISTRY_UNREACHABLE
                + Duration::from_secs(1);
            consensus_time_source.set_time(new_time).unwrap();
            assert!(!consensus_impl
                .on_state_change(pool.borrow(), &ingress_pool)
                .is_empty());
        })
    }
}
