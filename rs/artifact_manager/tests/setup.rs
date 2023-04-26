use ic_artifact_manager::manager;
use ic_artifact_pool::consensus_pool::ConsensusPoolImpl;
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_interfaces::artifact_manager::*;
use ic_interfaces::artifact_pool::{ChangeSetProducer, PriorityFnAndFilterProducer};
use ic_interfaces::consensus_pool::ChangeSet;
use ic_interfaces::time_source::SysTimeSource;
use ic_logger::replica_logger::{no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_test_utilities::{
    consensus::{fake::*, make_genesis},
    types::ids::subnet_test_id,
};
use ic_types::artifact::{ArtifactKind, ArtifactTag, ConsensusMessageId, PriorityFn};
use ic_types::artifact_kind::ConsensusArtifact;
use ic_types::consensus::ConsensusMessageAttribute;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

struct UnimplementedConsensusPoolDescriptor {}

impl PriorityFnAndFilterProducer<ConsensusArtifact, ConsensusPoolImpl>
    for UnimplementedConsensusPoolDescriptor
{
    fn get_priority_function(
        &self,
        _pool: &ConsensusPoolImpl,
    ) -> PriorityFn<ConsensusMessageId, ConsensusMessageAttribute> {
        unimplemented!()
    }
}

struct MockConsensus {}

impl ChangeSetProducer<ConsensusPoolImpl> for MockConsensus {
    type ChangeSet = ChangeSet;

    fn on_state_change(&self, _pool: &ConsensusPoolImpl) -> ChangeSet {
        vec![]
    }
}

fn setup_manager(
    artifact_pool_config: ArtifactPoolConfig,
) -> (Arc<dyn ArtifactManager>, ArtifactProcessorJoinGuard) {
    let time_source = Arc::new(SysTimeSource::new());
    let metrics_registry = MetricsRegistry::new();
    let replica_logger = no_op_logger();

    let consensus_pool = init_artifact_pools(
        artifact_pool_config,
        metrics_registry.clone(),
        replica_logger.clone(),
    );

    let consensus = MockConsensus {};
    let consensus_gossip = UnimplementedConsensusPoolDescriptor {};
    let mut backends: HashMap<ArtifactTag, Box<dyn manager::ArtifactManagerBackend>> =
        HashMap::new();

    let (client, jh) = ic_artifact_manager::create_consensus_handlers(
        |_| {},
        (consensus, consensus_gossip),
        Arc::clone(&time_source) as Arc<_>,
        Arc::clone(&consensus_pool),
        replica_logger,
        metrics_registry,
    );
    backends.insert(ConsensusArtifact::TAG, Box::new(client));

    (
        Arc::new(manager::ArtifactManagerImpl::new_with_default_priority_fn(
            backends,
        )),
        jh,
    )
}

fn init_artifact_pools(
    config: ArtifactPoolConfig,
    registry: MetricsRegistry,
    log: ReplicaLogger,
) -> Arc<RwLock<ConsensusPoolImpl>> {
    let cup = make_genesis(ic_types::consensus::dkg::Summary::fake());

    Arc::new(RwLock::new(ConsensusPoolImpl::new(
        subnet_test_id(0),
        ic_types::consensus::catchup::CUPWithOriginalProtobuf::from_cup(cup),
        config,
        registry,
        log,
    )))
}

/// Run an artifact manager test, which is a function that takes an
/// ArtifactManager object as input, which is already setup with
/// ingress pool, consensus pool and consensus client (using MockConsensus).
pub fn run_test<F: Fn(Arc<dyn ArtifactManager>)>(test: F) {
    ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
        let (manager, _jh) = setup_manager(pool_config);
        test(manager)
    })
}
