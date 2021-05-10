use actix::prelude::*;
use ic_artifact_manager::{actors, manager};
use ic_artifact_pool::{consensus_pool::ConsensusPoolImpl, ingress_pool::IngressPoolImpl};
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_consensus_message::make_genesis;
use ic_interfaces::artifact_manager::*;
use ic_interfaces::time_source::SysTimeSource;
use ic_logger::replica_logger::{no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_test_utilities::{
    consensus::{fake::*, MockConsensus},
    types::ids::subnet_test_id,
};
use std::sync::{Arc, RwLock};

fn setup_manager(artifact_pool_config: ArtifactPoolConfig) -> Arc<dyn ArtifactManager> {
    let system = System::current();
    let arbiter = system.arbiter();
    let time_source = Arc::new(SysTimeSource::new());
    let metrics_registry = MetricsRegistry::new();
    let replica_logger = no_op_logger();

    let mut artifact_manager_maker = manager::ArtifactManagerMaker::new(time_source.clone());

    let (ingress_pool, consensus_pool) = init_artifact_pools(
        artifact_pool_config,
        metrics_registry.clone(),
        replica_logger.clone(),
    );

    // Create consensus client
    let (consensus_client, addr) = actors::ConsensusClient::run(
        &arbiter,
        |_| {},
        || {
            let mut consensus = MockConsensus::new();
            consensus.expect_on_state_change().return_const(vec![]);
            let consensus_gossip = MockConsensus::new();
            (consensus, consensus_gossip)
        },
        Arc::clone(&time_source) as Arc<_>,
        Arc::clone(&consensus_pool),
        Arc::clone(&ingress_pool),
        replica_logger,
        metrics_registry,
    );
    artifact_manager_maker.add_client(consensus_client, addr);
    artifact_manager_maker.finish()
}

fn init_artifact_pools(
    config: ArtifactPoolConfig,
    registry: MetricsRegistry,
    log: ReplicaLogger,
) -> (Arc<RwLock<IngressPoolImpl>>, Arc<RwLock<ConsensusPoolImpl>>) {
    let cup = make_genesis(ic_types::consensus::dkg::Summary::fake());
    (
        Arc::new(RwLock::new(IngressPoolImpl::new(
            config.clone(),
            registry.clone(),
            log.clone(),
        ))),
        Arc::new(RwLock::new(ConsensusPoolImpl::new(
            subnet_test_id(0),
            ic_types::consensus::catchup::CUPWithOriginalProtobuf::from_cup(cup),
            config,
            registry,
            log,
        ))),
    )
}

/// Run an artifact manager test, which is a function that takes an
/// ArtifactManager object as input, which is already setup with
/// ingress pool, consensus pool and consensus client (using MockConsensus).
pub fn run_test<F: Fn(Arc<dyn ArtifactManager>)>(test: F) {
    ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
        let manager = setup_manager(pool_config);
        test(manager)
    })
}
