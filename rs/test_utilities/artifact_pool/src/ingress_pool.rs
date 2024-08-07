use ic_artifact_pool::ingress_pool::IngressPoolImpl;
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_interfaces::{
    ingress_pool::{
        ChangeSet, IngressPool, IngressPoolThrottler, PoolSection, UnvalidatedIngressArtifact,
        ValidatedIngressArtifact,
    },
    p2p::consensus::{ChangeResult, MutablePool, UnvalidatedArtifact},
};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_types::{artifact::IngressMessageId, messages::SignedIngress, NodeId};

pub struct TestIngressPool {
    pub pool: IngressPoolImpl,
}

impl TestIngressPool {
    pub fn new(node_id: NodeId, pool_config: ArtifactPoolConfig) -> TestIngressPool {
        TestIngressPool {
            pool: IngressPoolImpl::new(
                node_id,
                pool_config,
                MetricsRegistry::new(),
                no_op_logger(),
            ),
        }
    }
}

impl IngressPool for TestIngressPool {
    fn validated(&self) -> &dyn PoolSection<ValidatedIngressArtifact> {
        self.pool.validated()
    }

    fn unvalidated(&self) -> &dyn PoolSection<UnvalidatedIngressArtifact> {
        self.pool.unvalidated()
    }
}

impl IngressPoolThrottler for TestIngressPool {
    fn exceeds_threshold(&self) -> bool {
        self.pool.exceeds_threshold()
    }
}

impl MutablePool<SignedIngress> for TestIngressPool {
    type ChangeSet = ChangeSet;

    fn insert(&mut self, unvalidated_artifact: UnvalidatedArtifact<SignedIngress>) {
        self.pool.insert(unvalidated_artifact)
    }

    fn remove(&mut self, id: &IngressMessageId) {
        self.pool.remove(id)
    }

    fn apply_changes(&mut self, change_set: ChangeSet) -> ChangeResult<SignedIngress> {
        self.pool.apply_changes(change_set)
    }
}
