use ic_artifact_pool::ingress_pool::IngressPoolImpl;
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_interfaces::{
    artifact_pool::UnvalidatedArtifact,
    ingress_pool::{
        ChangeSet, IngressPool, IngressPoolObject, IngressPoolSelect, IngressPoolThrottler,
        MutableIngressPool, PoolSection, SelectResult, UnvalidatedIngressArtifact,
        ValidatedIngressArtifact,
    },
};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_types::{messages::SignedIngress, Time};

pub struct TestIngressPool {
    pub pool: IngressPoolImpl,
}

impl TestIngressPool {
    pub fn new(pool_config: ArtifactPoolConfig) -> TestIngressPool {
        TestIngressPool {
            pool: IngressPoolImpl::new(pool_config, MetricsRegistry::new(), no_op_logger()),
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

impl MutableIngressPool for TestIngressPool {
    fn insert(&mut self, unvalidated_artifact: UnvalidatedArtifact<SignedIngress>) {
        self.pool.insert(unvalidated_artifact)
    }

    fn apply_changeset(&mut self, change_set: ChangeSet) {
        self.pool.apply_changeset(change_set)
    }
}

impl IngressPoolSelect for TestIngressPool {
    fn select_validated<'a>(
        &self,
        range: std::ops::RangeInclusive<Time>,
        f: Box<dyn FnMut(&IngressPoolObject) -> SelectResult<SignedIngress> + 'a>,
    ) -> Vec<SignedIngress> {
        self.pool.select_validated(range, f)
    }
}
