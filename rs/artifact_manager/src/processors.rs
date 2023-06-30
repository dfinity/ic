//! The module contains implementations of the 'ArtifactProcessor' trait for all
//! P2P clients that require consensus over their artifacts.

use ic_interfaces::{
    artifact_manager::ArtifactProcessor,
    artifact_pool::{ChangeSetProducer, MutablePool, UnvalidatedArtifact},
    time_source::TimeSource,
};
use ic_types::{artifact::*, artifact_kind::*, messages::SignedIngress};
use std::sync::{Arc, RwLock};

pub struct Processor<P, C> {
    pool: Arc<RwLock<P>>,
    change_set_producer: Box<dyn ChangeSetProducer<P, ChangeSet = C>>,
}

impl<P, C> Processor<P, C> {
    pub fn new(
        pool: Arc<RwLock<P>>,
        change_set_producer: Box<dyn ChangeSetProducer<P, ChangeSet = C>>,
    ) -> Self {
        Self {
            pool,
            change_set_producer,
        }
    }
}

impl<A: ArtifactKind, C, P: MutablePool<A, C> + Send + Sync + 'static> ArtifactProcessor<A>
    for Processor<P, C>
{
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<A::Message>>,
    ) -> (Vec<Advert<A>>, bool) {
        {
            let mut pool = self.pool.write().unwrap();
            for artifact in artifacts {
                pool.insert(artifact)
            }
        }
        let change_set = {
            let pool = self.pool.read().unwrap();
            self.change_set_producer.on_state_change(&*pool)
        };
        let result = self
            .pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);

        (result.adverts, result.changed)
    }
}

/// The ingress `OnStateChange` client.
pub struct IngressProcessor<P, C> {
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    ingress_pool: Arc<RwLock<P>>,
    /// The ingress handler.
    client: Arc<dyn ChangeSetProducer<P, ChangeSet = C> + Send + Sync>,
}

impl<P, C> IngressProcessor<P, C> {
    pub fn new(
        ingress_pool: Arc<RwLock<P>>,
        client: Arc<dyn ChangeSetProducer<P, ChangeSet = C> + Send + Sync>,
    ) -> Self {
        Self {
            ingress_pool,
            client,
        }
    }
}

impl<C, P: MutablePool<IngressArtifact, C> + Send + Sync + 'static>
    ArtifactProcessor<IngressArtifact> for IngressProcessor<P, C>
{
    /// The method processes changes in the ingress pool.
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<SignedIngress>>,
    ) -> (Vec<Advert<IngressArtifact>>, bool) {
        {
            let mut ingress_pool = self.ingress_pool.write().unwrap();
            for artifact in artifacts {
                ingress_pool.insert(artifact)
            }
        }
        let change_set = {
            let pool = self.ingress_pool.read().unwrap();
            self.client.on_state_change(&*pool)
        };
        let result = self
            .ingress_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);
        // We ignore the ingress pool's "changed" result and return StateUnchanged,
        // in order to not trigger an immediate re-processing.
        (result.adverts, false)
    }
}
