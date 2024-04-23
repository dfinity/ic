//! The module contains implementations of the 'ArtifactProcessor' trait for all
//! P2P clients that require consensus over their artifacts.

use crate::ArtifactProcessor;
use ic_interfaces::{
    p2p::consensus::{ChangeResult, ChangeSetProducer, MutablePool, UnvalidatedArtifact},
    time_source::TimeSource,
};
use ic_types::{artifact::*, artifact_kind::*};
use std::sync::{Arc, RwLock};

pub struct Processor<
    A: ArtifactKind + Send,
    P: MutablePool<A>,
    C: ChangeSetProducer<P, ChangeSet = <P as MutablePool<A>>::ChangeSet>,
> {
    pool: Arc<RwLock<P>>,
    change_set_producer: C,
    unused: std::marker::PhantomData<A>,
}

impl<
        A: ArtifactKind + Send,
        P: MutablePool<A>,
        C: ChangeSetProducer<P, ChangeSet = <P as MutablePool<A>>::ChangeSet>,
    > Processor<A, P, C>
{
    pub fn new(pool: Arc<RwLock<P>>, change_set_producer: C) -> Self {
        Self {
            pool,
            change_set_producer,
            unused: std::marker::PhantomData,
        }
    }
}

impl<
        A: ArtifactKind + Send,
        P: MutablePool<A> + Send + Sync + 'static,
        C: ChangeSetProducer<P, ChangeSet = <P as MutablePool<A>>::ChangeSet>,
    > ArtifactProcessor<A> for Processor<A, P, C>
{
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifact_events: Vec<UnvalidatedArtifactMutation<A>>,
    ) -> ChangeResult<A> {
        {
            let mut pool = self.pool.write().unwrap();
            for artifact_event in artifact_events {
                match artifact_event {
                    UnvalidatedArtifactMutation::Insert((message, peer_id)) => {
                        let unvalidated_artifact = UnvalidatedArtifact {
                            message,
                            peer_id,
                            timestamp: time_source.get_relative_time(),
                        };
                        pool.insert(unvalidated_artifact);
                    }
                    UnvalidatedArtifactMutation::Remove(id) => pool.remove(&id),
                }
            }
        }
        let change_set = self
            .change_set_producer
            .on_state_change(&self.pool.read().unwrap());
        self.pool.write().unwrap().apply_changes(change_set)
    }
}

/// The ingress `OnStateChange` client.
pub(crate) struct IngressProcessor<P: MutablePool<IngressArtifact>> {
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    ingress_pool: Arc<RwLock<P>>,
    /// The ingress handler.
    client: Arc<
        dyn ChangeSetProducer<P, ChangeSet = <P as MutablePool<IngressArtifact>>::ChangeSet>
            + Send
            + Sync,
    >,
}

impl<P: MutablePool<IngressArtifact>> IngressProcessor<P> {
    pub fn new(
        ingress_pool: Arc<RwLock<P>>,
        client: Arc<
            dyn ChangeSetProducer<P, ChangeSet = <P as MutablePool<IngressArtifact>>::ChangeSet>
                + Send
                + Sync,
        >,
    ) -> Self {
        Self {
            ingress_pool,
            client,
        }
    }
}

impl<P: MutablePool<IngressArtifact> + Send + Sync + 'static> ArtifactProcessor<IngressArtifact>
    for IngressProcessor<P>
{
    /// The method processes changes in the ingress pool.
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifact_events: Vec<UnvalidatedArtifactMutation<IngressArtifact>>,
    ) -> ChangeResult<IngressArtifact> {
        {
            let mut ingress_pool = self.ingress_pool.write().unwrap();
            for artifact_event in artifact_events {
                match artifact_event {
                    UnvalidatedArtifactMutation::Insert((message, peer_id)) => {
                        let unvalidated_artifact = UnvalidatedArtifact {
                            message,
                            peer_id,
                            timestamp: time_source.get_relative_time(),
                        };
                        ingress_pool.insert(unvalidated_artifact);
                    }
                    UnvalidatedArtifactMutation::Remove(id) => ingress_pool.remove(&id),
                }
            }
        }
        let change_set = self
            .client
            .on_state_change(&self.ingress_pool.read().unwrap());
        self.ingress_pool.write().unwrap().apply_changes(change_set)
    }
}
