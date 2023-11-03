use std::{
    collections::{HashSet, VecDeque},
    sync::{Arc, Mutex},
};

use ic_interfaces::{
    artifact_pool::{
        ChangeResult, ChangeSetProducer, MutablePool, PriorityFnAndFilterProducer,
        UnvalidatedArtifact, ValidatedPoolReader,
    },
    time_source::TimeSource,
};
use ic_logger::{info, ReplicaLogger};
use ic_types::{
    artifact::{Advert, ArtifactKind, ArtifactTag, Priority},
    crypto::CryptoHash,
    NodeId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct U64Artifact;

impl ArtifactKind for U64Artifact {
    // Does not matter
    const TAG: ArtifactTag = ArtifactTag::ConsensusArtifact;
    // Id==Message
    type Message = u64;
    type Id = u64;
    type Attribute = ();
    type Filter = ();

    /// The function converts a U64ArtifactMessage to an advert for a
    /// U64Artifact.
    fn message_to_advert(msg: &Self::Message) -> Advert<U64Artifact> {
        Advert {
            attribute: (),
            size: 64,
            id: *msg,
            integrity_hash: CryptoHash(vec![]),
        }
    }
}

#[derive(Clone)]
pub struct TestConsensus<Artifact: ArtifactKind> {
    log: ReplicaLogger,
    node_id: NodeId,
    adverts: Arc<Mutex<VecDeque<Artifact::Message>>>,
    purge: Arc<Mutex<VecDeque<Artifact::Id>>>,
    received_remove: Arc<Mutex<HashSet<Artifact::Id>>>,
    received_unvalidated: Arc<Mutex<HashSet<Artifact::Id>>>,
    pool: Arc<Mutex<HashSet<Artifact::Id>>>,
}

impl MutablePool<U64Artifact> for TestConsensus<U64Artifact> {
    type ChangeSet = (Vec<u64>, Vec<u64>);

    fn insert(&mut self, msg: UnvalidatedArtifact<u64>) {
        self.received_unvalidated
            .lock()
            .unwrap()
            .insert(msg.message);
        self.pool.lock().unwrap().insert(msg.message);
    }

    fn remove(&mut self, id: &u64) {
        self.received_remove.lock().unwrap().insert(*id);
        self.pool.lock().unwrap().remove(id);
    }

    fn apply_changes(
        &mut self,
        _time_source: &dyn TimeSource,
        change_set: Self::ChangeSet,
    ) -> ChangeResult<U64Artifact> {
        let mut pool = self.pool.lock().unwrap();
        let mut poll_immediately = false;
        for add in &change_set.0 {
            pool.insert(*add);
            poll_immediately = true;
        }
        for remove in &change_set.1 {
            pool.remove(remove);
            poll_immediately = true;
        }
        ChangeResult {
            purged: change_set.1,
            adverts: change_set
                .0
                .into_iter()
                .map(|m| U64Artifact::message_to_advert(&m))
                .collect(),
            poll_immediately,
        }
    }
}

impl ChangeSetProducer<TestConsensus<U64Artifact>> for TestConsensus<U64Artifact> {
    type ChangeSet = <TestConsensus<U64Artifact> as MutablePool<U64Artifact>>::ChangeSet;
    fn on_state_change(&self, _pool: &TestConsensus<U64Artifact>) -> Self::ChangeSet {
        let advert: Vec<_> = self.adverts.lock().unwrap().drain(..).collect();
        let purged: Vec<_> = self.purge.lock().unwrap().drain(..).collect();
        (advert, purged)
    }
}

#[allow(dead_code)]
impl TestConsensus<U64Artifact> {
    pub fn new(log: ReplicaLogger, node_id: NodeId) -> Self {
        Self {
            log,
            node_id,
            adverts: Arc::new(Mutex::new(VecDeque::new())),
            purge: Arc::new(Mutex::new(VecDeque::new())),
            received_remove: Arc::new(Mutex::new(HashSet::new())),
            received_unvalidated: Arc::new(Mutex::new(HashSet::new())),
            pool: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn push_advert(&self, artifact: u64) {
        self.pool.lock().unwrap().insert(artifact);
        self.adverts.lock().unwrap().push_back(artifact);
    }

    pub fn push_purge(&self, id: u64) {
        self.pool.lock().unwrap().remove(&id);
        self.purge.lock().unwrap().push_back(id);
    }

    pub fn received_advert(&self, id: u64) -> bool {
        self.received_unvalidated
            .lock()
            .unwrap()
            .iter()
            .any(|&x| x == id)
    }

    pub fn received_remove(&self, id: u64) -> bool {
        self.received_remove
            .lock()
            .unwrap()
            .iter()
            .any(|&x| x == id)
    }

    pub fn pool(&self) -> HashSet<u64> {
        self.pool.lock().unwrap().clone()
    }
}

impl ValidatedPoolReader<U64Artifact> for TestConsensus<U64Artifact> {
    fn contains(&self, id: &<U64Artifact as ArtifactKind>::Id) -> bool {
        self.pool().contains(id)
    }
    fn get_validated_by_identifier(
        &self,
        id: &<U64Artifact as ArtifactKind>::Id,
    ) -> Option<<U64Artifact as ArtifactKind>::Message> {
        info!(
            self.log,
            "{}: Get validated by id {} {:?}",
            self.node_id,
            id,
            self.pool().get(id).copied()
        );
        self.pool().get(id).copied()
    }
    fn get_all_validated_by_filter(
        &self,
        _filter: &<U64Artifact as ArtifactKind>::Filter,
    ) -> Box<dyn Iterator<Item = <U64Artifact as ArtifactKind>::Message> + '_> {
        Box::new(self.pool().into_iter())
    }
}

impl PriorityFnAndFilterProducer<U64Artifact, TestConsensus<U64Artifact>>
    for TestConsensus<U64Artifact>
{
    fn get_priority_function(
        &self,
        _pool: &TestConsensus<U64Artifact>,
    ) -> ic_types::artifact::PriorityFn<
        <U64Artifact as ArtifactKind>::Id,
        <U64Artifact as ArtifactKind>::Attribute,
    > {
        Box::new(|_, _| Priority::Fetch)
    }
    fn get_filter(&self) -> <U64Artifact as ArtifactKind>::Filter {
        todo!()
    }
}
