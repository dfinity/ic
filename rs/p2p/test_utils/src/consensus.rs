use std::collections::HashMap;
use std::convert::Infallible;
use std::{
    collections::{HashSet, VecDeque},
    sync::{Arc, Mutex},
};

use ic_interfaces::p2p::consensus::{
    ArtifactWithOpt, ChangeResult, ChangeSetProducer, MutablePool, PriorityFnAndFilterProducer,
    UnvalidatedArtifact, ValidatedPoolReader,
};
use ic_logger::ReplicaLogger;
use ic_types::{
    artifact::{Advert, ArtifactKind, ArtifactTag, Priority},
    crypto::CryptoHash,
    NodeId,
};
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct U64Artifact;

impl ArtifactKind for U64Artifact {
    // Does not matter
    const TAG: ArtifactTag = ArtifactTag::ConsensusArtifact;
    // Id==Message
    type PbMessage = u64;
    type PbIdError = Infallible;
    type PbMessageError = Infallible;
    type PbAttributeError = Infallible;
    type PbFilterError = Infallible;
    type Message = u64;
    type PbId = u64;
    type Id = u64;
    type PbAttribute = ();
    type Attribute = ();
    type PbFilter = ();
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

#[derive(Debug, Default)]
struct PeerPool {
    pool_events: Vec<PoolEvent>,
    // Pool with events applied.
    pool: HashSet<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolEvent {
    Insert(u64),
    Remove(u64),
}

impl PeerPool {
    pub fn new() -> Self {
        Self {
            pool_events: Vec::new(),
            pool: HashSet::new(),
        }
    }
    pub fn insert(&mut self, id: u64) {
        self.pool.insert(id);
        self.pool_events.push(PoolEvent::Insert(id))
    }
    pub fn remove(&mut self, id: u64) {
        self.pool.remove(&id);
        self.pool_events.push(PoolEvent::Remove(id))
    }
    pub fn num_inserts(&self, id: u64) -> usize {
        self.pool_events
            .iter()
            .filter(|e| e == &&PoolEvent::Insert(id))
            .count()
    }
    pub fn num_removes(&self, id: u64) -> usize {
        self.pool_events
            .iter()
            .filter(|e| e == &&PoolEvent::Remove(id))
            .count()
    }

    pub fn pool(&self) -> HashSet<u64> {
        self.pool.clone()
    }
}

#[derive(Clone)]
pub struct TestConsensus<Artifact: ArtifactKind> {
    _log: ReplicaLogger,
    node_id: NodeId,
    inner: Arc<Mutex<TestConsensusInner<Artifact>>>,
}

pub struct TestConsensusInner<Artifact: ArtifactKind> {
    adverts: VecDeque<Artifact::Message>,
    purge: VecDeque<Artifact::Id>,
    peer_pool: HashMap<NodeId, PeerPool>,
}

impl MutablePool<U64Artifact> for TestConsensus<U64Artifact> {
    type ChangeSet = (Vec<u64>, Vec<u64>);

    fn insert(&mut self, msg: UnvalidatedArtifact<u64>) {
        let mut inner = self.inner.lock().unwrap();
        let peer_pool = &mut inner.peer_pool;
        assert!(self.node_id != msg.peer_id);
        peer_pool
            .entry(msg.peer_id)
            .and_modify(|x| x.insert(msg.message))
            .or_insert_with(|| {
                let mut pool = PeerPool::new();
                pool.insert(msg.message);
                pool
            });
    }

    fn remove(&mut self, id: &u64) {
        let mut inner = self.inner.lock().unwrap();
        let peer_pool = &mut inner.peer_pool;
        peer_pool.values_mut().for_each(|x| x.remove(*id));
    }

    fn apply_changes(&mut self, change_set: Self::ChangeSet) -> ChangeResult<U64Artifact> {
        let mut poll_immediately = false;
        if !change_set.0.is_empty() {
            poll_immediately = true;
        }
        if !change_set.1.is_empty() {
            poll_immediately = true;
        }
        ChangeResult {
            purged: change_set.1,
            artifacts_with_opt: change_set
                .0
                .into_iter()
                .map(|m| ArtifactWithOpt {
                    advert: U64Artifact::message_to_advert(&m),
                    is_latency_sensitive: false,
                })
                .collect(),
            poll_immediately,
        }
    }
}

impl ChangeSetProducer<TestConsensus<U64Artifact>> for TestConsensus<U64Artifact> {
    type ChangeSet = <TestConsensus<U64Artifact> as MutablePool<U64Artifact>>::ChangeSet;
    fn on_state_change(&self, _pool: &TestConsensus<U64Artifact>) -> Self::ChangeSet {
        let mut inner = self.inner.lock().unwrap();
        let purged: Vec<_> = inner.purge.drain(..).collect();
        let mut advert = Vec::new();
        if purged.is_empty() {
            advert = inner.adverts.drain(..).collect();
        }
        (advert, purged)
    }
}

#[allow(dead_code)]
impl TestConsensus<U64Artifact> {
    pub fn new(log: ReplicaLogger, node_id: NodeId) -> Self {
        Self {
            _log: log,
            node_id,
            inner: Arc::new(Mutex::new(TestConsensusInner {
                adverts: VecDeque::new(),
                purge: VecDeque::new(),
                peer_pool: HashMap::from_iter(vec![(node_id, PeerPool::default())]),
            })),
        }
    }

    pub fn push_advert(&self, id: u64) {
        let mut inner = self.inner.lock().unwrap();
        let my_pool = inner.peer_pool.get_mut(&self.node_id).unwrap();
        my_pool.insert(id);

        inner.adverts.push_back(id);
    }

    pub fn push_purge(&self, id: u64) {
        let mut inner = self.inner.lock().unwrap();
        let my_pool = inner.peer_pool.get_mut(&self.node_id).unwrap();
        my_pool.remove(id);

        inner.purge.push_back(id);
    }

    pub fn received_advert_once(&self, id: u64) -> bool {
        let inner = self.inner.lock().unwrap();
        inner
            .peer_pool
            .iter()
            .filter(|(&n, _)| n != self.node_id)
            .map(|(_, x)| x.num_inserts(id))
            .sum::<usize>()
            == 1
    }

    pub fn received_advert_count(&self, id: u64) -> usize {
        let inner = self.inner.lock().unwrap();
        inner
            .peer_pool
            .iter()
            .filter(|(&n, _)| n != self.node_id)
            .map(|(_, x)| x.num_inserts(id))
            .sum()
    }

    pub fn received_remove_count(&self, id: u64) -> usize {
        let inner = self.inner.lock().unwrap();
        inner
            .peer_pool
            .iter()
            .filter(|(&n, _)| n != self.node_id)
            .map(|(_, x)| x.num_removes(id))
            .sum()
    }

    pub fn received_remove_once(&self, id: u64) -> bool {
        let inner = self.inner.lock().unwrap();
        inner
            .peer_pool
            .iter()
            .filter(|(&n, _)| n != self.node_id)
            .map(|(_, x)| x.num_removes(id))
            .sum::<usize>()
            == 1
    }

    pub fn my_pool(&self) -> HashSet<u64> {
        self.peer_pool(&self.node_id)
    }

    pub fn peer_pool(&self, peer_id: &NodeId) -> HashSet<u64> {
        let inner = self.inner.lock().unwrap();
        inner
            .peer_pool
            .get(peer_id)
            .map(|p| p.pool())
            .unwrap_or_default()
            .clone()
    }
}

impl ValidatedPoolReader<U64Artifact> for TestConsensus<U64Artifact> {
    fn contains(&self, id: &<U64Artifact as ArtifactKind>::Id) -> bool {
        self.my_pool().contains(id)
    }
    fn get_validated_by_identifier(
        &self,
        id: &<U64Artifact as ArtifactKind>::Id,
    ) -> Option<<U64Artifact as ArtifactKind>::Message> {
        self.my_pool().get(id).copied()
    }
    fn get_all_validated_by_filter(
        &self,
        _filter: &<U64Artifact as ArtifactKind>::Filter,
    ) -> Box<dyn Iterator<Item = <U64Artifact as ArtifactKind>::Message> + '_> {
        Box::new(self.my_pool().into_iter())
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
