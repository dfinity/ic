use std::collections::HashMap;
use std::convert::Infallible;
use std::{
    collections::{HashSet, VecDeque},
    sync::{Arc, Mutex},
};

use ic_interfaces::p2p::consensus::{
    ArtifactMutation, ArtifactWithOpt, BouncerFactory, BouncerValue, ChangeResult,
    ChangeSetProducer, MutablePool, UnvalidatedArtifact, ValidatedPoolReader,
};
use ic_logger::ReplicaLogger;
use ic_types::artifact::{IdentifiableArtifact, PbArtifact};
use ic_types::NodeId;
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct U64Artifact(Vec<u8>);

impl IdentifiableArtifact for U64Artifact {
    const NAME: &'static str = "artifact";
    type Id = u64;
    fn id(&self) -> Self::Id {
        u64::from_le_bytes(self.0[..8].try_into().unwrap())
    }
}

impl From<U64Artifact> for Vec<u8> {
    fn from(value: U64Artifact) -> Self {
        value.0
    }
}
impl From<Vec<u8>> for U64Artifact {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl PbArtifact for U64Artifact {
    type PbMessage = Vec<u8>;
    type PbIdError = Infallible;
    type PbMessageError = Infallible;
    type PbId = u64;
}

impl U64Artifact {
    pub fn id_to_msg(id: u64, msg_size: usize) -> Self {
        let mut msg = id.to_le_bytes().to_vec();
        msg.resize(msg_size, 0);
        Self(msg)
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
pub struct TestConsensus<Artifact: IdentifiableArtifact> {
    _log: ReplicaLogger,
    node_id: NodeId,
    inner: Arc<Mutex<TestConsensusInner<Artifact>>>,
    msg_size: usize,
    latency_sensitive: bool,
}

pub struct TestConsensusInner<Artifact: IdentifiableArtifact> {
    adverts: VecDeque<Artifact::Id>,
    purge: VecDeque<Artifact::Id>,
    peer_pool: HashMap<NodeId, PeerPool>,
}

impl MutablePool<U64Artifact> for TestConsensus<U64Artifact> {
    type ChangeSet = (Vec<u64>, Vec<u64>);

    fn insert(&mut self, msg: UnvalidatedArtifact<U64Artifact>) {
        let mut inner = self.inner.lock().unwrap();
        let peer_pool = &mut inner.peer_pool;
        assert!(self.node_id != msg.peer_id);
        peer_pool
            .entry(msg.peer_id)
            .and_modify(|x| x.insert(msg.message.id()))
            .or_insert_with(|| {
                let mut pool = PeerPool::new();
                pool.insert(msg.message.id());
                pool
            });
    }

    fn remove(&mut self, id: &u64) {
        let mut inner = self.inner.lock().unwrap();
        let peer_pool = &mut inner.peer_pool;
        peer_pool.values_mut().for_each(|x| x.remove(*id));
    }

    fn apply_changes(&mut self, mut change_set: Self::ChangeSet) -> ChangeResult<U64Artifact> {
        let mut poll_immediately = false;
        if !change_set.0.is_empty() {
            poll_immediately = true;
        }
        if !change_set.1.is_empty() {
            poll_immediately = true;
        }
        let mut mutations = vec![];
        mutations.extend(change_set.0.drain(..).map(|m| {
            ArtifactMutation::Insert(ArtifactWithOpt {
                artifact: self.id_to_msg(m).into(),
                is_latency_sensitive: self.latency_sensitive,
            })
        }));

        mutations.extend(change_set.1.drain(..).map(ArtifactMutation::Remove));
        ChangeResult {
            mutations,
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
    pub fn new(
        log: ReplicaLogger,
        node_id: NodeId,
        msg_size: usize,
        latency_sensitive: bool,
    ) -> Self {
        Self {
            _log: log,
            node_id,
            inner: Arc::new(Mutex::new(TestConsensusInner {
                adverts: VecDeque::new(),
                purge: VecDeque::new(),
                peer_pool: HashMap::from_iter(vec![(node_id, PeerPool::default())]),
            })),
            msg_size,
            latency_sensitive,
        }
    }

    pub fn id_to_msg(&self, id: u64) -> Vec<u8> {
        U64Artifact::id_to_msg(id, self.msg_size).into()
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
    fn get(&self, id: &<U64Artifact as IdentifiableArtifact>::Id) -> Option<U64Artifact> {
        self.my_pool().get(id).map(|id| self.id_to_msg(*id).into())
    }
    fn get_all_validated(&self) -> Box<dyn Iterator<Item = U64Artifact> + '_> {
        Box::new(
            self.my_pool()
                .into_iter()
                .map(|id| self.id_to_msg(id).into()),
        )
    }
}

impl BouncerFactory<u64, TestConsensus<U64Artifact>> for TestConsensus<U64Artifact> {
    fn new_bouncer(
        &self,
        _pool: &TestConsensus<U64Artifact>,
    ) -> ic_interfaces::p2p::consensus::Bouncer<u64> {
        Box::new(|_| BouncerValue::Wants)
    }

    fn refresh_period(&self) -> Duration {
        Duration::from_secs(3)
    }
}
