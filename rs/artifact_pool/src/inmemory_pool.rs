use crate::{
    consensus_pool::{MutablePoolSection, PoolSectionOp, PoolSectionOps},
    height_index::{HeightIndex, Indexes, SelectIndex},
};
use ic_interfaces::{
    artifact_pool::{HasTimestamp, IntoInner},
    consensus_pool::{HeightIndexedPool, HeightRange, OnlyError, PoolSection},
};
use ic_logger::{warn, ReplicaLogger};
use ic_types::{
    artifact::ConsensusMessageId,
    consensus::*,
    crypto::{CryptoHash, CryptoHashOf},
    Height, Time,
};
use std::collections::BTreeMap;

pub struct InMemoryPoolSection<T: IntoInner<ConsensusMessage>> {
    indexes: Indexes,
    artifacts: BTreeMap<CryptoHash, T>,
    log: ReplicaLogger,
}

impl<T: IntoInner<ConsensusMessage> + HasTimestamp + Clone> InMemoryPoolSection<T> {
    pub fn new(log: ReplicaLogger) -> InMemoryPoolSection<T> {
        InMemoryPoolSection {
            artifacts: BTreeMap::new(),
            indexes: Indexes::new(),
            log,
        }
    }

    fn insert(&mut self, artifact: T) {
        let msg = artifact.as_ref();
        let hash = msg.get_cm_hash().digest().clone();
        self.indexes.insert(msg, &hash);
        self.artifacts.entry(hash).or_insert(artifact);
    }

    fn remove(&mut self, msg_id: &ConsensusMessageId) -> Option<T> {
        self.remove_by_hash(msg_id.hash.digest())
    }

    fn purge_below(&mut self, height: Height, only_shares: bool) {
        macro_rules! purge {
            ($artifact_name:ident) => {
                if let Some(range) = self.$artifact_name().height_range() {
                    for h in range.min.get()..height.get() {
                        let height = Height::from(h);
                        for hash in self.indexes.$artifact_name.remove_all(height) {
                            self.artifacts.remove(hash.get_ref());
                        }
                    }
                };
            };
        }

        purge!(finalization_share);
        purge!(notarization_share);

        if !only_shares {
            purge!(random_beacon);
            purge!(random_beacon_share);
            purge!(finalization);
            purge!(notarization);
            purge!(block_proposal);
            purge!(random_tape);
            purge!(random_tape_share);
            purge!(catch_up_package);
            purge!(catch_up_package_share);
        }
    }

    fn get_by_hashes<S: ConsensusMessageHashable>(&self, hashes: Vec<&CryptoHashOf<S>>) -> Vec<S> {
        hashes
            .iter()
            .map(|hash| {
                let artifact_opt = self.get_by_hash(hash.get_ref());
                match artifact_opt {
                    Some(artifact) => match S::assert(artifact.as_ref()) {
                        Some(value) => value.clone(),
                        _ => panic!("Unexpected message type"),
                    },
                    _ => panic!("Can't find artifact with hash: {:?}", hash.get_ref()),
                }
            })
            .collect()
    }

    /// Get a consensus message by its hash
    pub fn get_by_hash(&self, hash: &CryptoHash) -> Option<T> {
        self.artifacts.get(hash).cloned()
    }

    /// Get a consensus message by its hash
    pub fn remove_by_hash(&mut self, hash: &CryptoHash) -> Option<T> {
        self.artifacts.remove(hash).map(|artifact| {
            self.indexes.remove(artifact.as_ref(), hash);
            artifact
        })
    }

    fn select_index<S: SelectIndex>(&self) -> &HeightIndex<S> {
        SelectIndex::select_index(&self.indexes)
    }
}

impl<
        T: ConsensusMessageHashable + 'static,
        S: IntoInner<ConsensusMessage> + HasTimestamp + Clone,
    > HeightIndexedPool<T> for InMemoryPoolSection<S>
where
    CryptoHashOf<T>: SelectIndex,
{
    fn get_all(&self) -> Box<dyn Iterator<Item = T>> {
        Box::new(
            self.get_by_hashes(self.select_index().get_all().collect())
                .into_iter(),
        )
    }

    fn get_by_height(&self, h: Height) -> Box<dyn Iterator<Item = T>> {
        let hashes = self.select_index().lookup(h).collect();

        Box::new(self.get_by_hashes(hashes).into_iter())
    }

    fn height_range(&self) -> Option<HeightRange> {
        let heights = CryptoHashOf::<T>::select_index(&self.indexes)
            .heights()
            .cloned()
            .collect::<Vec<_>>();
        match (heights.first(), heights.last()) {
            (Some(min), Some(max)) => Some(HeightRange::new(*min, *max)),
            _ => None,
        }
    }

    fn max_height(&self) -> Option<Height> {
        self.height_range().map(|range| range.max)
    }

    fn get_by_height_range(&self, range: HeightRange) -> Box<dyn Iterator<Item = T>> {
        if range.min > range.max {
            return Box::new(std::iter::empty());
        }
        let heights = CryptoHashOf::<T>::select_index(&self.indexes)
            .range((
                std::ops::Bound::Included(range.min),
                std::ops::Bound::Included(range.max),
            ))
            .map(|(h, _)| h);

        // returning the iterator directly isn't trusted due to the use of `self` in the
        // closure
        #[allow(clippy::needless_collect)]
        let vec: Vec<T> = heights.flat_map(|h| self.get_by_height(*h)).collect();
        Box::new(vec.into_iter())
    }

    fn get_only_by_height(&self, h: Height) -> Result<T, OnlyError> {
        let mut to_vec: Vec<T> = self.get_by_height(h).collect();
        match to_vec.len() {
            0 => Err(OnlyError::NoneAvailable),
            1 => Ok(to_vec.remove(0)),
            _ => Err(OnlyError::MultipleValues),
        }
    }

    fn get_highest(&self) -> Result<T, OnlyError> {
        if let Some(range) = self.height_range() {
            self.get_only_by_height(range.max)
        } else {
            Err(OnlyError::NoneAvailable)
        }
    }

    fn get_highest_iter(&self) -> Box<dyn Iterator<Item = T>> {
        if let Some(range) = self.height_range() {
            self.get_by_height(range.max)
        } else {
            Box::new(std::iter::empty())
        }
    }
}

impl<T: IntoInner<ConsensusMessage> + HasTimestamp + Clone> PoolSection<T>
    for InMemoryPoolSection<T>
{
    fn contains(&self, msg_id: &ConsensusMessageId) -> bool {
        self.artifacts.get(msg_id.hash.digest()).is_some()
    }

    fn get(&self, msg_id: &ConsensusMessageId) -> Option<ConsensusMessage> {
        self.get_by_hash(msg_id.hash.digest())
            .map(|x| x.into_inner())
    }

    fn get_timestamp(&self, msg_id: &ConsensusMessageId) -> Option<Time> {
        self.get_by_hash(msg_id.hash.digest())
            .map(|x| x.timestamp())
    }

    fn size(&self) -> u64 {
        self.artifacts.len() as u64
    }

    fn random_beacon(&self) -> &dyn HeightIndexedPool<RandomBeacon> {
        self
    }
    fn block_proposal(&self) -> &dyn HeightIndexedPool<BlockProposal> {
        self
    }
    fn notarization(&self) -> &dyn HeightIndexedPool<Notarization> {
        self
    }
    fn finalization(&self) -> &dyn HeightIndexedPool<Finalization> {
        self
    }
    fn random_beacon_share(&self) -> &dyn HeightIndexedPool<RandomBeaconShare> {
        self
    }
    fn notarization_share(&self) -> &dyn HeightIndexedPool<NotarizationShare> {
        self
    }
    fn finalization_share(&self) -> &dyn HeightIndexedPool<FinalizationShare> {
        self
    }
    fn random_tape(&self) -> &dyn HeightIndexedPool<RandomTape> {
        self
    }
    fn random_tape_share(&self) -> &dyn HeightIndexedPool<RandomTapeShare> {
        self
    }
    fn catch_up_package(&self) -> &dyn HeightIndexedPool<CatchUpPackage> {
        self
    }
    fn catch_up_package_share(&self) -> &dyn HeightIndexedPool<CatchUpPackageShare> {
        self
    }
}

impl<T: IntoInner<ConsensusMessage> + HasTimestamp + Clone> MutablePoolSection<T>
    for InMemoryPoolSection<T>
{
    fn mutate(&mut self, ops: PoolSectionOps<T>) {
        for op in ops.ops {
            match op {
                PoolSectionOp::Insert(artifact) => self.insert(artifact),
                PoolSectionOp::Remove(msg_id) => {
                    if self.remove(&msg_id).is_none() {
                        warn!(self.log, "Error removing artifact {:?}", &msg_id)
                    }
                }
                PoolSectionOp::PurgeBelow(height) => {
                    self.purge_below(height, /*only_shares=*/ false)
                }
                PoolSectionOp::PurgeSharesBelow(height) => {
                    self.purge_below(height, /*only_shares=*/ true)
                }
            }
        }
    }

    fn pool_section(&self) -> &dyn PoolSection<T> {
        self
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use ic_interfaces::artifact_pool::ValidatedArtifact;
    use ic_test_utilities::consensus::{fake::*, make_genesis};

    fn make_summary(genesis_height: Height) -> ic_types::consensus::dkg::Summary {
        let mut summary = ic_types::consensus::dkg::Summary::fake();
        summary.height = genesis_height;
        summary
    }

    fn fake_random_beacon(h: Height) -> RandomBeacon {
        let parent = make_genesis(make_summary(h.decrement()))
            .content
            .random_beacon;
        RandomBeacon::from_parent(parent.as_ref())
    }

    fn make_artifact(beacon: RandomBeacon) -> ValidatedArtifact<ConsensusMessage> {
        ValidatedArtifact {
            msg: ConsensusMessage::RandomBeacon(beacon),
            timestamp: ic_types::time::UNIX_EPOCH,
        }
    }

    #[test]
    fn test_iterate_with_large_range() {
        assert!(ic_test_utilities::with_timeout(
            std::time::Duration::new(12, 0),
            || {
                let mut pool = InMemoryPoolSection::new(ic_logger::replica_logger::no_op_logger());
                let min = Height::from(1);
                let max = Height::from(std::u64::MAX);
                pool.insert(make_artifact(fake_random_beacon(min)));
                pool.insert(make_artifact(fake_random_beacon(max)));

                let result = pool
                    .random_beacon()
                    .get_by_height_range(pool.random_beacon().height_range().unwrap());
                assert_eq!(result.count(), 2);
            }
        ));
    }
}
