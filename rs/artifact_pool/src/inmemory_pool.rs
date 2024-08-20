use crate::{
    consensus_pool::{MutablePoolSection, PoolSectionOp, PoolSectionOps},
    height_index::{HeightIndex, Indexes, SelectIndex},
    HasTimestamp, IntoInner,
};
use ic_interfaces::consensus_pool::{
    HeightIndexedPool, HeightRange, OnlyError, PoolSection, PurgeableArtifactType,
};
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
}

impl<T: IntoInner<ConsensusMessage> + HasTimestamp + Clone> InMemoryPoolSection<T> {
    pub fn new() -> InMemoryPoolSection<T> {
        InMemoryPoolSection {
            artifacts: BTreeMap::new(),
            indexes: Indexes::new(),
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

    /// Purge artifacts below the given [`Height`].
    ///
    /// If `artifact_type` is provided, we will purge only artifacts of the given type. Otherwise we
    /// will purge *all* artifacts.
    ///
    /// Return [`ConsensusMessageId`]s of deleted artifacts.
    fn purge_below(
        &mut self,
        height: Height,
        artifact_type: Option<PurgeableArtifactType>,
    ) -> Vec<ConsensusMessageId> {
        let mut purged = Vec::new();

        macro_rules! purge {
            ($artifact_name:ident, $artifact_type:ident) => {
                if let Some(range) = self.$artifact_name().height_range() {
                    for h in range.min.get()..height.get() {
                        let height = Height::from(h);
                        for hash in self.indexes.$artifact_name.remove_all(height) {
                            self.artifacts.remove(hash.get_ref());
                            purged.push(ConsensusMessageId {
                                hash: ConsensusMessageHash::$artifact_type(hash),
                                height,
                            });
                        }
                    }
                };
            };
        }

        if let Some(artifact_type) = artifact_type {
            match artifact_type {
                PurgeableArtifactType::NotarizationShare => {
                    purge!(notarization_share, NotarizationShare);
                }
                PurgeableArtifactType::FinalizationShare => {
                    purge!(finalization_share, FinalizationShare);
                }
                PurgeableArtifactType::EquivocationProof => {
                    purge!(equivocation_proof, EquivocationProof);
                }
            }
        } else {
            purge!(random_beacon, RandomBeacon);
            purge!(random_beacon_share, RandomBeaconShare);
            purge!(finalization, Finalization);
            purge!(finalization_share, FinalizationShare);
            purge!(notarization, Notarization);
            purge!(notarization_share, NotarizationShare);
            purge!(block_proposal, BlockProposal);
            purge!(random_tape, RandomTape);
            purge!(random_tape_share, RandomTapeShare);
            purge!(catch_up_package, CatchUpPackage);
            purge!(catch_up_package_share, CatchUpPackageShare);
            purge!(equivocation_proof, EquivocationProof);
        }

        purged
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

    fn size(&self) -> usize {
        self.select_index::<CryptoHashOf<T>>().size()
    }
}

impl<T: IntoInner<ConsensusMessage> + HasTimestamp + Clone> PoolSection<T>
    for InMemoryPoolSection<T>
{
    fn contains(&self, msg_id: &ConsensusMessageId) -> bool {
        self.artifacts.contains_key(msg_id.hash.digest())
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
    fn equivocation_proof(&self) -> &dyn HeightIndexedPool<EquivocationProof> {
        self
    }
}

impl<T: IntoInner<ConsensusMessage> + HasTimestamp + Clone> MutablePoolSection<T>
    for InMemoryPoolSection<T>
{
    fn mutate(&mut self, ops: PoolSectionOps<T>) -> Vec<ConsensusMessageId> {
        let mut purged = Vec::new();
        for op in ops.ops {
            match op {
                PoolSectionOp::Insert(artifact) => self.insert(artifact),
                PoolSectionOp::Remove(msg_id) => {
                    if self.remove(&msg_id).is_some() {
                        purged.push(msg_id)
                    }
                }
                PoolSectionOp::PurgeBelow(height) => {
                    purged.append(&mut self.purge_below(height, None))
                }
                PoolSectionOp::PurgeTypeBelow(artifact_type, height) => {
                    purged.append(&mut self.purge_below(height, Some(artifact_type)))
                }
            }
        }
        purged
    }

    fn pool_section(&self) -> &dyn PoolSection<T> {
        self
    }
}

#[cfg(test)]
pub mod test {
    use std::collections::HashSet;

    use super::*;
    use ic_interfaces::consensus_pool::ValidatedArtifact;
    use ic_test_utilities_consensus::{fake::*, make_genesis};

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
        assert!(ic_test_utilities_time::with_timeout(
            std::time::Duration::new(12, 0),
            || {
                let mut pool = InMemoryPoolSection::new();
                let min = Height::from(1);
                let max = Height::from(u64::MAX);
                pool.insert(make_artifact(fake_random_beacon(min)));
                pool.insert(make_artifact(fake_random_beacon(max)));

                let result = pool
                    .random_beacon()
                    .get_by_height_range(pool.random_beacon().height_range().unwrap());
                assert_eq!(result.count(), 2);
            }
        ));
    }

    #[test]
    fn test_purging() {
        assert!(ic_test_utilities_time::with_timeout(
            std::time::Duration::new(12, 0),
            || {
                let beacons = (1..=10)
                    .map(|i| fake_random_beacon(Height::from(i)))
                    .collect::<Vec<_>>();
                let ids = beacons.iter().map(|b| b.get_id()).collect::<HashSet<_>>();

                let mut pool = InMemoryPoolSection::new();
                beacons
                    .into_iter()
                    .for_each(|b| pool.insert(make_artifact(b)));

                assert_eq!(pool.random_beacon().get_all().count(), ids.len());
                let h30 = Height::from(30);
                pool.insert(make_artifact(fake_random_beacon(Height::from(30))));

                let mut ops = PoolSectionOps::new();
                ops.purge_type_below(PurgeableArtifactType::NotarizationShare, Height::from(20));
                ops.purge_type_below(PurgeableArtifactType::FinalizationShare, Height::from(20));
                let result = pool.mutate(ops);
                assert!(result.is_empty());

                let mut ops = PoolSectionOps::new();
                ops.purge_below(Height::from(20));
                let result = pool.mutate(ops);
                assert_eq!(ids.len(), result.len());
                assert_eq!(ids, HashSet::from_iter(result));

                let range = pool.random_beacon().height_range().unwrap();
                assert_eq!(range.min, h30);
                assert_eq!(range.max, h30);
            }
        ));
    }
}
