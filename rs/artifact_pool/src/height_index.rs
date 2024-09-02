use ic_types::{
    consensus::*,
    crypto::{CryptoHash, CryptoHashOf},
    Height,
};
use std::collections::BTreeMap;
use std::time::Instant;

pub struct HeightIndex<T: Eq> {
    buckets: BTreeMap<Height, Vec<T>>,
}

impl<T: Eq> Default for HeightIndex<T> {
    fn default() -> Self {
        Self {
            buckets: BTreeMap::new(),
        }
    }
}

/// Provides a thin wrapper around a sorted map of buckets and provides
/// height-indexed access to the buckets.
impl<T: Eq + Clone> HeightIndex<T> {
    pub fn new() -> HeightIndex<T> {
        HeightIndex::default()
    }

    /// Inserts `value` at `height`. Returns `true` if `value` was inserted,
    /// `false` if already present.
    pub fn insert(&mut self, height: Height, value: &T) -> bool {
        let values = self.buckets.entry(height).or_default();
        if !values.contains(value) {
            values.push(value.clone());
            return true;
        }
        false
    }

    pub fn remove_all(&mut self, height: Height) -> Vec<T> {
        self.buckets.remove(&height).unwrap_or_default()
    }

    pub fn remove_all_below(&mut self, height: Height) {
        self.buckets = self.buckets.split_off(&height);
    }

    /// Removes `value` from `height`. Returns `true` if `value` was removed,
    /// `false` if not present.
    pub fn remove(&mut self, height: Height, value: &T) -> bool {
        self.retain(height, |x| x != value)
    }

    /// Retains only the elements of the given height that match the predicate.
    /// Returns `true` if any value was removed, otherwise `false`.
    pub fn retain<F>(&mut self, height: Height, f: F) -> bool
    where
        F: FnMut(&T) -> bool,
    {
        if let Some(bucket) = self.buckets.get_mut(&height) {
            let len = bucket.len();
            bucket.retain(f);
            let removed = len != bucket.len();
            if bucket.is_empty() {
                self.buckets.remove(&height);
            }
            return removed;
        }
        false
    }

    pub fn lookup(&self, height: Height) -> impl Iterator<Item = &T> {
        self.buckets.get(&height).into_iter().flatten()
    }

    pub fn get_all(&self) -> Box<dyn Iterator<Item = &T> + '_> {
        Box::new(self.buckets.values().flat_map(|bucket| bucket.iter()))
    }

    pub fn size(&self) -> usize {
        self.buckets.values().map(Vec::len).sum()
    }

    /// Returns all heights of the index, in sorted order.
    pub fn heights(&self) -> Box<dyn Iterator<Item = &Height> + '_> {
        Box::new(self.buckets.keys())
    }

    pub fn range<R>(&self, range: R) -> std::collections::btree_map::Range<'_, Height, Vec<T>>
    where
        R: std::ops::RangeBounds<Height>,
    {
        self.buckets.range(range)
    }
}

pub struct Indexes {
    pub random_beacon: HeightIndex<CryptoHashOf<RandomBeacon>>,
    pub finalization: HeightIndex<CryptoHashOf<Finalization>>,
    pub notarization: HeightIndex<CryptoHashOf<Notarization>>,
    pub block_proposal: HeightIndex<CryptoHashOf<BlockProposal>>,
    pub random_beacon_share: HeightIndex<CryptoHashOf<RandomBeaconShare>>,
    pub notarization_share: HeightIndex<CryptoHashOf<NotarizationShare>>,
    pub finalization_share: HeightIndex<CryptoHashOf<FinalizationShare>>,
    pub random_tape: HeightIndex<CryptoHashOf<RandomTape>>,
    pub random_tape_share: HeightIndex<CryptoHashOf<RandomTapeShare>>,
    pub catch_up_package: HeightIndex<CryptoHashOf<CatchUpPackage>>,
    pub catch_up_package_share: HeightIndex<CryptoHashOf<CatchUpPackageShare>>,
    pub equivocation_proof: HeightIndex<CryptoHashOf<EquivocationProof>>,
}

#[allow(clippy::new_without_default)]
impl Indexes {
    pub fn new() -> Indexes {
        Indexes {
            random_beacon: HeightIndex::new(),
            finalization: HeightIndex::new(),
            notarization: HeightIndex::new(),
            block_proposal: HeightIndex::new(),
            random_beacon_share: HeightIndex::new(),
            notarization_share: HeightIndex::new(),
            finalization_share: HeightIndex::new(),
            random_tape: HeightIndex::new(),
            random_tape_share: HeightIndex::new(),
            catch_up_package: HeightIndex::new(),
            catch_up_package_share: HeightIndex::new(),
            equivocation_proof: HeightIndex::new(),
        }
    }

    pub fn insert(&mut self, msg: &ConsensusMessage, hash: &CryptoHash) {
        match msg {
            ConsensusMessage::RandomBeacon(artifact) => self
                .random_beacon
                .insert(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::Finalization(artifact) => self
                .finalization
                .insert(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::Notarization(artifact) => self
                .notarization
                .insert(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::BlockProposal(artifact) => self
                .block_proposal
                .insert(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::RandomBeaconShare(artifact) => self
                .random_beacon_share
                .insert(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::NotarizationShare(artifact) => self
                .notarization_share
                .insert(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::FinalizationShare(artifact) => self
                .finalization_share
                .insert(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::RandomTape(artifact) => self
                .random_tape
                .insert(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::RandomTapeShare(artifact) => self
                .random_tape_share
                .insert(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::CatchUpPackage(artifact) => self
                .catch_up_package
                .insert(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::CatchUpPackageShare(artifact) => self
                .catch_up_package_share
                .insert(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::EquivocationProof(artifact) => self
                .equivocation_proof
                .insert(artifact.height(), &CryptoHashOf::from(hash.clone())),
        };
    }

    pub fn remove(&mut self, msg: &ConsensusMessage, hash: &CryptoHash) {
        match msg {
            ConsensusMessage::RandomBeacon(artifact) => self
                .random_beacon
                .remove(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::Finalization(artifact) => self
                .finalization
                .remove(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::Notarization(artifact) => self
                .notarization
                .remove(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::BlockProposal(artifact) => self
                .block_proposal
                .remove(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::RandomBeaconShare(artifact) => self
                .random_beacon_share
                .remove(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::NotarizationShare(artifact) => self
                .notarization_share
                .remove(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::FinalizationShare(artifact) => self
                .finalization_share
                .remove(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::RandomTape(artifact) => self
                .random_tape
                .remove(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::RandomTapeShare(artifact) => self
                .random_tape_share
                .remove(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::CatchUpPackage(artifact) => self
                .catch_up_package
                .remove(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::CatchUpPackageShare(artifact) => self
                .catch_up_package_share
                .remove(artifact.height(), &CryptoHashOf::from(hash.clone())),
            ConsensusMessage::EquivocationProof(artifact) => self
                .equivocation_proof
                .remove(artifact.height(), &CryptoHashOf::from(hash.clone())),
        };
    }
}

pub trait SelectIndex: Eq + Sized {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self>;
}

impl SelectIndex for CryptoHashOf<RandomBeacon> {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self> {
        &indexes.random_beacon
    }
}

impl SelectIndex for CryptoHashOf<Finalization> {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self> {
        &indexes.finalization
    }
}

impl SelectIndex for CryptoHashOf<Notarization> {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self> {
        &indexes.notarization
    }
}

impl SelectIndex for CryptoHashOf<BlockProposal> {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self> {
        &indexes.block_proposal
    }
}

impl SelectIndex for CryptoHashOf<RandomBeaconShare> {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self> {
        &indexes.random_beacon_share
    }
}

impl SelectIndex for CryptoHashOf<NotarizationShare> {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self> {
        &indexes.notarization_share
    }
}

impl SelectIndex for CryptoHashOf<FinalizationShare> {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self> {
        &indexes.finalization_share
    }
}

impl SelectIndex for CryptoHashOf<RandomTape> {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self> {
        &indexes.random_tape
    }
}

impl SelectIndex for CryptoHashOf<RandomTapeShare> {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self> {
        &indexes.random_tape_share
    }
}

impl SelectIndex for CryptoHashOf<CatchUpPackage> {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self> {
        &indexes.catch_up_package
    }
}

impl SelectIndex for CryptoHashOf<CatchUpPackageShare> {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self> {
        &indexes.catch_up_package_share
    }
}

impl SelectIndex for CryptoHashOf<EquivocationProof> {
    fn select_index(indexes: &Indexes) -> &HeightIndex<Self> {
        &indexes.equivocation_proof
    }
}

/// Stores instants for any object, and indexes them by height
pub struct HeightIndexedInstants<T: Eq + Ord + Clone> {
    instants: BTreeMap<T, Instant>,
    index: HeightIndex<T>,
}

impl<T: Eq + Ord + Clone> Default for HeightIndexedInstants<T> {
    fn default() -> Self {
        Self {
            instants: Default::default(),
            index: Default::default(),
        }
    }
}

impl<T: Eq + Ord + Clone> HeightIndexedInstants<T> {
    pub fn get(&self, key: &T) -> Option<&Instant> {
        self.instants.get(key)
    }

    /// Inserts the key-value pair at the given height. If the key
    /// already exists, the value is *not* updated.
    pub fn insert(&mut self, key: &T, value: Instant, height: Height) {
        if self.index.insert(height, key) {
            self.instants.entry(key.clone()).or_insert(value);
        }
    }

    pub fn clear(&mut self, h: Height) {
        let range = self.index.range(Height::new(0)..h);
        for (_, bucket) in range {
            for hash in bucket {
                self.instants.remove(hash);
            }
        }
        self.index.remove_all_below(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gaps_are_handled() {
        let mut index = HeightIndex::new();
        let fifteen = Height::from(15);
        let one_hundred = Height::from(100);
        index.insert(fifteen, &12);
        index.insert(one_hundred, &13);

        let mut expected = vec![13];
        assert_eq!(
            &index.lookup(one_hundred).cloned().collect::<Vec<i32>>(),
            &expected
        );

        index.insert(one_hundred, &17);
        expected.push(17);

        assert_eq!(
            &index.lookup(one_hundred).cloned().collect::<Vec<i32>>(),
            &expected
        );

        let sixty_six = Height::from(66);
        index.insert(sixty_six, &44);

        assert_eq!(
            vec![fifteen, sixty_six, one_hundred],
            index.heights().cloned().collect::<Vec<_>>()
        );

        let expected_values = vec![&12, &13, &17, &44];
        let mut actual_values: Vec<_> = index.get_all().collect();
        actual_values.sort();
        assert_eq!(actual_values, expected_values);

        let twelve = Height::from(12);
        index.insert(twelve, &1);
        index.insert(twelve, &2);

        let mut expected = vec![1, 2];
        assert_eq!(
            &index.lookup(twelve).cloned().collect::<Vec<i32>>(),
            &expected
        );

        index.remove(twelve, &1);

        expected.retain(|x| x != &1);
        assert_eq!(
            &index.lookup(twelve).cloned().collect::<Vec<i32>>(),
            &expected
        );
        assert_eq!(index.buckets.len(), 4);

        index.remove(twelve, &2);
        assert_eq!(index.buckets.len(), 3);
    }

    #[test]
    // Tests that removal empties all buckets
    fn test_height_index() {
        let mut index = HeightIndex::new();

        use std::collections::HashSet;
        let mut elems = HashSet::new();

        let num_heights = 1000;
        let num_elems = 1000;
        for e in 0..num_elems {
            elems.insert(e);
        }

        let elems: Vec<_> = elems.iter().collect(); // shuffled vector

        for (i, e) in elems.iter().enumerate() {
            index.insert(Height::from((i % num_heights) as u64), e);
        }

        for (i, e) in elems.iter().enumerate() {
            index.remove(Height::from((i % num_heights) as u64), e);
        }

        assert!(index.buckets.is_empty());
    }

    #[test]
    fn test_height_index_retain() {
        let mut index = HeightIndex::new();
        let max = 100;
        let height = Height::from(0);

        for i in 0..max {
            index.insert(height, &i);
        }

        assert!(!index.retain(height, |&x| x < max));
        assert!(index.retain(height, |&x| x % 2 == 0));

        assert!(!index
            .buckets
            .get(&height)
            .unwrap()
            .iter()
            .any(|x| x % 2 != 0));
    }
}
