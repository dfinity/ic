use ic_base_types::PrincipalId;
use ic_principal::Principal;
use ic_stable_structures::{Memory, StableBTreeMap, Storable};
use num_traits::bounds::LowerBounded;
use std::{
    clone::Clone,
    cmp::Ord,
    collections::{btree_map::Entry, BTreeMap, HashSet},
    hash::Hash,
};

/// An index to make it easy to look up neuron ids by principal id.
pub trait NeuronPrincipalIndex<NeuronId> {
    /// Adds a neuron-principal pair to the index and returns whether the change was actually made: the pair was newly
    /// inserted.
    #[must_use]
    fn add_neuron_id_principal_id(
        &mut self,
        neuron_id: &NeuronId,
        principal_id: PrincipalId,
    ) -> bool;

    /// Removes a neuron-principal pair to the index and returns whether the change was actually made: the pair was
    /// newly removed.
    #[must_use]
    fn remove_neuron_id_principal_id(
        &mut self,
        neuron_id: &NeuronId,
        principal_id: PrincipalId,
    ) -> bool;

    /// Returns a list of neuron ids by principal id.
    fn get_neuron_ids(&self, principal: PrincipalId) -> HashSet<NeuronId>;
}

/// Adds a neuron id and a list of principal ids and returns a list of principal ids that were already present.
#[must_use]
pub fn add_neuron_id_principal_ids<NeuronId>(
    index: &mut dyn NeuronPrincipalIndex<NeuronId>,
    neuron_id: &NeuronId,
    principal_ids: Vec<PrincipalId>,
) -> Vec<PrincipalId> {
    principal_ids
        .into_iter()
        .filter(|principal_id| {
            let newly_added = index.add_neuron_id_principal_id(neuron_id, *principal_id);
            !newly_added
        })
        .collect()
}

/// Removes a neuron id and a list of principal ids and returns a list of principal ids that were already absent.
#[must_use]
pub fn remove_neuron_id_principal_ids<NeuronId>(
    index: &mut dyn NeuronPrincipalIndex<NeuronId>,
    neuron_id: &NeuronId,
    principal_ids: Vec<PrincipalId>,
) -> Vec<PrincipalId> {
    principal_ids
        .into_iter()
        .filter(|principal_id| {
            let newly_removed = index.remove_neuron_id_principal_id(neuron_id, *principal_id);
            !newly_removed
        })
        .collect()
}

/// An in-memory implementation of the neuron principal index.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct HeapNeuronPrincipalIndex<NeuronId>
where
    NeuronId: Hash + Eq,
{
    principal_to_neuron_id_set: BTreeMap<PrincipalId, HashSet<NeuronId>>,
}

impl<NeuronId> HeapNeuronPrincipalIndex<NeuronId>
where
    NeuronId: Hash + Eq,
{
    pub fn new() -> Self {
        Self {
            principal_to_neuron_id_set: BTreeMap::new(),
        }
    }
}

impl<NeuronId> NeuronPrincipalIndex<NeuronId> for HeapNeuronPrincipalIndex<NeuronId>
where
    NeuronId: Eq + Hash + Clone,
{
    fn add_neuron_id_principal_id(&mut self, neuron_id: &NeuronId, principal: PrincipalId) -> bool {
        self.principal_to_neuron_id_set
            .entry(principal)
            .or_default()
            .insert(neuron_id.clone())
    }

    fn remove_neuron_id_principal_id(
        &mut self,
        neuron_id: &NeuronId,
        principal: PrincipalId,
    ) -> bool {
        let entry = self.principal_to_neuron_id_set.entry(principal);
        let mut entry = match entry {
            Entry::Vacant(_) => return false,
            Entry::Occupied(entry) => entry,
        };

        let neuron_ids = entry.get_mut();
        let newly_absent = neuron_ids.remove(neuron_id);

        // Removes the set if empty.
        if neuron_ids.is_empty() {
            entry.remove();
        }

        newly_absent
    }

    fn get_neuron_ids(&self, principal: PrincipalId) -> HashSet<NeuronId> {
        self.principal_to_neuron_id_set
            .get(&principal)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// A stable memory implementation of the index.
pub struct StableNeuronPrincipalIndex<NeuronId, M>
where
    NeuronId: Storable + Default + Clone + Ord,
    M: Memory,
{
    principal_and_neuron_id_set: StableBTreeMap<(Principal, NeuronId), (), M>,
}

impl<NeuronId, M> StableNeuronPrincipalIndex<NeuronId, M>
where
    NeuronId: Storable + Default + Clone + Ord,
    M: Memory,
{
    pub fn new(memory: M) -> Self {
        Self {
            principal_and_neuron_id_set: StableBTreeMap::init(memory),
        }
    }

    /// Returns the number of entries (principal, neuron_id) in the index. This is for validation
    /// purpose: this should be equal to the number of neurons (controller) plus the size of the hot
    /// key collection within primary storage.
    pub fn num_entries(&self) -> usize {
        self.principal_and_neuron_id_set.len() as usize
    }

    /// Returns whether the (principal_id, neuron_id) entry exists in the index. This is for
    /// validation purpose: each such pair in the primary storage should exist in the index.
    pub fn contains_entry(&self, neuron_id: &NeuronId, principal_id: PrincipalId) -> bool {
        let key = (principal_id.0, neuron_id.clone());
        self.principal_and_neuron_id_set.contains_key(&key)
    }

    /// Validates that some of the data in stable storage can be read, in order to prevent broken
    /// schema. Should only be called in post_upgrade.
    pub fn validate(&self) {
        super::validate_stable_btree_map(&self.principal_and_neuron_id_set);
    }
}

impl<NeuronId, M> NeuronPrincipalIndex<NeuronId> for StableNeuronPrincipalIndex<NeuronId, M>
where
    NeuronId: Storable + Default + Clone + Ord + LowerBounded + Hash,
    M: Memory,
{
    fn add_neuron_id_principal_id(
        &mut self,
        neuron_id: &NeuronId,
        principal_id: PrincipalId,
    ) -> bool {
        self.principal_and_neuron_id_set
            .insert((principal_id.into(), neuron_id.clone()), ())
            .is_none()
    }

    fn remove_neuron_id_principal_id(
        &mut self,
        neuron_id: &NeuronId,
        principal_id: PrincipalId,
    ) -> bool {
        self.principal_and_neuron_id_set
            .remove(&(principal_id.into(), neuron_id.clone()))
            .is_some()
    }

    fn get_neuron_ids(&self, principal_id: PrincipalId) -> HashSet<NeuronId> {
        self.principal_and_neuron_id_set
            .range((principal_id.into(), NeuronId::min_value())..)
            .take_while(|(k, _)| k.0 == principal_id.into())
            .map(|(k, _)| k.1)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_stable_structures::storable::Bound;
    use ic_stable_structures::{Storable, VectorMemory};
    use maplit::hashset;
    use num_traits::bounds::LowerBounded;
    use std::borrow::Cow;

    #[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
    struct TestNeuronId([u8; 32]);

    impl Storable for TestNeuronId {
        fn to_bytes(&self) -> Cow<[u8]> {
            self.0.to_bytes()
        }

        fn from_bytes(bytes: Cow<[u8]>) -> Self {
            TestNeuronId(<[u8; 32]>::from_bytes(bytes))
        }

        const BOUND: Bound = Bound::Bounded {
            max_size: 32,
            is_fixed_size: true,
        };
    }

    impl LowerBounded for TestNeuronId {
        fn min_value() -> Self {
            TestNeuronId([0u8; 32])
        }
    }

    fn get_stable_index() -> StableNeuronPrincipalIndex<TestNeuronId, VectorMemory> {
        StableNeuronPrincipalIndex::new(VectorMemory::default())
    }

    fn get_heap_index() -> HeapNeuronPrincipalIndex<TestNeuronId> {
        HeapNeuronPrincipalIndex::new()
    }

    // The following test helpers will be run by both implementations.
    fn test_add_single_neuron_helper(mut index: impl NeuronPrincipalIndex<TestNeuronId>) {
        assert_eq!(
            add_neuron_id_principal_ids(
                &mut index,
                &TestNeuronId([1u8; 32]),
                vec![
                    PrincipalId::new_user_test_id(1),
                    PrincipalId::new_user_test_id(2),
                ],
            ),
            vec![]
        );
        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(1)),
            hashset! {TestNeuronId([1u8; 32])}
        );
        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(2)),
            hashset! {TestNeuronId([1u8; 32])}
        );
    }

    fn test_remove_neuron_helper(mut index: impl NeuronPrincipalIndex<TestNeuronId>) {
        assert_eq!(
            add_neuron_id_principal_ids(
                &mut index,
                &TestNeuronId([1u8; 32]),
                vec![PrincipalId::new_user_test_id(1)],
            ),
            vec![]
        );
        assert_eq!(
            remove_neuron_id_principal_ids(
                &mut index,
                &TestNeuronId([1u8; 32]),
                vec![PrincipalId::new_user_test_id(1)],
            ),
            vec![]
        );
        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(1)),
            hashset! {}
        );
    }

    fn test_add_multiple_neurons_helper(mut index: impl NeuronPrincipalIndex<TestNeuronId>) {
        assert_eq!(
            add_neuron_id_principal_ids(
                &mut index,
                &TestNeuronId([1u8; 32]),
                vec![
                    PrincipalId::new_user_test_id(1),
                    PrincipalId::new_user_test_id(2),
                ],
            ),
            vec![]
        );
        assert_eq!(
            add_neuron_id_principal_ids(
                &mut index,
                &TestNeuronId([2u8; 32]),
                vec![
                    PrincipalId::new_user_test_id(2),
                    PrincipalId::new_user_test_id(3),
                ],
            ),
            vec![]
        );

        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(1)),
            hashset! {TestNeuronId([1u8; 32])}
        );
        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(2)),
            hashset! {TestNeuronId([1u8; 32]), TestNeuronId([2u8; 32])}
        );
        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(3)),
            hashset! {TestNeuronId([2u8; 32])}
        );
    }

    fn test_remove_add_principal_helper(mut index: impl NeuronPrincipalIndex<TestNeuronId>) {
        let neuron_id = TestNeuronId([1u8; 32]);
        let principal_id_1 = PrincipalId::new_user_test_id(1);
        let principal_id_2 = PrincipalId::new_user_test_id(2);
        let principal_id_3 = PrincipalId::new_user_test_id(3);
        // At first, principal ids 1 and 2 are in the index.
        assert_eq!(
            add_neuron_id_principal_ids(
                &mut index,
                &neuron_id,
                vec![principal_id_1, principal_id_2,],
            ),
            vec![]
        );

        // After removing 1, only 2 is in the index.
        assert!(index.remove_neuron_id_principal_id(&neuron_id, principal_id_1));
        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(1)),
            hashset! {}
        );
        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(2)),
            hashset! {neuron_id.clone()}
        );
        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(3)),
            hashset! {}
        );

        // After adding 3, 2 and 3 are in the index.
        assert!(index.add_neuron_id_principal_id(&neuron_id, principal_id_3));
        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(1)),
            hashset! {}
        );
        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(2)),
            hashset! {neuron_id.clone()}
        );
        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(3)),
            hashset! {neuron_id.clone()}
        );
    }

    fn test_add_existing_neuron_helper(mut index: impl NeuronPrincipalIndex<TestNeuronId>) {
        let neuron_id = TestNeuronId([1u8; 32]);
        let principal_id_1 = PrincipalId::new_user_test_id(1);
        let principal_id_2 = PrincipalId::new_user_test_id(2);

        // First add returns empty.
        assert_eq!(
            add_neuron_id_principal_ids(
                &mut index,
                &neuron_id,
                vec![principal_id_1, principal_id_2],
            ),
            vec![]
        );

        // Second add returns principal_id_1 since it's already present.
        assert_eq!(
            add_neuron_id_principal_ids(&mut index, &neuron_id, vec![principal_id_1],),
            vec![principal_id_1]
        );
    }

    fn test_remove_absent_neuron_helper(mut index: impl NeuronPrincipalIndex<TestNeuronId>) {
        let neuron_id = TestNeuronId([1u8; 32]);
        let principal_id_1 = PrincipalId::new_user_test_id(1);
        let principal_id_2 = PrincipalId::new_user_test_id(2);
        assert_eq!(
            add_neuron_id_principal_ids(
                &mut index,
                &neuron_id,
                vec![principal_id_1, principal_id_2],
            ),
            vec![]
        );

        // First remove returns empty.
        assert_eq!(
            remove_neuron_id_principal_ids(&mut index, &neuron_id, vec![principal_id_2],),
            vec![]
        );

        // Second add returns principal_id_2 since it's already absent.
        assert_eq!(
            remove_neuron_id_principal_ids(&mut index, &neuron_id, vec![principal_id_2],),
            vec![principal_id_2]
        );
    }

    #[test]
    fn test_single_neuron_heap() {
        test_add_single_neuron_helper(get_heap_index());
    }

    #[test]
    fn test_single_neuron_stable() {
        test_add_single_neuron_helper(get_stable_index());
    }

    #[test]
    fn test_remove_neuron_heap() {
        test_remove_neuron_helper(get_heap_index());
    }

    #[test]
    fn test_remove_neuron_stable() {
        test_remove_neuron_helper(get_stable_index());
    }

    #[test]
    fn test_add_multiple_neurons_heap() {
        test_add_multiple_neurons_helper(get_heap_index());
    }

    #[test]
    fn test_add_multiple_neurons_stable() {
        test_add_multiple_neurons_helper(get_stable_index());
    }

    #[test]
    fn test_remove_add_principal_in_memory() {
        test_remove_add_principal_helper(get_heap_index());
    }

    #[test]
    fn test_remove_add_principal_stable() {
        test_remove_add_principal_helper(get_stable_index());
    }

    #[test]
    fn test_add_existing_neuron_in_memory() {
        test_add_existing_neuron_helper(get_heap_index());
    }

    #[test]
    fn test_add_existing_neuron_stable() {
        test_add_existing_neuron_helper(get_stable_index());
    }

    #[test]
    fn test_remove_absent_neuron_in_memory() {
        test_remove_absent_neuron_helper(get_heap_index());
    }

    #[test]
    fn test_remove_absent_neuron_stable() {
        test_remove_absent_neuron_helper(get_stable_index());
    }

    #[test]
    fn test_stable_neuron_index_len() {
        let mut index = get_stable_index();

        assert_eq!(index.num_entries(), 0);

        assert_eq!(
            add_neuron_id_principal_ids(
                &mut index,
                &TestNeuronId([1u8; 32]),
                vec![
                    PrincipalId::new_user_test_id(1),
                    PrincipalId::new_user_test_id(2),
                ],
            ),
            vec![]
        );

        assert_eq!(index.num_entries(), 2);
    }

    #[test]
    fn test_stable_neuron_index_contains_entry() {
        let mut index = get_stable_index();

        assert_eq!(
            add_neuron_id_principal_ids(
                &mut index,
                &TestNeuronId([1u8; 32]),
                vec![
                    PrincipalId::new_user_test_id(1),
                    PrincipalId::new_user_test_id(2),
                ],
            ),
            vec![]
        );

        assert!(index.contains_entry(&TestNeuronId([1u8; 32]), PrincipalId::new_user_test_id(1)));
        assert!(index.contains_entry(&TestNeuronId([1u8; 32]), PrincipalId::new_user_test_id(2)));
        assert!(!index.contains_entry(&TestNeuronId([1u8; 32]), PrincipalId::new_user_test_id(3)));
    }
}
