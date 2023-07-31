use ic_base_types::PrincipalId;
use ic_stable_structures::{
    memory_manager::VirtualMemory, BoundedStorable, DefaultMemoryImpl, StableBTreeMap,
};
use num_traits::bounds::LowerBounded;
use std::collections::{BTreeMap, HashSet};
use std::{clone::Clone, cmp::Ord, hash::Hash};

/// An index to make it easy to look up neuron ids by principal.
pub trait NeuronPrincipalIndex<ID> {
    /// Adds a neuron-principal pair to the index.
    fn add_neuron_id_principal_id(&mut self, neuron_id: &ID, principal_id: PrincipalId);
    /// Removes a neuron-principal pair to the index. It is OK if the pair does not exist.
    fn remove_neuron_id_principal_id(&mut self, neuron_id: &ID, principal_id: PrincipalId);
    /// Returns a list of neuron ids by principal.
    fn get_neuron_ids(&self, principal: PrincipalId) -> HashSet<ID>;

    /// Adds a neuron id and a list of principals.
    fn add_neuron_id_principal_ids(&mut self, neuron_id: &ID, principal_ids: Vec<PrincipalId>) {
        for principal_id in principal_ids {
            self.add_neuron_id_principal_id(neuron_id, principal_id);
        }
    }

    /// Removes a neuron id and a list of principals.
    fn remove_neuron_id_principal_ids(&mut self, neuron_id: &ID, principal_ids: Vec<PrincipalId>) {
        for principal_id in principal_ids {
            self.remove_neuron_id_principal_id(neuron_id, principal_id);
        }
    }
}

/// An in-memory implementation of the neuron principal index.
pub struct HeapNeuronPrincipalIndex<ID> {
    index_map: BTreeMap<PrincipalId, HashSet<ID>>,
}

impl<ID> HeapNeuronPrincipalIndex<ID> {
    pub fn new() -> Self {
        Self {
            index_map: BTreeMap::new(),
        }
    }
}

impl<ID> Default for HeapNeuronPrincipalIndex<ID> {
    fn default() -> Self {
        Self::new()
    }
}

impl<ID: Eq + Hash + Clone> NeuronPrincipalIndex<ID> for HeapNeuronPrincipalIndex<ID> {
    fn add_neuron_id_principal_id(&mut self, neuron_id: &ID, principal: PrincipalId) {
        self.index_map
            .entry(principal)
            .or_insert_with(HashSet::new)
            .insert(neuron_id.clone());
    }

    fn remove_neuron_id_principal_id(&mut self, neuron_id: &ID, principal: PrincipalId) {
        self.index_map.entry(principal).and_modify(|neuron_ids| {
            neuron_ids.remove(neuron_id);
        });
        // Removes the set if empty.
        if self
            .index_map
            .get(&principal)
            .map(|neuron_ids| neuron_ids.is_empty())
            .unwrap_or_default()
        {
            self.index_map.remove(&principal);
        }
    }

    fn get_neuron_ids(&self, principal: PrincipalId) -> HashSet<ID> {
        self.index_map
            .get(&principal)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// A stable memory implementation of the index.
pub struct StableNeuronPrincipalIndex<ID: BoundedStorable + Default + Clone + Ord> {
    index_map: StableBTreeMap<(PrincipalId, ID), (), VirtualMemory<DefaultMemoryImpl>>,
}

impl<ID: BoundedStorable + Default + Clone + Ord> StableNeuronPrincipalIndex<ID> {
    pub fn new(memory: VirtualMemory<DefaultMemoryImpl>) -> Self {
        Self {
            index_map: StableBTreeMap::init(memory),
        }
    }
}

impl<ID: BoundedStorable + Default + Clone + Ord + LowerBounded + Hash> NeuronPrincipalIndex<ID>
    for StableNeuronPrincipalIndex<ID>
{
    fn add_neuron_id_principal_id(&mut self, neuron_id: &ID, principal: PrincipalId) {
        self.index_map.insert((principal, neuron_id.clone()), ());
    }

    fn remove_neuron_id_principal_id(&mut self, neuron_id: &ID, principal: PrincipalId) {
        self.index_map.remove(&(principal, neuron_id.clone()));
    }

    fn get_neuron_ids(&self, principal: PrincipalId) -> HashSet<ID> {
        self.index_map
            .range((principal, ID::min_value())..)
            .take_while(|(k, _)| k.0 == principal)
            .map(|(k, _)| k.1)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::index::neuron_principal::{
        HeapNeuronPrincipalIndex, NeuronPrincipalIndex, StableNeuronPrincipalIndex,
    };

    use ic_base_types::PrincipalId;
    use ic_stable_structures::{
        memory_manager::{MemoryId, MemoryManager, VirtualMemory},
        BoundedStorable, DefaultMemoryImpl, Storable,
    };
    use maplit::hashset;
    use num_traits::bounds::LowerBounded;
    use std::borrow::Cow;

    thread_local! {
        // Each test will have a separate copy of the memory manager since each thread
        // is run in a separate thread.
        static MEMORY_MANAGER: MemoryManager<DefaultMemoryImpl> =  MemoryManager::init(DefaultMemoryImpl::default());
    }

    #[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    struct TestNeuronId([u8; 32]);

    impl Storable for TestNeuronId {
        fn to_bytes(&self) -> Cow<[u8]> {
            self.0.to_bytes()
        }

        fn from_bytes(bytes: Cow<[u8]>) -> Self {
            TestNeuronId(<[u8; 32]>::from_bytes(bytes))
        }
    }

    impl BoundedStorable for TestNeuronId {
        const MAX_SIZE: u32 = 32;
        const IS_FIXED_SIZE: bool = true;
    }

    impl LowerBounded for TestNeuronId {
        fn min_value() -> Self {
            TestNeuronId([0u8; 32])
        }
    }

    fn get_memory() -> VirtualMemory<DefaultMemoryImpl> {
        MEMORY_MANAGER.with(|memory_manager| memory_manager.get(MemoryId::new(0)))
    }

    fn get_stable_index() -> StableNeuronPrincipalIndex<TestNeuronId> {
        StableNeuronPrincipalIndex::<TestNeuronId>::new(get_memory())
    }

    fn get_heap_index() -> HeapNeuronPrincipalIndex<TestNeuronId> {
        HeapNeuronPrincipalIndex::<TestNeuronId>::new()
    }

    // The following test helpers will be run by both implementations.
    fn test_add_single_neuron_helper(mut index: impl NeuronPrincipalIndex<TestNeuronId>) {
        index.add_neuron_id_principal_ids(
            &TestNeuronId([1u8; 32]),
            vec![
                PrincipalId::new_user_test_id(1),
                PrincipalId::new_user_test_id(2),
            ],
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
        index.add_neuron_id_principal_ids(
            &TestNeuronId([1u8; 32]),
            vec![PrincipalId::new_user_test_id(1)],
        );
        index.remove_neuron_id_principal_ids(
            &TestNeuronId([1u8; 32]),
            vec![PrincipalId::new_user_test_id(1)],
        );
        assert_eq!(
            index.get_neuron_ids(PrincipalId::new_user_test_id(1)),
            hashset! {}
        );
    }

    fn test_add_multiple_neurons_helper(mut index: impl NeuronPrincipalIndex<TestNeuronId>) {
        index.add_neuron_id_principal_ids(
            &TestNeuronId([1u8; 32]),
            vec![
                PrincipalId::new_user_test_id(1),
                PrincipalId::new_user_test_id(2),
            ],
        );
        index.add_neuron_id_principal_ids(
            &TestNeuronId([2u8; 32]),
            vec![
                PrincipalId::new_user_test_id(2),
                PrincipalId::new_user_test_id(3),
            ],
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
}
