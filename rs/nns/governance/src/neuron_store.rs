use crate::pb::v1::Neuron;
use ic_nns_common::pb::v1::NeuronId;
use std::collections::BTreeMap;

/// This struct stores and provides access to all neurons within NNS Governance, which can live
/// in either heap memory or stable memory.
pub struct NeuronStore {
    heap_neurons: BTreeMap<u64, Neuron>,
}

impl NeuronStore {
    pub fn new(heap_neurons: BTreeMap<u64, Neuron>) -> Self {
        Self { heap_neurons }
    }

    /// Takes the heap neurons for serialization. The `self.heap_neurons` will become empty, so
    /// it should only be called once at pre_upgrade.
    pub fn take_heap_neurons(&mut self) -> BTreeMap<u64, Neuron> {
        std::mem::take(&mut self.heap_neurons)
    }

    /// Clones all the neurons. This is only used for testing.
    /// TODO(NNS-2474) clean it up after NNSState stop using GovernanceProto.
    pub fn clone_neurons(&self) -> BTreeMap<u64, Neuron> {
        self.heap_neurons.clone()
    }

    /// Returns if store contains a Neuron by id
    pub fn contains(&self, neuron_id: NeuronId) -> bool {
        self.heap_neurons.contains_key(&neuron_id.id)
    }

    /// Get the number of neurons in the Store
    pub fn len(&self) -> usize {
        self.heap_neurons.len()
    }

    /// Insert or update a Neuron
    pub fn upsert(&mut self, neuron: Neuron) {
        self.heap_neurons
            .insert(neuron.id.expect("Neuron must have an id").id, neuron);
    }

    /// Remove a Neuron by id
    pub fn remove(&mut self, neuron_id: &NeuronId) {
        self.heap_neurons.remove(&neuron_id.id);
    }

    /// Get a reference to heap neurons.  Temporary method to allow
    /// access to the heap neurons during transition to better data hiding.
    pub fn heap_neurons(&self) -> &BTreeMap<u64, Neuron> {
        &self.heap_neurons
    }

    /// Get a mutable reference to heap neurons.  Temporary method to allow
    /// access to the heap neurons during transition to better data hiding.
    pub fn heap_neurons_mut(&mut self) -> &mut BTreeMap<u64, Neuron> {
        &mut self.heap_neurons
    }
}
