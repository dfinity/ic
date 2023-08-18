use crate::pb::v1::Neuron;
use std::collections::BTreeMap;

/// This struct stores and provides access to all neurons within NNS Governance, which can live
/// in either heap memory or stable memory.
pub struct NeuronStore {
    pub heap_neurons: BTreeMap<u64, Neuron>,
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
}
