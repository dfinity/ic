use crate::{pb::v1::Neuron, storage::NEURON_INDEXES};
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

    /// For heap neurons starting from `last_neuron_id + 1` where `last_neuron_id` is the last neuron id that has been
    /// migrated, and it adds at most `batch_size` of them into stable storage indexes. It is an undefined behavior if
    /// `last_neuron_id` passed in was not returned by the one returned by the same function.
    ///
    /// Returns `Err(failure_reason)` if it failed; returns Ok(None) if the cursor reaches the end; returns
    /// `Ok(last_neuron_id)` if the cursor has not reached the end.
    ///
    /// Note that a Neuron with id 0 will never be scan, and it's OK because it is not a valid id.
    ///
    #[allow(dead_code)] // TODO(NNS1-2409): Re-enable clippy.
    pub(crate) fn batch_add_heap_neurons_to_stable_indexes(
        &self,
        last_neuron_id: u64,
        batch_size: usize,
    ) -> Result<Option<u64>, String> {
        let mut new_last_neuron_id = None;
        let mut count = 0;
        for (neuron_id, neuron) in self
            .heap_neurons
            .range(last_neuron_id + 1..)
            .take(batch_size)
        {
            NEURON_INDEXES.with(|indexes| indexes.borrow_mut().add_neuron(neuron))?;
            count += 1;
            new_last_neuron_id = Some(*neuron_id);
        }

        if count < batch_size {
            // No more neurons to migrate
            new_last_neuron_id = None
        }
        Ok(new_last_neuron_id)
    }
}

#[cfg(test)]
mod neuron_store_tests;
