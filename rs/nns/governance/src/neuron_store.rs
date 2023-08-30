use crate::{
    governance::{Environment, LOG_PREFIX},
    pb::v1::{governance_error::ErrorType, GovernanceError, Neuron},
    storage::NEURON_INDEXES,
};
use ic_nns_common::pb::v1::NeuronId;
use std::collections::BTreeMap;

#[derive(Debug)]
pub enum NeuronStoreError {
    NeuronNotFound(NeuronNotFound),
}

impl NeuronStoreError {
    fn not_found(neuron_id: &NeuronId) -> Self {
        NeuronStoreError::NeuronNotFound(NeuronNotFound {
            neuron_id: *neuron_id,
        })
    }
}

#[derive(Debug)]
pub struct NeuronNotFound {
    neuron_id: NeuronId,
}

impl From<NeuronStoreError> for GovernanceError {
    fn from(value: NeuronStoreError) -> Self {
        match value {
            NeuronStoreError::NeuronNotFound(neuron_not_found) => {
                GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!("Neuron not found: {:?}", neuron_not_found.neuron_id),
                )
            }
        }
    }
}

/// This struct stores and provides access to all neurons within NNS Governance, which can live
/// in either heap memory or stable memory.
#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
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

    pub fn new_neuron_id(&self, env: &mut dyn Environment) -> NeuronId {
        loop {
            let id = env
                .random_u64()
                // Let there be no question that id was chosen
                // intentionally, not just 0 by default.
                .saturating_add(1);
            let neuron_id = NeuronId { id };

            let is_unique = !self.contains(neuron_id);

            if is_unique {
                return neuron_id;
            }

            dfn_core::println!(
                "{}WARNING: A suspiciously near-impossible event has just occurred: \
                 we randomly picked a NeuronId, but it's already used: \
                 {:?}. Trying again...",
                LOG_PREFIX,
                neuron_id,
            );
        }
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

    /// Private method - not intended to be used externally, as we want to over-time hide from
    /// application logic the storage location of the neurons, and only expose operations that
    /// can be done in a performant manner from here.
    fn heap_neurons_filtered(&self, filter: impl Fn(&Neuron) -> bool) -> Vec<&Neuron> {
        self.heap_neurons.values().filter(|n| filter(n)).collect()
    }

    fn heap_neuron_ids_filtered(&self, filter: impl Fn(&Neuron) -> bool) -> Vec<NeuronId> {
        self.heap_neurons_filtered(filter)
            .into_iter()
            .flat_map(|n| n.id)
            .collect()
    }

    /// List all neuron ids that are in the community fund.
    pub fn list_community_fund_neuron_ids(&self) -> Vec<NeuronId> {
        self.heap_neuron_ids_filtered(|n| {
            n.joined_community_fund_timestamp_seconds
                .unwrap_or_default()
                > 0
        })
    }

    /// List all neuron ids whose neurons have staked maturity greater than 0.
    pub fn list_staked_maturity_neuron_ids(&self) -> Vec<NeuronId> {
        self.heap_neuron_ids_filtered(|n| n.staked_maturity_e8s_equivalent.unwrap_or_default() > 0)
    }

    /// Execute a function with a mutable reference to a neuron, returning the result of the function,
    /// unless the neuron is not found
    pub fn with_neuron_mut<R>(
        &mut self,
        nid: &NeuronId,
        f: impl FnOnce(&mut Neuron) -> R,
    ) -> Result<R, NeuronStoreError> {
        let neuron = self
            .heap_neurons
            .get_mut(&nid.id)
            .ok_or_else(|| NeuronStoreError::not_found(nid))?;
        Ok(f(neuron))
    }

    /// Execute a function with a reference to a neuron, returning the result of the function,
    /// unless the neuron is not found
    pub fn with_neuron<R>(
        &self,
        nid: &NeuronId,
        f: impl FnOnce(&Neuron) -> R,
    ) -> Result<R, GovernanceError> {
        let neuron = self
            .heap_neurons
            .get(&nid.id)
            .ok_or_else(|| NeuronStoreError::not_found(nid))?;
        Ok(f(neuron))
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
        &mut self,
        last_neuron_id: NeuronId,
        batch_size: usize,
    ) -> Result<Option<NeuronId>, String> {
        let mut new_last_neuron_id = None;
        let mut count = 0;
        for (neuron_id, neuron) in self
            .heap_neurons
            .range(last_neuron_id.id + 1..)
            .take(batch_size)
        {
            NEURON_INDEXES.with(|indexes| indexes.borrow_mut().add_neuron(neuron))?;
            count += 1;
            new_last_neuron_id = Some(NeuronId { id: *neuron_id });
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
