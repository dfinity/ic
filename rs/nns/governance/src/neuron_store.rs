use crate::{
    governance::{Environment, LOG_PREFIX},
    pb::v1::{governance_error::ErrorType, GovernanceError, Neuron, Topic},
    storage::NEURON_INDEXES,
};
use ic_base_types::PrincipalId;
use ic_nervous_system_governance::index::{
    neuron_following::{
        add_neuron_followees, remove_neuron_followees, update_neuron_category_followees,
        HeapNeuronFollowingIndex, NeuronFollowingIndex,
    },
    neuron_principal::{
        add_neuron_id_principal_ids, remove_neuron_id_principal_ids, HeapNeuronPrincipalIndex,
        NeuronPrincipalIndex,
    },
};
use ic_nns_common::pb::v1::NeuronId;
use std::collections::{BTreeMap, BTreeSet, HashSet};

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

    /// Cached data structure that (for each topic) maps a followee to
    /// the set of followers. This is the inverse of the mapping from
    /// neuron (follower) to followees, in the neurons. This is a
    /// cached index and will be removed and recreated when the state
    /// is saved and restored.
    ///
    /// (Topic, Followee) -> set of followers.
    pub topic_followee_index: HeapNeuronFollowingIndex<NeuronId, Topic>,

    /// Maps Principals to the Neuron IDs of all Neurons that have this
    /// Principal as their controller or as one of their hot keys
    ///
    /// This is a cached index and will be removed and recreated when the state
    /// is saved and restored.
    pub principal_to_neuron_ids_index: HeapNeuronPrincipalIndex<NeuronId>,

    /// Set of all names given to Known Neurons, to prevent duplication.
    ///
    /// This set is cached and will be removed and recreated when the state is saved and restored.
    pub known_neuron_name_set: HashSet<String>,
}

impl NeuronStore {
    pub fn new(heap_neurons: BTreeMap<u64, Neuron>) -> Self {
        let topic_followee_index = build_topic_followee_index(&heap_neurons);
        let principal_to_neuron_ids_index = build_principal_to_neuron_ids_index(&heap_neurons);
        let known_neuron_name_set = build_known_neuron_name_index(&heap_neurons);
        Self {
            heap_neurons,
            topic_followee_index,
            principal_to_neuron_ids_index,
            known_neuron_name_set,
        }
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
    ) -> Result<R, NeuronStoreError> {
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

    // Below are indexes related methods. They don't have a unified interface yet, but NNS1-2507 will change that.

    /// Update `index` to map all the given Neuron's hot keys and controller to
    /// `neuron_id`
    pub fn add_neuron_to_principal_to_neuron_ids_index(
        &mut self,
        neuron_id: NeuronId,
        principal_ids: Vec<PrincipalId>,
    ) {
        let already_present_principal_ids = add_neuron_id_principal_ids(
            &mut self.principal_to_neuron_ids_index,
            &neuron_id,
            principal_ids,
        );
        for already_present_principal_id in already_present_principal_ids {
            println!(
                "{} Principal {:?}  already present in the index for neuron {:?}",
                LOG_PREFIX, already_present_principal_id, neuron_id
            );
        }
    }

    pub fn add_neuron_to_principal_in_principal_to_neuron_ids_index(
        &mut self,
        neuron_id: NeuronId,
        principal_id: PrincipalId,
    ) {
        // TODO(NNS1-2409): Apply index updates to stable storage index.
        if !self
            .principal_to_neuron_ids_index
            .add_neuron_id_principal_id(&neuron_id, principal_id)
        {
            println!(
                "{} Principal {:?}  already present in the index for neuron {:?}",
                LOG_PREFIX, principal_id, neuron_id
            );
        }
    }

    /// Update `index` to remove the neuron from the list of neurons mapped to
    /// principals.
    pub fn remove_neuron_from_principal_to_neuron_ids_index(
        &mut self,
        neuron_id: NeuronId,
        principal_ids: Vec<PrincipalId>,
    ) {
        // TODO(NNS1-2409): Apply index updates to stable storage index.
        let already_absent_principal_ids = remove_neuron_id_principal_ids(
            &mut self.principal_to_neuron_ids_index,
            &neuron_id,
            principal_ids,
        );
        for already_absent_principal_id in already_absent_principal_ids {
            println!(
                "{} Principal {:?}  already absent in the index for neuron {:?}",
                LOG_PREFIX, already_absent_principal_id, neuron_id
            );
        }
    }

    pub fn remove_neuron_from_principal_in_principal_to_neuron_ids_index(
        &mut self,
        neuron_id: NeuronId,
        principal_id: PrincipalId,
    ) {
        // TODO(NNS1-2409): Apply index updates to stable storage index.
        if !self
            .principal_to_neuron_ids_index
            .remove_neuron_id_principal_id(&neuron_id, principal_id)
        {
            println!(
                "{} Principal {:?}  already absent in the index for neuron {:?}",
                LOG_PREFIX, principal_id, neuron_id
            );
        }
    }

    pub fn add_neuron_to_topic_followee_index(
        &mut self,
        neuron_id: NeuronId,
        topic_followee_pairs: BTreeSet<(Topic, NeuronId)>,
    ) {
        // TODO(NNS1-2409): Apply index updates to stable storage index.
        let already_present_topic_followee_pairs = add_neuron_followees(
            &mut self.topic_followee_index,
            &neuron_id,
            topic_followee_pairs,
        );
        log_already_present_topic_followee_pairs(neuron_id, already_present_topic_followee_pairs);
    }

    pub fn remove_neuron_from_topic_followee_index(
        &mut self,
        neuron_id: NeuronId,
        topic_followee_pairs: BTreeSet<(Topic, NeuronId)>,
    ) {
        // TODO(NNS1-2409): Apply index updates to stable storage index.
        let already_absent_topic_followee_pairs = remove_neuron_followees(
            &mut self.topic_followee_index,
            &neuron_id,
            topic_followee_pairs,
        );
        log_already_absent_topic_followee_pairs(neuron_id, already_absent_topic_followee_pairs);
    }

    pub fn update_neuron_followees_for_topic(
        &mut self,
        follower_id: NeuronId,
        topic: Topic,
        old_followee_ids: BTreeSet<NeuronId>,
        new_followee_ids: BTreeSet<NeuronId>,
    ) {
        let (already_absent_old_followees, already_present_new_followees) =
            update_neuron_category_followees(
                &mut self.topic_followee_index,
                &follower_id,
                topic,
                old_followee_ids,
                new_followee_ids,
            );
        log_already_present_topic_followee_pairs(
            follower_id,
            already_present_new_followees
                .iter()
                .map(|followee| (topic, *followee))
                .collect(),
        );
        log_already_absent_topic_followee_pairs(
            follower_id,
            already_absent_old_followees
                .iter()
                .map(|followee| (topic, *followee))
                .collect(),
        );
    }

    pub fn add_known_neuron_to_index(&mut self, known_neuron_name: &str) {
        // TODO(NNS1-2409): Apply index updates to stable storage index.
        self.known_neuron_name_set
            .insert(known_neuron_name.to_string());
    }

    pub fn remove_known_neuron_from_index(&mut self, known_neuron_name: &str) {
        // TODO(NNS1-2409): Apply index updates to stable storage index.
        self.known_neuron_name_set.remove(known_neuron_name);
    }

    // Read methods for indexes.

    // Gets followers by a followee id and topic.
    pub fn get_followers_by_followee_and_topic(
        &self,
        followee: NeuronId,
        topic: Topic,
    ) -> Vec<NeuronId> {
        self.topic_followee_index
            .get_followers_by_followee_and_category(&followee, topic)
    }

    // Gets all neuron ids associated with the given principal id (hot-key or controller).
    pub fn get_neuron_ids_readable_by_caller(
        &self,
        principal_id: PrincipalId,
    ) -> HashSet<NeuronId> {
        self.principal_to_neuron_ids_index
            .get_neuron_ids(principal_id)
    }

    // Returns whether the known neuron name already exists.
    pub fn contains_known_neuron_name(&self, known_neuron_name: &str) -> bool {
        self.known_neuron_name_set.contains(known_neuron_name)
    }
}

fn build_principal_to_neuron_ids_index(
    heap_neurons: &BTreeMap<u64, Neuron>,
) -> HeapNeuronPrincipalIndex<NeuronId> {
    let mut index = HeapNeuronPrincipalIndex::new();
    for neuron in heap_neurons.values() {
        let already_present_principal_ids = add_neuron_id_principal_ids(
            &mut index,
            &neuron.id.unwrap(),
            neuron.principal_ids_with_special_permissions(),
        );
        for already_present_principal_id in already_present_principal_ids {
            println!(
                "{} Principal {:?}  already present in the index for neuron {:?}",
                LOG_PREFIX, already_present_principal_id, neuron.id
            );
        }
    }
    index
}

/// From the `neurons` part of this `Governance` struct, build the
/// index (per topic) from followee to set of followers. The
/// neurons themselves map followers (the neuron ID) to a set of
/// followees (per topic).
fn build_topic_followee_index(
    heap_neurons: &BTreeMap<u64, Neuron>,
) -> HeapNeuronFollowingIndex<NeuronId, Topic> {
    let mut index = HeapNeuronFollowingIndex::new();
    for neuron in heap_neurons.values() {
        let neuron_id = neuron.id.expect("Neuron must have an id");
        let already_present_topic_followee_pairs =
            add_neuron_followees(&mut index, &neuron_id, neuron.topic_followee_pairs());
        log_already_present_topic_followee_pairs(neuron_id, already_present_topic_followee_pairs);
    }
    index
}

fn build_known_neuron_name_index(heap_neurons: &BTreeMap<u64, Neuron>) -> HashSet<String> {
    let mut index = HashSet::new();
    for neuron in heap_neurons.values() {
        if let Some(known_neuron_data) = &neuron.known_neuron_data {
            index.insert(known_neuron_data.name.clone());
        }
    }
    index
}

fn log_already_present_topic_followee_pairs(
    neuron_id: NeuronId,
    already_present_topic_followee_pairs: Vec<(Topic, NeuronId)>,
) {
    for (topic, followee) in already_present_topic_followee_pairs {
        println!(
            "{} Topic {:?} and followee {:?} already present in the index for neuron {:?}",
            LOG_PREFIX, topic, followee, neuron_id
        );
    }
}

fn log_already_absent_topic_followee_pairs(
    neuron_id: NeuronId,
    already_absent_topic_followee_pairs: Vec<(Topic, NeuronId)>,
) {
    for (topic, followee) in already_absent_topic_followee_pairs {
        println!(
            "{} Topic {:?} and followee {:?} already absent in the index for neuron {:?}",
            LOG_PREFIX, topic, followee, neuron_id
        );
    }
}

#[cfg(test)]
mod neuron_store_tests;
