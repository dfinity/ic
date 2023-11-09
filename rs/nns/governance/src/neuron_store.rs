use crate::{
    governance::{
        Environment, TimeWarp, LOG_PREFIX, MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
    },
    is_copy_inactive_neurons_to_stable_memory_enabled,
    neuron::neuron_id_range_to_u64_range,
    pb::v1::{governance_error::ErrorType, GovernanceError, Neuron, NeuronState, Topic},
    storage::{
        neuron_indexes::{CorruptedNeuronIndexes, NeuronIndex},
        with_stable_neuron_indexes, with_stable_neuron_indexes_mut, with_stable_neuron_store,
        with_stable_neuron_store_mut, NeuronIdU64, TopicSigned32,
    },
    Clock, IcClock,
};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use dyn_clone::DynClone;
use ic_base_types::PrincipalId;
use ic_nervous_system_governance::index::{
    neuron_following::{HeapNeuronFollowingIndex, NeuronFollowingIndex},
    neuron_principal::{
        add_neuron_id_principal_ids, remove_neuron_id_principal_ids, HeapNeuronPrincipalIndex,
        NeuronPrincipalIndex,
    },
};
use ic_nns_common::pb::v1::NeuronId;
use icp_ledger::Subaccount;
use std::{
    collections::{BTreeMap, HashSet},
    fmt::{Debug, Display, Formatter},
    ops::RangeBounds,
};

#[derive(Debug, Eq, PartialEq)]
pub enum NeuronStoreError {
    NeuronNotFound(NeuronNotFound),
    CorruptedNeuronIndexes(CorruptedNeuronIndexes),
    NeuronIdIsNone,
    InvalidSubaccount {
        neuron_id: NeuronId,
        subaccount_bytes: Vec<u8>,
    },
    NeuronIdModified {
        old_neuron_id: NeuronId,
        new_neuron_id: NeuronId,
    },
    SubaccountModified {
        old_subaccount: Subaccount,
        new_subaccount: Subaccount,
    },
    NeuronAlreadyExists(NeuronId),
}

impl NeuronStoreError {
    pub fn not_found(neuron_id: &NeuronId) -> Self {
        NeuronStoreError::NeuronNotFound(NeuronNotFound {
            neuron_id: *neuron_id,
        })
    }

    pub fn invalid_subaccount(neuron_id: NeuronId, subaccount_bytes: Vec<u8>) -> Self {
        NeuronStoreError::InvalidSubaccount {
            neuron_id,
            subaccount_bytes,
        }
    }

    pub fn neuron_id_modified(old_neuron_id: NeuronId, new_neuron_id: NeuronId) -> Self {
        NeuronStoreError::NeuronIdModified {
            old_neuron_id,
            new_neuron_id,
        }
    }

    pub fn subaccount_modified(old_subaccount: Subaccount, new_subaccount: Subaccount) -> Self {
        NeuronStoreError::SubaccountModified {
            old_subaccount,
            new_subaccount,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct NeuronNotFound {
    neuron_id: NeuronId,
}

impl Display for NeuronStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NeuronStoreError::NeuronNotFound(neuron_not_found) => {
                write!(f, "Neuron not found: {:?}", neuron_not_found.neuron_id)
            }
            NeuronStoreError::CorruptedNeuronIndexes(corrupted_neuron_indexes) => {
                write!(
                    f,
                    "Neuron indexes are corrupted: {:?}",
                    corrupted_neuron_indexes
                )
            }
            NeuronStoreError::NeuronIdIsNone => write!(f, "Neuron id is none"),
            NeuronStoreError::InvalidSubaccount {
                neuron_id,
                subaccount_bytes,
            } => write!(
                f,
                "Neuron {:?} has an invalid subaccount {:?}",
                neuron_id, subaccount_bytes
            ),
            NeuronStoreError::NeuronIdModified {
                old_neuron_id,
                new_neuron_id,
            } => write!(
                f,
                "Attempting to modify neuron id from {} to {}",
                old_neuron_id.id, new_neuron_id.id
            ),
            NeuronStoreError::SubaccountModified {
                old_subaccount,
                new_subaccount,
            } => write!(
                f,
                "Attempting to modify neuron subaccount from {:?} to {:?}",
                old_subaccount, new_subaccount
            ),
            NeuronStoreError::NeuronAlreadyExists(neuron_id) => {
                write!(
                    f,
                    "Attempting to add a neuron with an existing ID: {:?}",
                    neuron_id
                )
            }
        }
    }
}

impl From<NeuronStoreError> for GovernanceError {
    fn from(value: NeuronStoreError) -> Self {
        let error_type = match &value {
            NeuronStoreError::NeuronNotFound(_) => ErrorType::NotFound,
            NeuronStoreError::CorruptedNeuronIndexes(_) => ErrorType::PreconditionFailed,
            NeuronStoreError::NeuronIdIsNone => ErrorType::PreconditionFailed,
            NeuronStoreError::InvalidSubaccount { .. } => ErrorType::PreconditionFailed,
            NeuronStoreError::NeuronIdModified { .. } => ErrorType::PreconditionFailed,
            NeuronStoreError::SubaccountModified { .. } => ErrorType::PreconditionFailed,
            NeuronStoreError::NeuronAlreadyExists(_) => ErrorType::PreconditionFailed,
        };
        GovernanceError::new_with_message(error_type, value.to_string())
    }
}

pub fn get_neuron_subaccount(
    neuron_store: &NeuronStore,
    neuron_id: NeuronId,
) -> Result<Subaccount, NeuronStoreError> {
    neuron_store.with_neuron(&neuron_id, |neuron| {
        neuron
            .subaccount()
            .map_err(|_| NeuronStoreError::InvalidSubaccount {
                neuron_id,
                subaccount_bytes: neuron.account.clone(),
            })
    })?
}

trait PracticalClock: Clock + Send + Sync + Debug + DynClone {}
dyn_clone::clone_trait_object!(PracticalClock);

impl PracticalClock for IcClock {}

/// This structure represents a whole Neuron's Fund neuron.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeuronsFundNeuron {
    pub id: NeuronId,
    pub maturity_equivalent_icp_e8s: u64,
    pub controller: PrincipalId,
}

/// This struct stores and provides access to all neurons within NNS Governance, which can live
/// in either heap memory or stable memory.
#[cfg_attr(test, derive(Clone, Debug))]
pub struct NeuronStore {
    /// Neurons stored in heap (as supposed to StableNeuronStore). The invariant regarding neurons
    /// in heap v.s. stable storage: "all neurons in the stable storage should be inactive", which
    /// is equivalent to: "all active neurons should remain on the heap". The invariant holds
    /// because: (1) all neuron mutations go through `add_neuron`, `remove_neuron` and
    /// `with_neuron_mut` which is responsible for upholding the invariant. (2) neuron being
    /// inactive is monotonic through passage of time without mutation - when time increases, an
    /// inactive neuron will stay inactive without mutation.
    ///
    /// Note that 'inactive' definition comes from `Neuron::is_inactive` which takes current time as
    /// an argument.
    ///
    /// All accesses to heap_neurons need to be aware that it is only guaranteed that active neurons
    /// are always returned, and the current use cases are (which also means new use cases should be
    /// evaluated this way):
    /// - building indexes on post_upgrade: soon to be deprecated since we switched to indexes
    ///   persisted through upgrades.
    /// - computing cached entries: when it involves neurons, it mostly cares about stake, maturity
    ///   and NF fund.
    /// - `Governance::validate`: soon to be deprecated since we have subaccount index.
    /// - Copying inactive neurons from heap to stable storage: it is intended to only loop through
    ///   neurons in heap.
    /// - `voting_eligible_neurons()`: inactive neurons have been dissolved for 14 days, so it
    ///   cannot be voting eligible.
    /// - `list_community_fund_neuron_ids` and `list_active_neurons_fund_neurons`: inactive neurons
    ///   must not be NF.
    /// - `list_neurons_ready_to_unstake_maturity`: inactive neurons have 0 stake (which also means
    ///   0 staked maturity), so no inactive neurons need to unstake maturity.
    /// - `list_known_neuron_ids`: soon to be deprecated because of known neuron index.
    /// - `list_ready_to_spawn_neuron_ids`: inactive neurons must have 0 maturity, and spawning
    ///   neurons must have maturity.
    heap_neurons: BTreeMap<u64, Neuron>,

    /// Cached data structure that (for each topic) maps a followee to
    /// the set of followers. This is the inverse of the mapping from
    /// neuron (follower) to followees, in the neurons. This is a
    /// cached index and will be removed and recreated when the state
    /// is saved and restored.
    ///
    /// (Topic, Followee) -> set of followers.
    topic_followee_index: HeapNeuronFollowingIndex<NeuronIdU64, TopicSigned32>,

    /// Maps Principals to the Neuron IDs of all Neurons that have this
    /// Principal as their controller or as one of their hot keys
    ///
    /// This is a cached index and will be removed and recreated when the state
    /// is saved and restored.
    principal_to_neuron_ids_index: HeapNeuronPrincipalIndex<NeuronId>,

    /// Set of all names given to Known Neurons, to prevent duplication.
    ///
    /// This set is cached and will be removed and recreated when the state is saved and restored.
    known_neuron_name_set: HashSet<String>,

    // In non-test builds, Box would suffice. However, in test, the containing struct (to wit,
    // NeuronStore) implements additional traits. Therefore, more elaborate wrapping is needed.
    clock: Box<dyn PracticalClock>,
}

/// Does not use clock, but other than that, behaves as you would expect.
///
/// clock is excluded, because you cannot compare two objects of type `Box<dyn SomeTrait>`.
#[cfg(test)]
impl PartialEq for NeuronStore {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            heap_neurons,
            topic_followee_index,
            principal_to_neuron_ids_index,
            known_neuron_name_set,

            clock: _,
        } = self;

        *heap_neurons == other.heap_neurons
            && *topic_followee_index == other.topic_followee_index
            && *principal_to_neuron_ids_index == other.principal_to_neuron_ids_index
            && *known_neuron_name_set == other.known_neuron_name_set
    }
}

impl NeuronStore {
    // Initializes NeuronStore for the first time assuming no persisted data has been prepared (e.g.
    // data in stable storage and those persisted through serialization/deserialization like
    // topic_followee_index). If restoring after an upgrade, call NeuronStore::new_restored instead.
    pub fn new(neurons: BTreeMap<u64, Neuron>) -> Self {
        // Initializes a neuron store with no neurons.
        let mut neuron_store = Self {
            heap_neurons: BTreeMap::new(),
            topic_followee_index: HeapNeuronFollowingIndex::new(BTreeMap::new()),
            principal_to_neuron_ids_index: HeapNeuronPrincipalIndex::new(),
            known_neuron_name_set: HashSet::new(),
            clock: Box::new(IcClock::new()),
        };

        // Adds the neurons one by one into neuron store.
        for neuron in neurons.into_values() {
            // We are still relying on `Governance::add_neuron()` to call this method. This will be
            // gone when the stable storage indexes is used and the heap version is retired.
            neuron_store.add_neuron_to_principal_to_neuron_ids_index(
                neuron.id.expect("Neuron must have an id"),
                neuron.principal_ids_with_special_permissions(),
            );
            // We are not adding the neuron into the known_neuron_index even if it has known neuron
            // data. This is somewhat what we want - we can never create a neuron as a known neuron,
            // and it requires a proposal to do so. Ideally, the neuron type accepted by
            // `NeuronStore::new` should not have the known neuron data to begin with.
            neuron_store
                .add_neuron(neuron)
                .expect("Failed to add neuron during initialization");
        }

        neuron_store
    }

    // Restores NeuronStore after an upgrade, assuming data  are already in the stable storage (e.g.
    // neuron indexes and inactive neurons) and persisted data are already calculated (e.g.
    // topic_followee_index).
    pub fn new_restored(
        heap_neurons: BTreeMap<u64, Neuron>,
        topic_followee_index: HeapNeuronFollowingIndex<NeuronIdU64, TopicSigned32>,
    ) -> Self {
        let principal_to_neuron_ids_index = build_principal_to_neuron_ids_index(&heap_neurons);
        let known_neuron_name_set = build_known_neuron_name_index(&heap_neurons);
        let clock = Box::new(IcClock::new());

        Self {
            heap_neurons,
            topic_followee_index,
            principal_to_neuron_ids_index,
            known_neuron_name_set,
            clock,
        }
    }

    /// Takes the heap neurons for serialization. The `self.heap_neurons` will become empty, so
    /// it should only be called once at pre_upgrade.
    pub fn take_heap_neurons(&mut self) -> BTreeMap<u64, Neuron> {
        std::mem::take(&mut self.heap_neurons)
    }

    /// Takes the HeapNeuronFollowingIndex.  The `self.topic_followee_index` will become empty, so
    /// it should only be called once at pre_upgrade.
    pub fn take_heap_topic_followee_index(
        &mut self,
    ) -> HeapNeuronFollowingIndex<NeuronIdU64, TopicSigned32> {
        std::mem::take(&mut self.topic_followee_index)
    }

    /// If there is a bug (related to lock acquisition), this could return u64::MAX.
    fn now(&self) -> u64 {
        self.clock.now()
    }

    pub fn set_time_warp(&mut self, new_time_warp: TimeWarp) {
        self.clock.set_time_warp(new_time_warp);
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

    pub fn clone_topic_followee_index(
        &self,
    ) -> HeapNeuronFollowingIndex<NeuronIdU64, TopicSigned32> {
        self.topic_followee_index.clone()
    }

    /// Returns if store contains a Neuron by id
    pub fn contains(&self, neuron_id: NeuronId) -> bool {
        self.heap_neurons.contains_key(&neuron_id.id)
    }

    /// Get the number of neurons in the Store
    pub fn len(&self) -> usize {
        self.heap_neurons.len()
    }

    /// Add a new neuron
    pub fn add_neuron(&mut self, neuron: Neuron) -> Result<NeuronId, NeuronStoreError> {
        let neuron_id = neuron.id.expect("Neuron must have an id");

        // TODO check stable storage also
        if self.contains(neuron_id) {
            return Err(NeuronStoreError::NeuronAlreadyExists(neuron_id));
        }

        self.add_neuron_to_indexes(&neuron);

        if is_copy_inactive_neurons_to_stable_memory_enabled() {
            maybe_add_to_stable_neuron_store(neuron.clone(), self.clock.now());
        }

        self.heap_neurons.insert(neuron_id.id, neuron);

        Ok(neuron_id)
    }

    fn add_neuron_to_indexes(&mut self, neuron: &Neuron) {
        if let Err(error) = with_stable_neuron_indexes_mut(|indexes| indexes.add_neuron(neuron)) {
            println!(
                "{}WARNING: issues found when adding neuron to indexes, possibly because \
                     neuron indexes are out-of-sync with neurons: {}",
                LOG_PREFIX, error
            );
        }

        if let Err(defects) = self.topic_followee_index.add_neuron(neuron) {
            println!(
                "{}WARNING: issues found when adding neuron to indexes, possibly because \
                 neuron indexes are out-of-sync with neurons: {}",
                LOG_PREFIX,
                NeuronStoreError::CorruptedNeuronIndexes(CorruptedNeuronIndexes {
                    neuron_id: neuron.id.unwrap().id,
                    indexes: vec![defects],
                })
            );
        };
    }

    /// Remove a Neuron by id
    pub fn remove_neuron(&mut self, neuron_id: &NeuronId) {
        let removed_neuron = self.heap_neurons.remove(&neuron_id.id);

        if is_copy_inactive_neurons_to_stable_memory_enabled() {
            delete_from_stable_neuron_store(*neuron_id);
        }

        let removed_neuron = match removed_neuron {
            Some(removed_neuron) => removed_neuron,
            None => {
                println!("WARNING: trying to remove a neuron that does not exist");
                return;
            }
        };

        self.remove_neuron_from_indexes(&removed_neuron);
    }

    fn remove_neuron_from_indexes(&mut self, neuron: &Neuron) {
        let neuron_id = neuron.id.expect("Neuron must have id");
        if let Err(error) = with_stable_neuron_indexes_mut(|indexes| indexes.remove_neuron(neuron))
        {
            println!(
                "{}WARNING: issues found when adding neuron to indexes, possibly because of \
                     neuron indexes are out-of-sync with neurons: {}",
                LOG_PREFIX, error
            );
        }

        if let Err(defects) = self.topic_followee_index.remove_neuron(neuron) {
            println!(
                "{}WARNING: issues found when adding neuron to indexes, possibly because \
                 neuron indexes are out-of-sync with neurons: {}",
                LOG_PREFIX,
                NeuronStoreError::CorruptedNeuronIndexes(CorruptedNeuronIndexes {
                    neuron_id: neuron_id.id,
                    indexes: vec![defects],
                })
            );
        };
    }

    /// Get NeuronId for a particular subaccount.
    pub fn get_neuron_id_for_subaccount(&self, subaccount: Subaccount) -> Option<NeuronId> {
        let neuron_id = if crate::use_neuron_stable_indexes() {
            with_stable_neuron_indexes(|indexes| {
                indexes
                    .subaccount()
                    .get_neuron_id_by_subaccount(&subaccount)
            })
        } else {
            self.heap_neurons
                .values()
                .find(|n| {
                    n.subaccount()
                        .map(|neuron_subaccount| neuron_subaccount == subaccount)
                        .unwrap_or_default()
                })
                .and_then(|n| n.id)
        };
        neuron_id
    }

    pub fn has_neuron_with_subaccount(&self, subaccount: Subaccount) -> bool {
        self.get_neuron_id_for_subaccount(subaccount).is_some()
    }

    /// Get a reference to heap neurons.  Temporary method to allow
    /// access to the heap neurons during transition to better data hiding.
    pub fn heap_neurons(&self) -> &BTreeMap<u64, Neuron> {
        &self.heap_neurons
    }

    fn heap_neurons_iter(&self) -> impl Iterator<Item = &Neuron> {
        self.heap_neurons.values()
    }

    /// Returns Neurons in heap starting with the first one whose ID is >= begin.
    ///
    /// The len of the result is at most limit. It is also maximal; that is, if the return value has
    /// len < limit, then the caller can assume that there are no more Neurons.
    pub fn range_heap_neurons<R>(&self, range: R) -> impl Iterator<Item = Neuron> + '_
    where
        R: RangeBounds<NeuronId>,
    {
        let range = neuron_id_range_to_u64_range(&range);

        self.heap_neurons
            .range(range)
            .map(|(_id, neuron)| neuron.clone())
    }

    /// Internal - map over neurons after filtering
    fn map_heap_neurons_filtered<R>(
        &self,
        filter: impl Fn(&Neuron) -> bool,
        f: impl FnMut(&Neuron) -> R,
    ) -> Vec<R> {
        self.heap_neurons_iter()
            .filter(|n| filter(n))
            .map(f)
            .collect()
    }

    /// List all neuron ids that are in the community fund.
    pub fn list_community_fund_neuron_ids(&self) -> Vec<NeuronId> {
        let filter = |n: &Neuron| {
            n.joined_community_fund_timestamp_seconds
                .unwrap_or_default()
                > 0
        };
        self.map_heap_neurons_filtered(filter, |n| n.id)
            .into_iter()
            .flatten()
            .collect()
    }

    /// List all neuron ids that are in the community fund.
    pub fn list_active_neurons_fund_neurons(&self) -> Vec<NeuronsFundNeuron> {
        let now = self.now();
        let filter = |n: &Neuron| {
            !n.is_inactive(now)
                && n.joined_community_fund_timestamp_seconds
                    .unwrap_or_default()
                    > 0
        };
        self.map_heap_neurons_filtered(filter, |n| NeuronsFundNeuron {
            id: n.id.unwrap(),
            controller: n.controller.unwrap(),
            maturity_equivalent_icp_e8s: n.maturity_e8s_equivalent,
        })
        .into_iter()
        .collect()
    }

    /// List all neuron ids whose neurons have staked maturity greater than 0.
    pub fn list_neurons_ready_to_unstake_maturity(&self, now_seconds: u64) -> Vec<NeuronId> {
        let filter = |neuron: &Neuron| neuron.ready_to_unstake_maturity(now_seconds);
        self.map_heap_neurons_filtered(filter, |neuron| neuron.id)
            .into_iter()
            .flatten()
            .collect()
    }

    /// List all neuron ids of known neurons
    pub fn list_known_neuron_ids(&self) -> Vec<NeuronId> {
        if crate::use_neuron_stable_indexes() {
            with_stable_neuron_indexes(|indexes| indexes.known_neuron().list_known_neuron_ids())
        } else {
            let filter = |n: &Neuron| n.known_neuron_data.is_some();
            self.map_heap_neurons_filtered(filter, |n| n.id)
                .into_iter()
                .flatten()
                .collect()
        }
    }

    /// List all neurons that are spawning
    pub fn list_ready_to_spawn_neuron_ids(&self, now_seconds: u64) -> Vec<NeuronId> {
        let filter = |n: &Neuron| {
            let spawning_state = n.state(now_seconds) == NeuronState::Spawning;
            if !spawning_state {
                return false;
            }
            // spawning_state is calculated based on presence of spawn_at_atimestamp_seconds
            // so it would be quite surprising if it is missing here (impossible in fact)
            now_seconds >= n.spawn_at_timestamp_seconds.unwrap_or(u64::MAX)
        };
        self.map_heap_neurons_filtered(filter, |n| n.id)
            .into_iter()
            .flatten()
            .collect()
    }

    /// Returns an iterator of all voting-eligible neurons
    pub fn voting_eligible_neurons(&self, now_seconds: u64) -> impl Iterator<Item = &Neuron> {
        // This should be safe to do without with_neuron because
        // all voting_eligible neurons should be in the heap
        self.heap_neurons_iter().filter(move |&neuron| {
            neuron.dissolve_delay_seconds(now_seconds)
                >= MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS
        })
    }

    /// Execute a function with a mutable reference to a neuron, returning the result of the function,
    /// unless the neuron is not found
    pub fn with_neuron_mut<R>(
        &mut self,
        neuron_id: &NeuronId,
        f: impl FnOnce(&mut Neuron) -> R,
    ) -> Result<R, NeuronStoreError> {
        let now = self.now();
        let old_neuron = self
            .heap_neurons
            .get(&neuron_id.id)
            .cloned()
            .ok_or_else(|| NeuronStoreError::not_found(neuron_id))?;

        // Clone and call f() to possibly modify the neuron.
        let mut new_neuron = old_neuron.clone();

        // TODO(NNS1-2584): let was_inactive_before = neuron.is_inactive(self.now());
        // TODO(NNS1-2582): let original_neuron = neuron.clone()

        let result = Ok(f(&mut new_neuron));

        // Update stable_neuron_store. For now, this functionality is disabled by default. It is
        // enabled when building tests, and when feature = "test" is enabled.
        if is_copy_inactive_neurons_to_stable_memory_enabled() {
            write_through_to_stable_neuron_store(&new_neuron, now);
        }

        self.update_neuron_indexes(&old_neuron, &new_neuron);

        // TODO switch to stable storage in the neuron is inactive and vice versa
        self.heap_neurons.insert(neuron_id.id, new_neuron);

        result
    }

    /// Internal function to update neuron indexes when an existing neuron is changed.
    /// Each index is responsible for its own change detection (i.e. if the change should cause
    ///  and update in the index)
    fn update_neuron_indexes(&mut self, old_neuron: &Neuron, new_neuron: &Neuron) {
        // Update indexes by passing in both old and new versions of neuron.
        if let Err(error) =
            with_stable_neuron_indexes_mut(|indexes| indexes.update_neuron(old_neuron, new_neuron))
        {
            println!(
                "{}WARNING: issues found when updating neuron indexes, possibly because of \
                 neuron indexes are out-of-sync with neurons: {}",
                LOG_PREFIX, error
            );
        }

        if let Err(defects) = self
            .topic_followee_index
            .update_neuron(old_neuron, new_neuron)
        {
            println!(
                "{}WARNING: issues found when updating neuron indexes, possibly because of \
                 neuron indexes are out-of-sync with neurons: {}",
                LOG_PREFIX,
                NeuronStoreError::CorruptedNeuronIndexes(CorruptedNeuronIndexes {
                    neuron_id: old_neuron.id.unwrap().id,
                    indexes: defects,
                })
            );
        };
    }

    /// Execute a function with a reference to a neuron, returning the result of the function,
    /// unless the neuron is not found
    pub fn with_neuron<R>(
        &self,
        neuron_id: &NeuronId,
        f: impl FnOnce(&Neuron) -> R,
    ) -> Result<R, NeuronStoreError> {
        let neuron = self
            .heap_neurons
            .get(&neuron_id.id)
            .ok_or_else(|| NeuronStoreError::not_found(neuron_id))?;
        Ok(f(neuron))
    }

    /// Does what the name says: copies inactive Neurons from heap to stable memory.
    ///
    /// Why not pass (begin, size) instead of batch: Unfortunately, it is not enough to have the
    /// Neuron itself (available here) in order to determine whether it is active or not. Rather,
    /// there are a couple other pieces of data that are needed: locks and open proposals. These are
    /// not available in NeuronStore; Governance has them.
    ///
    /// As a result, batch is constructed by the caller (Governance), since it has the
    /// aforementioned needed supporting auxiliary data. Of course, to do this, Governance still
    /// needs some help from self to scan a range of heap neurons based on begin, and limit
    /// (i.e. batch size). That functionality is provided by heap_neurons_range_with_begin_and_limit
    pub(crate) fn batch_add_inactive_neurons_to_stable_memory(
        &mut self,
        batch: Vec<(Neuron, /* is_inactive */ bool)>,
    ) -> Result<Option<NeuronId>, String> {
        // TODO: Make this owned by self, and stop accessing accessing data via global. There is
        // no known way to do this right now, because StableBTreeMap is used, and it is not
        // Send.
        with_stable_neuron_store_mut(|stable_neuron_store| {
            let batch_len = batch.len();

            let mut new_last_neuron_id = None; // result/work tracker

            // The actual/main work itself.
            let mut copy_count = 0;
            for (neuron, is_inactive) in batch {
                // Track the work that is about to be performed.
                new_last_neuron_id = neuron.id;

                if !is_inactive {
                    // TODO(NNS1-2493): We could try to delete neuron from stable_neuron_store, but
                    // it should already not be there. A neuron might already be in
                    // stable_neuron_store if it was previously active, but is now
                    // inactive. However, in that case, the mutation that caused it to go from
                    // active to inactive is responsible for deleting the neuron from
                    // stable_neuron_store. This is where we can double check that such
                    // responsibilities were actually fulfilled.
                    continue;
                }
                copy_count += 1;

                // TODO(NNS1-2493): If neuron is already in stable_neuron_store, then it should be
                // equivalent to the one we have here. If it isn't, that's a bug, because any
                // mutation of the neuron that later took place is responsible for writing it
                // through to stable_neuron_store, like above.

                stable_neuron_store
                    // Here, upsert is used instead of create, because it is possible that online
                    // copying already copied neuron to stable_neuron_store, and in that case, we do
                    // not want to trigger the Err behavior of create.
                    .upsert(neuron) // The real work takes place here.
                    .map_err(|governance_err| {
                        // TODO(NNS1-2493): Increment an error counter metric, since this should
                        // never happen. Also, alert on it, and have it notify NNS team via Slack,
                        // not page FITS team, since this does not indicate that operators need to
                        // quickly intervene. Rather, it is a bug that developers (i.e. NNS team)
                        // should be made aware of, investigate, and fix.
                        governance_err.to_string()
                    })?;
            }
            // TODO(NNS1-2493): Don't just log this: increment a metric (or maybe do that from
            // within the loop instead of after?).
            println!(
                "{} out of {} Neruons in batch were inactive/copied",
                copy_count, batch_len
            );

            Ok(new_last_neuron_id)
        })
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
            .get_followers_by_followee_and_category(
                &NeuronIdU64::from(followee),
                TopicSigned32::from(topic),
            )
            .into_iter()
            .map(|id| NeuronId { id })
            .collect()
    }

    // Gets all neuron ids associated with the given principal id (hot-key or controller).
    pub fn get_neuron_ids_readable_by_caller(
        &self,
        principal_id: PrincipalId,
    ) -> HashSet<NeuronId> {
        if crate::use_neuron_stable_indexes() {
            with_stable_neuron_indexes(|indexes| {
                indexes
                    .principal()
                    .get_neuron_ids(principal_id)
                    .into_iter()
                    .map(|id| NeuronId { id })
                    .collect()
            })
        } else {
            self.principal_to_neuron_ids_index
                .get_neuron_ids(principal_id)
        }
    }

    // Returns whether the known neuron name already exists.
    pub fn contains_known_neuron_name(&self, known_neuron_name: &str) -> bool {
        if crate::use_neuron_stable_indexes() {
            with_stable_neuron_indexes(|indexes| {
                indexes
                    .known_neuron()
                    .contains_known_neuron_name(known_neuron_name)
            })
        } else {
            self.known_neuron_name_set.contains(known_neuron_name)
        }
    }

    // Census

    pub fn stable_neuron_store_len(&self) -> u64 {
        with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.len())
    }

    pub fn stable_indexes_lens(&self) -> NeuronIndexesLens {
        with_stable_neuron_indexes_mut(|indexes| NeuronIndexesLens {
            subaccount: indexes.subaccount().num_entries(),
            principal: indexes.principal().num_entries(),
            following: indexes.following().num_entries(),
            known_neuron: indexes.known_neuron().num_entries(),
        })
    }
}

/// Number of entries for each neuron indexes (in stable storage)
pub struct NeuronIndexesLens {
    pub subaccount: usize,
    pub principal: usize,
    pub following: usize,
    pub known_neuron: usize,
}

fn maybe_add_to_stable_neuron_store(neuron: Neuron, now: u64) {
    if !neuron.is_inactive(now) {
        return;
    }
    let insert_result =
        with_stable_neuron_store_mut(|stable_neuron_store| stable_neuron_store.create(neuron));
    if let Err(err) = insert_result {
        // TODO(NNS1-2493): Increment some error metric.
        println!(
            "{}ERROR: Failed to add inactive Neuron in stable_neuron_store: {}",
            LOG_PREFIX, err,
        );
    }
}

fn delete_from_stable_neuron_store(neuron_id: NeuronId) {
    // Since the neuron can go from active to inactive through the passage of time, when it's
    // inactive now, it can also not exist in stable neuron store as it was active the last time.
    // Therefore we have to ignore the result.
    let _ignore_result =
        with_stable_neuron_store_mut(|stable_neuron_store| stable_neuron_store.delete(neuron_id));
}

fn write_through_to_stable_neuron_store(neuron: &Neuron, now: u64) {
    let neuron_id = match neuron.id {
        Some(ok) => ok,
        None => {
            println!(
                "{}ERROR: Tried to write through a Neuron that has no ID to \
                 StableNeuronStore:\n{:#?}",
                LOG_PREFIX, neuron,
            );

            // TODO(NNS1-2493): Increment some error metric.

            return;
        }
    };

    if neuron.is_inactive(now) {
        // TODO(NNS1-2584): Once a full copy sweep of inactive Neuron copying has been
        // performed, then we can use was_inactive_before to know precisely whether we
        // should be calling create or update here (instead of upsert), and expect Ok is
        // returned. Before a full copy sweep has been performed, we have to instead use
        // more the "permissive" upsert method, because it is not necessary wrong that the
        // Neuron was not already in stable_neuron_store.
        let upsert_result = with_stable_neuron_store_mut(|stable_neuron_store| {
            stable_neuron_store.upsert(neuron.clone())
        });
        if let Err(err) = upsert_result {
            // TODO(NNS1-2493): Increment some error metric.
            println!(
                "{}ERROR: Failed to update inactive Neuron in stable_neuron_store: {}",
                LOG_PREFIX, err,
            );
        }
    // neuron is active. Therefore, it should not be in StableNeuronStore (anymore).
    } else {
        // TODO(NNS1-2584): Once a full sweep of inactive Neuron copying has been performed,
        // then we can expect that delete returns Ok or Err, depending on
        // was_inactive_before. Before a full copy sweep has been performed, it is not feasible
        // to determine whether the Neuron should have been there or not.
        let _ignore_result = with_stable_neuron_store_mut(|stable_neuron_store| {
            stable_neuron_store.delete(neuron_id)
        });
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

fn build_known_neuron_name_index(heap_neurons: &BTreeMap<u64, Neuron>) -> HashSet<String> {
    let mut index = HashSet::new();
    for neuron in heap_neurons.values() {
        if let Some(known_neuron_data) = &neuron.known_neuron_data {
            index.insert(known_neuron_data.name.clone());
        }
    }
    index
}

#[cfg(test)]
mod neuron_store_tests;
