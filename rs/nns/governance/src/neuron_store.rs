use crate::{
    governance::{Environment, LOG_PREFIX, MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS},
    is_copy_inactive_neurons_to_stable_memory_enabled,
    neuron::neuron_id_range_to_u64_range,
    pb::v1::{
        governance::{
            migration::{MigrationStatus, Progress},
            Migration,
        },
        governance_error::ErrorType,
        GovernanceError, Neuron, NeuronState, Topic,
    },
    storage::{neuron_indexes::CorruptedNeuronIndexes, NEURON_INDEXES, STABLE_NEURON_STORE},
};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
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
use icp_ledger::Subaccount;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt::{Display, Formatter},
    ops::RangeBounds,
};

// TODO(NNS1-2417): tune this before starting migration.
const NEURON_INDEXES_MIGRATION_BATCH_SIZE: usize = 1000;

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
    topic_followee_index: HeapNeuronFollowingIndex<NeuronId, Topic>,

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

    /// Neuron indexes migration state.
    indexes_migration: Migration,
}

impl NeuronStore {
    pub fn new(
        heap_neurons: BTreeMap<u64, Neuron>,
        topic_followee_index: Option<HeapNeuronFollowingIndex<NeuronId, Topic>>,
        indexes_migration: Migration,
    ) -> Self {
        // As an intermediate state, this may not be available post_upgrade.
        let topic_followee_index =
            topic_followee_index.unwrap_or_else(|| build_topic_followee_index(&heap_neurons));

        let principal_to_neuron_ids_index = build_principal_to_neuron_ids_index(&heap_neurons);
        let known_neuron_name_set = build_known_neuron_name_index(&heap_neurons);

        Self {
            heap_neurons,
            topic_followee_index,
            principal_to_neuron_ids_index,
            known_neuron_name_set,
            indexes_migration,
        }
    }

    #[cfg(test)]
    pub fn new_for_test(heap_neurons: Vec<Neuron>) -> Self {
        let mut neuron_store = Self::new(
            heap_neurons
                .into_iter()
                .map(|neuron| (neuron.id.unwrap().id, neuron))
                .collect(),
            None,
            Migration {
                status: Some(MigrationStatus::Succeeded as i32),
                failure_reason: None,
                progress: None,
            },
        );
        assert_eq!(
            neuron_store
                .batch_add_heap_neurons_to_stable_indexes(NeuronId { id: 0 }, u64::MAX as usize)
                .unwrap(),
            None
        );
        neuron_store
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
        let neuron_id = neuron.id.expect("Neuron must have an id");

        if Self::is_indexes_migrated_for_neuron(&self.indexes_migration, neuron_id) {
            if let Err(error) =
                NEURON_INDEXES.with(|indexes| indexes.borrow_mut().add_neuron(&neuron))
            {
                println!(
                    "{}WARNING: issues found when adding neuron to indexes, possibly because of \
                     neuron indexes are out-of-sync with neurons: {}",
                    LOG_PREFIX, error
                );
            }
        }

        self.heap_neurons.insert(neuron_id.id, neuron);
    }

    /// Remove a Neuron by id
    pub fn remove(&mut self, neuron_id: &NeuronId) {
        let removed_neuron = self.heap_neurons.remove(&neuron_id.id);

        let removed_neuron = match removed_neuron {
            Some(removed_neuron) => removed_neuron,
            None => {
                println!("WARNING: trying to remove a neuron that does not exist");
                return;
            }
        };

        if Self::is_indexes_migrated_for_neuron(&self.indexes_migration, *neuron_id) {
            if let Err(error) =
                NEURON_INDEXES.with(|indexes| indexes.borrow_mut().remove_neuron(&removed_neuron))
            {
                println!(
                    "{}WARNING: issues found when adding neuron to indexes, possibly because of \
                     neuron indexes are out-of-sync with neurons: {}",
                    LOG_PREFIX, error
                );
            }
        }
    }

    /// Get NeuronId for a particular subaccount.
    pub fn get_neuron_id_for_subaccount(&self, subaccount: Subaccount) -> Option<NeuronId> {
        self.heap_neurons
            .values()
            .find(|n| {
                n.subaccount()
                    .map(|neuron_subaccount| neuron_subaccount == subaccount)
                    .unwrap_or_default()
            })
            .and_then(|n| n.id)
    }

    pub fn has_neuron_with_subaccount(&self, subaccount: Subaccount) -> bool {
        self.get_neuron_id_for_subaccount(subaccount).is_some()
    }

    /// Get a reference to heap neurons.  Temporary method to allow
    /// access to the heap neurons during transition to better data hiding.
    pub fn heap_neurons(&self) -> &BTreeMap<u64, Neuron> {
        &self.heap_neurons
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
        self.heap_neurons
            .values()
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
    pub fn list_active_neurons_fund_neurons_with_maturity_e8s_equivalent(
        &self,
        is_neuron_inactive: impl Fn(&Neuron) -> bool,
    ) -> Vec<(Option<NeuronId>, u64, Option<PrincipalId>)> {
        let filter = |n: &Neuron| {
            !is_neuron_inactive(n)
                && n.joined_community_fund_timestamp_seconds
                    .unwrap_or_default()
                    > 0
        };
        self.map_heap_neurons_filtered(filter, |n| (n.id, n.maturity_e8s_equivalent, n.controller))
            .into_iter()
            .collect()
    }

    /// List all neuron ids whose neurons have staked maturity greater than 0.
    pub fn list_staked_maturity_neuron_ids(&self) -> Vec<NeuronId> {
        let filter = |n: &Neuron| n.staked_maturity_e8s_equivalent.unwrap_or_default() > 0;
        self.map_heap_neurons_filtered(filter, |n| n.id)
            .into_iter()
            .flatten()
            .collect()
    }

    /// List all neuron ids of known neurons
    pub fn list_known_neuron_ids(&self) -> Vec<NeuronId> {
        let filter = |n: &Neuron| n.known_neuron_data.is_some();
        self.map_heap_neurons_filtered(filter, |n| n.id)
            .into_iter()
            .flatten()
            .collect()
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

    /// Execute a function against each voting eligible neuron
    pub fn map_voting_eligible_neurons<R>(
        &self,
        now_seconds: u64,
        mut f: impl FnMut(&Neuron) -> R,
    ) -> Vec<R> {
        let filter = |n: &Neuron| {
            n.dissolve_delay_seconds(now_seconds) >= MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS
        };

        // This should be safe to do without with_neuron because
        // all voting_eligible neurons should be in the heap
        self.map_heap_neurons_filtered(filter, |neuron| f(neuron))
    }

    /// Execute a function with a mutable reference to a neuron, returning the result of the function,
    /// unless the neuron is not found
    pub fn with_neuron_mut<R>(
        &mut self,
        neuron_id: &NeuronId,
        is_neuron_inactive: impl Fn(&Neuron) -> bool,
        f: impl FnOnce(&mut Neuron) -> R,
    ) -> Result<R, NeuronStoreError> {
        let old_neuron = self
            .heap_neurons
            .get_mut(&neuron_id.id)
            .ok_or_else(|| NeuronStoreError::not_found(neuron_id))?;

        // Clone and call f() to possibly modify the neuron.
        let mut new_neuron = old_neuron.clone();

        // TODO(NNS1-2584): let was_inactive_before = is_neuron_inactive(neuron);
        // TODO(NNS1-2582): let original_neuron = neuron.clone()

        let result = Ok(f(&mut new_neuron));

        // Update STABLE_NEURON_STORE. For now, this functionality is disabled by default. It is
        // enabled when building tests, and when feature = "test" is enabled.
        if is_copy_inactive_neurons_to_stable_memory_enabled() {
            write_through_to_stable_neuron_store(is_neuron_inactive, &new_neuron);
        }

        // Update indexes by passing in both old and new versions of neuron.
        if Self::is_indexes_migrated_for_neuron(&self.indexes_migration, *neuron_id) {
            if let Err(error) = NEURON_INDEXES
                .with(|indexes| indexes.borrow_mut().update_neuron(old_neuron, &new_neuron))
            {
                println!(
                    "{}WARNING: issues found when updating neuron indexes, possibly because of \
                 neuron indexes are out-of-sync with neurons: {}",
                    LOG_PREFIX, error
                );
            }
        }

        *old_neuron = new_neuron;

        result
    }

    fn is_indexes_migrated_for_neuron(indexes_migration: &Migration, neuron_id: NeuronId) -> bool {
        match indexes_migration.migration_status() {
            MigrationStatus::Unspecified => false,
            MigrationStatus::InProgress => match indexes_migration.progress {
                Some(Progress::LastNeuronId(last_neuron_id)) => neuron_id <= last_neuron_id,
                None => {
                    eprintln!("{}Neuron index migration progress is wrong", LOG_PREFIX);
                    false
                }
            },
            MigrationStatus::Succeeded => true,
            // Some intervention is needed when it failed, so although some neurons are migrated, we
            // do not keep updating the indexes.
            MigrationStatus::Failed => false,
        }
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

    pub(crate) fn maybe_batch_add_heap_neurons_to_stable_indexes(&mut self) -> Migration {
        let migration = &self.indexes_migration;
        let last_neuron_id = match migration.migration_status() {
            MigrationStatus::Unspecified => NeuronId { id: 0 },
            MigrationStatus::InProgress => match migration.progress {
                Some(Progress::LastNeuronId(last_neuron_id)) => last_neuron_id,
                None => {
                    eprintln!("{}Neuron index migration progress is wrong", LOG_PREFIX);
                    return migration.clone();
                }
            },
            _ => return migration.clone(),
        };

        let result = self.batch_add_heap_neurons_to_stable_indexes(
            last_neuron_id,
            NEURON_INDEXES_MIGRATION_BATCH_SIZE,
        );

        let new_migration = match result {
            Err(failure_reason) => Migration {
                status: Some(MigrationStatus::Failed as i32),
                failure_reason: Some(failure_reason),
                progress: None,
            },
            Ok(Some(new_last_neuron_id)) => Migration {
                status: Some(MigrationStatus::InProgress as i32),
                failure_reason: None,
                progress: Some(Progress::LastNeuronId(new_last_neuron_id)),
            },
            Ok(None) => Migration {
                status: Some(MigrationStatus::Succeeded as i32),
                failure_reason: None,
                progress: None,
            },
        };

        self.indexes_migration = new_migration.clone();
        new_migration
    }

    /// For heap neurons starting from `last_neuron_id + 1` where `last_neuron_id` is the last
    /// neuron id that has been migrated, and it adds at most `batch_size` of them into stable
    /// storage indexes. It is an undefined behavior if `last_neuron_id` passed in was not returned
    /// by the one returned by the same function.
    ///
    /// Returns `Err(failure_reason)` if it failed; returns Ok(None) if the cursor reaches the end;
    /// returns `Ok(last_neuron_id)` if the cursor has not reached the end.
    ///
    /// Note that a Neuron with id 0 will never be scan, and it's OK because it is not a valid id.
    fn batch_add_heap_neurons_to_stable_indexes(
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
            NEURON_INDEXES
                .with(|indexes| indexes.borrow_mut().add_neuron(neuron))
                .map_err(|error| GovernanceError::from(error).error_message)?;
            count += 1;
            new_last_neuron_id = Some(NeuronId { id: *neuron_id });
        }

        if count < batch_size {
            // No more neurons to migrate
            new_last_neuron_id = None
        }
        Ok(new_last_neuron_id)
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
    ///
    // Alternatively, we could have caller (Governance) pass the auxilliary data. Even better if
    // this took a lambda (named is_neuron_inactive) that captures the necessary auxiliary data from
    // Governance. need-to-know basis for the win!
    #[allow(dead_code)]
    pub(crate) fn batch_add_inactive_neurons_to_stable_memory(
        &mut self,
        batch: Vec<(Neuron, /* is_inactive */ bool)>,
    ) -> Result<Option<NeuronId>, String> {
        // TODO: Make this owned by self, and stop accessing accessing data via global. There is
        // no known way to do this right now, because StableBTreeMap is used, and it is not
        // Send.
        STABLE_NEURON_STORE.with(|stable_neuron_store| {
            let mut stable_neuron_store = stable_neuron_store.borrow_mut();

            let mut new_last_neuron_id = None; // result/work tracker

            // The actual/main work itself.
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

    pub fn stable_indexes_lens(&self) -> NeuronIndexesLens {
        NEURON_INDEXES.with(|indexes| {
            let indexes = indexes.borrow();
            NeuronIndexesLens {
                subaccount: indexes.subaccount().num_entries(),
                principal: indexes.principal().num_entries(),
                following: indexes.following().num_entries(),
                known_neuron: indexes.known_neuron().num_entries(),
            }
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

fn write_through_to_stable_neuron_store(
    is_neuron_inactive: impl Fn(&Neuron) -> bool,
    neuron: &Neuron,
) {
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

    if is_neuron_inactive(neuron) {
        // TODO(NNS1-2584): Once a full copy sweep of inactive Neuron copying has been
        // performed, then we can use was_inactive_before to know precisely whether we
        // should be calling create or update here (instead of upsert), and expect Ok is
        // returned. Before a full copy sweep has been performed, we have to instead use
        // more the "permissive" upsert method, because it is not necessary wrong that the
        // Neuron was not already in stable_neuron_store.
        let upsert_result = STABLE_NEURON_STORE
            .with(|stable_neuron_store| stable_neuron_store.borrow_mut().upsert(neuron.clone()));
        if let Err(err) = upsert_result {
            // TODO(NNS1-2493): Increment some error metric.
            println!(
                "{}ERROR: Failed to update inactive Neuron in STABLE_NEURON_STORE: {}",
                LOG_PREFIX, err,
            );
        }
    // neuron is active. Therefore, it should not be in StableNeuronStore (anymore).
    } else {
        // TODO(NNS1-2584): Once a full sweep of inactive Neuron copying has been performed,
        // then we can expect that delete returns Ok or Err, depending on
        // was_inactive_before. Before a full copy sweep has been performed, it is not feasible
        // to determine whether the Neuron should have been there or not.
        let _ignore_result = STABLE_NEURON_STORE
            .with(|stable_neuron_store| stable_neuron_store.borrow_mut().delete(neuron_id));
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
