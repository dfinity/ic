use crate::{
    governance::{
        Environment, TimeWarp, LOG_PREFIX, MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
    },
    neuron::{neuron_id_range_to_u64_range, types::Neuron},
    neurons_fund::neurons_fund_neuron::pick_most_important_hotkeys,
    pb::v1::{
        governance::{followers_map::Followers, FollowersMap},
        governance_error::ErrorType,
        GovernanceError, Neuron as NeuronProto, NeuronState, Topic,
    },
    storage::{
        neuron_indexes::{CorruptedNeuronIndexes, NeuronIndex},
        neurons::NeuronSections,
        with_stable_neuron_indexes, with_stable_neuron_indexes_mut, with_stable_neuron_store,
        with_stable_neuron_store_mut,
    },
    Clock, IcClock,
};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use dyn_clone::DynClone;
use ic_base_types::PrincipalId;
use ic_nervous_system_governance::index::{
    neuron_following::{HeapNeuronFollowingIndex, NeuronFollowingIndex},
    neuron_principal::NeuronPrincipalIndex,
};
use ic_nns_common::pb::v1::NeuronId;
use icp_ledger::{AccountIdentifier, Subaccount};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet},
    fmt::{Debug, Display, Formatter},
    ops::{Deref, RangeBounds},
};

pub mod metrics;
pub(crate) use metrics::NeuronMetrics;

#[derive(Eq, PartialEq, Debug)]
pub enum NeuronStoreError {
    NeuronNotFound {
        neuron_id: NeuronId,
    },
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
    InvalidData {
        reason: String,
    },
    NotAuthorizedToGetFullNeuron {
        principal_id: PrincipalId,
        neuron_id: NeuronId,
    },
}

impl NeuronStoreError {
    pub fn not_found(neuron_id: NeuronId) -> Self {
        NeuronStoreError::NeuronNotFound { neuron_id }
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

    pub fn not_authorized_to_get_full_neuron(
        principal_id: PrincipalId,
        neuron_id: NeuronId,
    ) -> Self {
        NeuronStoreError::NotAuthorizedToGetFullNeuron {
            principal_id,
            neuron_id,
        }
    }
}

impl Display for NeuronStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NeuronStoreError::NeuronNotFound { neuron_id } => {
                write!(f, "Neuron not found: {:?}", neuron_id)
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
            NeuronStoreError::InvalidData { reason } => {
                write!(f, "Failed to store neuron with invalid data: {:?}", reason)
            }
            NeuronStoreError::NotAuthorizedToGetFullNeuron {
                principal_id,
                neuron_id,
            } => {
                write!(
                    f,
                    "Principal {:?} is not authorized to get full neuron information for neuron {:?}",
                    principal_id, neuron_id
                )
            }
        }
    }
}

impl From<NeuronStoreError> for GovernanceError {
    fn from(value: NeuronStoreError) -> Self {
        let error_type = match &value {
            NeuronStoreError::NeuronNotFound { .. } => ErrorType::NotFound,
            NeuronStoreError::CorruptedNeuronIndexes(_) => ErrorType::PreconditionFailed,
            NeuronStoreError::NeuronIdIsNone => ErrorType::PreconditionFailed,
            NeuronStoreError::InvalidSubaccount { .. } => ErrorType::PreconditionFailed,
            NeuronStoreError::NeuronIdModified { .. } => ErrorType::PreconditionFailed,
            NeuronStoreError::SubaccountModified { .. } => ErrorType::PreconditionFailed,
            NeuronStoreError::NeuronAlreadyExists(_) => ErrorType::PreconditionFailed,
            NeuronStoreError::InvalidData { .. } => ErrorType::PreconditionFailed,
            NeuronStoreError::NotAuthorizedToGetFullNeuron { .. } => ErrorType::NotAuthorized,
        };
        GovernanceError::new_with_message(error_type, value.to_string())
    }
}

trait PracticalClock: Clock + Send + Sync + Debug + DynClone {}
dyn_clone::clone_trait_object!(PracticalClock);

impl PracticalClock for IcClock {}

/// This structure represents a whole Neuron's Fund neuron.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct NeuronsFundNeuron {
    pub id: NeuronId,
    pub maturity_equivalent_icp_e8s: u64,
    pub controller: PrincipalId,
    pub hotkeys: Vec<PrincipalId>,
}

enum StorageLocation {
    Heap,
    Stable,
}

pub type NeuronStoreState = (BTreeMap<u64, NeuronProto>, HashMap<i32, FollowersMap>);

fn proto_to_heap_topic_followee_index(
    proto: HashMap<i32, FollowersMap>,
) -> HeapNeuronFollowingIndex<NeuronId, Topic> {
    let map = proto
        .into_iter()
        .map(|(topic_i32, followers_map)| {
            // The potential panic is OK to be called in post_upgrade.
            let topic = Topic::try_from(topic_i32).expect("Invalid topic");

            let followers_map = followers_map
                .followers_map
                .into_iter()
                .map(|(neuron_id, followers)| {
                    let followers = followers.followers.into_iter().collect();
                    (NeuronId { id: neuron_id }, followers)
                })
                .collect();
            (topic, followers_map)
        })
        .collect();
    HeapNeuronFollowingIndex::new(map)
}

fn heap_topic_followee_index_to_proto(
    heap: HeapNeuronFollowingIndex<NeuronId, Topic>,
) -> HashMap<i32, FollowersMap> {
    heap.into_inner()
        .into_iter()
        .map(|(topic, followers_map)| {
            let topic_i32 = topic as i32;
            let followers_map = followers_map
                .into_iter()
                .map(|(followee, followers)| {
                    let followers = Followers {
                        followers: followers.into_iter().collect(),
                    };
                    (followee.id, followers)
                })
                .collect();

            let followers_map = FollowersMap { followers_map };

            (topic_i32, followers_map)
        })
        .collect()
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
    /// - computing cached entries: when it involves neurons, it mostly cares about stake, maturity
    ///   and NF fund.
    /// - validating indexes by checking whether each neuron in the heap has corresponding entries
    ///   in the indexes.
    /// - `Governance::validate`: soon to be deprecated since we have subaccount index.
    /// - `voting_eligible_neurons()`: inactive neurons have been dissolved for 14 days, so it
    ///   cannot be voting eligible.
    /// - `list_active_neurons_fund_neurons`: inactive neurons must not be NF.
    /// - `list_neurons_ready_to_unstake_maturity`: inactive neurons have 0 stake (which also means
    ///   0 staked maturity), so no inactive neurons need to unstake maturity.
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
    topic_followee_index: HeapNeuronFollowingIndex<NeuronId, Topic>,

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
            clock: _,
        } = self;

        *heap_neurons == other.heap_neurons && *topic_followee_index == other.topic_followee_index
    }
}

impl Default for NeuronStore {
    fn default() -> Self {
        Self {
            heap_neurons: BTreeMap::new(),
            topic_followee_index: HeapNeuronFollowingIndex::new(BTreeMap::new()),
            clock: Box::new(IcClock::new()),
        }
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
            clock: Box::new(IcClock::new()),
        };

        // Adds the neurons one by one into neuron store.
        for neuron in neurons.into_values() {
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

    // Restores NeuronStore after an upgrade, assuming data are already in the stable storage (e.g.
    // neuron indexes and inactive neurons) and persisted data are already calculated (e.g.
    // topic_followee_index).
    pub fn new_restored(state: NeuronStoreState) -> Self {
        let clock = Box::new(IcClock::new());
        let (neurons, topic_followee_index) = state;

        Self {
            heap_neurons: neurons
                .into_iter()
                .map(|(id, proto)| (id, Neuron::try_from(proto).unwrap()))
                .collect(),
            topic_followee_index: proto_to_heap_topic_followee_index(topic_followee_index),
            clock,
        }
    }

    /// Takes the neuron store state which should be persisted through upgrades.
    pub fn take(self) -> NeuronStoreState {
        (
            self.heap_neurons
                .into_iter()
                .map(|(id, neuron)| (id, neuron.into()))
                .collect(),
            heap_topic_followee_index_to_proto(self.topic_followee_index),
        )
    }

    /// If there is a bug (related to lock acquisition), this could return u64::MAX.
    pub fn now(&self) -> u64 {
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
    pub fn clone_neurons(&self) -> BTreeMap<u64, NeuronProto> {
        self.heap_neurons
            .iter()
            .map(|(id, neuron)| (*id, neuron.clone().into()))
            .collect()
    }

    pub fn clone_topic_followee_index(&self) -> HashMap<i32, FollowersMap> {
        heap_topic_followee_index_to_proto(self.topic_followee_index.clone())
    }

    /// Returns if store contains a Neuron by id
    pub fn contains(&self, neuron_id: NeuronId) -> bool {
        let in_heap = self.heap_neurons.contains_key(&neuron_id.id);
        let in_stable =
            with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.contains(neuron_id));
        in_heap || in_stable
    }

    /// Get the number of neurons in the Store
    pub fn len(&self) -> usize {
        let heap_len = self.heap_neurons.len();
        let stable_len = with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.len());
        heap_len + stable_len
    }

    /// Add a new neuron
    pub fn add_neuron(&mut self, neuron: Neuron) -> Result<NeuronId, NeuronStoreError> {
        let neuron_id = neuron.id();

        if self.contains(neuron_id) {
            return Err(NeuronStoreError::NeuronAlreadyExists(neuron_id));
        }

        if neuron.is_inactive(self.now()) {
            // Write as primary copy in stable storage.
            with_stable_neuron_store_mut(|stable_neuron_store| {
                stable_neuron_store.create(neuron.clone())
            })?;
        } else {
            // Write as primary copy in heap.
            self.heap_neurons.insert(neuron_id.id, neuron.clone());
        }

        // Write to indexes after writing to primary storage as the write to primary storage can
        // fail.
        self.add_neuron_to_indexes(&neuron);

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
                    neuron_id: neuron.id(),
                    indexes: vec![defects],
                })
            );
        };
    }

    /// Remove a Neuron by id
    pub fn remove_neuron(&mut self, neuron_id: &NeuronId) {
        let load_neuron_result = self.load_neuron_all_sections(*neuron_id);
        let (neuron_to_remove, primary_location) = match load_neuron_result {
            Ok(load_neuron_result) => load_neuron_result,
            Err(error) => {
                println!(
                    "{}WARNING: cannot find neuron {:?} while trying to remove it: {}",
                    LOG_PREFIX, *neuron_id, error
                );
                return;
            }
        };

        let neuron_to_remove = neuron_to_remove.deref().clone();

        match primary_location {
            StorageLocation::Heap => {
                // Remove its primary copy.
                self.heap_neurons.remove(&neuron_id.id);
            }
            StorageLocation::Stable => {
                let _remove_result = with_stable_neuron_store_mut(|stable_neuron_store| {
                    stable_neuron_store.delete(*neuron_id)
                });
            }
        }

        self.remove_neuron_from_indexes(&neuron_to_remove);
    }

    fn remove_neuron_from_indexes(&mut self, neuron: &Neuron) {
        let neuron_id = neuron.id();
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
                    neuron_id,
                    indexes: vec![defects],
                })
            );
        };
    }

    // Loads a neuron from either heap or stable storage and returns its primary storage location,
    // given a list of sections. Note that all neuron reads go through this method. Use
    // `load_neuron_all_sections` if the read is later used for modification.
    fn load_neuron_with_sections(
        &self,
        neuron_id: NeuronId,
        sections: NeuronSections,
    ) -> Result<(Cow<Neuron>, StorageLocation), NeuronStoreError> {
        let heap_neuron = self.heap_neurons.get(&neuron_id.id).map(Cow::Borrowed);

        if let Some(heap_neuron) = heap_neuron.clone() {
            // If the neuron is active on heap, return early to avoid any operation on stable
            // storage. The StableStorageNeuronValidator ensures that active neuron cannot also be
            // on stable storage.
            if !heap_neuron.is_inactive(self.now()) {
                return Ok((heap_neuron, StorageLocation::Heap));
            }
        }

        let stable_neuron = with_stable_neuron_store(|stable_neuron_store| {
            stable_neuron_store
                .read(neuron_id, sections)
                .ok()
                .map(Cow::Owned)
        });

        match (stable_neuron, heap_neuron) {
            // 1 copy cases.
            (Some(stable), None) => Ok((stable, StorageLocation::Stable)),
            (None, Some(heap)) => Ok((heap, StorageLocation::Heap)),

            // 2 copies case.
            (Some(stable), Some(_)) => {
                println!(
                    "{}WARNING: neuron {:?} is in both stable memory and heap memory, \
                     we are at risk of having stale copies",
                    LOG_PREFIX, neuron_id
                );
                Ok((stable, StorageLocation::Stable))
            }

            // 0 copies case.
            (None, None) => Err(NeuronStoreError::not_found(neuron_id)),
        }
    }

    // Loads the entire neuron from either heap or stable storage and returns its primary storage.
    // All neuron reads that can later be used for modification (`with_neuron_mut` and
    // `remove_neuron`) needs to use this method.
    fn load_neuron_all_sections(
        &self,
        neuron_id: NeuronId,
    ) -> Result<(Cow<Neuron>, StorageLocation), NeuronStoreError> {
        self.load_neuron_with_sections(neuron_id, NeuronSections::all())
    }

    fn update_neuron(
        &mut self,
        neuron_id: NeuronId,
        old_neuron: &Neuron,
        new_neuron: Neuron,
        previous_location: StorageLocation,
    ) -> Result<(), NeuronStoreError> {
        let target_location = if new_neuron.is_inactive(self.now()) {
            StorageLocation::Stable
        } else {
            StorageLocation::Heap
        };
        let is_neuron_changed = *old_neuron != new_neuron;

        // Perform transition between 2 storage if necessary.
        //
        // Note:
        // - the location here is the primary location. Currently, StorageLocation::Stable means the
        // neuron is stored in stable storage while having a copy on the heap. StorageLocation::Heap
        // means the neuron will have its only copy in heap.
        // - The `self.heap_neurons.insert(..)` can be done outside of the match expression, but
        // since they have different meanings regarding primary/secondary copies, and the logic will
        // diverge as we remove the secondary copy, we call it in the same way in all 4 cases.
        match (previous_location, target_location) {
            (StorageLocation::Heap, StorageLocation::Heap) => {
                // We might be able to improve the performance by comparing and changing each field of neuron separately.
                if is_neuron_changed {
                    self.heap_neurons.insert(neuron_id.id, new_neuron);
                }
            }
            (StorageLocation::Heap, StorageLocation::Stable) => {
                // It is guaranteed that when previous location is Heap, there is not an entry in
                // stable neuron store. Therefore we want to exist when there is an error in create,
                // since there is probably a real issue.
                with_stable_neuron_store_mut(|stable_neuron_store| {
                    stable_neuron_store.create(new_neuron.clone())
                })?;
                self.heap_neurons.remove(&neuron_id.id);
            }
            (StorageLocation::Stable, StorageLocation::Heap) => {
                // Now the neuron in heap becomes its primary copy and the one in stable memory is
                // the secondary copy.
                self.heap_neurons.insert(neuron_id.id, new_neuron);
                with_stable_neuron_store_mut(|stable_neuron_store| {
                    stable_neuron_store.delete(neuron_id)
                })?;
            }
            (StorageLocation::Stable, StorageLocation::Stable) => {
                // There should be a previous version in stable storage. Use update and return with
                // error since it signals a real issue.
                if is_neuron_changed {
                    with_stable_neuron_store_mut(|stable_neuron_store| {
                        stable_neuron_store.update(old_neuron, new_neuron)
                    })?;
                }
            }
        };
        Ok(())
    }

    /// Get NeuronId for a particular subaccount.
    pub fn get_neuron_id_for_subaccount(&self, subaccount: Subaccount) -> Option<NeuronId> {
        with_stable_neuron_indexes(|indexes| {
            indexes
                .subaccount()
                .get_neuron_id_by_subaccount(&subaccount)
        })
    }

    pub fn has_neuron_with_subaccount(&self, subaccount: Subaccount) -> bool {
        self.get_neuron_id_for_subaccount(subaccount).is_some()
    }

    pub fn get_neuron_id_for_account_id(&self, account_id: &AccountIdentifier) -> Option<NeuronId> {
        with_stable_neuron_indexes(|indexes| {
            indexes.account_id().get_neuron_id_by_account_id(account_id)
        })
    }

    pub fn has_neuron_with_account_id(&self, account_id: &AccountIdentifier) -> bool {
        self.get_neuron_id_for_account_id(account_id).is_some()
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

    /// List all neuron ids that are in the Neurons' Fund.
    pub fn list_active_neurons_fund_neurons(&self) -> Vec<NeuronsFundNeuron> {
        let now = self.now();
        let filter = |n: &Neuron| {
            !n.is_inactive(now)
                && n.joined_community_fund_timestamp_seconds
                    .unwrap_or_default()
                    > 0
        };
        self.map_heap_neurons_filtered(filter, |n| NeuronsFundNeuron {
            id: n.id(),
            controller: n.controller(),
            hotkeys: pick_most_important_hotkeys(&n.hot_keys),
            maturity_equivalent_icp_e8s: n.maturity_e8s_equivalent,
        })
        .into_iter()
        .collect()
    }

    /// List all neuron ids whose neurons have staked maturity greater than 0.
    pub fn list_neurons_ready_to_unstake_maturity(&self, now_seconds: u64) -> Vec<NeuronId> {
        let filter = |neuron: &Neuron| neuron.ready_to_unstake_maturity(now_seconds);
        self.map_heap_neurons_filtered(filter, |neuron| neuron.id())
    }

    /// List all neuron ids of known neurons
    pub fn list_known_neuron_ids(&self) -> Vec<NeuronId> {
        with_stable_neuron_indexes(|indexes| indexes.known_neuron().list_known_neuron_ids())
    }

    /// List all neurons that are spawning
    pub fn list_ready_to_spawn_neuron_ids(&self, now_seconds: u64) -> Vec<NeuronId> {
        let filter = |n: &Neuron| {
            let spawning_state = n.state(now_seconds) == NeuronState::Spawning;
            if !spawning_state {
                return false;
            }
            // spawning_state is calculated based on presence of spawn_at_timestamp_seconds
            // so it would be quite surprising if it is missing here (impossible in fact)
            now_seconds >= n.spawn_at_timestamp_seconds.unwrap_or(u64::MAX)
        };
        self.map_heap_neurons_filtered(filter, |n| n.id())
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

    /// Returns the full neuron if the given principal is authorized - either it can vote for the
    /// given neuron or any of its neuron managers.
    pub fn get_full_neuron(
        &self,
        neuron_id: NeuronId,
        principal_id: PrincipalId,
    ) -> Result<Neuron, NeuronStoreError> {
        // There is a trade-off between (1) the current approach - read the whole neuron and use it
        // to determine access, then return the previously fetched neuron (2) alternative - only
        // read the information needed the determine access, and then read the full neuron if it
        // does have access. When most of the calls do have access, the current approach is more
        // efficient since it avoids reading the same data twice. However, if most of the calls do
        // not have access, the current approach is less efficient since it always reads the whole
        // neuron first. This current approach is chosen based on the assumption that most of the
        // calls come from list_neurons with `include_neurons_readable_by_caller` set to true, where
        // get_full_neuron is only called for the neurons that the caller has access to.
        let neuron_clone = self.with_neuron(&neuron_id, |neuron| neuron.clone())?;

        if neuron_clone.is_authorized_to_vote(&principal_id) {
            return Ok(neuron_clone);
        }

        if self.can_principal_vote_on_proposals_that_target_neuron(principal_id, &neuron_clone) {
            Ok(neuron_clone)
        } else {
            Err(NeuronStoreError::not_authorized_to_get_full_neuron(
                principal_id,
                neuron_id,
            ))
        }
    }

    fn is_authorized_to_vote(&self, principal_id: PrincipalId, neuron_id: NeuronId) -> bool {
        self.with_neuron_sections(
            &neuron_id,
            NeuronSections {
                hot_keys: true,
                ..Default::default()
            },
            |neuron| neuron.is_authorized_to_vote(&principal_id),
        )
        .unwrap_or(false)
    }

    pub fn can_principal_vote_on_proposals_that_target_neuron(
        &self,
        principal_id: PrincipalId,
        neuron: &Neuron,
    ) -> bool {
        neuron
            .neuron_managers()
            .into_iter()
            .any(|manager_neuron_id| self.is_authorized_to_vote(principal_id, manager_neuron_id))
    }

    /// Execute a function with a mutable reference to a neuron, returning the result of the function,
    /// unless the neuron is not found
    pub fn with_neuron_mut<R>(
        &mut self,
        neuron_id: &NeuronId,
        f: impl FnOnce(&mut Neuron) -> R,
    ) -> Result<R, NeuronStoreError> {
        let (neuron, location) = self.load_neuron_all_sections(*neuron_id)?;
        let old_neuron = neuron.deref().clone();
        let mut new_neuron = old_neuron.clone();
        let result = f(&mut new_neuron);
        self.update_neuron(*neuron_id, &old_neuron, new_neuron.clone(), location)?;
        // Updating indexes needs to happen after successfully storing primary data.
        self.update_neuron_indexes(&old_neuron, &new_neuron);
        Ok(result)
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
                    neuron_id: old_neuron.id(),
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
        let (neuron, _) = self.load_neuron_all_sections(*neuron_id)?;
        Ok(f(neuron.deref()))
    }

    /// Reads a neuron with specific sections.
    fn with_neuron_sections<R>(
        &self,
        neuron_id: &NeuronId,
        sections: NeuronSections,
        f: impl FnOnce(&Neuron) -> R,
    ) -> Result<R, NeuronStoreError> {
        let (neuron, _) = self.load_neuron_with_sections(*neuron_id, sections)?;
        Ok(f(neuron.deref()))
    }

    // Below are indexes related methods. They don't have a unified interface yet, but NNS1-2507 will change that.

    // Read methods for indexes.

    // Gets followers by a followee id and topic.
    pub fn get_followers_by_followee_and_topic(
        &self,
        followee: NeuronId,
        topic: Topic,
    ) -> Vec<NeuronId> {
        self.topic_followee_index
            .get_followers_by_followee_and_category(&followee, topic)
            .into_iter()
            .collect()
    }

    // Gets all neuron ids associated with the given principal id (hot-key or controller).
    pub fn get_neuron_ids_readable_by_caller(
        &self,
        principal_id: PrincipalId,
    ) -> HashSet<NeuronId> {
        with_stable_neuron_indexes(|indexes| {
            indexes
                .principal()
                .get_neuron_ids(principal_id)
                .into_iter()
                .collect()
        })
    }

    /// Returns non-empty neuron ids readable by the caller. The definition of "empty" is that the
    /// neuron doesn't have any stake, maturity, or staked maturity.
    pub fn get_non_empty_neuron_ids_readable_by_caller(
        &self,
        caller: PrincipalId,
    ) -> Vec<NeuronId> {
        let is_non_empty = |neuron_id: &NeuronId| {
            // If the neuron does not exist on the heap, then it must be inactive and empty.
            self.heap_neurons
                .get(&neuron_id.id)
                .map(|neuron| neuron.is_funded())
                .unwrap_or(false)
        };

        self.get_neuron_ids_readable_by_caller(caller)
            .into_iter()
            .filter(is_non_empty)
            .collect()
    }

    // Returns whether the known neuron name already exists.
    pub fn contains_known_neuron_name(&self, known_neuron_name: &str) -> bool {
        with_stable_neuron_indexes(|indexes| {
            indexes
                .known_neuron()
                .contains_known_neuron_name(known_neuron_name)
        })
    }

    /// Validates a batch of neurons in stable neuron store are all inactive.
    ///
    /// The batch is defined as the `next_neuron_id` to start and the `batch_size` for the upper
    /// bound of the number of neurons to validate.
    ///
    /// Returns the neuron id the next batch will start with (the neuron id last validated + 1). If
    /// no neuron is validated in this batch, returns None.
    pub fn batch_validate_neurons_in_stable_store_are_inactive(
        &self,
        next_neuron_id: NeuronId,
        batch_size: usize,
    ) -> (Vec<NeuronId>, Option<NeuronId>) {
        let mut neuron_id_for_next_batch = None;
        let active_neurons_in_stable_store = with_stable_neuron_store(|stable_neuron_store| {
            stable_neuron_store
                .range_neurons(next_neuron_id..)
                .take(batch_size)
                .flat_map(|neuron| {
                    let current_neuron_id = neuron.id();
                    neuron_id_for_next_batch = current_neuron_id.next();

                    let is_neuron_inactive = neuron.is_inactive(self.now());

                    if is_neuron_inactive {
                        None
                    } else {
                        // An active neuron in stable neuron store is invalid.
                        Some(current_neuron_id)
                    }
                })
                .collect()
        });

        (active_neurons_in_stable_store, neuron_id_for_next_batch)
    }

    // Census

    pub fn stable_neuron_store_len(&self) -> usize {
        with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.len())
    }

    pub fn stable_indexes_lens(&self) -> NeuronIndexesLens {
        with_stable_neuron_indexes_mut(|indexes| NeuronIndexesLens {
            subaccount: indexes.subaccount().num_entries(),
            principal: indexes.principal().num_entries(),
            following: indexes.following().num_entries(),
            known_neuron: indexes.known_neuron().num_entries(),
            account_id: indexes.account_id().num_entries(),
        })
    }
}

/// Number of entries for each neuron indexes (in stable storage)
pub struct NeuronIndexesLens {
    pub subaccount: usize,
    pub principal: usize,
    pub following: usize,
    pub known_neuron: usize,
    pub account_id: usize,
}

#[cfg(test)]
mod neuron_store_tests;

#[cfg(feature = "canbench-rs")]
mod benches;
