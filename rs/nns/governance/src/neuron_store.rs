use crate::{
    CURRENT_PRUNE_FOLLOWING_FULL_CYCLE_START_TIMESTAMP_SECONDS, Clock, IcClock,
    governance::{LOG_PREFIX, TimeWarp},
    neuron::types::Neuron,
    neurons_fund::neurons_fund_neuron::pick_most_important_hotkeys,
    pb::v1::{GovernanceError, Topic, VotingPowerEconomics, governance_error::ErrorType},
    storage::{
        neuron_indexes::CorruptedNeuronIndexes, neurons::NeuronSections,
        with_stable_neuron_indexes, with_stable_neuron_indexes_mut, with_stable_neuron_store,
        with_stable_neuron_store_mut, with_voting_history_store_mut,
    },
};
use dyn_clone::DynClone;
use ic_base_types::PrincipalId;
use ic_cdk::println;
use ic_nervous_system_governance::index::{
    neuron_following::NeuronFollowingIndex, neuron_principal::NeuronPrincipalIndex,
};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_governance_api::NeuronInfo;
use icp_ledger::{AccountIdentifier, Subaccount};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::{Debug, Display, Formatter},
    ops::Bound,
};

pub mod metrics;
pub mod voting_power;

use crate::governance::RandomnessGenerator;
use crate::pb::v1::{Ballot, Vote};
pub(crate) use metrics::NeuronMetrics;

// All information about a neuron can be up to 6 KiB.
// To avoid hitting the message size limit of 2 MiB, we limit the
// number of neurons returned in a single page to 300.
pub const MAX_NEURON_PAGE_SIZE: u32 = 300;

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
    NeuronIdGenerationUnavailable,
    InvalidOperation {
        reason: String,
    },
    TotalPotentialVotingPowerOverflow,
    TotalDecidingVotingPowerOverflow,
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
                write!(f, "Neuron not found: {neuron_id:?}")
            }
            NeuronStoreError::CorruptedNeuronIndexes(corrupted_neuron_indexes) => {
                write!(
                    f,
                    "Neuron indexes are corrupted: {corrupted_neuron_indexes:?}"
                )
            }
            NeuronStoreError::NeuronIdIsNone => write!(f, "Neuron id is none"),
            NeuronStoreError::InvalidSubaccount {
                neuron_id,
                subaccount_bytes,
            } => write!(
                f,
                "Neuron {neuron_id:?} has an invalid subaccount {subaccount_bytes:?}"
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
                "Attempting to modify neuron subaccount from {old_subaccount:?} to {new_subaccount:?}"
            ),
            NeuronStoreError::NeuronAlreadyExists(neuron_id) => {
                write!(
                    f,
                    "Attempting to add a neuron with an existing ID: {neuron_id:?}"
                )
            }
            NeuronStoreError::InvalidData { reason } => {
                write!(f, "Failed to store neuron with invalid data: {reason:?}")
            }
            NeuronStoreError::NotAuthorizedToGetFullNeuron {
                principal_id,
                neuron_id,
            } => {
                write!(
                    f,
                    "Principal {principal_id:?} is not authorized to get full neuron information for neuron {neuron_id:?}"
                )
            }
            NeuronStoreError::NeuronIdGenerationUnavailable => {
                write!(
                    f,
                    "Neuron ID generation is not available currently. \
                    Likely due to uninitialized RNG."
                )
            }
            NeuronStoreError::InvalidOperation { reason } => {
                write!(f, "Invalid operation: {reason}")
            }
            NeuronStoreError::TotalPotentialVotingPowerOverflow => {
                write!(f, "Total potential voting power overflow")
            }
            NeuronStoreError::TotalDecidingVotingPowerOverflow => {
                write!(f, "Total deciding voting power overflow")
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
            NeuronStoreError::NeuronIdGenerationUnavailable => ErrorType::Unavailable,
            NeuronStoreError::InvalidOperation { .. } => ErrorType::PreconditionFailed,
            NeuronStoreError::TotalPotentialVotingPowerOverflow => ErrorType::PreconditionFailed,
            NeuronStoreError::TotalDecidingVotingPowerOverflow => ErrorType::PreconditionFailed,
        };
        GovernanceError::new_with_message(error_type, value.to_string())
    }
}

trait PracticalClock: Clock + Send + Sync + Debug + DynClone {}
dyn_clone::clone_trait_object!(PracticalClock);

impl PracticalClock for IcClock {}

// TODO impl PracticalClock for MockClock {}
// This does not work, because MockClock does not implement Clone. Not sure how
// to do that. Might be impossible, because MockClock is generated by
// mockall/automock.

/// This structure represents a whole Neuron's Fund neuron.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct NeuronsFundNeuron {
    pub id: NeuronId,
    pub maturity_equivalent_icp_e8s: u64,
    pub controller: PrincipalId,
    pub hotkeys: Vec<PrincipalId>,
}

/// This struct stores and provides access to all neurons within NNS Governance, which can live
/// in either heap memory or stable memory.
#[cfg_attr(test, derive(Clone, Debug))]
pub struct NeuronStore {
    // In non-test builds, Box would suffice. However, in test, the containing struct (to wit,
    // NeuronStore) implements additional traits. Therefore, more elaborate wrapping is needed.
    clock: Box<dyn PracticalClock>,
}

impl NeuronStore {
    // Initializes NeuronStore for the first time assuming no persisted data has been prepared (e.g.
    // data in stable storage). If restoring after an upgrade, call NeuronStore::new_restored
    // instead.
    pub fn new(neurons: BTreeMap<u64, Neuron>) -> Self {
        // Initializes a neuron store with no neurons.
        let mut neuron_store = Self {
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
    // neuron indexes and inactive neurons).
    pub fn new_restored() -> Self {
        Self {
            clock: Box::new(IcClock::new()),
        }
    }

    /// If there is a bug (related to lock acquisition), this could return u64::MAX.
    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    pub fn set_time_warp(&mut self, new_time_warp: TimeWarp) {
        self.clock.set_time_warp(new_time_warp);
    }

    pub fn new_neuron_id(
        &self,
        random: &mut dyn RandomnessGenerator,
    ) -> Result<NeuronId, NeuronStoreError> {
        loop {
            let id = random
                .random_u64()
                .map_err(|_| NeuronStoreError::NeuronIdGenerationUnavailable)?
                // Let there be no question that id was chosen
                // intentionally, not just 0 by default.
                .saturating_add(1);
            let neuron_id = NeuronId { id };

            let is_unique = !self.contains(neuron_id);

            if is_unique {
                return Ok(neuron_id);
            }

            ic_cdk::println!(
                "{}WARNING: A suspiciously near-impossible event has just occurred: \
                 we randomly picked a NeuronId, but it's already used: \
                 {:?}. Trying again...",
                LOG_PREFIX,
                neuron_id,
            );
        }
    }

    /// Returns if store contains a Neuron by id
    pub fn contains(&self, neuron_id: NeuronId) -> bool {
        with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.contains(neuron_id))
    }

    /// Get the number of neurons in the Store
    pub fn len(&self) -> usize {
        with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.len())
    }

    /// Add a new neuron
    pub fn add_neuron(&mut self, neuron: Neuron) -> Result<NeuronId, NeuronStoreError> {
        let neuron_id = neuron.id();

        self.validate_neuron(&neuron)?;

        if self.contains(neuron_id) {
            return Err(NeuronStoreError::NeuronAlreadyExists(neuron_id));
        }

        // Write as primary copy in stable storage.
        with_stable_neuron_store_mut(|stable_neuron_store| {
            stable_neuron_store.create(neuron.clone())
        })?;

        // Write to indexes after writing to primary storage as the write to primary storage can
        // fail.
        self.add_neuron_to_indexes(&neuron);

        Ok(neuron_id)
    }

    fn validate_neuron(&self, neuron: &Neuron) -> Result<(), NeuronStoreError> {
        neuron
            .dissolve_state_and_age()
            .validate()
            .map_err(|reason| NeuronStoreError::InvalidData {
                reason: format!("Neuron cannot be saved: {reason}"),
            })?;

        Ok(())
    }

    fn add_neuron_to_indexes(&mut self, neuron: &Neuron) {
        if let Err(error) = with_stable_neuron_indexes_mut(|indexes| indexes.add_neuron(neuron)) {
            println!(
                "{}WARNING: issues found when adding neuron to indexes, possibly because \
                     neuron indexes are out-of-sync with neurons: {}",
                LOG_PREFIX, error
            );
        }
    }

    /// Remove a Neuron by id
    pub fn remove_neuron(&mut self, neuron_id: &NeuronId) {
        let load_neuron_result = self.load_neuron_all_sections(*neuron_id);
        let neuron_to_remove = match load_neuron_result {
            Ok(load_neuron_result) => load_neuron_result,
            Err(error) => {
                println!(
                    "{}WARNING: cannot find neuron {:?} while trying to remove it: {}",
                    LOG_PREFIX, *neuron_id, error
                );
                return;
            }
        };

        let _remove_result = with_stable_neuron_store_mut(|stable_neuron_store| {
            stable_neuron_store.delete(*neuron_id)
        });
        self.remove_neuron_from_indexes(&neuron_to_remove);
    }

    fn remove_neuron_from_indexes(&mut self, neuron: &Neuron) {
        if let Err(error) = with_stable_neuron_indexes_mut(|indexes| indexes.remove_neuron(neuron))
        {
            println!(
                "{}WARNING: issues found when adding neuron to indexes, possibly because of \
                     neuron indexes are out-of-sync with neurons: {}",
                LOG_PREFIX, error
            );
        }
    }

    // Loads a neuron from either heap or stable storage and returns its primary storage location,
    // given a list of sections. Note that all neuron reads go through this method. Use
    // `load_neuron_all_sections` if the read is later used for modification.
    fn load_neuron_with_sections(
        &self,
        neuron_id: NeuronId,
        sections: NeuronSections,
    ) -> Result<Neuron, NeuronStoreError> {
        let neuron = with_stable_neuron_store(|stable_neuron_store| {
            stable_neuron_store.read(neuron_id, sections).ok()
        });

        match neuron {
            Some(neuron) => Ok(neuron),
            None => Err(NeuronStoreError::not_found(neuron_id)),
        }
    }

    // Loads the entire neuron from either heap or stable storage and returns its primary storage.
    // All neuron reads that can later be used for modification (`with_neuron_mut` and
    // `remove_neuron`) needs to use this method.
    fn load_neuron_all_sections(&self, neuron_id: NeuronId) -> Result<Neuron, NeuronStoreError> {
        self.load_neuron_with_sections(neuron_id, NeuronSections::ALL)
    }

    fn update_neuron(
        &mut self,
        old_neuron: &Neuron,
        new_neuron: Neuron,
    ) -> Result<(), NeuronStoreError> {
        let is_neuron_changed = *old_neuron != new_neuron;

        self.validate_neuron(&new_neuron)?;

        if is_neuron_changed {
            with_stable_neuron_store_mut(|stable_neuron_store| {
                stable_neuron_store.update(old_neuron, new_neuron)
            })
        } else {
            Ok(())
        }
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

    pub fn with_active_neurons_iter<R>(
        &self,
        callback: impl for<'b> FnOnce(Box<dyn Iterator<Item = Neuron> + 'b>) -> R,
    ) -> R {
        self.with_active_neurons_iter_sections(callback, NeuronSections::ALL)
    }

    fn with_active_neurons_iter_sections<R>(
        &self,
        callback: impl for<'b> FnOnce(Box<dyn Iterator<Item = Neuron> + 'b>) -> R,
        sections: NeuronSections,
    ) -> R {
        with_stable_neuron_store(|stable_store| {
            let now = self.now();
            let iter = Box::new(
                stable_store
                    .range_neurons_sections(.., sections)
                    .filter(|n| !n.is_inactive(now)),
            );
            callback(iter)
        })
    }

    /// Returns the smallest neuron ID that is in range and in self.
    ///
    /// If there is no such neuron ID, returns None.
    ///
    /// This is useful for background/offline "grooming" ALL neurons, regardless
    /// of their storage location.
    ///
    /// For a simple yet realistic example, see prune_some_following.
    fn first_neuron_id(&self, bound: Bound<NeuronId>) -> Option<NeuronId> {
        with_stable_neuron_store(|stable_store| {
            stable_store
                .range_neurons_sections((bound, Bound::Unbounded), NeuronSections::NONE)
                .next()
                .map(|neuron| neuron.id())
        })
    }

    fn is_active_neurons_fund_neuron(neuron: &Neuron, now: u64) -> bool {
        !neuron.is_inactive(now) && neuron.is_a_neurons_fund_member()
    }

    /// List all neuron ids that are in the Neurons' Fund.
    pub fn list_active_neurons_fund_neurons(&self) -> Vec<NeuronsFundNeuron> {
        let now = self.now();
        self.with_active_neurons_iter_sections(
            |iter| {
                iter.filter(|neuron| Self::is_active_neurons_fund_neuron(neuron, now))
                    .map(|neuron| NeuronsFundNeuron {
                        id: neuron.id(),
                        controller: neuron.controller(),
                        hotkeys: pick_most_important_hotkeys(&neuron.hot_keys),
                        maturity_equivalent_icp_e8s: neuron.maturity_e8s_equivalent,
                    })
                    .collect()
            },
            NeuronSections {
                hot_keys: true,
                ..NeuronSections::NONE
            },
        )
    }

    /// List all neuron ids whose neurons have staked maturity greater than 0.
    fn list_neurons_ready_to_unstake_maturity(
        &self,
        now_seconds: u64,
        max_num_neurons: usize,
    ) -> Vec<NeuronId> {
        self.with_active_neurons_iter_sections(
            |iter| {
                iter.filter(|neuron| neuron.ready_to_unstake_maturity(now_seconds))
                    .take(max_num_neurons)
                    .map(|neuron| neuron.id())
                    .collect()
            },
            NeuronSections::NONE,
        )
    }

    /// List all neuron ids of known neurons
    pub fn list_known_neuron_ids(&self) -> Vec<NeuronId> {
        with_stable_neuron_indexes(|indexes| indexes.known_neuron().list_known_neuron_ids())
    }

    pub fn list_all_neurons_paginated(
        &self,
        exclusive_start_id: NeuronId,
        page_size: u32,
        requester: PrincipalId,
        now_seconds: u64,
        voting_power_economics: &VotingPowerEconomics,
    ) -> Vec<NeuronInfo> {
        with_stable_neuron_store(|stable_store| {
            stable_store
                .range_neurons((Bound::Excluded(exclusive_start_id), Bound::Unbounded))
                .take(page_size as usize)
                .map(|neuron| {
                    neuron.get_neuron_info(voting_power_economics, now_seconds, requester, true)
                })
                .collect()
        })
    }

    /// List all neurons that are spawning
    pub fn list_ready_to_spawn_neuron_ids(&self, now_seconds: u64) -> Vec<NeuronId> {
        self.with_active_neurons_iter_sections(
            |iter| {
                iter.filter(|neuron| neuron.ready_to_spawn(now_seconds))
                    .map(|neuron| neuron.id())
                    .collect()
            },
            NeuronSections::NONE,
        )
    }

    /// When a neuron is finally dissolved, if there is any staked maturity it is moved to regular maturity
    /// which can be spawned (and is modulated).
    pub fn unstake_maturity_of_dissolved_neurons(
        &mut self,
        now_seconds: u64,
        max_num_neurons: usize,
    ) {
        let neuron_ids = {
            #[cfg(feature = "canbench-rs")]
            let _scope_list = canbench_rs::bench_scope("list_neuron_ids");
            self.list_neurons_ready_to_unstake_maturity(now_seconds, max_num_neurons)
        };

        #[cfg(feature = "canbench-rs")]
        let _scope_unstake = canbench_rs::bench_scope("unstake_maturity");
        // Filter all the neurons that are currently in "dissolved" state and have some staked maturity.
        // No neuron in stable storage should have staked maturity.
        for neuron_id in neuron_ids {
            let unstake_result =
                self.with_neuron_mut(&neuron_id, |neuron| neuron.unstake_maturity(now_seconds));

            match unstake_result {
                Ok(_) => {}
                Err(e) => {
                    println!(
                        "{}Error when moving staked maturity for neuron {:?}: {:?}",
                        LOG_PREFIX, neuron_id, e
                    );
                }
            };
        }
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
                ..NeuronSections::NONE
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
        let old_neuron = self.load_neuron_all_sections(*neuron_id)?;
        let mut new_neuron = old_neuron.clone();
        let result = f(&mut new_neuron);
        self.update_neuron(&old_neuron, new_neuron.clone())?;
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
    }

    /// Execute a function with a reference to a neuron, returning the result of the function,
    /// unless the neuron is not found
    pub fn with_neuron<R>(
        &self,
        neuron_id: &NeuronId,
        f: impl FnOnce(&Neuron) -> R,
    ) -> Result<R, NeuronStoreError> {
        let neuron = self.load_neuron_all_sections(*neuron_id)?;
        Ok(f(&neuron))
    }

    /// Reads a neuron with specific sections.
    fn with_neuron_sections<R>(
        &self,
        neuron_id: &NeuronId,
        sections: NeuronSections,
        f: impl FnOnce(&Neuron) -> R,
    ) -> Result<R, NeuronStoreError> {
        let neuron = self.load_neuron_with_sections(*neuron_id, sections)?;
        Ok(f(&neuron))
    }

    /// Method to efficiently call Neuron.would_follow_ballots without loading all of the
    /// neuron's data.
    pub fn neuron_would_follow_ballots(
        &self,
        neuron_id: NeuronId,
        topic: Topic,
        ballots: &HashMap<u64, Ballot>,
    ) -> Result<Vote, NeuronStoreError> {
        let needed_sections = NeuronSections {
            followees: true,
            ..NeuronSections::NONE
        };
        self.with_neuron_sections(&neuron_id, needed_sections, |neuron| {
            neuron.would_follow_ballots(topic, ballots)
        })
    }

    /// Records a vote for a neuron.
    pub fn record_neuron_vote(
        &mut self,
        neuron_id: NeuronId,
        topic: Topic,
        proposal_id: ProposalId,
        vote: Vote,
    ) -> Result<(), NeuronStoreError> {
        let should_record_voting_history = with_stable_neuron_store_mut(
            |stable_neuron_store| -> Result<bool, NeuronStoreError> {
                stable_neuron_store.register_recent_neuron_ballot(
                    neuron_id,
                    topic,
                    proposal_id,
                    vote,
                )?;
                let should_record_voting_history = stable_neuron_store.is_known_neuron(neuron_id);
                Ok(should_record_voting_history)
            },
        )?;
        if should_record_voting_history {
            with_voting_history_store_mut(|voting_history_store| {
                voting_history_store.record_vote(neuron_id, proposal_id, vote);
            });
        }
        Ok(())
    }

    /// Modifies the maturity of the neuron.
    pub fn modify_neuron_maturity(
        &mut self,
        neuron_id: &NeuronId,
        modify: impl FnOnce(u64) -> Result<u64, String>,
    ) -> Result<(), NeuronStoreError> {
        with_stable_neuron_store_mut(|stable_neuron_store| {
            stable_neuron_store
                .with_main_part_mut(*neuron_id, |neuron| -> Result<(), String> {
                    let new_maturity = modify(neuron.maturity_e8s_equivalent)?;
                    neuron.maturity_e8s_equivalent = new_maturity;
                    Ok(())
                })?
                .map_err(|e| NeuronStoreError::InvalidData { reason: e })?;
            Ok(())
        })
    }

    // Below are indexes related methods. They don't have a unified interface yet, but NNS1-2507 will change that.

    // Read methods for indexes.

    // Gets followers by a followee id and topic.
    pub fn get_followers_by_followee_and_topic(
        &self,
        followee: NeuronId,
        topic: Topic,
    ) -> Vec<NeuronId> {
        with_stable_neuron_indexes(|indexes| {
            indexes
                .following()
                .get_followers_by_followee_and_category(&followee, topic)
        })
    }

    // Gets all neuron ids associated with the given principal id (hot-key or controller).
    pub fn get_neuron_ids_readable_by_caller(
        &self,
        principal_id: PrincipalId,
    ) -> BTreeSet<NeuronId> {
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
    ) -> BTreeSet<NeuronId> {
        let is_non_empty = |neuron_id: &NeuronId| {
            self.with_neuron_sections(
                neuron_id,
                NeuronSections {
                    maturity_disbursements: true,
                    ..NeuronSections::NONE
                },
                |neuron| neuron.is_funded() || neuron.has_maturity_disbursement_in_progress(),
            )
            .unwrap_or(false)
        };

        self.get_neuron_ids_readable_by_caller(caller)
            .into_iter()
            .filter(is_non_empty)
            .collect()
    }

    // Returns the neuron id for the given known neuron name if it exists. Returns None if the known
    // neuron name does not exist.
    pub fn known_neuron_id_by_name(&self, known_neuron_name: &str) -> Option<NeuronId> {
        with_stable_neuron_indexes(|indexes| {
            indexes
                .known_neuron()
                .known_neuron_id_by_name(known_neuron_name)
        })
    }

    /// Returns if the neuron is a known neuron.
    pub fn is_known_neuron(&self, neuron_id: NeuronId) -> bool {
        with_stable_neuron_store(|stable_neuron_store| {
            stable_neuron_store.is_known_neuron(neuron_id)
        })
    }

    /// Returns the neuron ids that are ready to finalize maturity disbursement.
    pub fn get_neuron_ids_ready_to_finalize_maturity_disbursement(
        &self,
        now_seconds: u64,
    ) -> BTreeSet<NeuronId> {
        with_stable_neuron_indexes(|indexes| {
            indexes
                .maturity_disbursement()
                .get_neuron_ids_ready_to_finalize(now_seconds)
                .into_iter()
                .map(|id| NeuronId { id })
                .collect()
        })
    }

    /// Returns the finalization timestamp and the neuron id of the next maturity disbursement.
    /// Returns `None` if there is no maturity disbursement at all.
    pub fn get_next_maturity_disbursement(&self) -> Option<(u64, NeuronId)> {
        with_stable_neuron_indexes(|indexes| indexes.maturity_disbursement().get_next_entry())
    }

    // Census

    pub fn stable_neuron_store_len(&self) -> usize {
        with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.len())
    }

    pub fn stable_indexes_lens(&self) -> NeuronIndexesLens {
        with_stable_neuron_indexes(|indexes| NeuronIndexesLens {
            subaccount: indexes.subaccount().num_entries(),
            principal: indexes.principal().num_entries(),
            following: indexes.following().num_entries(),
            known_neuron: indexes.known_neuron().num_entries(),
            account_id: indexes.account_id().num_entries(),
            maturity_disbursement: indexes.maturity_disbursement().num_entries(),
        })
    }
}

/// Does what the name says.
///
/// If a neuron's voting power has not been refreshed in a "long" time (see the
/// voting_power_refreshed_timestamp_seconds field), then, their following needs
/// to be deleted.
///
/// This scans some neurons, starting with start. This stops scanning when
/// carry_on returns false. carry_on is called after processing each neuron.
/// Therefore, this processes at least one neuron (if there is one).
///
/// Returns where the scan should pick up from next time. I.e. the return value
/// should be passed via start next time.
pub fn prune_some_following(
    voting_power_economics: &VotingPowerEconomics,
    neuron_store: &mut NeuronStore,
    next: Bound<NeuronId>,
    carry_on: impl FnMut() -> bool,
) -> Bound<NeuronId> {
    let now_seconds = neuron_store.now();

    if next == Bound::Unbounded {
        CURRENT_PRUNE_FOLLOWING_FULL_CYCLE_START_TIMESTAMP_SECONDS.with(
            |start_timestamp_seconds| {
                start_timestamp_seconds.set(now_seconds);
            },
        );
    }

    groom_some_neurons(
        neuron_store,
        |neuron| {
            neuron.prune_following(voting_power_economics, now_seconds);
        },
        next,
        carry_on,
    )
}

pub fn groom_some_neurons(
    neuron_store: &mut NeuronStore,
    mut touch_neuron: impl FnMut(&mut Neuron),
    mut next: Bound<NeuronId>,
    mut carry_on: impl FnMut() -> bool,
) -> Bound<NeuronId> {
    // Here, do-while semantics is used, rather than while. I.e. carry_on is
    // only called at the end of the loop, not the beginnin. This results in the
    // nice property that (when there are more neurons), this ALWAYS makes SOME
    // progress.
    loop {
        // Which neuron do we operate on next?
        let current_neuron_id = neuron_store.first_neuron_id(next);

        // If we reached the end, return.
        let current_neuron_id = match current_neuron_id {
            Some(ok) => ok,
            None => {
                // Tell caller to loop back to the beginning of neurons. That
                // way, we keep scanning indefinitely.
                return Bound::Unbounded;
            }
        };

        // Get ready for the next iteration.
        next = Bound::Excluded(current_neuron_id);

        let result = neuron_store.with_neuron_mut(&current_neuron_id, |neuron| {
            touch_neuron(neuron);
        });

        // Log if somehow with_neuron_mut returns Err. This should not be
        // possible, since first_neuron_id must have returned Some in order for
        // this line to be reached.
        if let Err(err) = result {
            println!(
                "{}ERROR: Unable to find neuron {} while pruning following: {:?}",
                LOG_PREFIX, current_neuron_id.id, err,
            );
        }

        if !carry_on() {
            return next;
        }
    }
}

/// Approves KYC for the neurons with the given principals. Returns an error if the number of
/// neurons to approve KYC for exceeds the maximum allowed, in which case no neurons are approved.
pub fn approve_genesis_kyc(
    neuron_store: &mut NeuronStore,
    principals: &[PrincipalId],
) -> Result<(), GovernanceError> {
    const APPROVE_GENESIS_KYC_MAX_NEURONS: usize = 1000;

    let principal_set: HashSet<PrincipalId> = principals.iter().cloned().collect();
    let neuron_id_to_principal = principal_set
        .into_iter()
        .flat_map(|principal| {
            neuron_store
                .get_neuron_ids_readable_by_caller(principal)
                .into_iter()
                .map(move |neuron_id| (neuron_id, principal))
        })
        .collect::<HashMap<_, _>>();

    if neuron_id_to_principal.len() > APPROVE_GENESIS_KYC_MAX_NEURONS {
        return Err(GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            format!(
                "ApproveGenesisKyc can only change the KYC status of up to {APPROVE_GENESIS_KYC_MAX_NEURONS} neurons at a time"
            ),
        ));
    }

    for (neuron_id, principal) in neuron_id_to_principal {
        let result = neuron_store.with_neuron_mut(&neuron_id, |neuron| {
            if neuron.controller() == principal {
                neuron.kyc_verified = true;
            }
        });
        // Log errors but continue with the rest of the neurons.
        if let Err(e) = result {
            eprintln!("{LOG_PREFIX}ERROR: Failed to approve KYC for neuron {neuron_id:?}: {e:?}");
        }
    }
    Ok(())
}

/// Number of entries for each neuron indexes (in stable storage)
pub struct NeuronIndexesLens {
    pub subaccount: usize,
    pub principal: usize,
    pub following: usize,
    pub known_neuron: usize,
    pub account_id: usize,
    pub maturity_disbursement: usize,
}

#[cfg(test)]
mod neuron_store_tests;

#[cfg(feature = "canbench-rs")]
mod benches;
