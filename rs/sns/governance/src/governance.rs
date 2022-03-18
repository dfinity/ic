use std::cmp::Ordering;
use std::collections::btree_map::BTreeMap;
use std::collections::btree_set::BTreeSet;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::ops::Bound::{Excluded, Unbounded};
use std::str::FromStr;
use std::string::ToString;

use crate::pb::v1::{
    get_neuron_response, get_proposal_response,
    governance::neuron_in_flight_command::Command as InFlightCommand,
    governance::NeuronInFlightCommand,
    governance_error::ErrorType,
    manage_neuron,
    manage_neuron::{
        claim_or_refresh::{By, MemoAndController},
        ClaimOrRefresh,
    },
    neuron::DissolveState,
    neuron::Followees,
    proposal, Ballot, DefaultFollowees, Empty, GetNeuron, GetNeuronResponse, GetProposal,
    GetProposalResponse, Governance as GovernanceProto, GovernanceError, ListNeurons,
    ListNeuronsResponse, ListProposals, ListProposalsResponse, ManageNeuron, ManageNeuronResponse,
    NervousSystemParameters, Neuron, NeuronId, NeuronPermission, NeuronPermissionList,
    NeuronPermissionType, Proposal, ProposalData, ProposalDecisionStatus, ProposalId,
    ProposalRewardStatus, RewardEvent, Tally, Vote,
};
use ic_base_types::PrincipalId;
use ledger_canister::{AccountIdentifier, Subaccount};
use strum::IntoEnumIterator;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use crate::neuron::{NeuronState, MAX_LIST_NEURONS_RESULTS};
use crate::pb::v1::manage_neuron::Command::DisburseMaturity;
use crate::pb::v1::manage_neuron_response::{DisburseMaturityResponse, MergeMaturityResponse};
use crate::pb::v1::proposal::Action;
use crate::pb::v1::WaitForQuietState;
use crate::proposal::{
    MAX_LIST_PROPOSAL_RESULTS, MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS,
    PROPOSAL_MOTION_TEXT_BYTES_MAX, PROPOSAL_SUMMARY_BYTES_MAX, PROPOSAL_TITLE_BYTES_MAX,
    PROPOSAL_URL_CHAR_MAX,
};
use crate::types::{Environment, HeapGrowthPotential, LedgerUpdateLock};
use dfn_core::api::{id, spawn};
use ic_nervous_system_common::ledger;
use ic_nervous_system_common::{ledger::Ledger, NervousSystemError};
use ledger_canister::Tokens;

// When `list_proposals` is called, for each proposal if a payload exceeds
// this limit (1 KB) it's payload will not be returned in the reply.
pub const EXECUTE_NERVOUS_SYSTEM_FUNCTION_PAYLOAD_LISTING_BYTES_MAX: usize = 1000;

const MAX_HEAP_SIZE_IN_KIB: usize = 4 * 1024 * 1024;
const WASM32_PAGE_SIZE_IN_KIB: usize = 64;

/// Max number of wasm32 pages for the heap after which we consider that there
/// is a risk to the ability to grow the heap.
///
/// This is 7/8 of the maximum number of pages. This corresponds to 3.5 GiB.
pub const HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES: usize =
    MAX_HEAP_SIZE_IN_KIB / WASM32_PAGE_SIZE_IN_KIB * 7 / 8;

/// Prefixes each log line for this canister
#[cfg(not(test))]
pub fn log_prefix() -> String {
    format!("[{}][Governance] ", id())
}

/// Prefixes each log line for this canister. Note that `id()` panics when not called
/// within a canister env, so we remove its use in the test env.
#[cfg(test)]
pub fn log_prefix() -> String {
    "[Governance] ".into()
}

impl NeuronPermissionType {
    /// Returns all the permissions as a vector
    pub fn all() -> Vec<i32> {
        NeuronPermissionType::iter()
            .map(|permission| permission as i32)
            .collect()
    }
}

impl NeuronPermission {
    /// Grants all permissions to the given principal
    pub fn all(principal: &PrincipalId) -> NeuronPermission {
        NeuronPermission::new(principal, NeuronPermissionType::all())
    }

    pub fn new(principal: &PrincipalId, permissions: Vec<i32>) -> NeuronPermission {
        NeuronPermission {
            principal: Some(*principal),
            permission_type: permissions,
        }
    }
}

impl GovernanceProto {
    /// From the `neurons` part of this `Governance` struct, build the
    /// index (per action) from followee to set of followers. The
    /// neurons themselves map followers (the neuron ID) to a set of
    /// followees (per action).
    pub fn build_action_followee_index(
        &self,
        neurons: &BTreeMap<String, Neuron>,
    ) -> BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>> {
        let mut action_followee_index = BTreeMap::new();
        for neuron in neurons.values() {
            GovernanceProto::add_neuron_to_action_followee_index(
                &mut action_followee_index,
                neuron,
            );
        }
        action_followee_index
    }

    pub fn add_neuron_to_action_followee_index(
        index: &mut BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>>,
        neuron: &Neuron,
    ) {
        for (action, followees) in neuron.followees.iter() {
            if Action::is_valid_action(action) {
                // Note: if there are actions in the data (e.g.,
                // file) that the Governance struct was
                // (re-)constructed from that are no longer
                // valid in the `oneof action`, the entries are
                // not put into the action_followee_index.
                //
                // This is okay, as the actions are only changed on
                // upgrades, and the index is rebuilt on upgrade.
                let followee_index = index.entry(*action).or_insert_with(BTreeMap::new);
                for followee in followees.followees.iter() {
                    followee_index
                        .entry(followee.to_string())
                        .or_insert_with(BTreeSet::new)
                        .insert(
                            neuron
                                .id
                                .as_ref()
                                .expect("Neuron must have a NeuronId")
                                .clone(),
                        );
                }
            }
        }
    }

    pub fn remove_neuron_from_action_followee_index(
        index: &mut BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>>,
        neuron: &Neuron,
    ) {
        for (action, followees) in neuron.followees.iter() {
            if let Some(followee_index) = index.get_mut(action) {
                if Action::is_valid_action(action) {
                    for followee in followees.followees.iter() {
                        let nid = followee.to_string();
                        if let Some(followee_set) = followee_index.get_mut(&nid) {
                            followee_set
                                .remove(neuron.id.as_ref().expect("Neuron must have an id"));
                            if followee_set.is_empty() {
                                followee_index.remove(&nid);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Update `index` to map all the principals that have a
    /// permission in a Neuron's access control list to `neuron_id`
    pub fn add_neuron_to_principal_to_neuron_ids_index(
        index: &mut BTreeMap<PrincipalId, HashSet<NeuronId>>,
        neuron: &Neuron,
    ) {
        let neuron_id = neuron.id.as_ref().expect("Neuron must have a NeuronId");

        neuron
            .permissions
            .iter()
            .filter_map(|permission| permission.principal)
            .for_each(|principal| {
                Self::add_neuron_to_principal_in_principal_to_neuron_ids_index(
                    index, neuron_id, &principal,
                )
            })
    }

    pub fn add_neuron_to_principal_in_principal_to_neuron_ids_index(
        index: &mut BTreeMap<PrincipalId, HashSet<NeuronId>>,
        neuron_id: &NeuronId,
        principal: &PrincipalId,
    ) {
        let neuron_ids = index.entry(*principal).or_insert_with(HashSet::new);
        neuron_ids.insert(neuron_id.clone());
    }

    /// Update `index` to remove the neuron from the list of neurons mapped to
    /// principals.
    pub fn remove_neuron_from_principal_to_neuron_ids_index(
        index: &mut BTreeMap<PrincipalId, HashSet<NeuronId>>,
        neuron: &Neuron,
    ) {
        let neuron_id = neuron.id.as_ref().expect("Neuron must have a NeuronId");

        neuron
            .permissions
            .iter()
            .filter_map(|permission| permission.principal)
            .for_each(|principal| {
                Self::remove_neuron_from_principal_in_principal_to_neuron_ids_index(
                    index, neuron_id, &principal,
                )
            })
    }

    pub fn remove_neuron_from_principal_in_principal_to_neuron_ids_index(
        index: &mut BTreeMap<PrincipalId, HashSet<NeuronId>>,
        neuron_id: &NeuronId,
        principal: &PrincipalId,
    ) {
        let neuron_ids = index.get_mut(principal);
        // Shouldn't fail if the index is broken, so just continue.
        if neuron_ids.is_none() {
            return;
        }
        let neuron_ids = neuron_ids.unwrap();
        neuron_ids.remove(neuron_id);
        // If there are no neurons left, remove the entry from the index.
        if neuron_ids.is_empty() {
            index.remove(principal);
        }
    }

    pub fn build_principal_to_neuron_ids_index(
        &self,
        neurons: &BTreeMap<String, Neuron>,
    ) -> BTreeMap<PrincipalId, HashSet<NeuronId>> {
        let mut index = BTreeMap::new();

        for neuron in neurons.values() {
            Self::add_neuron_to_principal_to_neuron_ids_index(&mut index, neuron);
        }

        index
    }

    // Returns whether the proposed default following is valid by making
    // sure that the referred to neurons exist.
    fn validate_default_followees(
        &self,
        neurons: &BTreeMap<String, Neuron>,
        proposed_followees: &HashMap<u64, Followees>,
    ) -> Result<(), GovernanceError> {
        for followees in proposed_followees.values() {
            for followee in &followees.followees {
                if !neurons.contains_key(&followee.to_string()) {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::NotFound,
                        "One or more of the neurons proposed to become\
                         the new default followees don't exist.",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The `Governance` canister implements the full public interface of the
/// SNS' governance.
pub struct Governance {
    /// The Governance Protobuf which contains all persistent state of
    /// the SNS' governance system. Needs to be stored and retrieved
    /// on upgrades.
    pub proto: GovernanceProto,

    /// Implementation of Environment to make unit testing easier.
    pub env: Box<dyn Environment>,

    /// Implementation of the interface with the SNS ledger canister.
    ledger: Box<dyn Ledger>,

    /// Cached data structure that (for each action) maps a followee to
    /// the set of followers. This is the inverse of the mapping from
    /// neuron (follower) to followees, in the neurons. This is a
    /// cached index and will be removed and recreated when the state
    /// is saved and restored.
    ///
    /// Action -> (followee's neuron ID) -> set of followers' neuron IDs.
    pub action_followee_index: BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>>,

    /// Maps Principals to the Neuron IDs of all Neurons that have this
    /// Principal associated with a NeuronPermissionType for the Neuron.
    ///
    /// This is a cached index and will be removed and recreated when the state
    /// is saved and restored.
    pub principal_to_neuron_ids_index: BTreeMap<PrincipalId, HashSet<NeuronId>>,

    /// Timestamp, in seconds since the unix epoch, of the "closest"
    /// open proposal's deadline tracked by the governance.
    closest_proposal_deadline_timestamp_seconds: u64,

    /// The time of the latest "garbage collection" - when obsolete
    /// proposals were cleaned up.
    pub latest_gc_timestamp_seconds: u64,

    /// The number of proposals after the last time GC was run.
    pub latest_gc_num_proposals: usize,
}

pub fn governance_minting_account() -> AccountIdentifier {
    AccountIdentifier::new(id().get(), None)
}

pub fn neuron_account_id(subaccount: Subaccount) -> AccountIdentifier {
    AccountIdentifier::new(id().get(), Some(subaccount))
}

impl Governance {
    pub fn new(
        mut proto: GovernanceProto,
        env: Box<dyn Environment>,
        ledger: Box<dyn Ledger>,
    ) -> Self {
        if proto.genesis_timestamp_seconds == 0 {
            proto.genesis_timestamp_seconds = env.now();
        }
        if proto.latest_reward_event.is_none() {
            // Introduce a dummy reward event to mark the origin of the SNS instance era.
            // This is required to be able to compute accurately the rewards for the
            // very first reward distribution.
            proto.latest_reward_event = Some(RewardEvent {
                actual_timestamp_seconds: env.now(),
                periods_since_genesis: 0,
                settled_proposals: vec![],
                distributed_e8s_equivalent: 0,
            })
        }

        let mut gov = Self {
            proto,
            env,
            ledger,
            action_followee_index: BTreeMap::new(),
            principal_to_neuron_ids_index: BTreeMap::new(),
            closest_proposal_deadline_timestamp_seconds: 0,
            latest_gc_timestamp_seconds: 0,
            latest_gc_num_proposals: 0,
        };

        gov.initialize_indices();

        gov
    }

    /// Validates that the underlying protobuf is well formed.
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if self.proto.parameters.is_none() {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                "NervousSystemParameters was not found",
            ));
        }

        let default_followee = &self
            .proto
            .parameters
            .as_ref()
            .expect("Governance must have NervousSystemParameters.")
            .default_followees
            .clone()
            .unwrap_or_else(|| DefaultFollowees::default())
            .followees;

        self.proto
            .validate_default_followees(&self.proto.neurons, default_followee)?;

        Ok(())
    }

    /// Initializes the indices.
    /// Must be called after the state has been externally changed (e.g. by
    /// setting a new proto).
    fn initialize_indices(&mut self) {
        self.action_followee_index = self.proto.build_action_followee_index(&self.proto.neurons);
        self.principal_to_neuron_ids_index = self
            .proto
            .build_principal_to_neuron_ids_index(&self.proto.neurons);
    }

    fn transaction_fee(&self) -> u64 {
        self.nervous_system_parameters()
            .transaction_fee_e8s
            .expect("NervousSystemParameters must have transaction_fee_e8s")
    }

    /// Return the effective _voting period_ of a given action.
    ///
    /// This function is "curried" to alleviate lifetime issues on the
    /// `self` parameter.
    fn voting_period_seconds(&self) -> impl Fn() -> u64 {
        let voting_period = self
            .nervous_system_parameters()
            .initial_voting_period
            .expect("NervousSystemParameters must have wait_for_quiet_threshold_seconds");

        move || voting_period
    }

    /// Generates a new, unused, NeuronId.
    fn new_neuron_id(
        &mut self,
        controller: &PrincipalId,
        memo: u64,
    ) -> Result<NeuronId, GovernanceError> {
        let subaccount = ledger::compute_neuron_staking_subaccount(*controller, memo);
        let nid = NeuronId::from(subaccount);
        // Don't allow IDs that are already in use.
        if self.proto.neurons.contains_key(&nid.to_string()) {
            return Err(Self::invalid_subaccount_with_nonce(memo));
        }
        Ok(nid)
    }

    fn neuron_not_found_error(nid: &NeuronId) -> GovernanceError {
        GovernanceError::new_with_message(ErrorType::NotFound, format!("Neuron not found: {}", nid))
    }

    fn invalid_subaccount_with_nonce(memo: u64) -> GovernanceError {
        GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            format!(
                "A neuron already exists with given PrincipalId and memo: {:?}",
                memo
            ),
        )
    }

    fn bytes_to_subaccount(bytes: &[u8]) -> Result<ledger_canister::Subaccount, GovernanceError> {
        bytes.try_into().map_err(|_| {
            GovernanceError::new_with_message(ErrorType::PreconditionFailed, "Invalid subaccount")
        })
    }

    // TODO verify accuracy of this comment on launch of SNS
    /// Locks a given neuron, signaling there is an ongoing neuron operation.
    ///
    /// This stores the in-flight operation in the proto so that, if anything
    /// goes wrong we can:
    ///
    /// 1 - Know what was happening.
    /// 2 - Reconcile the state post-upgrade, if necessary.
    ///
    /// No concurrent updates to this neuron's state are possible
    /// until the lock is released.
    ///
    /// ***** IMPORTANT *****
    /// The return value MUST be allocated to a variable with a name that is NOT
    /// "_" !
    ///
    /// The LedgerUpdateLock must remain alive for the entire duration of the
    /// ledger call. Quoting
    /// https://doc.rust-lang.org/book/ch18-03-pattern-syntax.html#ignoring-an-unused-variable-by-starting-its-name-with-_
    ///
    /// > Note that there is a subtle difference between using only _ and using
    /// > a name that starts with an underscore. The syntax _x still binds
    /// > the value to the variable, whereas _ doesn't bind at all.
    ///
    /// What this means is that the expression
    /// ```text
    /// let _ = lock_neuron_for_command(...);
    /// ```
    /// is useless, because the
    /// LedgerUpdateLock is a temporary object. It is constructed (and the lock
    /// is acquired), the immediately dropped (and the lock is released).
    ///
    /// However, the expression
    /// ```text
    /// let _my_lock = lock_neuron_for_command(...);
    /// ```
    /// will retain the lock for the entire scope.
    fn lock_neuron_for_command(
        &mut self,
        nid: &NeuronId,
        command: NeuronInFlightCommand,
    ) -> Result<LedgerUpdateLock, GovernanceError> {
        let nid = nid.to_string();
        if self.proto.in_flight_commands.contains_key(&nid) {
            return Err(GovernanceError::new_with_message(
                ErrorType::NeuronLocked,
                "Neuron has an ongoing operation.",
            ));
        }

        self.proto.in_flight_commands.insert(nid.clone(), command);

        Ok(LedgerUpdateLock { nid, gov: self })
    }

    /// Unlocks a given neuron.
    pub(crate) fn unlock_neuron(&mut self, id: &str) {
        match self.proto.in_flight_commands.remove(id) {
            None => {
                println!(
                    "Unexpected condition when unlocking neuron {}: the neuron was not registered as 'in flight'",
                    id
                );
            }
            // This is the expected case...
            Some(_) => (),
        }
    }

    /// Add a neuron to the list of neurons and update
    /// `principal_to_neuron_ids_index` and `action_followee_index`
    ///
    /// Fails under the following conditions:
    /// - the maximum number of neurons has been reached, or
    /// - the given `neuron_id` already exists in `self.proto.neurons`, or
    fn add_neuron(&mut self, neuron: Neuron) -> Result<(), GovernanceError> {
        let neuron_id = neuron
            .id
            .as_ref()
            .expect("Neuron must have a NeuronId")
            .clone();

        // New neurons are not allowed when the heap is too large.
        self.check_heap_can_grow()?;

        // New neurons are not allowed when the maximum configured is reached
        self.check_neuron_population_can_grow()?;

        if self.proto.neurons.contains_key(&neuron_id.to_string()) {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Cannot add neuron. There is already a neuron with id: {}",
                    neuron_id
                ),
            ));
        }

        GovernanceProto::add_neuron_to_principal_to_neuron_ids_index(
            &mut self.principal_to_neuron_ids_index,
            &neuron,
        );

        GovernanceProto::add_neuron_to_action_followee_index(
            &mut self.action_followee_index,
            &neuron,
        );

        self.proto.neurons.insert(neuron_id.to_string(), neuron);

        Ok(())
    }

    // TODO derive `neuron_id` from `neuron`. Verify there is no edge case where neuron_id != neuron.id
    /// Remove a neuron from the list of neurons and update
    /// indices `principal_to_neuron_ids_index` and `action_followee_index`
    ///
    /// Fail if the given `neuron_id` doesn't exist in `self.proto.neurons`
    fn remove_neuron(
        &mut self,
        neuron_id: &NeuronId,
        neuron: Neuron,
    ) -> Result<(), GovernanceError> {
        if !self.proto.neurons.contains_key(&neuron_id.to_string()) {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!(
                    "Cannot remove neuron. Can't find a neuron with id: {}",
                    neuron_id
                ),
            ));
        }

        GovernanceProto::remove_neuron_from_principal_to_neuron_ids_index(
            &mut self.principal_to_neuron_ids_index,
            &neuron,
        );

        GovernanceProto::remove_neuron_from_action_followee_index(
            &mut self.action_followee_index,
            &neuron,
        );

        self.proto.neurons.remove(&neuron_id.to_string());

        Ok(())
    }

    /// Tries to get a neuron given a NeuronId
    pub fn get_neuron(&self, req: &GetNeuron) -> GetNeuronResponse {
        let nid = &req
            .neuron_id
            .as_ref()
            .expect("GetNeuron must have neuron_id");
        let neuron = match self.proto.neurons.get(&nid.to_string()) {
            None => get_neuron_response::Result::Error(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "No neuron for given NeuronId.",
            )),
            Some(neuron) => get_neuron_response::Result::Neuron(neuron.clone()),
        };

        GetNeuronResponse {
            result: Some(neuron),
        }
    }

    /// Return a deterministically ordered list of size `limit` containing
    /// Neurons starting at but not including `start_page_at`.
    fn list_neurons_ordered(&self, start_page_at: &Option<NeuronId>, limit: usize) -> Vec<Neuron> {
        let neuron_range = if let Some(neuron_id) = start_page_at {
            self.proto
                .neurons
                .range((Excluded(neuron_id.to_string()), Unbounded))
        } else {
            self.proto.neurons.range((String::from("0"))..)
        };

        // Now restrict to 'limit'.
        neuron_range.take(limit).map(|(_, y)| y.clone()).collect()
    }

    /// Return a list of size `limit` containing Neurons that have `principal`
    /// in their permissions
    fn list_neurons_by_principal(&self, principal: &PrincipalId, limit: usize) -> Vec<Neuron> {
        self.get_neuron_ids_by_principal(principal)
            .iter()
            .map(|nid| self.proto.neurons.get(&nid.to_string()))
            .flatten()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Return the Neuron IDs of all Neurons that have `principal` in their
    /// permissions
    fn get_neuron_ids_by_principal(&self, principal: &PrincipalId) -> Vec<NeuronId> {
        self.principal_to_neuron_ids_index
            .get(principal)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// See `ListNeurons`.
    pub fn list_neurons(&self, req: &ListNeurons) -> ListNeuronsResponse {
        let limit = if req.limit == 0 || req.limit > MAX_LIST_NEURONS_RESULTS {
            MAX_LIST_NEURONS_RESULTS
        } else {
            req.limit
        } as usize;

        let limited_neurons = match req.of_principal {
            Some(principal) => self.list_neurons_by_principal(&principal, limit),
            None => self.list_neurons_ordered(&req.start_page_at, limit),
        };

        ListNeuronsResponse {
            neurons: limited_neurons,
        }
    }

    /// Disburse the stake of a neuron.
    ///
    /// This causes the stake of a neuron to be disbursed to the provided
    /// principal (and optional subaccount). If `amount` is provided then
    /// that amount is disbursed.
    /// TODO explain other affects i.e. rewards that will be minted.
    ///
    /// Note that we don't enforce that 'amount' is actually smaller
    /// than or equal to the cached stake in the neuron.
    /// This will allow a user to still disburse funds if:
    /// - Someone transferred more funds to the neuron's subaccount after the
    ///   the initial neuron claim that we didn't know about.
    /// - The transfer of funds previously failed for some reason (e.g. the
    ///   ledger was unavailable or broken).
    ///
    /// On success returns the block height at which the transfer happened.
    ///
    /// Preconditions:
    /// - The neuron exists.
    /// - The caller is the controller of the neuron.
    /// - The neuron's state is `Dissolved` at the current timestamp.
    pub async fn disburse_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        disburse: &manage_neuron::Disburse,
    ) -> Result<u64, GovernanceError> {
        let transaction_fee_e8s = self.transaction_fee();
        let neuron = self.get_neuron_result(id)?;

        neuron.check_authorized(caller, NeuronPermissionType::Disburse)?;

        let state = neuron.state(self.env.now());
        if state != NeuronState::Dissolved {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!("Neuron {} is NOT dissolved. It is in state {:?}", id, state),
            ));
        }

        let from_subaccount = neuron.subaccount()?;

        // If no account was provided, transfer to the caller's account.
        let to_account: AccountIdentifier = match disburse.to_account.as_ref() {
            None => AccountIdentifier::new(*caller, None),
            Some(ai_pb) => AccountIdentifier::try_from(ai_pb).map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    format!("The recipient's subaccount is invalid due to: {}", e),
                )
            })?,
        };

        let rewards_amount_e8s = neuron.maturity_e8s_equivalent;
        let fees_amount_e8s = neuron.neuron_fees_e8s;
        // Calculate the amount to transfer, and adjust the cached stake,
        // accordingly. Make sure no matter what the user disburses we still
        // take the fees into account.
        //
        // Note that the implementation of stake_e8s is effectively:
        //   neuron.cached_neuron_stake_e8s.saturating_sub(neuron.neuron_fees_e8s)
        // So there is symmetry here in that we are subtracting
        // fees_amount_e8s from both sides of this `map_or`.
        let mut disburse_amount_e8s = disburse.amount.as_ref().map_or(neuron.stake_e8s(), |a| {
            a.e8s.saturating_sub(fees_amount_e8s)
        });

        // Subtract the transaction fee from the amount to disburse since it'll
        // be deducted from the source (the neuron's) account.
        if disburse_amount_e8s > transaction_fee_e8s {
            disburse_amount_e8s -= transaction_fee_e8s
        }

        // Add the neuron's id to the set of neurons with ongoing ledger updates.
        let _neuron_lock = self.lock_neuron_for_command(
            id,
            NeuronInFlightCommand {
                timestamp: self.env.now(),
                command: Some(InFlightCommand::Disburse(disburse.clone())),
            },
        )?;

        // We need to do 3 transfers:
        // 1 - Burn the neuron management fees.
        // 2 - Transfer the disbursed amount to the target account
        // 3 - Transfer the accumulated rewards that haven't been spawned yet
        //     to the target account.

        // Transfer 1 - burn the fees, but only if the value exceeds the cost of
        // a transaction fee, as the ledger doesn't support burn transfers for
        // an amount less than the transaction fee.
        if fees_amount_e8s > transaction_fee_e8s {
            let _result = self
                .ledger
                .transfer_funds(
                    fees_amount_e8s,
                    0, // Burning transfers don't pay a fee.
                    Some(from_subaccount),
                    governance_minting_account(),
                    self.env.now(),
                )
                .await?;
        }

        let nid = id.to_string();
        let neuron = self
            .proto
            .neurons
            .get_mut(&nid)
            .expect("Expected the parent neuron to exist");

        // Update the stake and the fees to reflect the burning above.
        if neuron.cached_neuron_stake_e8s > fees_amount_e8s {
            neuron.cached_neuron_stake_e8s -= fees_amount_e8s;
        } else {
            neuron.cached_neuron_stake_e8s = 0;
        }
        neuron.neuron_fees_e8s = 0;

        // Transfer 2 - Disburse to the chosen account. This may fail if the
        // user told us to disburse more than they had in their account (but
        // the burn still happened).
        let block_height = self
            .ledger
            .transfer_funds(
                disburse_amount_e8s,
                transaction_fee_e8s,
                Some(from_subaccount),
                to_account,
                self.env.now(),
            )
            .await?;

        let to_deduct = disburse_amount_e8s + transaction_fee_e8s;
        // The transfer was successful we can change the stake of the neuron.
        neuron.cached_neuron_stake_e8s = neuron.cached_neuron_stake_e8s.saturating_sub(to_deduct);

        // Transfer 3 - Transfer the accumulated maturity by minting into the
        // chosen account, but only if the value exceeds the cost of a transaction fee
        // as the ledger doesn't support ledger transfers for an amount less than the
        // transaction fee.
        if rewards_amount_e8s > transaction_fee_e8s {
            let _ = self
                .ledger
                .transfer_funds(
                    rewards_amount_e8s,
                    0, // Minting transfer don't pay a fee.
                    None,
                    to_account,
                    self.env.now(),
                )
                .await?;
        }

        neuron.maturity_e8s_equivalent = 0;

        Ok(block_height)
    }

    /// Splits a neuron into two neurons.
    ///
    /// The parent neuron's stake is decreased by the amount specified in
    /// Split, while the child neuron is created with a stake
    /// equal to that amount, minus the transfer fee.
    ///
    /// The child neuron inherits all the properties of its parent
    /// including age and dissolve state.
    ///
    /// On success returns the newly created neuron's id.
    ///
    /// Preconditions:
    /// - The parent neuron exists
    /// - The caller has the `NeuronPermissionType::Disburse` permission for the
    ///   neuron
    /// - The parent neuron is not already undergoing ledger updates.
    /// - The staked amount minus amount to split is more than the minimum
    ///   stake.
    /// - The amount to split minus the transfer fee is more than the minimum
    ///   stake.
    pub async fn split_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        split: &manage_neuron::Split,
    ) -> Result<NeuronId, GovernanceError> {
        // New neurons are not allowed when the heap is too large.
        self.check_heap_can_grow()?;

        let min_stake = self
            .proto
            .parameters
            .as_ref()
            .expect("Governance must have NervousSystemParameters.")
            .neuron_minimum_stake_e8s
            .expect("NervousSystemParameters must have neuron_minimum_stake_e8s");

        let transaction_fee_e8s = self.transaction_fee();

        // Get the neuron and clone to appease the borrow checker.
        // We'll get a mutable reference when we need to change it later.
        let parent_neuron = self.get_neuron_result(id)?.clone();
        let parent_nid = parent_neuron.id.as_ref().expect("Neurons must have an id");

        parent_neuron.check_authorized(caller, NeuronPermissionType::Split)?;

        if split.amount_e8s < min_stake + transaction_fee_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!(
                    "Trying to split a neuron with argument {} e8s. This is too little: \
                      at the minimum, one needs the minimum neuron stake, which is {} e8s, \
                      plus the transaction fee, which is {}. Hence the minimum split amount is {}.",
                    split.amount_e8s,
                    min_stake,
                    transaction_fee_e8s,
                    min_stake + transaction_fee_e8s
                ),
            ));
        }

        if parent_neuron.stake_e8s() < min_stake + split.amount_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!(
                    "Trying to split {} e8s out of neuron {}. \
                     This is not allowed, because the parent has stake {} e8s. \
                     If the requested amount was subtracted from it, there would be less than \
                     the minimum allowed stake, which is {} e8s. ",
                    split.amount_e8s,
                    parent_nid,
                    parent_neuron.stake_e8s(),
                    min_stake
                ),
            ));
        }

        let creation_timestamp_seconds = self.env.now();

        let from_subaccount = parent_neuron.subaccount()?;

        let child_nid = self.new_neuron_id(caller, split.memo)?;
        let to_subaccount = child_nid.subaccount()?;

        let in_flight_command = NeuronInFlightCommand {
            timestamp: creation_timestamp_seconds,
            command: Some(InFlightCommand::Split(split.clone())),
        };

        let staked_amount = split.amount_e8s - transaction_fee_e8s;

        // Make sure the parent neuron is not already undergoing a ledger
        // update.
        let _parent_lock = self.lock_neuron_for_command(parent_nid, in_flight_command.clone())?;

        // Before we do the transfer, we need to save the neuron in the map
        // otherwise a trap after the transfer is successful but before this
        // method finishes would cause the funds to be lost.
        // However the new neuron is not yet ready to be used as we can't know
        // whether the transfer will succeed, so we temporarily set the
        // stake to 0 and only change it after the transfer is successful.
        let child_neuron = Neuron {
            id: Some(child_nid.clone()),
            permissions: parent_neuron.permissions.clone(),
            cached_neuron_stake_e8s: 0,
            neuron_fees_e8s: 0,
            created_timestamp_seconds: creation_timestamp_seconds,
            aging_since_timestamp_seconds: parent_neuron.aging_since_timestamp_seconds,
            followees: parent_neuron.followees.clone(),
            maturity_e8s_equivalent: 0,
            dissolve_state: parent_neuron.dissolve_state.clone(),
        };

        // Add the child neuron to the set of neurons undergoing ledger updates.
        let _child_lock = self.lock_neuron_for_command(&child_nid, in_flight_command.clone())?;

        // We need to add the "embryo neuron" to the governance proto only after
        // acquiring the lock. Indeed, in case there is already a pending
        // command, we return without state rollback. If we had already created
        // the embryo, it would not be garbage collected.
        self.add_neuron(child_neuron.clone())?;

        // Do the transfer.
        let result: Result<u64, NervousSystemError> = self
            .ledger
            .transfer_funds(
                staked_amount,
                transaction_fee_e8s,
                Some(from_subaccount),
                neuron_account_id(to_subaccount),
                split.memo,
            )
            .await;

        if let Err(error) = result {
            let error = GovernanceError::from(error);
            // If we've got an error, we assume the transfer didn't happen for
            // some reason. The only state to cleanup is to delete the child
            // neuron, since we haven't mutated the parent yet.
            self.remove_neuron(&child_nid, child_neuron)?;
            println!(
                "Neuron stake transfer of split_neuron: {:?} \
                     failed with error: {:?}. Neuron can't be staked.",
                child_nid, error
            );
            return Err(error);
        }

        // Get the neuron again, but this time a mutable reference.
        // Expect it to exist, since we acquired a lock above.
        let parent_neuron = self.get_neuron_result_mut(id).expect("Neuron not found");

        // Update the state of the parent and child neurons.
        parent_neuron.cached_neuron_stake_e8s -= split.amount_e8s;

        let child_neuron = self
            .get_neuron_result_mut(&child_nid)
            .expect("Expected the child neuron to exist");

        child_neuron.cached_neuron_stake_e8s = staked_amount;
        Ok(child_nid)
    }

    /// Merges the maturity of a neuron into the neuron's stake.
    ///
    /// This method allows a neuron controller to merge the currently
    /// existing maturity of a neuron into the neuron's stake. The
    /// caller can choose a percentage of maturity to merge.
    ///
    /// Pre-conditions:
    /// - The caller has the `NeuronPermissionType::ManageMaturity` permission
    ///   for the neuron
    /// - The neuron has some maturity to merge.
    /// - The e8s equivalent of the amount of maturity to merge must be more
    ///   than the transaction fee.
    pub async fn merge_maturity(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        merge_maturity: &manage_neuron::MergeMaturity,
    ) -> Result<MergeMaturityResponse, GovernanceError> {
        let neuron = self.get_neuron_result(id)?.clone();
        let nid = neuron.id.as_ref().expect("Neurons must have an id");
        let subaccount = neuron.subaccount()?;

        neuron.check_authorized(caller, NeuronPermissionType::MergeMaturity)?;

        if merge_maturity.percentage_to_merge > 100 || merge_maturity.percentage_to_merge == 0 {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "The percentage of maturity to merge must be a value between 0 (exclusive) and 1 (inclusive)."));
        }

        let transaction_fee_e8s = self.transaction_fee();

        let mut maturity_to_merge =
            (neuron.maturity_e8s_equivalent * merge_maturity.percentage_to_merge as u64) / 100;

        // Converting u64 to f64 can cause the u64 to be "rounded up", so we
        // need to account for this possibility.
        if maturity_to_merge > neuron.maturity_e8s_equivalent {
            maturity_to_merge = neuron.maturity_e8s_equivalent;
        }

        if maturity_to_merge <= transaction_fee_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Tried to merge {} e8s, but can't merge an amount less than the transaction fee of {} e8s",
                    maturity_to_merge,
                    transaction_fee_e8s
                ),
            ));
        }

        let now = self.env.now();
        let in_flight_command = NeuronInFlightCommand {
            timestamp: now,
            command: Some(InFlightCommand::MergeMaturity(merge_maturity.clone())),
        };

        // Lock the neuron so that no other operation can change the maturity while we
        // mint and merge the new stake from the maturity.
        let _neuron_lock = self.lock_neuron_for_command(nid, in_flight_command.clone())?;

        // Do the transfer, this is a minting transfer, from the governance canister's
        // (which is also the minting canister) main account into the neuron's
        // subaccount.
        #[rustfmt::skip]
        let _block_height: u64 = self
            .ledger
            .transfer_funds(
                maturity_to_merge,
                0, // Minting transfer don't pay a fee
                None, // This is a minting transfer, no 'from' account is needed
                neuron_account_id(subaccount), // The account of the neuron on the ledger
                self.env.random_u64(), // Random memo(nonce) for the ledger's transaction
            )
            .await?;

        // Adjust the maturity, stake and age of the neuron
        let neuron = self
            .get_neuron_result_mut(nid)
            .expect("Expected the neuron to exist");

        neuron.maturity_e8s_equivalent = neuron
            .maturity_e8s_equivalent
            .saturating_sub(maturity_to_merge);
        let new_stake = neuron
            .cached_neuron_stake_e8s
            .saturating_add(maturity_to_merge);
        neuron.update_stake(new_stake, now);
        let new_stake_e8s = neuron.cached_neuron_stake_e8s;

        Ok(MergeMaturityResponse {
            merged_maturity_e8s: maturity_to_merge,
            new_stake_e8s,
        })
    }

    pub async fn disburse_maturity(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        disburse_maturity: &manage_neuron::DisburseMaturity,
    ) -> Result<DisburseMaturityResponse, GovernanceError> {
        let neuron = self.get_neuron_result(id)?;
        neuron.check_authorized(caller, NeuronPermissionType::DisburseMaturity)?;

        // If no account was provided, transfer to the caller's account.
        let to_account: AccountIdentifier = match disburse_maturity.to_account.as_ref() {
            None => AccountIdentifier::new(*caller, None),
            Some(account_identifier) => {
                AccountIdentifier::try_from(account_identifier).map_err(|e| {
                    GovernanceError::new_with_message(
                        ErrorType::InvalidCommand,
                        format!(
                            "The given account to disburse the maturity to is invalid due to: {}",
                            e
                        ),
                    )
                })?
            }
        };

        if disburse_maturity.percentage_to_disburse > 100
            || disburse_maturity.percentage_to_disburse == 0
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "The percentage of maturity to disburse must be a value between 1 and 100 (inclusive)."));
        }

        let maturity_to_disburse = neuron
            .maturity_e8s_equivalent
            .checked_mul(disburse_maturity.percentage_to_disburse as u64)
            .expect("Overflow while processing maturity to disburse.")
            .checked_div(100)
            .expect("Error when processing maturity to disburse.");

        // Add the neuron's id to the set of neurons with ongoing ledger updates.
        let _neuron_lock = self.lock_neuron_for_command(
            id,
            NeuronInFlightCommand {
                timestamp: self.env.now(),
                command: Some(InFlightCommand::DisburseMaturity(disburse_maturity.clone())),
            },
        )?;

        let transaction_fee_e8s = self.transaction_fee();
        if maturity_to_disburse < transaction_fee_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Ledger transfers of an amount({}) less than \
                    transaction fee({}) not supported.",
                    maturity_to_disburse, transaction_fee_e8s
                ),
            ));
        }

        // Do the transfer, this is a minting transfer, from the governance canister's
        // main account (which is also the minting account) to the provided account.
        let block_height = self
            .ledger
            .transfer_funds(
                maturity_to_disburse,
                0,    // Minting transfers don't pay a fee.
                None, // This is a minting transfer, no 'from' account is needed
                to_account,
                self.env.now(), // The memo(nonce) for the ledger's transaction
            )
            .await?;

        // Re-borrow the neuron mutably to update now that the maturity has been
        // disbursed.
        let mut neuron = self.get_neuron_result_mut(id)?;
        neuron.maturity_e8s_equivalent = neuron
            .maturity_e8s_equivalent
            .saturating_sub(maturity_to_disburse);

        Ok(DisburseMaturityResponse {
            transfer_block_height: block_height,
            amount_disbursed_e8s: maturity_to_disburse,
        })
    }

    /// Set the status of a proposal that is 'being executed' to
    /// 'executed' or 'failed' depending on the value of 'success'.
    ///
    /// The proposal ID 'pid' is taken as a raw integer to avoid
    /// lifetime issues.
    pub fn set_proposal_execution_status(&mut self, pid: u64, result: Result<(), GovernanceError>) {
        match self.proto.proposals.get_mut(&pid) {
            Some(mut proposal) => {
                // The proposal has to be adopted before it is executed.
                assert_eq!(
                    proposal.status(),
                    ProposalDecisionStatus::ProposalStatusAdopted
                );
                match result {
                    Ok(_) => {
                        println!("Execution of proposal: {} succeeded.", pid);
                        // The proposal was executed 'now'.
                        proposal.executed_timestamp_seconds = self.env.now();
                        // If the proposal previously failed to be
                        // executed, it is no longer that case that the
                        // proposal failed to be executed.
                        proposal.failed_timestamp_seconds = 0;
                        proposal.failure_reason = None;
                    }
                    Err(error) => {
                        println!("Execution of proposal: {} failed. Reason: {:?}", pid, error);
                        // Only update the failure timestamp is there if
                        // not yet any report of success in executing this
                        // proposal. If success already has been reported,
                        // it may be that the failure is reported after
                        // the success, e.g., due to a retry.
                        if proposal.executed_timestamp_seconds == 0 {
                            proposal.failed_timestamp_seconds = self.env.now();
                            proposal.failure_reason = Some(error);
                        }
                    }
                }
            }
            None => {
                // The proposal ID was not found. Something is wrong:
                // just log this information to aid debugging.
                println!(
                    "{}Proposal {:?} not found when attempt to set execution result to {:?}",
                    log_prefix(),
                    pid,
                    result
                );
            }
        }
    }

    pub fn latest_reward_event(&self) -> RewardEvent {
        self.proto
            .latest_reward_event
            .as_ref()
            .expect("Invariant violation! There should always be a latest_reward_event.")
            .clone()
    }

    /// Tries to get a proposal given a proposal id
    pub fn get_proposal(&self, req: &GetProposal) -> GetProposalResponse {
        let pid = req.proposal_id.expect("GetProposal must have proposal_id");
        let proposal_data = match self.proto.proposals.get(&pid.id) {
            None => get_proposal_response::Result::Error(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "No proposal for given ProposalId.",
            )),
            Some(pd) => get_proposal_response::Result::Proposal(pd.clone()),
        };

        GetProposalResponse {
            result: Some(proposal_data),
        }
    }

    fn limit_proposal_data(&self, data: &ProposalData) -> ProposalData {
        let mut new_proposal = data.proposal.clone();
        if let Some(proposal) = &mut new_proposal {
            if let Some(proposal::Action::ExecuteNervousSystemFunction(m)) = &mut proposal.action {
                if m.payload.len() > EXECUTE_NERVOUS_SYSTEM_FUNCTION_PAYLOAD_LISTING_BYTES_MAX {
                    m.payload.clear();
                }
            }
        }

        ProposalData {
            action: data.action,
            id: data.id,
            proposer: data.proposer.clone(),
            reject_cost_e8s: data.reject_cost_e8s,
            proposal: new_proposal,
            proposal_creation_timestamp_seconds: data.proposal_creation_timestamp_seconds,
            ballots: HashMap::new(), // To reduce size of payload, exclude ballots
            latest_tally: data.latest_tally.clone(),
            decided_timestamp_seconds: data.decided_timestamp_seconds,
            executed_timestamp_seconds: data.executed_timestamp_seconds,
            failed_timestamp_seconds: data.failed_timestamp_seconds,
            failure_reason: data.failure_reason.clone(),
            reward_event_round: data.reward_event_round,
            wait_for_quiet_state: data.wait_for_quiet_state.clone(),
        }
    }

    /// Returns the proposals info of proposals with proposal ID less
    /// than `before_proposal` (exclusive), returning at most `limit` proposal
    /// infos. If `before_proposal` is not provided, start from the highest
    /// available proposal ID (inclusive). If `limit` is not provided, the
    /// system max MAX_LIST_PROPOSAL_RESULTS will be used.
    ///
    /// As proposal IDs are assigned sequentially, this retrieves up to
    /// `limit` proposals older (in terms of creation) than a specific
    /// proposal. This can be used to paginate through proposals, as follows:
    ///
    /// `
    /// let mut lst = gov.list_proposals(ListProposalInfo {});
    /// while !lst.empty() {
    ///   /* do stuff with lst */
    ///   lst = gov.list_proposals(ListProposalInfo {
    ///     before_proposal: lst.last().and_then(|x|x.id)
    ///   });
    /// }
    /// `
    ///
    /// - The proposal's ballots are not returned in the `ListProposalResponse`.
    ///
    /// - Proposals with `ExecuteNervousSystemFunction` as action have their
    /// `payload` cleared if larger than
    /// EXECUTE_NERVOUS_SYSTEM_FUNCTION_PAYLOAD_LISTING_BYTES_MAX.
    ///
    /// The caller can retrieve dropped payloads by calling `get_proposal` for
    /// each proposal of interest.
    pub fn list_proposals(&self, req: &ListProposals) -> ListProposalsResponse {
        let exclude_type: HashSet<u64> = req.exclude_type.iter().cloned().collect();
        let include_reward_status: HashSet<i32> =
            req.include_reward_status.iter().cloned().collect();
        let include_status: HashSet<i32> = req.include_status.iter().cloned().collect();
        let now = self.env.now();
        let filter_all = |data: &ProposalData| -> bool {
            let action = data.action;
            let voting_period_seconds = self.voting_period_seconds()();
            // Filter out proposals by topic.
            if exclude_type.contains(&action) {
                return false;
            }
            // Filter out proposals by reward status.
            if !(include_reward_status.is_empty()
                || include_reward_status
                    .contains(&(data.reward_status(now, voting_period_seconds) as i32)))
            {
                return false;
            }
            // Filter out proposals by status.
            if !(include_status.is_empty() || include_status.contains(&(data.status() as i32))) {
                return false;
            }

            true
        };
        let limit = if req.limit == 0 || req.limit > MAX_LIST_PROPOSAL_RESULTS {
            MAX_LIST_PROPOSAL_RESULTS
        } else {
            req.limit
        } as usize;
        let props = &self.proto.proposals;
        // Proposals are stored in a sorted map. If 'before_proposal'
        // is provided, grab all proposals before that, else grab the
        // whole range.
        let rng = if let Some(n) = req.before_proposal {
            props.range(..(n.id))
        } else {
            props.range(..)
        };
        // Now reverse the range, filter, and restrict to 'limit'.
        let limited_rng = rng.rev().filter(|(_, x)| filter_all(x)).take(limit);
        //
        let proposal_info = limited_rng
            .map(|(_, y)| y)
            .map(|pd| self.limit_proposal_data(pd))
            .collect();

        // Ignore the keys and clone to a vector.
        ListProposalsResponse {
            proposals: proposal_info,
        }
    }

    fn ready_to_be_settled_proposal_ids(&self) -> impl Iterator<Item = ProposalId> + '_ {
        let now = self.env.now();
        self.proto
            .proposals
            .iter()
            .filter(move |(_, data)| {
                let voting_period_seconds = self.voting_period_seconds()();
                data.reward_status(now, voting_period_seconds)
                    == ProposalRewardStatus::ReadyToSettle
            })
            .map(|(k, _)| ProposalId { id: *k })
    }

    /// This method attempts to move a proposal forward in the process,
    /// from open to adopted or rejected, to executed or failed (for a
    /// previously adopted proposal).
    ///
    /// If the proposal is open, it tallies the ballots and updates the
    /// `yes`, `no`, and `undecided` voting power accordingly.
    ///
    /// This may result in the proposal becoming adopted or rejected.
    ///
    /// If a proposal is adopted but not executed, this method
    /// attempts to execute it.
    pub fn process_proposal(&mut self, pid: u64) {
        let now_seconds = self.env.now();
        // Due to Rust lifetime issues, we must extract a closure that
        // computes the voting period from a topic before we borrow
        // `self.proposals` mutably.
        let voting_period_seconds_fn = self.voting_period_seconds();
        if let Some(p) = self.proto.proposals.get_mut(&pid) {
            if p.status() != ProposalDecisionStatus::ProposalStatusOpen {
                return;
            }
            let voting_period_seconds = voting_period_seconds_fn();
            // Recompute the tally here. It is imperative that only
            // 'open' proposals have their tally recomputed. Votes may
            // arrive after a decision has been made: such votes count
            // for voting rewards, but shall not make it into the
            // tally.
            p.recompute_tally(now_seconds, voting_period_seconds);
            if p.can_make_decision(now_seconds, voting_period_seconds) {
                // This marks the proposal as no longer open.
                p.decided_timestamp_seconds = now_seconds;
                if p.is_accepted() {
                    // The proposal was adopted, return the rejection fee.
                    if let Some(nid) = &p.proposer {
                        if let Some(neuron) = self.proto.neurons.get_mut(&nid.to_string()) {
                            if neuron.neuron_fees_e8s >= p.reject_cost_e8s {
                                neuron.neuron_fees_e8s -= p.reject_cost_e8s;
                            }
                        }
                    }
                    if let Some(action) = p.proposal.as_ref().and_then(|x| x.action.clone()) {
                        // A yes decision as been made, execute the proposal!
                        self.start_proposal_execution(pid, &action);
                    } else {
                        self.set_proposal_execution_status(
                            pid,
                            Err(GovernanceError::new_with_message(
                                ErrorType::PreconditionFailed,
                                "Proposal action is missing.",
                            )),
                        );
                    }
                }
            }
        }
    }

    /// Process all the open proposals.
    fn process_proposals(&mut self) {
        if self.env.now() < self.closest_proposal_deadline_timestamp_seconds {
            // Nothing to do.
            return;
        }

        let pids = self
            .proto
            .proposals
            .iter()
            .filter(|(_, info)| info.status() == ProposalDecisionStatus::ProposalStatusOpen)
            .map(|(pid, _)| *pid)
            .collect::<Vec<u64>>();

        for pid in pids {
            self.process_proposal(pid);
        }

        self.closest_proposal_deadline_timestamp_seconds = self
            .proto
            .proposals
            .values()
            .filter(|data| data.status() == ProposalDecisionStatus::ProposalStatusOpen)
            .map(|data| {
                data.proposal_creation_timestamp_seconds
                    .saturating_add(self.voting_period_seconds()())
            })
            .min()
            .unwrap_or(u64::MAX);
    }

    /// Starts execution of the given proposal in the background.
    fn start_proposal_execution(&mut self, pid: u64, action: &proposal::Action) {
        // `perform_action` is an async method of &mut self.
        //
        // Starting it and letting it run in the background requires knowing that
        // the `self` reference will last until the future has completed.
        //
        // The compiler cannot know that, but this is actually true:
        //
        // - in unit tests, all futures are immediately ready, because no real async
        //   call is made. In this case, the transmutation to a static ref is abusive,
        //   but it's still ok since the future will immediately resolve.
        //
        // - in prod, "self" in a reference to the GOVERNANCE static variable, which is
        //   initialized only once (in canister_init or canister_post_upgrade)
        let governance: &'static mut Governance = unsafe { std::mem::transmute(self) };
        spawn(governance.perform_action(pid, action.clone()));
    }

    async fn perform_action(&mut self, pid: u64, action: proposal::Action) {
        match action {
            // A motion is not executed, just recorded for posterity.
            proposal::Action::Motion(_) => {
                self.set_proposal_execution_status(pid, Ok(()));
            }
            proposal::Action::ManageNervousSystemParameters(params) => {
                let result = self.perform_manage_nervous_system_parameters_action(params);
                self.set_proposal_execution_status(pid, result);
            }
            proposal::Action::UpgradeSnsControlledCanister(_) => {
                // TODO
            }
            proposal::Action::ExecuteNervousSystemFunction(_) => {
                // TODO
            }
            proposal::Action::Unspecified(_) => {
                // throw an error
            }
        }
    }

    /// Execute a ManageNervousSystemParameters proposal by updating Governance's NervousSystemParameters
    fn perform_manage_nervous_system_parameters_action(
        &mut self,
        proposed_params: NervousSystemParameters,
    ) -> Result<(), GovernanceError> {
        // Only set `self.proto.parameters` if "applying" the proposed params to the
        // current params results in valid params
        let new_params = proposed_params.inherit_from(self.nervous_system_parameters());

        println!(
            "{}Setting Governance nervous system params to: {:?}",
            log_prefix(),
            &new_params
        );

        match new_params.validate() {
            Ok(()) => {
                self.proto.parameters = Some(new_params);
                Ok(())
            }
            Err(msg) => Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Failed to perform ManageNervousSystemParameters action, proposed \
                        parameters would lead to invalid NervousSystemParameters: {}",
                    msg
                ),
            )),
        }
    }

    fn nervous_system_parameters(&self) -> &NervousSystemParameters {
        self.proto
            .parameters
            .as_ref()
            .expect("NervousSystemParameters not present")
    }

    fn neuron_claimer_permissions(&self) -> NeuronPermissionList {
        self.nervous_system_parameters()
            .neuron_claimer_permissions
            .as_ref()
            .expect("NervousSystemParameters.neuron_claimer_permissions must be present")
            .clone()
    }

    fn default_followees(&self) -> DefaultFollowees {
        self.nervous_system_parameters()
            .default_followees
            .as_ref()
            .expect("NervousSystemParameters.default_followees must be present")
            .clone()
    }

    /// Inserts a proposals that has already been validated in the state.
    ///
    /// This is a low-level function that makes no verification whatsoever.
    fn insert_proposal(&mut self, pid: u64, data: ProposalData) {
        let voting_period_seconds = self.voting_period_seconds()();
        self.closest_proposal_deadline_timestamp_seconds = std::cmp::min(
            data.proposal_creation_timestamp_seconds + voting_period_seconds,
            self.closest_proposal_deadline_timestamp_seconds,
        );
        self.proto.proposals.insert(pid, data);
        self.process_proposal(pid);
    }

    /// The proposal id of the next proposal.
    fn next_proposal_id(&self) -> u64 {
        // Correctness is based on the following observations:
        // * Proposal GC never removes the proposal with highest ID.
        // * The proposal map is a BTreeMap, so the proposals are ordered by id.
        self.proto
            .proposals
            .iter()
            .next_back()
            .map_or(1, |(k, _)| k + 1)
    }

    fn validate_proposal(&mut self, proposal: &Proposal) -> Result<(), GovernanceError> {
        if !proposal.allowed_when_resources_are_low() {
            self.check_heap_can_grow()?;
        }

        let error_str = if proposal.title.len() > PROPOSAL_TITLE_BYTES_MAX {
            format!(
                "The maximum proposal title size is {} bytes, this proposal title is: {} bytes",
                PROPOSAL_TITLE_BYTES_MAX,
                proposal.title.len(),
            )
        } else if proposal.summary.len() > PROPOSAL_SUMMARY_BYTES_MAX {
            format!(
                "The maximum proposal summary size is {} bytes, this proposal is: {} bytes",
                PROPOSAL_SUMMARY_BYTES_MAX,
                proposal.summary.len(),
            )
        } else if proposal.url.chars().count() > PROPOSAL_URL_CHAR_MAX {
            format!(
                "The maximum proposal url size is {} characters, this proposal has: {} characters",
                PROPOSAL_URL_CHAR_MAX,
                proposal.url.chars().count()
            )
        } else if let Some(proposal::Action::Motion(motion)) = &proposal.action {
            if motion.motion_text.len() > PROPOSAL_MOTION_TEXT_BYTES_MAX {
                format!(
                    "The maximum motion text size in a proposal action is {} bytes, this motion text is: {} bytes",
                    PROPOSAL_MOTION_TEXT_BYTES_MAX,
                    motion.motion_text.len()
                )
            } else {
                return Ok(());
            }
        } else if let Some(proposal::Action::ManageNervousSystemParameters(params)) =
            &proposal.action
        {
            // Proposed NervousSystemParameters are valid if when "applied" to the current system
            // params the resulting NervousSystemParameters are valid.
            return params
                .clone()
                .inherit_from(self.nervous_system_parameters())
                .validate()
                .map_err(|msg| GovernanceError::new_with_message(ErrorType::InvalidProposal, msg));
        } else {
            return Ok(());
        };

        Err(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            &error_str,
        ))
    }

    pub fn make_proposal(
        &mut self,
        proposer_id: &NeuronId,
        caller: &PrincipalId,
        proposal: &Proposal,
    ) -> Result<ProposalId, GovernanceError> {
        let now_seconds = self.env.now();
        let unspecified = Action::Unspecified(Empty {});

        // Validate proposal
        self.validate_proposal(proposal)?;

        let action = proposal.action.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "Proposal must have an action",
            )
        })?;

        if action == &unspecified {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "Proposal cannot be submitted with action set to Action::Unspecified",
            ));
        }

        let reject_cost_e8s = self
            .nervous_system_parameters()
            .reject_cost_e8s
            .expect("NervousSystemParameters must have reject_cost_e8s");

        // Before actually modifying anything, we first make sure that
        // the neuron is allowed to make this proposal and create the
        // electoral roll.
        //
        // Find the proposing neuron.
        let proposer = self.get_neuron_result(proposer_id)?;

        // === Validation
        //
        // Check that the caller is authorized to make a proposal
        proposer.check_authorized(caller, NeuronPermissionType::SubmitProposal)?;

        let min_dissolve_delay_for_vote = self
            .nervous_system_parameters()
            .neuron_minimum_dissolve_delay_to_vote_seconds
            .expect("NervousSystemParameters must have min_dissolve_delay_for_vote");
        // The neuron cannot be dissolved until the proposal has been adopted or
        // rejected.
        if proposer.dissolve_delay_seconds(now_seconds) < min_dissolve_delay_for_vote {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Neuron's dissolve delay is too short.",
            ));
        }

        // If the current stake of this neuron is less than the cost
        // of having a proposal rejected, the neuron cannot vote -
        // because the proposal may be rejected.
        if proposer.stake_e8s() < reject_cost_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Neuron doesn't have enough stake to submit proposal.",
            ));
        }

        // Check that there are not too many proposals.  What matters
        // here is the number of proposals for which ballots have not
        // yet been cleared, because ballots take the most amount of
        // space.
        if self
            .proto
            .proposals
            .values()
            .filter(|data| !data.ballots.is_empty())
            .count()
            >= MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS
            && !proposal.allowed_when_resources_are_low()
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::ResourceExhausted,
                "Reached maximum number of proposals that have not yet \
                been taken into account for voting rewards. \
                Please try again later.",
            ));
        }

        // === Preparation
        //
        // For normal proposals, every neuron with a dissolve delay over
        // NervousSystemParameters.neuron_minimum_dissolve_delay_to_vote_seconds
        // is allowed to vote, with a voting power determined at the
        // time of the proposal (i.e., now).
        //
        // The electoral roll to put into the proposal.
        let mut electoral_roll = HashMap::<String, Ballot>::new();
        let mut total_power: u128 = 0;
        let max_dissolve_delay = self
            .nervous_system_parameters()
            .max_dissolve_delay_seconds
            .expect("NervousSystemParameters must have max_dissolve_delay_seconds");
        let max_age_bonus = self
            .nervous_system_parameters()
            .max_neuron_age_for_age_bonus
            .expect("NervousSystemParameters must have max_neuron_age_for_age_bonus");

        for (k, v) in self.proto.neurons.iter() {
            // If this neuron is eligible to vote, record its
            // voting power at the time of making the
            // proposal.
            if v.dissolve_delay_seconds(now_seconds) < min_dissolve_delay_for_vote {
                // Not eligible due to dissolve delay.
                continue;
            }
            let power = v.voting_power(now_seconds, max_dissolve_delay, max_age_bonus);
            total_power += power as u128;
            electoral_roll.insert(
                k.clone(),
                Ballot {
                    vote: Vote::Unspecified as i32,
                    voting_power: power,
                    cast_timestamp_seconds: 0,
                },
            );
        }
        if total_power >= (u64::MAX as u128) {
            // The way the neurons are configured, the total voting
            // power on this proposal would overflow a u64!
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Voting power overflow.",
            ));
        }
        if electoral_roll.is_empty() {
            // Cannot make a proposal with no eligible voters.  This
            // is a precaution that shouldn't happen as we check that
            // the voter is allowed to vote.
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "No eligible voters.",
            ));
        }
        // Create a new proposal ID for this proposal.
        let proposal_num = self.next_proposal_id();
        let proposal_id = ProposalId { id: proposal_num };
        // Create the proposal.
        let mut proposal_data = ProposalData {
            action: u64::from(action),
            id: Some(proposal_id),
            proposer: Some(proposer_id.clone()),
            reject_cost_e8s,
            proposal: Some(proposal.clone()),
            proposal_creation_timestamp_seconds: now_seconds,
            ballots: electoral_roll,
            ..Default::default()
        };

        proposal_data.wait_for_quiet_state = Some(WaitForQuietState {
            current_deadline_timestamp_seconds: now_seconds
                .saturating_add(self.voting_period_seconds()()),
        });

        // Charge the cost of rejection upfront.
        // This will protect from DOS in couple of ways:
        // - It prevents a neuron from having too many proposals outstanding.
        // - It reduces the voting power of the submitter so that for every proposal
        //   outstanding the submitter will have less voting power to get it approved.
        self.proto
            .neurons
            .get_mut(&proposer_id.to_string())
            .expect("Proposer not found.")
            .neuron_fees_e8s += proposal_data.reject_cost_e8s;

        // Cast self-vote, including following.
        Governance::cast_vote_and_cascade_follow(
            &mut proposal_data.ballots,
            proposer_id,
            Vote::Yes,
            action,
            &self.action_followee_index,
            &mut self.proto.neurons,
            now_seconds,
        );

        // Finally, add this proposal as an open proposal.
        self.insert_proposal(proposal_num, proposal_data);

        Ok(proposal_id)
    }

    // Register `voting_neuron_id` voting according to
    // `vote_of_neuron` (which must be `yes` or `no`) in 'ballots' and
    // cascade voting according to the following relationships
    // specified in 'followee_index' (mapping followees to followers for
    // the action) and 'neurons' (which contains a mapping of followers
    // to followees).
    fn cast_vote_and_cascade_follow(
        ballots: &mut HashMap<String, Ballot>,
        voting_neuron_id: &NeuronId,
        vote_of_neuron: Vote,
        action: &Action,
        action_followee_index: &BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>>,
        neurons: &mut BTreeMap<String, Neuron>,
        now_seconds: u64,
    ) {
        let unspecified_action = Action::Unspecified(Empty {});
        assert!(action != &unspecified_action);
        // This is the induction variable of the loop: a map from
        // neuron ID to the neuron's vote - 'yes' or 'no' (other
        // values not allowed).
        let mut induction_votes = BTreeMap::new();
        induction_votes.insert(voting_neuron_id.to_string(), vote_of_neuron);
        let action_key = u64::from(action);
        let action_cache = action_followee_index.get(&action_key);
        let unspecified_cache = action_followee_index.get(&u64::from(&unspecified_action));
        loop {
            // First, we cast the specified votes (in the first round,
            // this will be a single vote) and collect all neurons
            // that follow some of the neurons that are voting.
            let mut all_followers = BTreeSet::new();
            for (k, v) in induction_votes.iter() {
                // The new/induction votes cannot be unspecified.
                assert!(*v != Vote::Unspecified);
                if let Some(k_ballot) = ballots.get_mut(k) {
                    // Neuron with ID k is eligible to vote.
                    if k_ballot.vote == (Vote::Unspecified as i32) {
                        if let Some(_k_neuron) = neurons.get_mut(k) {
                            // Only update a vote if it was previously
                            // unspecified. Following can trigger votes
                            // for neurons that have already voted
                            // (manually) and we don't change these votes.
                            k_ballot.vote = *v as i32;
                            k_ballot.cast_timestamp_seconds = now_seconds;
                            // Here k is the followee, i.e., the neuron
                            // that has just cast a vote that may be
                            // followed by other neurons.
                            //
                            // Insert followers from 'action'
                            if let Some(more_followers) = action_cache.and_then(|x| x.get(k)) {
                                all_followers.append(&mut more_followers.clone());
                            }
                            // Insert followers from 'Unspecified' (default followers)
                            if let Some(more_followers) = unspecified_cache.and_then(|x| x.get(k)) {
                                all_followers.append(&mut more_followers.clone());
                            }
                        } else {
                            // The voting neuron not found in the
                            // neurons table. This is a bad
                            // inconsistency, but there is nothing
                            // that can be done about it at this
                            // place.
                        }
                    }
                } else {
                    // A non-eligible voter was specified in
                    // new/induction votes. We don't compute the
                    // followers of this neuron as it didn't actually
                    // vote.
                }
            }
            // Clear the induction_votes, as we are going to compute a
            // new set now.
            induction_votes.clear();
            for f in all_followers.iter() {
                if let Some(f_neuron) = neurons.get(&f.to_string()) {
                    let f_vote = f_neuron.would_follow_ballots(action_key, ballots);
                    if f_vote != Vote::Unspecified {
                        // f_vote is yes or no, i.e., f_neuron's
                        // followee relations indicates that it should
                        // vote now.
                        induction_votes.insert(f.to_string(), f_vote);
                    }
                }
            }
            // If induction_votes is empty, the loop will terminate
            // here.
            if induction_votes.is_empty() {
                return;
            }
            // We now continue to the next iteration of the loop.
            // Because induction_votes is not empty, either at least
            // one entry in 'ballots' will change from unspecified to
            // yes or no, or all_followers will be empty, whence
            // induction_votes will become empty.
            //
            // Thus, for each iteration of the loop, the number of
            // entries in 'ballots' that have an unspecified value
            // decreases, or else the loop terminates. As nothing is
            // added to 'ballots' (or removed for that matter), the
            // loop terminates in at most 'ballots.len()+1' steps.
            //
            // The worst case is attained if there is a linear
            // following graph, like this:
            //
            // X follows A follows B follows C,
            //
            // where X is not eligible to vote and nobody has
            // voted, i.e.,
            //
            // ballots = {
            //   A -> unspecified, B -> unspecified, C -> unspecified
            // }
            //
            // In this case, the subsequent values of
            // 'induction_votes' will be {C}, {B}, {A}, {X}.
            //
            // Note that it does not matter if X has followers. As X
            // doesn't vote, its followers are not considered.
        }
    }

    fn register_vote(
        &mut self,
        neuron_id: &NeuronId,
        caller: &PrincipalId,
        pb: &manage_neuron::RegisterVote,
    ) -> Result<(), GovernanceError> {
        let neuron = self
            .proto
            .neurons
            .get_mut(&neuron_id.to_string())
            .ok_or_else(||
            // The specified neuron is not present.
            GovernanceError::new_with_message(ErrorType::NotFound, "Neuron not found"))?;

        neuron.check_authorized(caller, NeuronPermissionType::Vote)?;
        let proposal_id = pb.proposal.as_ref().ok_or_else(||
            // Proposal not specified.
            GovernanceError::new_with_message(ErrorType::PreconditionFailed, "Registering of vote must include a proposal id."))?;
        let proposal = &mut (self.proto.proposals.get_mut(&proposal_id.id).ok_or_else(||
            // Proposal not found.
            GovernanceError::new_with_message(ErrorType::NotFound, "Can't find proposal."))?);
        let action = proposal
            .proposal
            .as_ref()
            .expect("ProposalData must have a proposal")
            .action
            .as_ref()
            .expect("Proposal must have an action");

        let vote = Vote::from_i32(pb.vote).unwrap_or(Vote::Unspecified);
        if vote == Vote::Unspecified {
            // Invalid vote specified, i.e., not yes or no.
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Invalid vote specified.",
            ));
        }
        let neuron_ballot = proposal.ballots.get_mut(&neuron_id.to_string()).ok_or_else(||
            // This neuron is not eligible to vote on this proposal.
            GovernanceError::new_with_message(ErrorType::NotAuthorized, "Neuron not eligible to vote on proposal."))?;
        if neuron_ballot.vote != (Vote::Unspecified as i32) {
            // Already voted.
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Neuron already voted on proposal.",
            ));
        }

        Governance::cast_vote_and_cascade_follow(
            // Actually update the ballot, including following.
            &mut proposal.ballots,
            neuron_id,
            vote,
            action,
            &self.action_followee_index,
            &mut self.proto.neurons,
            self.env.now(),
        );

        self.process_proposal(proposal_id.id);

        Ok(())
    }

    /// Add or remove followees for this neuron for a specified action.
    ///
    /// If the list of followees is empty, remove the followees for
    /// this action. If the list has at least one element, replace the
    /// current list of followees for the given topic with the
    /// provided list. Note that the list is replaced, not added to.
    fn follow(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        f: &manage_neuron::Follow,
    ) -> Result<(), GovernanceError> {
        // The implementation of this method is complicated by the
        // fact that we have to maintain a reverse index of all follow
        // relationships, i.e., the `topic_followee_index`.
        let neuron = self.proto.neurons.get_mut(&id.to_string()).ok_or_else(||
            // The specified neuron is not present.
            GovernanceError::new_with_message(ErrorType::NotFound, &format!("Follower neuron not found: {}", id)))?;

        // Check that the caller is authorized to change followers (same authorization
        // as voting required).
        neuron.check_authorized(caller, NeuronPermissionType::Vote)?;

        let max_followees_per_topic = self
            .proto
            .parameters
            .as_ref()
            .expect("NervousSystemParameters not present")
            .max_followees_per_action
            .expect("NervousSystemParameters must have max_followees_per_topic");

        // Check that the list of followees is not too
        // long. Allowing neurons to follow too many neurons
        // allows a memory exhaustion attack on the neurons
        // canister.
        if f.followees.len() > max_followees_per_topic as usize {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Too many followees.",
            ));
        }

        // First, remove the current followees for this neuron and
        // this action from the follower cache.
        if let Some(neuron_followees) = neuron.followees.get(&f.action_type) {
            // If this action is not represented in the
            // follower cache, there cannot be anything to remove.
            if let Some(followee_index) = self.action_followee_index.get_mut(&f.action_type) {
                // We need to remove this neuron as a follower
                // for all followees.
                for followee in &neuron_followees.followees {
                    if let Some(all_followers) = followee_index.get_mut(&followee.to_string()) {
                        all_followers.remove(id);
                    }
                    // Note: we don't check that the
                    // action_followee_index actually contains this
                    // neuron's ID as a follower for all the
                    // followees. This could be a warning, but
                    // it is not actionable.
                }
            }
        }
        if !f.followees.is_empty() {
            // TODO Since we want the flexibility of using u64 we may need a method that
            // doesn't allow users submitting a follow to spam "unofficial"
            // action_type_keys

            // Insert the new list of followees for this topic in
            // the neuron, removing the old list, which has
            // already been removed from the follower cache above.
            neuron.followees.insert(
                f.action_type,
                Followees {
                    followees: f.followees.clone(),
                },
            );
            let cache = self
                .action_followee_index
                .entry(f.action_type)
                .or_insert_with(BTreeMap::new);
            // We need to to add this neuron as a follower for
            // all followees.
            for followee in &f.followees {
                let all_followers = cache
                    .entry(followee.to_string())
                    .or_insert_with(BTreeSet::new);
                all_followers.insert(id.clone());
            }
            Ok(())
        } else {
            // This operation clears the followees for the given topic.
            neuron.followees.remove(&f.action_type);
            Ok(())
        }
    }

    fn configure_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        configure: &manage_neuron::Configure,
    ) -> Result<(), GovernanceError> {
        let neuron = self
            .proto
            .neurons
            .get_mut(&id.to_string())
            .ok_or_else(|| Self::neuron_not_found_error(id))?;

        neuron.check_authorized(caller, NeuronPermissionType::ConfigureDissolveState)?;

        let now_seconds = self.env.now();
        let max_dissolve_delay_seconds = self
            .proto
            .parameters
            .as_ref()
            .expect("NervousSystemParameters not present")
            .max_dissolve_delay_seconds
            .expect("NervousSystemParameters must have max_dissolve_delay_seconds");

        neuron.configure(now_seconds, configure, max_dissolve_delay_seconds)?;
        Ok(())
    }

    /// Creates a new neuron or refreshes the stake of an existing
    /// neuron from a ledger account.
    ///
    /// Pre-conditions:
    /// - The memo must match the nonce of the subaccount.
    ///
    /// Post-conditions:
    /// - If all the pre-conditions apply, either a new neuron is created or the
    ///   stake of an existing neuron is updated.
    async fn claim_or_refresh_neuron_by_memo_and_controller(
        &mut self,
        caller: &PrincipalId,
        memo_and_controller: MemoAndController,
        claim_or_refresh: &ClaimOrRefresh,
    ) -> Result<NeuronId, GovernanceError> {
        let controller = memo_and_controller.controller.unwrap_or(*caller);
        let memo = memo_and_controller.memo;
        let nid = NeuronId::from(ledger::compute_neuron_staking_subaccount(controller, memo));
        match self.get_neuron_result(&nid) {
            Ok(neuron) => {
                let nid = neuron.id.as_ref().expect("Neuron must have an id").clone();
                self.refresh_neuron(nid, claim_or_refresh).await
            }
            Err(_) => self.claim_neuron(nid, claim_or_refresh, &controller).await,
        }
    }

    /// Refreshes the neuron by it's id.
    async fn refresh_neuron_by_id(
        &mut self,
        id: NeuronId,
        claim_or_refresh: &ClaimOrRefresh,
    ) -> Result<NeuronId, GovernanceError> {
        self.refresh_neuron(id, claim_or_refresh).await
    }

    /// Refreshes the stake of a given neuron by checking it's account.
    async fn refresh_neuron(
        &mut self,
        nid: NeuronId,
        claim_or_refresh: &ClaimOrRefresh,
    ) -> Result<NeuronId, GovernanceError> {
        let now = self.env.now();
        let subaccount = nid.subaccount()?;
        let account = neuron_account_id(subaccount);
        // We need to lock the neuron to make sure it doesn't undergo
        // concurrent changes while we're checking the balance and
        // refreshing the stake.
        let _neuron_lock = self.lock_neuron_for_command(
            &nid,
            NeuronInFlightCommand {
                timestamp: self.env.now(),
                command: Some(InFlightCommand::ClaimOrRefreshNeuron(
                    claim_or_refresh.clone(),
                )),
            },
        )?;

        // Get the balance of the neuron from the ledger canister.
        let balance = self.ledger.account_balance(account).await?;
        let min_stake = self
            .nervous_system_parameters()
            .neuron_minimum_stake_e8s
            .expect("NervousSystemParameters must have neuron_minimum_stake_e8s");
        if balance.get_e8s() < min_stake {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!(
                    "Account does not have enough funds to refresh a neuron. \
                     Please make sure that account has at least {:?} e8s (was {:?} e8s)",
                    min_stake,
                    balance.get_e8s()
                ),
            ));
        }
        let neuron = self.get_neuron_result_mut(&nid)?;
        match neuron.cached_neuron_stake_e8s.cmp(&balance.get_e8s()) {
            Ordering::Greater => {
                println!(
                    "{}ERROR. Neuron cached stake was inconsistent.\
                     Neuron account: {} has less e8s: {} than the cached neuron stake: {}.\
                     Stake adjusted.",
                    log_prefix(),
                    account,
                    balance.get_e8s(),
                    neuron.cached_neuron_stake_e8s
                );
                neuron.update_stake(balance.get_e8s(), now);
            }
            Ordering::Less => {
                neuron.update_stake(balance.get_e8s(), now);
            }
            // If the stake is the same as the account balance,
            // just return the neuron id (this way this method
            // also serves the purpose of allowing to discover the
            // neuron id based on the memo and the controller).
            Ordering::Equal => (),
        };

        Ok(nid)
    }

    /// Claim a new neuron, unless the account doesn't have enough to stake a
    /// neuron or we've reached the maximum number of neurons, in which case
    /// we return an error.
    ///
    /// We can't return the funds without more information about the
    /// source account, so as a workaround for insufficient stake we can ask the
    /// user to transfer however much is missing to stake a neuron and they can
    /// then disburse if they so choose. We need to do something more involved
    /// if we've reached the max, TODO.
    ///
    /// Preconditions:
    /// - The new neuron won't take us above the `max_number_of_neurons`.
    /// - The amount transferred was greater than or equal to
    ///   `self.nervous_system_parameters.neuron_minimum_stake_e8s`.
    ///
    /// Note that we need to create the neuron before checking the balance
    /// so that we record the neuron and avoid a race where a user calls
    /// this method a second time before the first time responds. If we store
    /// the neuron and lock it before we make the call, we know that any
    /// concurrent call to mutate the same neuron will need to wait for this
    /// one to finish before proceeding.
    async fn claim_neuron(
        &mut self,
        nid: NeuronId,
        claim_or_refresh: &ClaimOrRefresh,
        claimer: &PrincipalId,
    ) -> Result<NeuronId, GovernanceError> {
        let now = self.env.now();

        let neuron = Neuron {
            id: Some(nid.clone()),
            permissions: vec![NeuronPermission::new(
                claimer,
                self.neuron_claimer_permissions().permissions,
            )],
            cached_neuron_stake_e8s: 0,
            neuron_fees_e8s: 0,
            created_timestamp_seconds: now,
            aging_since_timestamp_seconds: now,
            followees: self.default_followees().followees,
            maturity_e8s_equivalent: 0,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(0)),
        };

        // This also verifies that there are not too many neurons already.
        self.add_neuron(neuron.clone())?;

        let _neuron_lock = self.lock_neuron_for_command(
            &nid,
            NeuronInFlightCommand {
                timestamp: now,
                command: Some(InFlightCommand::ClaimOrRefreshNeuron(
                    claim_or_refresh.clone(),
                )),
            },
        )?;

        // Get the balance of the neuron's subaccount from ledger canister.
        let subaccount = nid.subaccount()?;
        let account = neuron_account_id(subaccount);
        let balance = self.ledger.account_balance(account).await?;
        let min_stake = self
            .nervous_system_parameters()
            .neuron_minimum_stake_e8s
            .expect("NervousSystemParameters must have neuron_minimum_stake_e8s");

        if balance.get_e8s() < min_stake {
            // To prevent this method from creating non-staked
            // neurons, we must also remove the neuron that was
            // previously created.
            self.remove_neuron(&nid, neuron)?;
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!(
                    "Account does not have enough funds to stake a neuron. \
                     Please make sure that account has at least {:?} e8s (was {:?} e8s)",
                    min_stake,
                    balance.get_e8s()
                ),
            ));
        }

        // Ok, we are able to stake the neuron.
        match self.get_neuron_result_mut(&nid) {
            Ok(neuron) => {
                // Adjust the stake.
                neuron.update_stake(balance.get_e8s(), now);
                Ok(nid)
            }
            Err(err) => {
                // This should not be possible, but let's be defensive and provide a
                // reasonable error message, but still panic so that the lock remains
                // acquired and we can investigate.
                panic!(
                    "When attempting to stake a neuron with ID {} and stake {:?},\
                     the neuron disappeared while the operation was in flight.\
                     Please try again: {}",
                    nid,
                    balance.get_e8s(),
                    err
                )
            }
        }
    }

    pub async fn manage_neuron(
        &mut self,
        mgmt: &ManageNeuron,
        caller: &PrincipalId,
    ) -> ManageNeuronResponse {
        self.manage_neuron_internal(caller, mgmt)
            .await
            .unwrap_or_else(ManageNeuronResponse::error)
    }

    pub async fn manage_neuron_internal(
        &mut self,
        caller: &PrincipalId,
        mgmt: &ManageNeuron,
    ) -> Result<ManageNeuronResponse, GovernanceError> {
        // We run claim or refresh before we check whether a neuron exists because it
        // may not in the case of the neuron being claimed
        if let Some(manage_neuron::Command::ClaimOrRefresh(claim_or_refresh)) = &mgmt.command {
            // Note that we return here, so none of the rest of this method is executed
            // in this case.
            return match &claim_or_refresh.by {
                Some(By::MemoAndController(memo_and_controller)) => self
                    .claim_or_refresh_neuron_by_memo_and_controller(
                        caller,
                        memo_and_controller.clone(),
                        claim_or_refresh,
                    )
                    .await
                    .map(ManageNeuronResponse::claim_or_refresh_neuron_response),

                Some(By::NeuronId(_)) => {
                    let id = NeuronId::from(Self::bytes_to_subaccount(&mgmt.subaccount)?);
                    self.refresh_neuron_by_id(id, claim_or_refresh)
                        .await
                        .map(ManageNeuronResponse::claim_or_refresh_neuron_response)
                }
                None => Err(GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    "Need to provide a way by which to claim or refresh the neuron.",
                )),
            };
        }

        let id = NeuronId::from(Self::bytes_to_subaccount(&mgmt.subaccount)?);

        match &mgmt.command {
            Some(manage_neuron::Command::Configure(c)) => self
                .configure_neuron(&id, caller, c)
                .map(|_| ManageNeuronResponse::configure_response()),
            Some(manage_neuron::Command::Disburse(d)) => self
                .disburse_neuron(&id, caller, d)
                .await
                .map(ManageNeuronResponse::disburse_response),
            Some(manage_neuron::Command::MergeMaturity(m)) => self
                .merge_maturity(&id, caller, m)
                .await
                .map(ManageNeuronResponse::merge_maturity_response),
            Some(DisburseMaturity(d)) => self
                .disburse_maturity(&id, caller, d)
                .await
                .map(ManageNeuronResponse::disburse_maturity_response),
            Some(manage_neuron::Command::Split(s)) => self
                .split_neuron(&id, caller, s)
                .await
                .map(ManageNeuronResponse::split_response),
            Some(manage_neuron::Command::Follow(f)) => self
                .follow(&id, caller, f)
                .map(|_| ManageNeuronResponse::follow_response()),
            Some(manage_neuron::Command::MakeProposal(p)) => self
                .make_proposal(&id, caller, p)
                .map(ManageNeuronResponse::make_proposal_response),
            Some(manage_neuron::Command::RegisterVote(v)) => self
                .register_vote(&id, caller, v)
                .map(|_| ManageNeuronResponse::register_vote_response()),
            Some(manage_neuron::Command::ClaimOrRefresh(_)) => {
                panic!("This should have already returned")
            }
            None => panic!(),
        }
    }

    /// Garbage collect obsolete data from the governance canister.
    ///
    /// Current implementation only garbage collects proposals - not neurons.
    ///
    /// Returns true if GC was run and false otherwise.
    pub fn maybe_gc(&mut self) -> bool {
        let now_seconds = self.env.now();
        // Run GC if either (a) more than 24 hours has passed since it
        // was run last, or (b) more than 100 proposals have been
        // added since it was run last.
        if !(now_seconds > self.latest_gc_timestamp_seconds + 60 * 60 * 24
            || self.proto.proposals.len() > self.latest_gc_num_proposals + 100)
        {
            // Condition to run was not met. Return false.
            return false;
        }
        self.latest_gc_timestamp_seconds = self.env.now();
        println!(
            "{}Running GC now at timestamp {} seconds",
            log_prefix(),
            self.latest_gc_timestamp_seconds
        );
        let max_proposals = self
            .nervous_system_parameters()
            .max_proposals_to_keep_per_action
            .expect("NervousSystemParameters must have max_proposals_to_keep_per_type")
            as usize;

        // This data structure contains proposals grouped by type.
        let proposals_by_type = {
            let mut tmp: HashMap<u64, Vec<u64>> = HashMap::new();
            for (id, prop) in self.proto.proposals.iter() {
                tmp.entry(prop.action).or_insert_with(Vec::new).push(*id);
            }
            tmp
        };
        // Only keep the latest 'max_proposals' per type.
        for (proposal_type, props) in proposals_by_type {
            let voting_period_seconds = self.voting_period_seconds()();
            println!(
                "{}GC - proposal_type {:#?} max {} current {}",
                log_prefix(),
                proposal_type,
                max_proposals,
                props.len()
            );
            if props.len() > max_proposals {
                for prop_id in props.iter().take(props.len() - max_proposals) {
                    // Check that this proposal can be purged.
                    if let Some(prop) = self.proto.proposals.get(prop_id) {
                        if prop.can_be_purged(now_seconds, voting_period_seconds) {
                            self.proto.proposals.remove(prop_id);
                        }
                    }
                }
            }
        }
        self.latest_gc_num_proposals = self.proto.proposals.len();
        true
    }

    /// Runs periodic tasks that needed and are not directly triggered by user
    /// input.
    pub async fn run_periodic_tasks(&mut self) {
        self.process_proposals();

        // Getting the total governance token supply from the ledger is expensive enough
        // that we don't want to do it on every call to `run_periodic_tasks`. So
        // we only fetch it when it's needed, which is when rewards should be
        // distributed.
        if self.should_distribute_rewards() {
            match self.ledger.total_supply().await {
                Ok(supply) => {
                    // Distribute rewards if enough time has passed since the last reward
                    // event.
                    if self.should_distribute_rewards() {
                        self.distribute_rewards(supply);
                    }
                }
                Err(e) => println!(
                    "{}Error when getting total governance token supply: {}",
                    log_prefix(),
                    GovernanceError::from(e)
                ),
            }
        }

        self.maybe_gc();
    }

    /// Return `true` if rewards should be distributed, `false` otherwise
    fn should_distribute_rewards(&self) -> bool {
        let reward_distribution_period_seconds = self
            .nervous_system_parameters()
            .reward_distribution_period_seconds
            .expect("NervousSystemParameters must have reward_distribution_period_seconds");

        self.env.now()
            >= self.proto.genesis_timestamp_seconds
                + (self.latest_reward_event().periods_since_genesis + 1)
                    * reward_distribution_period_seconds
    }

    /// Create a reward event.
    ///
    /// This method:
    /// * collects all proposals in state ReadyToSettle, that is, proposals that
    /// can no longer accept votes for the purpose of rewards and that have
    /// not yet been considered in a reward event.
    /// * Associate those proposals to the new reward event
    fn distribute_rewards(&mut self, supply: Tokens) {
        println!("{}distribute_rewards. Supply: {:?}", log_prefix(), supply);

        let reward_distribution_period_seconds = self
            .nervous_system_parameters()
            .reward_distribution_period_seconds
            .expect("NervousSystemParameters must have reward_distribution_period_seconds");

        let periods_since_genesis = (self.env.now() - self.proto.genesis_timestamp_seconds)
            / reward_distribution_period_seconds;

        if periods_since_genesis <= self.latest_reward_event().periods_since_genesis {
            // This may happen, in case consider_distributing_rewards was called
            // several times at almost the same time. This is
            // harmless, just abandon.
            return;
        }

        if periods_since_genesis > 1 + self.latest_reward_event().periods_since_genesis {
            println!(
                "{}Some reward distribution should have happened, but were missed.\
                      It is now {} full days since genesis, and the last distribution \
                      nominally happened at {} full days since genesis.",
                log_prefix(),
                periods_since_genesis,
                self.latest_reward_event().periods_since_genesis
            );
        }
        let periods = self.latest_reward_event().periods_since_genesis..periods_since_genesis;
        let fraction: f64 = periods
            .map(crate::reward::rewards_pool_to_distribute_in_supply_fraction_for_one_day)
            .sum();

        let distributed_e8s_equivalent_float = (supply.get_e8s() as f64) * fraction;
        // We should not convert right away to integer! The
        // "distributed_e8s_equivalent" recorded in the RewardEvent proto
        // should match exactly the sum of the distributed integer e8
        // equivalents. Due to rounding, we actually need to recompute this sum,
        // even though it will be very close to distributed_e8s_equivalent_float.
        let mut actually_distributed_e8s_equivalent = 0_u64;

        let considered_proposals: Vec<ProposalId> =
            self.ready_to_be_settled_proposal_ids().collect();

        // Construct map voters -> total _used_ voting rights for considered proposals
        let (voters_to_used_voting_right, total_voting_rights) =
            {
                let mut voters_to_used_voting_right: HashMap<NeuronId, f64> = HashMap::new();
                let mut total_voting_rights = 0f64;

                for pid in considered_proposals.iter() {
                    if let Some(proposal) = self.get_proposal_data(*pid) {
                        for (voter, ballot) in proposal.ballots.iter() {
                            if !Vote::from(ballot.vote).eligible_for_rewards() {
                                continue;
                            }
                            match NeuronId::from_str(voter) {
                                Ok(nid) => {
                                    let voting_power = ballot.voting_power as f64;
                                    *voters_to_used_voting_right.entry(nid).or_insert(0f64) +=
                                        voting_power;
                                    total_voting_rights += voting_power;
                                }
                                Err(e) => {
                                    println!(
                                    "{} Could not use voter {} to calculate total_voting_rights \
                                    since it's NeuronId was invalid. Underlying error: {:?}.",
                                    log_prefix(), voter, e
                                )
                                }
                            }
                        }
                    }
                }
                (voters_to_used_voting_right, total_voting_rights)
            };

        for (neuron_id, used_voting_rights) in voters_to_used_voting_right {
            match self.get_neuron_result_mut(&neuron_id) {
                Ok(mut neuron) => {
                    // Note that "as" rounds toward zero; this is the desired
                    // behavior here. Also note that `total_voting_rights` has
                    // to be positive because (1) voters_to_used_voting_right
                    // is non-empty (otherwise we wouldn't be here in the
                    // first place) and (2) the voting power of all ballots is
                    // positive (non-zero).
                    let reward = (used_voting_rights * distributed_e8s_equivalent_float
                        / total_voting_rights) as u64;
                    neuron.maturity_e8s_equivalent += reward;
                    actually_distributed_e8s_equivalent += reward;
                }
                Err(e) => println!(
                    "{}Cannot find neuron {}, despite having voted with power {} \
                        in the considered reward period. The reward that should have been \
                        distributed to this neuron is simply skipped, so the total amount \
                        of distributed reward for this period will be lower than the maximum \
                        allowed. Underlying error: {:?}.",
                    log_prefix(),
                    neuron_id,
                    used_voting_rights,
                    e
                ),
            }
        }

        let now = self.env.now();
        for pid in considered_proposals.iter() {
            // Before considering a proposal for reward, it must be fully processed --
            // because we're about to clear the ballots, so no further processing will be
            // possible.
            self.process_proposal(pid.id);

            match self.get_proposal_data_mut(*pid) {
                None =>  println!(
                    "{}Cannot find proposal {}, despite it being considered for rewards distribution.",
                    log_prefix(), pid.id
                ),
                Some(p) => {
                    if p.status() == ProposalDecisionStatus::ProposalStatusOpen {
                        println!("{}Proposal {} was considered for reward distribution despite \
                          being open. This code line is expected not to be reachable. We need to \
                          clear the ballots here to avoid a risk of the memory getting too large. \
                          In doubt, reject the proposal", log_prefix(), pid.id);
                        p.decided_timestamp_seconds = now;
                        p.latest_tally = Some(Tally {
                            timestamp_seconds: now,
                            yes:0,
                            no:0,
                            total:0,
                        })
                    };
                    p.reward_event_round = periods_since_genesis;
                    p.ballots.clear();
                }
            };
        }
        self.proto.latest_reward_event = Some(RewardEvent {
            periods_since_genesis,
            actual_timestamp_seconds: now,
            settled_proposals: considered_proposals,
            distributed_e8s_equivalent: actually_distributed_e8s_equivalent,
        })
    }

    fn check_heap_can_grow(&self) -> Result<(), GovernanceError> {
        match self.env.heap_growth_potential() {
            HeapGrowthPotential::NoIssue => Ok(()),
            HeapGrowthPotential::LimitedAvailability => Err(GovernanceError::new_with_message(
                ErrorType::ResourceExhausted,
                "Heap size too large; governance canister is running is degraded mode.",
            )),
        }
    }

    fn check_neuron_population_can_grow(&self) -> Result<(), GovernanceError> {
        let max_number_of_neurons = self
            .nervous_system_parameters()
            .max_number_of_neurons
            .expect("NervousSystemParameters must have wait_for_quiet_threshold_seconds")
            as usize;

        if self.proto.neurons.len() + 1 > max_number_of_neurons {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Cannot add neuron. Max number of neurons reached.",
            ));
        }

        Ok(())
    }

    // Gets the raw proposal data
    fn get_proposal_data(&self, pid: impl Into<ProposalId>) -> Option<&ProposalData> {
        self.proto.proposals.get(&pid.into().id)
    }

    fn get_proposal_data_mut(&mut self, pid: impl Into<ProposalId>) -> Option<&mut ProposalData> {
        self.proto.proposals.get_mut(&pid.into().id)
    }

    fn get_neuron_result(&self, nid: &NeuronId) -> Result<&Neuron, GovernanceError> {
        self.proto
            .neurons
            .get(&nid.to_string())
            .ok_or_else(|| Self::neuron_not_found_error(nid))
    }

    fn get_neuron_result_mut(&mut self, nid: &NeuronId) -> Result<&mut Neuron, GovernanceError> {
        self.proto
            .neurons
            .get_mut(&nid.to_string())
            .ok_or_else(|| Self::neuron_not_found_error(nid))
    }
}

/// Affects the perception of time by users of CanisterEnv (i.e. Governance).
///
/// Specifically, the time that Governance sees is the real time + delta.
#[derive(PartialEq, Clone, Copy, Debug, candid::CandidType, serde::Deserialize)]
pub struct TimeWarp {
    pub delta_s: i64,
}

impl TimeWarp {
    pub fn apply(&self, timestamp_s: u64) -> u64 {
        if self.delta_s >= 0 {
            timestamp_s + (self.delta_s as u64)
        } else {
            timestamp_s - ((-self.delta_s) as u64)
        }
    }
}

#[test]
fn test_time_warp() {
    let w = TimeWarp { delta_s: 0_i64 };
    assert_eq!(w.apply(100_u64), 100);

    let w = TimeWarp { delta_s: 42_i64 };
    assert_eq!(w.apply(100_u64), 142);

    let w = TimeWarp { delta_s: -42_i64 };
    assert_eq!(w.apply(100_u64), 58);
}

#[cfg(test)]
mod test_wait_for_quiet {
    use crate::pb::v1::{ProposalData, ProposalId, Tally, WaitForQuietState};
    use proptest::prelude::{prop_assert, proptest};

    proptest! {
        /// This test ensures that none of the asserts in
        /// `evaluate_wait_for_quiet` fire, and that the wait-for-quiet
        /// deadline is only ever increased, if at all.
        #[test]
        fn test_evaluate_wait_for_quiet(voting_period_seconds in 3600u64..604_800,
                                        now_seconds in 0u64..1_000_000,
                                        old_yes in 0u64..1_000_000,
                                        old_no in 0u64..1_000_000,
                                        old_total in 10_000_000u64..100_000_000,
                                        yes_votes in 0u64..1_000_000,
                                        no_votes in 0u64..1_000_000,
    ) {
            let current_deadline_timestamp_seconds = voting_period_seconds;
            let proposal_creation_timestamp_seconds = 0; // initial timestamp is always 0
            let mut proposal = ProposalData {
                id: Some(ProposalId { id: 0 }),
                proposal_creation_timestamp_seconds,
                wait_for_quiet_state: Some(WaitForQuietState {
                    current_deadline_timestamp_seconds,
                }),
                ..ProposalData::default()
            };
            let old_tally = Tally {
                timestamp_seconds: now_seconds,
                yes: old_yes,
                no: old_no,
                total: old_total,
            };
            let new_tally = Tally {
                timestamp_seconds: now_seconds,
                yes: old_yes + yes_votes,
                no: old_no + no_votes,
                total: old_total,
            };
            proposal.evaluate_wait_for_quiet(
                now_seconds,
                voting_period_seconds,
                &old_tally,
                &new_tally,
            );
            let new_deadline = proposal
                .wait_for_quiet_state
                .unwrap()
                .current_deadline_timestamp_seconds;
            prop_assert!(new_deadline >= current_deadline_timestamp_seconds);
        }
    }
}
