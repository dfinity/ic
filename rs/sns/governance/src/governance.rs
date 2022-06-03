use std::cmp::Ordering;
use std::collections::btree_map::{BTreeMap, Entry};
use std::collections::btree_set::BTreeSet;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::ops::Bound::{Excluded, Unbounded};
use std::str::FromStr;
use std::string::ToString;

use crate::canister_control::{
    get_canister_id, perform_execute_generic_nervous_system_function_call,
    upgrade_canister_directly,
};
use crate::pb::v1::{
    get_neuron_response, get_proposal_response,
    governance::{
        neuron_in_flight_command::Command as InFlightCommand, Mode, NeuronInFlightCommand,
    },
    governance_error::ErrorType,
    manage_neuron::{
        self,
        claim_or_refresh::{By, MemoAndController},
        ClaimOrRefresh,
    },
    neuron::{DissolveState, Followees},
    proposal, Ballot, DefaultFollowees, Empty, GetNeuron, GetNeuronResponse, GetProposal,
    GetProposalResponse, Governance as GovernanceProto, GovernanceError,
    ListNervousSystemFunctionsResponse, ListNeurons, ListNeuronsResponse, ListProposals,
    ListProposalsResponse, ManageNeuron, ManageNeuronResponse, NervousSystemParameters, Neuron,
    NeuronId, NeuronPermission, NeuronPermissionList, NeuronPermissionType, Proposal, ProposalData,
    ProposalDecisionStatus, ProposalId, ProposalRewardStatus, RewardEvent, Tally,
    UpgradeSnsControlledCanister, Vote,
};
use ic_base_types::PrincipalId;
use lazy_static::lazy_static;
use ledger_canister::{AccountIdentifier, Subaccount, Tokens};
use num::{bigint::BigInt, rational::Ratio, Zero};
use strum::IntoEnumIterator;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use crate::neuron::{NeuronState, RemovePermissionsStatus, MAX_LIST_NEURONS_RESULTS};
use crate::pb::v1::{
    manage_neuron::{AddNeuronPermissions, RemoveNeuronPermissions},
    manage_neuron_response::{DisburseMaturityResponse, MergeMaturityResponse},
    proposal::Action,
    ExecuteGenericNervousSystemFunction, NervousSystemFunction, WaitForQuietState,
};
use crate::proposal::{
    validate_and_render_proposal, ValidGenericNervousSystemFunction, MAX_LIST_PROPOSAL_RESULTS,
    MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS,
};

use crate::types::{is_registered_function_id, Environment, HeapGrowthPotential, LedgerUpdateLock};
use candid::Encode;
use dfn_core::api::{id, spawn, CanisterId};
use ic_nervous_system_common::{
    i2r,
    ledger::{self, Ledger},
    NervousSystemError,
};
use ic_nervous_system_root::ChangeCanisterProposal;

lazy_static! {
    pub static ref NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER: NervousSystemFunction =
        NervousSystemFunction {
            id: 0,
            name: "DELETION_MARKER".to_string(),
            ..Default::default()
        };
}

/// The maximum payload size that will be included in proposals when `list_proposals` is called.
/// That is, when `list_proposals` is called, for each proposal whose payload exceeds
/// this limit, the payload will not be returned in the reply.
pub const EXECUTE_NERVOUS_SYSTEM_FUNCTION_PAYLOAD_LISTING_BYTES_MAX: usize = 1000; // 1 KB

const MAX_HEAP_SIZE_IN_KIB: usize = 4 * 1024 * 1024;
const WASM32_PAGE_SIZE_IN_KIB: usize = 64;

/// The max number of wasm32 pages for the heap after which we consider that there
/// is a risk to the ability to grow the heap.
///
/// This is 7/8 of the maximum number of pages and corresponds to 3.5 GiB.
pub const HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES: usize =
    MAX_HEAP_SIZE_IN_KIB / WASM32_PAGE_SIZE_IN_KIB * 7 / 8;

/// Prefixes each log line for this canister.
pub fn log_prefix() -> String {
    "[Governance] ".into()
}

impl NeuronPermissionType {
    /// Returns all the different types of neuron permissions as a vector.
    pub fn all() -> Vec<i32> {
        NeuronPermissionType::iter()
            .map(|permission| permission as i32)
            .collect()
    }
}

impl NeuronPermission {
    /// Grants all permissions to the given principal.
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
    /// Builds an index that maps proposal sns functions to (followee) neuron IDs to these neuron's
    /// followers. The resulting index is a map
    /// Function Id -> (followee's neuron ID) -> set of followers' neuron IDs.
    ///
    /// The index is built from the `neurons` in the `Governance` struct, which map followers
    /// (the neuron ID) to a set of followees per function.
    pub fn build_function_followee_index(
        &self,
        neurons: &BTreeMap<String, Neuron>,
    ) -> BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>> {
        let mut function_followee_index = BTreeMap::new();
        for neuron in neurons.values() {
            GovernanceProto::add_neuron_to_function_followee_index(
                &mut function_followee_index,
                &self.id_to_nervous_system_functions,
                neuron,
            );
        }
        function_followee_index
    }

    /// Adds a neuron to the function_followee_index.
    pub fn add_neuron_to_function_followee_index(
        index: &mut BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>>,
        registered_functions: &BTreeMap<u64, NervousSystemFunction>,
        neuron: &Neuron,
    ) {
        for (function_id, followees) in neuron.followees.iter() {
            if !is_registered_function_id(*function_id, registered_functions) {
                continue;
            }

            let followee_index = index.entry(*function_id).or_insert_with(BTreeMap::new);
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

    /// Removes a neuron from the function_followee_index.
    pub fn remove_neuron_from_function_followee_index(
        index: &mut BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>>,
        neuron: &Neuron,
    ) {
        for (function, followees) in neuron.followees.iter() {
            if let Some(followee_index) = index.get_mut(function) {
                for followee in followees.followees.iter() {
                    let nid = followee.to_string();
                    if let Some(followee_set) = followee_index.get_mut(&nid) {
                        followee_set.remove(neuron.id.as_ref().expect("Neuron must have an id"));
                        if followee_set.is_empty() {
                            followee_index.remove(&nid);
                        }
                    }
                }
            }
        }
    }

    /// Iterate through one neuron and add all the principals that have some permission on this
    /// neuron to the index that maps principalIDs to a set of neurons for which the principal
    /// has some permissions.
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

    /// In the index that maps principalIDs to a set of neurons for which the principal
    /// has some permissions, add the given neuron_id to the set of neurons for which the
    /// given principalId has permissions.
    pub fn add_neuron_to_principal_in_principal_to_neuron_ids_index(
        index: &mut BTreeMap<PrincipalId, HashSet<NeuronId>>,
        neuron_id: &NeuronId,
        principal: &PrincipalId,
    ) {
        let neuron_ids = index.entry(*principal).or_insert_with(HashSet::new);
        neuron_ids.insert(neuron_id.clone());
    }

    /// Iterate through one neuron and remove all the principals that have some permission on this
    /// neuron from the index that maps principalIDs to a set of neurons for which the principal
    /// has some permissions.
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

    /// In the index that maps principalIDs to a set of neurons for which the principal
    /// has some permissions, remove the given neuron_id from the set of neurons for which the
    /// given principalId has permissions.
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

    /// Builds an index that maps principalIDs to a set of neurons for which the
    /// principals have some permissions.
    ///
    /// This index is build from the `neurons` in the `Governance` struct, which specify
    /// the principals that can modify the neuron.
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

    pub fn root_canister_id_or_panic(&self) -> CanisterId {
        CanisterId::new(self.root_canister_id.expect("No root_canister_id.")).unwrap()
    }

    pub fn ledger_canister_id_or_panic(&self) -> CanisterId {
        CanisterId::new(self.ledger_canister_id.expect("No ledger_canister_id.")).unwrap()
    }
}

pub struct ValidGovernanceProto(GovernanceProto);

impl ValidGovernanceProto {
    /// Returns a summary of some governance's settings
    pub fn summary(&self) -> String {
        let inner = &self.0;

        format!(
            "genesis_timestamp_seconds: {}, neuron count: {} parameters: {:?}",
            inner.genesis_timestamp_seconds,
            inner.neurons.len(),
            inner.parameters,
        )
    }

    /// Unwrap self. Also see Box::into_inner.
    fn into_inner(self) -> GovernanceProto {
        self.0
    }

    /// Returns the canister ID of the ledger canister set in governance.
    pub fn ledger_canister_id(&self) -> CanisterId {
        self.0.ledger_canister_id_or_panic()
    }

    /// Converts field_value into a Result.
    ///
    /// If field_value is None, returns Err with an inner value describing what's
    /// wrong with the field value (i.e. that it is None) and what's the name of the
    /// field in GovernanceProto.
    pub fn validate_required_field<'a, Inner>(
        field_name: &str,
        field_value: &'a Option<Inner>,
    ) -> Result<&'a Inner, String> {
        field_value
            .as_ref()
            .ok_or_else(|| format!("GovernanceProto {} field must be populated.", field_name))
    }
}

impl TryFrom<GovernanceProto> for ValidGovernanceProto {
    type Error = String;

    /// Converts GovernanceProto into ValidGovernanceProto (Self).
    ///
    /// If base is not valid, then Err is returned with an explanation.
    fn try_from(base: GovernanceProto) -> Result<Self, Self::Error> {
        Self::validate_required_field("root_canister_id", &base.root_canister_id)?;
        Self::validate_required_field("ledger_canister_id", &base.ledger_canister_id)?;

        let parameters = Self::validate_required_field("parameters", &base.parameters)?;
        parameters.validate()?;

        validate_default_followees(&base)?;

        for (id, function) in &base.id_to_nervous_system_functions {
            // These entries ensure that ids do not get recycled (after deletion).
            if function == &*NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER {
                continue;
            }
            let validated_function = ValidGenericNervousSystemFunction::try_from(function)?;

            // Require that the key match the value.
            if *id != validated_function.id {
                return Err("At least one entry in id_to_nervous_system_functions\
                            doesn't have a matching id to the map key."
                    .to_string());
            }
        }

        Ok(Self(base))
    }
}

/// Requires that the neurons identified in base.parameters.default_followeees
/// exist (i.e. be in base.neurons). default_followees can be None.
///
/// Assumes that base.parameters is Some.
///
/// If the validation fails, an Err is returned containing a string that explains why
/// base is invalid.
pub fn validate_default_followees(base: &GovernanceProto) -> Result<(), String> {
    let function_id_to_followee = match &base
        .parameters
        .as_ref()
        .expect("GovernanceProto.parameters is not populated.")
        .default_followees
    {
        None => return Ok(()),
        Some(default_followees) => &default_followees.followees,
    };

    let neuron_id_to_neuron = &base.neurons;

    // Iterate over neurons in default_followees.
    for followees in function_id_to_followee.values() {
        for followee in &followees.followees {
            // each followee must be a neuron that exists in governance
            if !neuron_id_to_neuron.contains_key(&followee.to_string()) {
                return Err(format!(
                    "Unknown neuron listed as a default followee: {} neuron_id_to_neurons: {:?}",
                    followee, neuron_id_to_neuron,
                ));
            }
        }
    }

    Ok(())
}

/// `Governance` implements the full public interface of the SNS' governance canister.
pub struct Governance {
    /// The Governance Protobuf which contains all persistent state of
    /// the SNS' governance system.
    /// This needs to be stored and retrieved on upgrades.
    pub proto: GovernanceProto,

    /// Implementation of Environment to make unit testing easier.
    pub env: Box<dyn Environment>,

    /// Implementation of the interface with the SNS ledger canister.
    ledger: Box<dyn Ledger>,

    /// Cached data structure that (for each proposal function_id) maps a followee to
    /// the set of its followers. It is the inverse of the mapping from follower
    /// to followees that is stored in each (follower) neuron.
    ///
    /// This is a cached index and will be removed and recreated when the state
    /// is saved and restored.
    ///
    /// Function ID -> (followee's neuron ID) -> set of followers' neuron IDs.
    pub function_followee_index: BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>>,

    /// Maps Principals to the Neuron IDs of all Neurons for which this principal
    /// has some permissions, i.e., all neurons that have this principal associated
    /// with a NeuronPermissionType for the Neuron.
    ///
    /// This is a cached index and will be removed and recreated when the state
    /// is saved and restored.
    pub principal_to_neuron_ids_index: BTreeMap<PrincipalId, HashSet<NeuronId>>,

    /// The timestamp, in seconds since the unix epoch, of the "closest"
    /// open proposal's deadline tracked by the governance (i.e., the deadline that will be
    /// reached first).
    closest_proposal_deadline_timestamp_seconds: u64,

    /// The timestamp, in seconds since the unix epoch, of the latest "garbage collection", i.e.,
    /// when obsolete proposals were cleaned up.
    pub latest_gc_timestamp_seconds: u64,

    /// The number of proposals after the last time "garbage collection" was run.
    pub latest_gc_num_proposals: usize,
}

/// Returns the ledger account identifier of the minting account on the ledger canister
/// (currently an account controlled by the governance canister).
/// TODO - if we later allow to set the minting account more flexibly, this method should be renamed
pub fn governance_minting_account() -> AccountIdentifier {
    AccountIdentifier::new(id().get(), None)
}

/// Returns the ledger account identifier of a given neuron, where the neuron is specified by
/// its subaccount.
pub fn neuron_account_id(subaccount: Subaccount) -> AccountIdentifier {
    AccountIdentifier::new(id().get(), Some(subaccount))
}

impl Governance {
    pub fn new(
        proto: ValidGovernanceProto,
        env: Box<dyn Environment>,
        ledger: Box<dyn Ledger>,
    ) -> Self {
        let mut proto = proto.into_inner();

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
            function_followee_index: BTreeMap::new(),
            principal_to_neuron_ids_index: BTreeMap::new(),
            closest_proposal_deadline_timestamp_seconds: 0,
            latest_gc_timestamp_seconds: 0,
            latest_gc_num_proposals: 0,
        };

        gov.initialize_indices();

        gov
    }

    pub fn set_mode(&mut self, mode: i32, caller: &PrincipalId) {
        if !Mode::is_valid(mode) {
            panic!("Unknown mode: {}", mode);
        }

        if !self.is_sale_canister(caller) {
            panic!("Caller must be the sale canister.");
        }

        self.proto.mode = mode as i32;
    }

    fn is_sale_canister(&self, _id: &PrincipalId) -> bool {
        // TODO: How do we know the sale canister's ID? Presumably, this would
        // be stored is some field in self.proto, but where do we get the value
        // to store in that field? For the time being, returning false is the
        // safest thing to do.
        false
    }

    /// Initializes the indices.
    /// Must be called after the state has been externally changed (e.g. by
    /// setting a new proto).
    fn initialize_indices(&mut self) {
        self.function_followee_index = self
            .proto
            .build_function_followee_index(&self.proto.neurons);
        self.principal_to_neuron_ids_index = self
            .proto
            .build_principal_to_neuron_ids_index(&self.proto.neurons);
    }

    /// Returns the ledger's transaction fee as stored in the service nervous parameters.
    fn transaction_fee_e8s(&self) -> u64 {
        self.nervous_system_parameters()
            .transaction_fee_e8s
            .expect("NervousSystemParameters must have transaction_fee_e8s")
    }

    /// Returns the initial voting period of proposals.
    fn initial_voting_period(&self) -> u64 {
        self.nervous_system_parameters()
            .initial_voting_period
            .expect("NervousSystemParameters must have initial_voting_period")
    }

    /// Computes the NeuronId or returns a GovernanceError if a neuron with this ID already exists.
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

    /// Returns an error to be used when a neuron is not found.
    fn neuron_not_found_error(nid: &NeuronId) -> GovernanceError {
        GovernanceError::new_with_message(ErrorType::NotFound, format!("Neuron not found: {}", nid))
    }

    /// Returns and error to be used if the subaccount computed from the given memo already exists
    /// in another neuron.
    /// TODO - change the name of the method and add the principalID to the returned message.
    fn invalid_subaccount_with_nonce(memo: u64) -> GovernanceError {
        GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            format!(
                "A neuron already exists with given PrincipalId and memo: {:?}",
                memo
            ),
        )
    }

    /// Converts bytes to a subaccount
    fn bytes_to_subaccount(bytes: &[u8]) -> Result<ledger_canister::Subaccount, GovernanceError> {
        bytes.try_into().map_err(|_| {
            GovernanceError::new_with_message(ErrorType::PreconditionFailed, "Invalid subaccount")
        })
    }

    /// Locks a given neuron, signaling there is an ongoing neuron operation.
    ///
    /// This stores the in-flight operation in the proto so that, if anything
    /// goes wrong we can:
    ///
    /// 1 - Know what was happening.
    /// 2 - Reconcile the state post-upgrade, if necessary.
    ///
    /// No concurrent updates that also acquire a lock to this neuron are possible
    /// until the lock is released.
    ///
    /// ***** IMPORTANT *****
    /// Remember to use the question mark operator (or otherwise handle
    /// Err). Otherwise, failed attempts to acquire will be ignored.
    ///
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
    /// is acquired), then immediately dropped (and the lock is released).
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

    /// Releases the lock on a given neuron.
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

    /// Adds a neuron to the list of neurons and updates the indices
    /// `principal_to_neuron_ids_index` and `function_followee_index`.
    ///
    /// Preconditions:
    /// - the heap can still grow
    /// - the maximum number of neurons has not been reached
    /// - the given `neuron_id` does not already exists in `self.proto.neurons`
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

        GovernanceProto::add_neuron_to_function_followee_index(
            &mut self.function_followee_index,
            &self.proto.id_to_nervous_system_functions,
            &neuron,
        );

        self.proto.neurons.insert(neuron_id.to_string(), neuron);

        Ok(())
    }

    /// Removes a neuron from the list of neurons and updates the indices
    /// `principal_to_neuron_ids_index` and `function_followee_index`.
    ///
    /// Preconditions:
    /// - the given `neuron_id` exists in `self.proto.neurons`
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

        GovernanceProto::remove_neuron_from_function_followee_index(
            &mut self.function_followee_index,
            &neuron,
        );

        self.proto.neurons.remove(&neuron_id.to_string());

        Ok(())
    }

    /// Returns a neuron given the neuron's ID or an error if no neuron with the given ID
    /// is found.
    pub fn get_neuron(&self, req: GetNeuron) -> GetNeuronResponse {
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

    /// Returns a deterministically ordered list of size `limit` containing
    /// Neurons starting at but not including the neuron with ID `start_page_at`.
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

    /// Returns a list of size `limit` containing Neurons that have `principal`
    /// in their permissions.
    fn list_neurons_by_principal(&self, principal: &PrincipalId, limit: usize) -> Vec<Neuron> {
        self.get_neuron_ids_by_principal(principal)
            .iter()
            .filter_map(|nid| self.proto.neurons.get(&nid.to_string()))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Returns the Neuron IDs of all Neurons that have `principal` in their
    /// permissions.
    fn get_neuron_ids_by_principal(&self, principal: &PrincipalId) -> Vec<NeuronId> {
        self.principal_to_neuron_ids_index
            .get(principal)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Allows listing all neurons tracked in the Governance state in a paginated fashion.
    /// See `ListNeurons` in the Governance's proto for details.
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
    /// ledger account. If no ledger account is given, the caller's default
    /// account is used. If an `amount` is provided, then that amount of is
    /// disbursed. If no amount is provided, the full stake of the neuron
    /// is disbursed.
    /// In addition, the neuron's management fees are burned.
    ///
    /// Note that we don't enforce that 'amount' is actually smaller
    /// than or equal to the neuron's stake.
    /// This will allow a user to still disburse funds if:
    /// - Someone transferred more funds to the neuron's subaccount after the
    ///   the initial neuron claim that we didn't know about.
    /// - The transfer of funds previously failed for some reason (e.g. the
    ///   ledger was unavailable or broken).
    /// The ledger canister still guarantees that a transaction cannot
    /// transfer, i.e., disburse, more than what was in the neuron's account
    /// on the ledger.
    ///
    /// On success returns the block height at which the transfer happened.
    ///
    /// Preconditions:
    /// - The neuron exists.
    /// - The caller is authorized to perform this neuron operation
    ///   (NeuronPermissionType::Disburse)
    /// - The neuron's state is `Dissolved` at the current timestamp
    /// - The neuron's id is not yet in the list of neurons with ongoing operations
    pub async fn disburse_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        disburse: &manage_neuron::Disburse,
    ) -> Result<u64, GovernanceError> {
        let transaction_fee_e8s = self.transaction_fee_e8s();
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

        // If no account was provided, transfer to the caller's (default) account.
        let to_account: AccountIdentifier = match disburse.to_account.as_ref() {
            None => AccountIdentifier::new(*caller, None),
            Some(ai_pb) => AccountIdentifier::try_from(ai_pb).map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    format!("The recipient's subaccount is invalid due to: {}", e),
                )
            })?,
        };

        let fees_amount_e8s = neuron.neuron_fees_e8s;
        // Calculate the amount to transfer and make sure no matter what the user
        // disburses we still take the neuron management fees into account.
        //
        // Note that the implementation of stake_e8s() is effectively:
        //   neuron.cached_neuron_stake_e8s.saturating_sub(neuron.neuron_fees_e8s)
        // So there is symmetry here in that we are subtracting
        // fees_amount_e8s from both sides of this `map_or`.
        let mut disburse_amount_e8s = disburse.amount.as_ref().map_or(neuron.stake_e8s(), |a| {
            a.e8s.saturating_sub(fees_amount_e8s)
        });

        // Subtract the transaction fee from the amount to disburse since it will
        // be deducted from the source (the neuron's) account.
        if disburse_amount_e8s > transaction_fee_e8s {
            disburse_amount_e8s -= transaction_fee_e8s
        }

        // We need to do 2 transfers:
        // 1 - Burn the neuron management fees.
        // 2 - Transfer the disburse_amount to the target account

        // Transfer 1 - burn the neuron management fees, but only if the value
        // exceeds the cost of a transaction fee, as the ledger doesn't support
        // burn transfers for an amount less than the transaction fee.
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

        // Update the neuron's stake and management fees to reflect the burning
        // above.
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

        Ok(block_height)
    }

    /// Splits a (parent) neuron into two neurons (the parent and child neuron).
    ///
    /// The parent neuron's cached stake is decreased by the amount specified in
    /// Split, while the child neuron is created with a stake equal to that
    /// amount, minus the transfer fee.
    /// The management fees and the maturity remain in the parent neuron.
    ///
    /// The child neuron inherits all the properties of its parent
    /// including age and dissolve state.
    ///
    /// On success returns the newly created neuron's id.
    ///
    /// Preconditions:
    /// - The heap can grow
    /// - The parent neuron exists
    /// - The caller is authorized to perform this neuron operation
    ///   (NeuronPermissionType::Split)
    /// - The amount to split minus the transfer fee is more than the minimum
    ///   stake (thus the child neuron will have at least the minimum stake)
    /// - The parent's stake minus amount to split is more than the minimum
    ///   stake (thus the parent neuron will have at least the minimum stake)
    /// - The parent neuron's id is not in the list of neurons with ongoing operations
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

        let transaction_fee_e8s = self.transaction_fee_e8s();

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

        let staked_amount = split.amount_e8s - transaction_fee_e8s;

        // Before we do the transfer, we need to save the child neuron in the map
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

        // Add the child neuron's id to the set of neurons with ongoing operations.
        let in_flight_command = NeuronInFlightCommand {
            timestamp: creation_timestamp_seconds,
            command: Some(InFlightCommand::Split(split.clone())),
        };
        let _child_lock = self.lock_neuron_for_command(&child_nid, in_flight_command)?;

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

        // Update the state of the parent and child neuron.
        parent_neuron.cached_neuron_stake_e8s -= split.amount_e8s;

        let child_neuron = self
            .get_neuron_result_mut(&child_nid)
            .expect("Expected the child neuron to exist");

        child_neuron.cached_neuron_stake_e8s = staked_amount;
        Ok(child_nid)
    }

    /// Merges the maturity of a neuron into the neuron's cached stake.
    ///
    /// This method allows a neuron controller to merge the currently
    /// existing maturity of a neuron into the neuron's stake. The
    /// caller can choose a percentage of maturity to merge.
    ///
    /// Pre-conditions:
    /// - The neuron exists
    /// - The caller is authorized to perform this neuron operation
    ///   (NeuronPermissionType::MergeMaturity)
    /// - The given percentage_to_merge is between 1 and 100 (inclusive)
    /// - The e8s equivalent of the amount of maturity to merge is more
    ///   than the transaction fee.
    /// - The neuron's id is not yet in the list of neurons with ongoing operations
    pub async fn merge_maturity(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        merge_maturity: &manage_neuron::MergeMaturity,
    ) -> Result<MergeMaturityResponse, GovernanceError> {
        let now = self.env.now();

        let neuron = self.get_neuron_result(id)?.clone();
        let nid = neuron.id.as_ref().expect("Neurons must have an id");
        let subaccount = neuron.subaccount()?;

        neuron.check_authorized(caller, NeuronPermissionType::MergeMaturity)?;

        if merge_maturity.percentage_to_merge > 100 || merge_maturity.percentage_to_merge == 0 {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "The percentage of maturity to merge must be a value between 1 and 100 (inclusive)."));
        }

        let transaction_fee_e8s = self.transaction_fee_e8s();

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

        // Adjust the maturity, stake, and age of the neuron
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

    /// Disburses a neuron's maturity.
    ///
    /// This causes the neuron's maturity to be disbursed to the provided
    /// ledger account. If no ledger account is given, the caller's default
    /// account is used.
    /// The caller can choose a percentage of maturity to disburse.
    ///
    /// Pre-conditions:
    /// - The neuron exists
    /// - The caller is authorized to perform this neuron operation
    ///   (NeuronPermissionType::DisburseMaturity)
    /// - The given percentage_to_merge is between 1 and 100 (inclusive)
    /// - The neuron's id is not yet in the list of neurons with ongoing operations
    /// - The e8s equivalent of the amount of maturity to disburse is more
    ///   than the transaction fee.
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

        let transaction_fee_e8s = self.transaction_fee_e8s();
        if maturity_to_disburse < transaction_fee_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Tried to merge {} e8s, but can't merge an amount\
                     less than the transaction fee of {} e8s.",
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

    /// Sets a proposal's status to 'executed' or 'failed' depending on the given result that
    /// was returned by the method that was supposed to execute the proposal.
    ///
    /// The proposal ID 'pid' is taken as a raw integer to avoid
    /// lifetime issues.
    ///
    /// Pre-conditions:
    /// - The proposal's decision status is ProposalStatusAdopted
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
                        // If the proposal was executed it has not failed,
                        // thus we set the failed_timestamp_seconds to zero
                        // (it should already be zero, but let's be defensive).
                        proposal.failed_timestamp_seconds = 0;
                        proposal.failure_reason = None;
                    }
                    Err(error) => {
                        println!("Execution of proposal: {} failed. Reason: {:?}", pid, error);
                        // To ensure that we don't update the failure timestamp
                        // if there has been success, check if executed_timestamp_seconds
                        // is set to a non-zero value (this should not happen).
                        // Then, record that the proposal failed 'now' with the
                        // given error.
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

    /// Returns the latest reward event.
    pub fn latest_reward_event(&self) -> RewardEvent {
        self.proto
            .latest_reward_event
            .as_ref()
            .expect("Invariant violation! There should always be a latest_reward_event.")
            .clone()
    }

    /// Tries to get a proposal given a proposal id.
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

    /// Removes some data from a given proposal data and returns it.
    ///
    /// Specifically, remove the ballots in the proposal data and possibly the proposal's payload.
    /// The payload is removed if the proposal is an ExecuteNervousSystemFunction or if it's
    /// a UpgradeSnsControlledCanister. The text rendering should include displayable information about
    /// the payload contents already.
    fn limit_proposal_data(&self, data: &ProposalData) -> ProposalData {
        let mut new_proposal = data.proposal.clone();
        if let Some(proposal) = &mut new_proposal {
            // We can't understand the payloads of nervous system functions, as well as the wasm
            // for upgrades, so just omit them when listing proposals.
            match &mut proposal.action {
                Some(Action::ExecuteGenericNervousSystemFunction(m)) => {
                    m.payload.clear();
                }
                Some(Action::UpgradeSnsControlledCanister(m)) => {
                    m.new_canister_wasm.clear();
                }
                _ => (),
            }
        }

        ProposalData {
            action: data.action,
            id: data.id,
            proposer: data.proposer.clone(),
            reject_cost_e8s: data.reject_cost_e8s,
            proposal: new_proposal,
            proposal_creation_timestamp_seconds: data.proposal_creation_timestamp_seconds,
            ballots: BTreeMap::new(), // To reduce size of payload, exclude ballots
            latest_tally: data.latest_tally.clone(),
            decided_timestamp_seconds: data.decided_timestamp_seconds,
            executed_timestamp_seconds: data.executed_timestamp_seconds,
            failed_timestamp_seconds: data.failed_timestamp_seconds,
            failure_reason: data.failure_reason.clone(),
            reward_event_round: data.reward_event_round,
            wait_for_quiet_state: data.wait_for_quiet_state.clone(),
            payload_text_rendering: data.payload_text_rendering.clone(),
        }
    }

    /// Returns proposal data of proposals with proposal ID less
    /// than `before_proposal` (exclusive), returning at most `limit` proposal
    /// data. If `before_proposal` is not provided, list_proposals() starts from the highest
    /// available proposal ID (inclusive). If `limit` is not provided, the
    /// system max MAX_LIST_PROPOSAL_RESULTS is used.
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
    /// The proposals' ballots are not returned in the `ListProposalResponse`.
    /// Proposals with `ExecuteNervousSystemFunction` as action have their
    /// `payload` cleared if larger than
    /// EXECUTE_NERVOUS_SYSTEM_FUNCTION_PAYLOAD_LISTING_BYTES_MAX.
    ///
    /// The caller can retrieve dropped payloads and ballots by calling `get_proposal`
    /// for each proposal of interest.
    pub fn list_proposals(&self, req: &ListProposals) -> ListProposalsResponse {
        let exclude_type: HashSet<u64> = req.exclude_type.iter().cloned().collect();
        let include_reward_status: HashSet<i32> =
            req.include_reward_status.iter().cloned().collect();
        let include_status: HashSet<i32> = req.include_status.iter().cloned().collect();
        let now = self.env.now();
        let filter_all = |data: &ProposalData| -> bool {
            let action = data.action;
            // Filter out proposals by action.
            if exclude_type.contains(&action) {
                return false;
            }
            // Filter out proposals by reward status.
            if !(include_reward_status.is_empty()
                || include_reward_status.contains(&(data.reward_status(now) as i32)))
            {
                return false;
            }
            // Filter out proposals by decision status.
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

        let proposal_info = limited_rng
            .map(|(_, y)| y)
            .map(|pd| self.limit_proposal_data(pd))
            .collect();

        // Ignore the keys and clone to a vector.
        ListProposalsResponse {
            proposals: proposal_info,
        }
    }

    /// Returns a list of all existing nervous system functions
    pub fn list_nervous_system_functions(&self) -> ListNervousSystemFunctionsResponse {
        let functions = Action::native_functions()
            .into_iter()
            .chain(
                self.proto
                    .id_to_nervous_system_functions
                    .values()
                    .cloned()
                    .filter(|f| f != &*NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER),
            )
            .collect();

        // Get the set of ids that have been used in the past.
        let reserved_ids = self
            .proto
            .id_to_nervous_system_functions
            .iter()
            .filter(|(_, f)| f == &&*NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER)
            .map(|(id, _)| *id)
            .collect();

        ListNervousSystemFunctionsResponse {
            functions,
            reserved_ids,
        }
    }

    /// Returns the proposal IDs for all proposals that have reward status ReadyToSettle
    fn ready_to_be_settled_proposal_ids(&self) -> impl Iterator<Item = ProposalId> + '_ {
        let now = self.env.now();
        self.proto
            .proposals
            .iter()
            .filter(move |(_, data)| data.reward_status(now) == ProposalRewardStatus::ReadyToSettle)
            .map(|(k, _)| ProposalId { id: *k })
    }

    /// Attempts to move the proposal with the given ID forward in the process,
    /// from open to adopted or rejected and from adopted to executed or failed.
    ///
    /// If the proposal is open, tallies the ballots and updates the `yes`, `no`, and
    /// `undecided` voting power accordingly.
    /// This may result in the proposal becoming adopted or rejected.
    ///
    /// If the proposal is adopted but not executed, attempts to execute it.
    pub fn process_proposal(&mut self, proposal_id: u64) {
        let now_seconds = self.env.now();
        let initial_voting_period = self.initial_voting_period();

        let proposal_data = match self.proto.proposals.get_mut(&proposal_id) {
            None => return,
            Some(p) => p,
        };

        if proposal_data.status() != ProposalDecisionStatus::ProposalStatusOpen {
            return;
        }

        // Recompute the tally here. It is imperative that only
        // 'open' proposals have their tally recomputed. Votes may
        // arrive after a decision has been made: such votes count
        // for voting rewards, but shall not make it into the
        // tally.
        proposal_data.recompute_tally(now_seconds, initial_voting_period);
        if !proposal_data.can_make_decision(now_seconds) {
            return;
        }

        // This marks the proposal_data as no longer open.
        proposal_data.decided_timestamp_seconds = now_seconds;
        if !proposal_data.is_accepted() {
            return;
        }

        // Return the rejection fee to the proposal's proposer
        if let Some(nid) = &proposal_data.proposer {
            if let Some(neuron) = self.proto.neurons.get_mut(&nid.to_string()) {
                if neuron.neuron_fees_e8s >= proposal_data.reject_cost_e8s {
                    neuron.neuron_fees_e8s -= proposal_data.reject_cost_e8s;
                }
            }
        }

        // A yes decision as been made, execute the proposal!
        // Safely unwrap action.
        let action = proposal_data
            .proposal
            .as_ref()
            .and_then(|p| p.action.clone());
        let action = match action {
            Some(action) => action,

            // This should not be possible, because proposal validation should
            // have been performed when the proposal was first made.
            None => {
                self.set_proposal_execution_status(
                    proposal_id,
                    Err(GovernanceError::new_with_message(
                        ErrorType::InvalidProposal,
                        "Proposal has no action.",
                    )),
                );
                return;
            }
        };
        self.start_proposal_execution(proposal_id, action);
    }

    /// Processes all proposals with decision status ProposalStatusOpen
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

        let initial_voting_period = self.initial_voting_period();

        self.closest_proposal_deadline_timestamp_seconds = self
            .proto
            .proposals
            .values()
            .filter(|data| data.status() == ProposalDecisionStatus::ProposalStatusOpen)
            .map(|data| {
                data.proposal_creation_timestamp_seconds
                    .saturating_add(initial_voting_period)
            })
            .min()
            .unwrap_or(u64::MAX);
    }

    /// Starts execution of the given proposal in the background.
    ///
    /// The given proposal ID specifies the proposal and the `action` specifies
    /// what the proposal should do (basically, function and parameters to be applied).
    fn start_proposal_execution(&mut self, proposal_id: u64, action: proposal::Action) {
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
        // - in prod, "self" is a reference to the GOVERNANCE static variable, which is
        //   initialized only once (in canister_init or canister_post_upgrade)
        let governance: &'static mut Governance = unsafe { std::mem::transmute(self) };
        spawn(governance.perform_action(proposal_id, action));
    }

    /// For a given proposal (given by its ID), selects and performs the right 'action',
    /// that is what this proposal is supposed to do as a result of the proposal being
    /// adopted.
    async fn perform_action(&mut self, proposal_id: u64, action: proposal::Action) {
        let result = match action {
            // Execution of Motion proposals is trivial.
            proposal::Action::Motion(_) => Ok(()),

            proposal::Action::ManageNervousSystemParameters(params) => {
                self.perform_manage_nervous_system_parameters(params)
            }
            proposal::Action::UpgradeSnsControlledCanister(params) => {
                self.perform_upgrade_sns_controlled_canister(proposal_id, params)
                    .await
            }
            proposal::Action::ExecuteGenericNervousSystemFunction(call) => {
                self.perform_execute_generic_nervous_system_function(call)
                    .await
            }
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                self.perform_add_generic_nervous_system_function(nervous_system_function)
            }
            proposal::Action::RemoveGenericNervousSystemFunction(id) => {
                self.perform_remove_generic_nervous_system_function(id)
            }
            // This should not be possible, because Proposal validation is performed when
            // a proposal is first made.
            proposal::Action::Unspecified(_) => Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "A Proposal somehow made it all the way to execution despite being \
                         invalid for having its `unspecified` field populated. action: {:?}",
                    action
                ),
            )),
        };

        self.set_proposal_execution_status(proposal_id, result);
    }

    /// Adds a new nervous system function to Governance if the given id for the nervous system
    /// function is not already taken.
    fn perform_add_generic_nervous_system_function(
        &mut self,
        nervous_system_function: NervousSystemFunction,
    ) -> Result<(), GovernanceError> {
        let id = nervous_system_function.id;

        if nervous_system_function.is_native() {
            return Err(GovernanceError::new_with_message(ErrorType::PreconditionFailed,
                                                         "Can only add NervousSystemFunction's of \
                                                          GenericNervousSystemFunction function_type"));
        }

        if is_registered_function_id(id, &self.proto.id_to_nervous_system_functions) {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Failed to add NervousSystemFunction. \
                             There is/was already a NervousSystemFunction with id: {}",
                    id
                ),
            ));
        }

        self.proto
            .id_to_nervous_system_functions
            .insert(id, nervous_system_function);
        Ok(())
    }

    /// Removes a nervous system function from Governance if the given id for the nervous system
    /// function exists.
    fn perform_remove_generic_nervous_system_function(
        &mut self,
        id: u64,
    ) -> Result<(), GovernanceError> {
        let entry = self.proto.id_to_nervous_system_functions.entry(id);
        match entry {
            Entry::Vacant(_) =>
                Err(GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!("Failed to remove NervousSystemFunction. There is no NervousSystemFunction with id: {}", id),
            )),
            Entry::Occupied(mut o) => {
                // Insert a deletion marker to signify that there was a NervousSystemFunction
                // with this id at some point, but that it was deleted.
                o.insert(NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER.clone());
                Ok(())
            },
        }
    }

    /// Executes a (non-native) nervous system function as a result of an adopted proposal.
    async fn perform_execute_generic_nervous_system_function(
        &self,
        call: ExecuteGenericNervousSystemFunction,
    ) -> Result<(), GovernanceError> {
        match self
            .proto
            .id_to_nervous_system_functions
            .get(&call.function_id)
        {
            None => Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!(
                    "There is no generic NervousSystemFunction with id: {}",
                    call.function_id
                ),
            )),
            Some(function) => {
                perform_execute_generic_nervous_system_function_call(
                    &*self.env,
                    function.clone(),
                    call,
                )
                .await
            }
        }
    }

    /// Executes a ManageNervousSystemParameters proposal by updating Governance's
    /// NervousSystemParameters
    fn perform_manage_nervous_system_parameters(
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

            // Even though proposals are validated when they are first made, this is still
            // possible, because the inner value of a ManageNervousSystemParameters
            // proposal is only valid with respect to the current
            // nervous_system_parameters() at the time when the proposal was first
            // made. If nervous_system_parameters() changed (by another proposal) since
            // the current proposal was first made, the current proposal might have become
            // invalid. Basically, this might occur if there are conflicting (concurrent)
            // proposals, but we expect this to be highly unusual in practice.
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

    /// Executes a UpgradeSnsControlledCanister proposal by either initializing the upgrade
    /// of the SNS canister (in the case where root is upgraded) or by calling the root canister
    /// to upgrade a SNS canister
    async fn perform_upgrade_sns_controlled_canister(
        &mut self,
        proposal_id: u64,
        upgrade: UpgradeSnsControlledCanister,
    ) -> Result<(), GovernanceError> {
        err_if_another_upgrade_is_in_progress(&self.proto.proposals, proposal_id)?;

        let target_canister_id = get_canister_id(&upgrade.canister_id)?;

        let target_is_root = target_canister_id == self.proto.root_canister_id_or_panic();
        println!(
            "{}target_is_root: {} (target_canister_id = {})",
            log_prefix(),
            target_is_root,
            target_canister_id
        );
        if target_is_root {
            return upgrade_canister_directly(
                &*self.env,
                target_canister_id,
                upgrade.new_canister_wasm,
            )
            .await;
        }

        // Serialize upgrade.
        let payload = {
            // We need to stop a canister before we upgrade it. Otherwise it might
            // receive callbacks to calls it made before the upgrade after the
            // upgrade when it might not have the context to parse those usefully.
            //
            // For more details, please refer to the comments above the (definition of the)
            // stop_before_installing field in ChangeCanisterProposal.
            let stop_before_installing = true;

            // The other values of this type (Install and Reinstall) are never
            // appropriate for us.
            let mode = ic_ic00_types::CanisterInstallMode::Upgrade;

            let change_canister_arg =
                ChangeCanisterProposal::new(stop_before_installing, mode, target_canister_id)
                    .with_wasm(upgrade.new_canister_wasm);

            candid::Encode!(&change_canister_arg).unwrap()
        };

        self.env
            .call_canister(
                self.proto.root_canister_id_or_panic(),
                "change_canister",
                payload,
            )
            .await
            // Convert to return type.
            .map(|_reply| ())
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Canister method call failed: {:?}", err),
                )
            })
    }

    /// Returns the nervous system parameters
    fn nervous_system_parameters(&self) -> &NervousSystemParameters {
        self.proto
            .parameters
            .as_ref()
            .expect("NervousSystemParameters not present")
    }

    /// Returns the list of permissions that a principal that claims a neuron will have for
    /// that neuron, as defined in the nervous system parameters' neuron_claimer_permissions.
    fn neuron_claimer_permissions(&self) -> NeuronPermissionList {
        self.nervous_system_parameters()
            .neuron_claimer_permissions
            .as_ref()
            .expect("NervousSystemParameters.neuron_claimer_permissions must be present")
            .clone()
    }

    /// Returns the default followees that a newly claimed neuron will have, as defined in
    /// the nervous system parameters' default_followees.
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
        let initial_voting_period = self.initial_voting_period();

        self.closest_proposal_deadline_timestamp_seconds = std::cmp::min(
            data.proposal_creation_timestamp_seconds + initial_voting_period,
            self.closest_proposal_deadline_timestamp_seconds,
        );
        self.proto.proposals.insert(pid, data);
        self.process_proposal(pid);
    }

    /// Returns the next proposal id.
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

    /// Validates and renders a proposal.
    /// If a proposal is valid it returns the rendering for the Proposals's payload.
    /// If the proposal is invalid it returns a descriptive error.
    async fn validate_and_render_proposal(
        &mut self,
        proposal: &Proposal,
    ) -> Result<String, GovernanceError> {
        if !proposal.allowed_when_resources_are_low() {
            self.check_heap_can_grow()?;
        }

        validate_and_render_proposal(
            proposal,
            &*self.env,
            self.proto
                .parameters
                .as_ref()
                .expect("Governance must have NervousSystemParameters."),
            &self.proto.id_to_nervous_system_functions,
        )
        .await
        .map_err(|e| GovernanceError::new_with_message(ErrorType::InvalidProposal, e))
    }

    /// Makes a new proposal with the given proposer neuron ID and proposal.
    ///
    /// The reject_cost_e8s (defined in the nervous system parameters) is added
    /// to the proposer's neuron management fees (they will be returned in case
    /// the proposal is adopted).
    /// The proposal is initialized with empty ballots for all neurons that are
    /// currently eligible and with their current voting power.
    /// A 'yes' vote is recorded for the proposer and this vote is propagated if
    /// the proposer has any followers on this kind of proposal. The proposal is
    /// then inserted.
    ///
    /// Preconditions:
    /// - the proposal is successfully validated
    /// - the proposer neuron exists
    /// - the caller has the permission to make a proposal in the proposer
    ///   neuron's name (permission `SubmitProposal`)
    /// - the proposer is eligible to vote (the dissolve delay is more than
    ///   min_dissolve_delay_for_vote)
    /// - the proposer's stake is at least the reject_cost_e8s
    /// - there are not already too many proposals that still contain ballots
    pub async fn make_proposal(
        &mut self,
        proposer_id: &NeuronId,
        caller: &PrincipalId,
        proposal: &Proposal,
    ) -> Result<ProposalId, GovernanceError> {
        let now_seconds = self.env.now();

        // Validate proposal
        let rendering = self.validate_and_render_proposal(proposal).await?;
        // This should not panic, because the proposal was just validated.
        let action = proposal.action.as_ref().expect("No action.");

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

        if proposer.dissolve_delay_seconds(now_seconds) < min_dissolve_delay_for_vote {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "The proposer's dissolve delay is too short, the proposer is not eligible.",
            ));
        }

        // If the current stake of the proposer neuron is less than the cost
        // of having a proposal rejected, the neuron cannot make a proposal.
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
        // Every neuron with a dissolve delay of at least
        // NervousSystemParameters.neuron_minimum_dissolve_delay_to_vote_seconds
        // is allowed to vote, with a voting power determined at the time of the
        // proposal creation (i.e., now).
        //
        // The electoral roll to put into the proposal.
        let mut electoral_roll = BTreeMap::<String, Ballot>::new();
        let mut total_power: u128 = 0;
        let max_dissolve_delay = self
            .nervous_system_parameters()
            .max_dissolve_delay_seconds
            .expect("NervousSystemParameters must have max_dissolve_delay_seconds");
        let max_age_bonus = self
            .nervous_system_parameters()
            .max_neuron_age_for_age_bonus
            .expect("NervousSystemParameters must have max_neuron_age_for_age_bonus");
        let initial_voting_period = self.initial_voting_period();

        for (k, v) in self.proto.neurons.iter() {
            // If this neuron is eligible to vote, record its
            // voting power at the time of proposal creation (now).
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
            payload_text_rendering: Some(rendering),
            ..Default::default()
        };

        proposal_data.wait_for_quiet_state = Some(WaitForQuietState {
            current_deadline_timestamp_seconds: now_seconds.saturating_add(initial_voting_period),
        });

        // Charge the cost of rejection upfront.
        // This will protect from DoS in couple of ways:
        // - It prevents a neuron from having too many proposals outstanding.
        // - It reduces the voting power of the submitter so that for every proposal
        //   outstanding the submitter will have less voting power to get it approved.
        self.proto
            .neurons
            .get_mut(&proposer_id.to_string())
            .expect("Proposer not found.")
            .neuron_fees_e8s += proposal_data.reject_cost_e8s;

        let function_id = u64::from(action);
        // Cast a 'yes'-vote for the proposer, including following.
        Governance::cast_vote_and_cascade_follow(
            &mut proposal_data.ballots,
            proposer_id,
            Vote::Yes,
            function_id,
            &self.function_followee_index,
            &mut self.proto.neurons,
            now_seconds,
        );

        // Finally, add this proposal as an open proposal.
        self.insert_proposal(proposal_num, proposal_data);

        Ok(proposal_id)
    }

    /// Registers the vote `vote_of_neuron` for the neuron `voting_neuron_id`
    /// and cascades voting according to the following relationship given in
    /// function_followee_index that (for each action) maps a followee to
    /// the set of followers.
    ///
    /// This method should only be called with `vote_of_neuron` being `yes`
    /// or `no`.
    fn cast_vote_and_cascade_follow(
        ballots: &mut BTreeMap<String, Ballot>,
        voting_neuron_id: &NeuronId,
        vote_of_neuron: Vote,
        function_id: u64,
        function_followee_index: &BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>>,
        neurons: &mut BTreeMap<String, Neuron>,
        now_seconds: u64,
    ) {
        let unspecified_function_id = u64::from(&Action::Unspecified(Empty {}));
        assert!(function_id != unspecified_function_id);
        // This is the induction variable of the loop: a map from
        // neuron ID to the neuron's vote - 'yes' or 'no' (other
        // values not allowed).
        let mut induction_votes = BTreeMap::new();
        induction_votes.insert(voting_neuron_id.to_string(), vote_of_neuron);
        let function_cache = function_followee_index.get(&function_id);
        let unspecified_cache = function_followee_index.get(&unspecified_function_id);
        loop {
            // First, we cast the specified votes (in the first round,
            // this will be a single vote) and collect all neurons
            // that follow some of the neurons that are voting.
            let mut all_followers = BTreeSet::new();
            for (k, v) in induction_votes.iter() {
                // The new/induction votes cannot be unspecified.
                assert_ne!(*v, Vote::Unspecified);
                if let Some(k_ballot) = ballots.get_mut(k) {
                    // Neuron with ID k is eligible to vote.

                    // Only update a vote if it was previously
                    // unspecified. Following can trigger votes
                    // for neurons that have already voted
                    // (manually) and we don't change these votes.
                    if k_ballot.vote == (Vote::Unspecified as i32) {
                        if let Some(_k_neuron) = neurons.get_mut(k) {
                            k_ballot.vote = *v as i32;
                            k_ballot.cast_timestamp_seconds = now_seconds;
                            // Here k is the followee, i.e., the neuron
                            // that has just cast a vote that may be
                            // followed by other neurons.
                            //
                            // Insert followers for 'action'
                            if let Some(more_followers) = function_cache.and_then(|x| x.get(k)) {
                                all_followers.append(&mut more_followers.clone());
                            }
                            // Insert followers for 'Unspecified' (default followers)
                            if let Some(more_followers) = unspecified_cache.and_then(|x| x.get(k)) {
                                all_followers.append(&mut more_followers.clone());
                            }
                        } else {
                            // The voting neuron was not found in the
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
                    let f_vote = f_neuron.would_follow_ballots(function_id, ballots);
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
            // yes or no, or all_followers will be empty, hence
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

    /// Registers a vote for a proposal for given neuron (specified by the neuron id).
    /// The method also triggers following (i.e. might send additional votes if the voting
    /// neuron has followers) and triggers the processing of the proposal (as the new
    /// votes might have changed the proposal's decision status).
    ///
    /// Preconditions:
    /// - the neuron exists
    /// - the caller has the permission to cast a vote for the given neuron
    ///   (permission `Vote`)
    /// - the given proposal exists
    /// - the cast vote is 'yes' or 'no'
    /// - the neuron is allowed to vote on this proposal (i.e., there is a ballot for this proposal
    ///   included in the proposal information)
    /// - the neuron has not voted already on this proposal
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

        let function_id = u64::from(action);
        Governance::cast_vote_and_cascade_follow(
            // Actually update the ballot, including following.
            &mut proposal.ballots,
            neuron_id,
            vote,
            function_id,
            &self.function_followee_index,
            &mut self.proto.neurons,
            self.env.now(),
        );

        self.process_proposal(proposal_id.id);

        Ok(())
    }

    /// Add or remove followees for a given neuron for a specified function_id.
    ///
    /// If the list of followees is empty, remove the followees for
    /// this function_id. If the list has at least one element, replace the
    /// current list of followees for the given function_id with the
    /// provided list. Note that the list is replaced, not added to.
    ///
    /// Preconditions:
    /// - the follower neuron exists
    /// - the caller has the permission to change followers (same authorization
    ///   as voting required, i.e., permission `Vote`)
    /// - the list of followers is not too long (does not exceed max_followees_per_function
    ///   as defined in the nervous system parameters)
    fn follow(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        f: &manage_neuron::Follow,
    ) -> Result<(), GovernanceError> {
        // The implementation of this method is complicated by the
        // fact that we have to maintain a reverse index of all follow
        // relationships, i.e., the `function_followee_index`.
        let neuron = self.proto.neurons.get_mut(&id.to_string()).ok_or_else(||
            // The specified neuron is not present.
            GovernanceError::new_with_message(ErrorType::NotFound, &format!("Follower neuron not found: {}", id)))?;

        // Check that the caller is authorized to change followers (same authorization
        // as voting required).
        neuron.check_authorized(caller, NeuronPermissionType::Vote)?;

        let max_followees_per_function = self
            .proto
            .parameters
            .as_ref()
            .expect("NervousSystemParameters not present")
            .max_followees_per_function
            .expect("NervousSystemParameters must have max_followees_per_function");

        // Check that the list of followees is not too
        // long. Allowing neurons to follow too many neurons
        // allows a memory exhaustion attack on the neurons
        // canister.
        if f.followees.len() > max_followees_per_function as usize {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Too many followees.",
            ));
        }

        if !is_registered_function_id(f.function_id, &self.proto.id_to_nervous_system_functions) {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                &format!(
                    "Function with id: {} is not present among the current set of functions.",
                    f.function_id,
                ),
            ));
        }

        // First, remove the current followees for this neuron and
        // this function_id from the neuron's followees.
        if let Some(neuron_followees) = neuron.followees.get(&f.function_id) {
            // If this function_id is not represented in the neuron's followees,
            // there is nothing to be removed.
            if let Some(followee_index) = self.function_followee_index.get_mut(&f.function_id) {
                // We need to remove this neuron as a follower
                // for all followees.
                for followee in &neuron_followees.followees {
                    if let Some(all_followers) = followee_index.get_mut(&followee.to_string()) {
                        all_followers.remove(id);
                    }
                    // Note: we don't check that the
                    // function_followee_index actually contains this
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

            // Insert the new list of followees for this function_id in
            // the neuron's followees, removing the old list, which has
            // already been removed from the followee index above.
            neuron.followees.insert(
                f.function_id,
                Followees {
                    followees: f.followees.clone(),
                },
            );
            let cache = self
                .function_followee_index
                .entry(f.function_id)
                .or_insert_with(BTreeMap::new);
            // We need to add this neuron as a follower for
            // all followees.
            for followee in &f.followees {
                let all_followers = cache
                    .entry(followee.to_string())
                    .or_insert_with(BTreeSet::new);
                all_followers.insert(id.clone());
            }
            Ok(())
        } else {
            // This operation clears the neuron's followees for the given function_id.
            neuron.followees.remove(&f.function_id);
            Ok(())
        }
    }

    /// Configures a given neuron (specified by the given neuron id).
    /// Specifically, this allows to stop and start dissolving a neuron
    /// as well as to increase a neuron's dissolve delay.
    ///
    /// Preconditions:
    /// - the neuron exists
    /// - the caller has the permission to configure a neuron
    ///   (permission `ConfigureDissolveState`)
    /// - the neuron is not in the set of neurons with ongoing operations
    fn configure_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        configure: &manage_neuron::Configure,
    ) -> Result<(), GovernanceError> {
        let now = self.env.now();

        self.proto
            .neurons
            .get(&id.to_string())
            .ok_or_else(|| Self::neuron_not_found_error(id))
            .and_then(|neuron| {
                neuron.check_authorized(caller, NeuronPermissionType::ConfigureDissolveState)
            })?;

        let max_dissolve_delay_seconds = self
            .proto
            .parameters
            .as_ref()
            .expect("NervousSystemParameters not present")
            .max_dissolve_delay_seconds
            .expect("NervousSystemParameters must have max_dissolve_delay_seconds");

        let neuron = self
            .proto
            .neurons
            .get_mut(&id.to_string())
            .ok_or_else(|| Self::neuron_not_found_error(id))?;

        neuron.configure(now, configure, max_dissolve_delay_seconds)?;
        Ok(())
    }

    /// Creates a new neuron or refreshes the stake of an existing
    /// neuron from a ledger account.
    /// The neuron id of the neuron to refresh or claim is computed
    /// with the given controller (if none is given the caller is taken)
    /// and the given memo.
    /// If the neuron id exists, the neuron is refreshed and if the neuron id
    /// does not yet exist, the neuron is claimed.
    async fn claim_or_refresh_neuron_by_memo_and_controller(
        &mut self,
        caller: &PrincipalId,
        memo_and_controller: &MemoAndController,
    ) -> Result<(), GovernanceError> {
        let controller = memo_and_controller.controller.unwrap_or(*caller);
        let memo = memo_and_controller.memo;
        let nid = NeuronId::from(ledger::compute_neuron_staking_subaccount(controller, memo));
        match self.get_neuron_result(&nid) {
            Ok(neuron) => {
                let nid = neuron.id.as_ref().expect("Neuron must have an id").clone();
                self.refresh_neuron(&nid).await
            }
            Err(_) => self.claim_neuron(nid, &controller).await,
        }
    }

    /// Refreshes the stake of a neuron specified by its id.
    ///
    /// Preconditions:
    /// - the neuron is not in the set of neurons with ongoing operations
    /// - the neuron's balance on the ledger account is at least
    ///   neuron_minimum_stake_e8s as defined in the nervous system parameters
    async fn refresh_neuron(&mut self, nid: &NeuronId) -> Result<(), GovernanceError> {
        let now = self.env.now();
        let subaccount = nid.subaccount()?;
        let account = neuron_account_id(subaccount);

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
        let neuron = self.get_neuron_result_mut(nid)?;
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

        Ok(())
    }

    /// Attempts to claim a new neuron.
    ///
    /// Preconditions:
    /// - adding the new neuron won't exceed the `max_number_of_neurons`
    /// - the (newly created) neuron is not already in the list of neurons with ongoing
    ///   operations
    /// - The neuron's balance on the ledger canister is at least neuron_minimum_stake_e8s
    ///   as defined in the nervous system parameters
    ///
    /// In the error cases, we can't return the funds without more information
    /// about the source account. So as a workaround for insufficient stake we can
    /// ask the user to transfer however much is missing to stake a neuron and they
    /// can then disburse if they so choose. We need to do something more involved
    /// if we've reached the max, TODO.
    ///
    /// # Arguments
    /// * `neuron_id` ID of the neuron being claimed/created.
    /// * `principal_id` ID to whom default permissions will be granted for the new neuron
    ///   being claimed/created.
    async fn claim_neuron(
        &mut self,
        neuron_id: NeuronId,
        principal_id: &PrincipalId,
    ) -> Result<(), GovernanceError> {
        let now = self.env.now();

        // We need to create the neuron before checking the balance so that we record
        // the neuron and add it to the set of neurons with ongoing operations. This
        // avoids a race where a user calls this method a second time before the first
        // time responds. If we store the neuron and lock it before we make the call,
        // we know that any concurrent call to mutate the same neuron will need to wait
        // for this one to finish before proceeding.
        let neuron = Neuron {
            id: Some(neuron_id.clone()),
            permissions: vec![NeuronPermission::new(
                principal_id,
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

        // Get the balance of the neuron's subaccount from ledger canister.
        let subaccount = neuron_id.subaccount()?;
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
            self.remove_neuron(&neuron_id, neuron)?;
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
        match self.get_neuron_result_mut(&neuron_id) {
            Ok(neuron) => {
                // Adjust the stake.
                neuron.update_stake(balance.get_e8s(), now);
                Ok(())
            }
            Err(err) => {
                // This should not be possible, but let's be defensive and provide a
                // reasonable error message, but still panic so that the lock remains
                // acquired and we can investigate.
                panic!(
                    "When attempting to stake a neuron with ID {} and stake {:?},\
                     the neuron disappeared while the operation was in flight.\
                     The returned error was: {}",
                    neuron_id,
                    balance.get_e8s(),
                    err
                )
            }
        }
    }

    /// Adds a `NeuronPermission` to an already existing Neuron for the given PrincipalId.
    ///
    /// If the PrincipalId doesn't have existing permissions, a new entry will be added for it
    /// with the provided permissions. If a principalId already has permissions for this neuron,
    /// the new permissions will be added to the existing permissions.
    ///
    /// Preconditions:
    /// - the caller has the permission to change a neuron's access control
    ///   (permission `ManagePrincipals`)
    /// - the permissions provided in the request are a subset of neuron_grantable_permissions
    ///   as defined in the nervous system paramters. To see what the current parameters are
    ///   for an SNS see `get_nervous_system_parameters`.
    /// - adding the new permissions for the principal does not exceed the limit of principals
    ///   that a neuron can have in its access control list, which is defined by the nervous
    ///   system parameter max_number_of_principals_per_neuron
    fn add_neuron_permissions(
        &mut self,
        neuron_id: &NeuronId,
        caller: &PrincipalId,
        add_neuron_permissions: &AddNeuronPermissions,
    ) -> Result<(), GovernanceError> {
        let neuron = self.get_neuron_result(neuron_id)?;

        neuron.check_authorized(caller, NeuronPermissionType::ManagePrincipals)?;

        let permissions_to_add = add_neuron_permissions
            .permissions_to_add
            .as_ref()
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    "AddNeuronPermissions command must provide permissions to add",
                )
            })?;

        // A simple check to prevent DoS attack with large number of permission changes.
        if permissions_to_add.permissions.len() > NeuronPermissionType::all().len() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "AddNeuronPermissions command provided more permissions than exist in the system",
            ));
        }

        self.nervous_system_parameters()
            .check_permissions_are_grantable(permissions_to_add)?;

        let principal_id = add_neuron_permissions.principal_id.ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "AddNeuronPermissions command must provide a PrincipalId to add permissions to",
            )
        })?;

        let existing_permissions = neuron
            .permissions
            .iter()
            .find(|permission| permission.principal == Some(principal_id));

        let max_number_of_principals_per_neuron = self
            .nervous_system_parameters()
            .max_number_of_principals_per_neuron
            .expect("NervousSystemParameters.max_number_of_principals_per_neuron must be present");

        // If the PrincipalId does not already exist in the neuron, make sure it can be added
        if existing_permissions.is_none()
            && neuron.permissions.len() == max_number_of_principals_per_neuron as usize
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Cannot add permission to neuron. Max \
                    number of principals reached {}",
                    max_number_of_principals_per_neuron
                ),
            ));
        }

        // Re-borrow the neuron mutably to update now that the preconditions have been met
        self.get_neuron_result_mut(neuron_id)?
            .add_permissions_for_principal(principal_id, permissions_to_add.permissions.clone());

        GovernanceProto::add_neuron_to_principal_in_principal_to_neuron_ids_index(
            &mut self.principal_to_neuron_ids_index,
            neuron_id,
            &principal_id,
        );

        Ok(())
    }

    /// Removes a set of permissions for a PrincipalId on an existing Neuron.
    ///
    /// If all the permissions are removed from the Neuron i.e. by removing all permissions for
    /// all PrincipalIds, the Neuron is not deleted. This is a dangerous operation as it is
    /// possible to remove all permissions for a neuron and no longer be able to modify its
    /// state, i.e. disbursing the neuron back into the governance token.
    ///
    /// Preconditions:
    /// - the caller has the permission to change a neuron's access control
    ///   (permission `ManagePrincipals`)
    /// - the PrincipalId exists within the neuron's permissions
    /// - the PrincipalId's NeuronPermission contains the permission_types that are to be removed
    fn remove_neuron_permissions(
        &mut self,
        neuron_id: &NeuronId,
        caller: &PrincipalId,
        remove_neuron_permissions: &RemoveNeuronPermissions,
    ) -> Result<(), GovernanceError> {
        let neuron = self.get_neuron_result(neuron_id)?;

        neuron.check_authorized(caller, NeuronPermissionType::ManagePrincipals)?;

        let permissions_to_remove = remove_neuron_permissions
            .permissions_to_remove
            .as_ref()
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    "RemoveNeuronPermissions command must provide permissions to remove",
                )
            })?;

        // A simple check to prevent DoS attack with large number of permission changes.
        if permissions_to_remove.permissions.len() > NeuronPermissionType::all().len() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "RemoveNeuronPermissions command provided more permissions than exist in the system",
            ));
        }

        let principal_id = remove_neuron_permissions
            .principal_id
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    "RemoveNeuronPermissions command must provide a PrincipalId to remove permissions from",
                )
            })?;

        // Re-borrow the neuron mutably to update now that the preconditions have been met
        let principal_id_was_removed = self
            .get_neuron_result_mut(neuron_id)?
            .remove_permissions_for_principal(
                principal_id,
                permissions_to_remove.permissions.clone(),
            )?;

        if principal_id_was_removed == RemovePermissionsStatus::AllPermissionTypesRemoved {
            GovernanceProto::remove_neuron_from_principal_in_principal_to_neuron_ids_index(
                &mut self.principal_to_neuron_ids_index,
                neuron_id,
                &principal_id,
            )
        }

        Ok(())
    }

    /// Calls manage_neuron_internal and unwraps the result in a ManageNeuronResponse.
    pub async fn manage_neuron(
        &mut self,
        mgmt: &ManageNeuron,
        caller: &PrincipalId,
    ) -> ManageNeuronResponse {
        self.manage_neuron_internal(caller, mgmt)
            .await
            .unwrap_or_else(ManageNeuronResponse::error)
    }

    /// Parses manage neuron commands coming from a given caller and calls the
    /// corresponding internal method to perform the neuron command.
    pub async fn manage_neuron_internal(
        &mut self,
        caller: &PrincipalId,
        manage_neuron: &ManageNeuron,
    ) -> Result<ManageNeuronResponse, GovernanceError> {
        let now = self.env.now();

        let neuron_id = get_neuron_id_from_manage_neuron(manage_neuron, caller)?;
        let command = manage_neuron
            .command
            .as_ref()
            .ok_or_else(|| -> GovernanceError {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    "ManageNeuron lacks a value in its command field.",
                )
            })?;

        // All operations on a neuron exclude each other.
        let _hold = self.lock_neuron_for_command(
            &neuron_id,
            NeuronInFlightCommand {
                timestamp: now,
                command: Some(command.into()),
            },
        )?;

        use manage_neuron::Command as C;
        match command {
            C::Configure(c) => self
                .configure_neuron(&neuron_id, caller, c)
                .map(|_| ManageNeuronResponse::configure_response()),
            C::Disburse(d) => self
                .disburse_neuron(&neuron_id, caller, d)
                .await
                .map(ManageNeuronResponse::disburse_response),
            C::MergeMaturity(m) => self
                .merge_maturity(&neuron_id, caller, m)
                .await
                .map(ManageNeuronResponse::merge_maturity_response),
            C::DisburseMaturity(d) => self
                .disburse_maturity(&neuron_id, caller, d)
                .await
                .map(ManageNeuronResponse::disburse_maturity_response),
            C::Split(s) => self
                .split_neuron(&neuron_id, caller, s)
                .await
                .map(ManageNeuronResponse::split_response),
            C::Follow(f) => self
                .follow(&neuron_id, caller, f)
                .map(|_| ManageNeuronResponse::follow_response()),
            C::MakeProposal(p) => self
                .make_proposal(&neuron_id, caller, p)
                .await
                .map(ManageNeuronResponse::make_proposal_response),
            C::RegisterVote(v) => self
                .register_vote(&neuron_id, caller, v)
                .map(|_| ManageNeuronResponse::register_vote_response()),
            C::AddNeuronPermissions(p) => self
                .add_neuron_permissions(&neuron_id, caller, p)
                .map(|_| ManageNeuronResponse::add_neuron_permissions_response()),
            C::RemoveNeuronPermissions(r) => self
                .remove_neuron_permissions(&neuron_id, caller, r)
                .map(|_| ManageNeuronResponse::remove_neuron_permissions_response()),
            C::ClaimOrRefresh(claim_or_refresh) => self
                .claim_or_refresh_neuron(&neuron_id, claim_or_refresh)
                .await
                .map(|_| ManageNeuronResponse::claim_or_refresh_neuron_response(neuron_id)),
        }
    }

    /// Calls dfn_core::api::caller.
    async fn claim_or_refresh_neuron(
        &mut self,
        neuron_id: &NeuronId,
        claim_or_refresh: &ClaimOrRefresh,
    ) -> Result<(), GovernanceError> {
        let locator = &claim_or_refresh.by.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Need to provide a way by which to claim or refresh the neuron.",
            )
        })?;

        match locator {
            By::MemoAndController(memo_and_controller) => {
                self.claim_or_refresh_neuron_by_memo_and_controller(
                    &dfn_core::api::caller(),
                    memo_and_controller,
                )
                .await
            }

            By::NeuronId(_) => self.refresh_neuron(neuron_id).await,
        }
    }

    /// Garbage collect obsolete data from the governance canister.
    ///
    /// Current implementation only garbage collects proposals - not neurons.
    ///
    /// Returns true if GC was run and false otherwise.
    pub fn maybe_gc(&mut self) -> bool {
        let now_seconds = self.env.now();
        // Run GC if either (a) more than 24 hours have passed since it
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
        let max_proposals_to_keep_per_action = self
            .nervous_system_parameters()
            .max_proposals_to_keep_per_action
            .expect("NervousSystemParameters must have max_proposals_to_keep_per_action")
            as usize;

        // This data structure contains proposals grouped by action.
        //
        // Proposals are stored in order based on ProposalId, where ProposalIds are assigned in
        // order of creation in the governance canister (i.e. chronologically). The following
        // data structure maintains the same chronological order for proposals in each action's
        // vector.
        let action_to_proposals: HashMap<u64, Vec<u64>> = {
            let mut tmp: HashMap<u64, Vec<u64>> = HashMap::new();
            for (proposal_id, proposal) in self.proto.proposals.iter() {
                tmp.entry(proposal.action)
                    .or_insert_with(Vec::new)
                    .push(*proposal_id);
            }
            tmp
        };
        // Only keep the latest 'max_proposals_to_keep_per_action'. This is a soft maximum
        // as garbage collection cannot purge un-finalized proposals, and only a subset of proposals
        // at the head of the list are examined.
        // TODO NNS1-1259: Improve "best-effort" garbage collection of proposals
        for (proposal_action, proposals_of_action) in action_to_proposals {
            println!(
                "{}GC - proposal_type {:#?} max {} current {}",
                log_prefix(),
                proposal_action,
                max_proposals_to_keep_per_action,
                proposals_of_action.len()
            );
            if proposals_of_action.len() > max_proposals_to_keep_per_action {
                for proposal_id in proposals_of_action
                    .iter()
                    .take(proposals_of_action.len() - max_proposals_to_keep_per_action)
                {
                    // Check that this proposal can be purged.
                    if let Some(proposal) = self.proto.proposals.get(proposal_id) {
                        if proposal.can_be_purged(now_seconds) {
                            self.proto.proposals.remove(proposal_id);
                        }
                    }
                }
            }
        }
        self.latest_gc_num_proposals = self.proto.proposals.len();
        true
    }

    /// Runs periodic tasks that are not directly triggered by user input.
    pub async fn run_periodic_tasks(&mut self) {
        self.process_proposals();

        // Getting the total governance token supply from the ledger is expensive enough
        // that we don't want to do it on every call to `run_periodic_tasks`. So
        // we only fetch it when it's needed, which is when rewards should be
        // distributed
        if self.should_distribute_rewards() {
            match self.ledger.total_supply().await {
                Ok(supply) => {
                    // Distribute rewards
                    self.distribute_rewards(supply);
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

    /// Returns `true` if rewards should be distributed (which is the case if
    /// enough time has passed since the last reward event) and `false` otherwise
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

    /// Creates a reward event.
    ///
    /// This method:
    /// * collects all proposals in state ReadyToSettle, that is, proposals that
    /// can no longer accept votes for the purpose of rewards and that have
    /// not yet been considered in a reward event
    /// * associates those proposals to the new reward event and cleans their ballots
    /// * currently, does not actually pay out rewards
    /// TODO NNS1-925 - Generic Voting Rewards. Re-enable modifying the neuron to distribute the
    ///                 reward. All other effects of distributing rewards are still in place.
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
                      It is now {} periods since genesis, and the last distribution \
                      nominally happened at {} periods since genesis.",
                log_prefix(),
                periods_since_genesis,
                self.latest_reward_event().periods_since_genesis
            );
        }
        let periods = self.latest_reward_event().periods_since_genesis..periods_since_genesis;
        let fraction: Ratio<BigInt> = periods
            .map(crate::reward::rewards_pool_to_distribute_in_supply_fraction_for_one_day)
            .sum();
        assert!(fraction >= i2r(0), "{}", fraction);

        // Because of rounding, and other possible shenanigans, it is possible
        // that some of this amount will not be distributed.
        let rewards_purse_e8s = fraction * i2r(supply.get_e8s());
        assert!(rewards_purse_e8s >= i2r(0), "{}", rewards_purse_e8s);

        let considered_proposals: Vec<ProposalId> =
            self.ready_to_be_settled_proposal_ids().collect();

        // Add up reward shares based on voting power that was exercised.
        // TODO NNS1-925 - We keep the below calculation as it will be needed when enabling
        //                 generic voting reward.
        let mut neuron_id_to_reward_shares: HashMap<NeuronId, Ratio<BigInt>> = HashMap::new();
        for proposal_id in &considered_proposals {
            if let Some(proposal) = self.get_proposal_data(*proposal_id) {
                for (voter, ballot) in &proposal.ballots {
                    if !Vote::from(ballot.vote).eligible_for_rewards() {
                        continue;
                    }

                    match NeuronId::from_str(voter) {
                        Ok(neuron_id) => {
                            let reward_shares = i2r(ballot.voting_power);
                            *neuron_id_to_reward_shares
                                .entry(neuron_id)
                                .or_insert_with(Ratio::zero) += reward_shares;
                        }
                        Err(e) => {
                            println!(
                                "{} Could not use voter {} to calculate total_voting_rights \
                                    since it's NeuronId was invalid. Underlying error: {:?}.",
                                log_prefix(),
                                voter,
                                e
                            );
                        }
                    }
                }
            }
        }
        // Freeze reward shares, now that we are done adding them up.
        let neuron_id_to_reward_shares = neuron_id_to_reward_shares;
        let total_reward_shares: Ratio<BigInt> = neuron_id_to_reward_shares.values().sum();
        assert!(
            total_reward_shares >= i2r(0),
            "total_reward_shares: {} neuron_id_to_reward_shares: {:#?}",
            total_reward_shares,
            neuron_id_to_reward_shares,
        );

        // As noted in an earlier comment, this could differ from
        // rewards_purse_e8s due to rounding, and other degenerate
        // circumstances.
        let distributed_e8s_equivalent = 0_u64;
        // Now that we know the size of the pie (rewards_purse_e8s), and how
        // much of it each neuron is supposed to get (*_reward_shares), we now
        // proceed to actually handing out those rewards.
        if total_reward_shares == i2r(0) {
            println!(
                "{}Warning: total_reward_shares is 0. Therefore, we skip increasing \
                 neuron maturity. neuron_id_to_reward_shares: {:#?}",
                log_prefix(),
                neuron_id_to_reward_shares,
            );
        } else {
            for (neuron_id, neuron_reward_shares) in neuron_id_to_reward_shares {
                match self.get_neuron_result_mut(&neuron_id) {
                    Ok(mut _neuron) => {
                        // TODO NNS1-925 - Generic Voting Rewards. Uncomment the following chunk to
                        //                 re-enable rewards for a neuron.
                        /*
                        use ic_nervous_system_common::try_r2u64;
                        use num::{CheckedDiv, CheckedMul};

                        // reward = purse * neuron_shares / total_shares
                        let reward = rewards_purse_e8s
                            .checked_mul(&neuron_reward_shares)
                            .expect("Multiplication of Ratio<BigInt>s is not supposed to overflow.")
                            .checked_div(&total_reward_shares)
                            .expect(
                                "Division of Ratio<BigInt>s is not supposed to overflow \
                                 nor underflow, and an earlier if should be gaurding against \
                                 dividing by 0.",
                            );

                        // Round down, and convert to u64.
                        let reward = try_r2u64(&reward.floor()).unwrap_or_else(|err| {
                            panic!(
                                "\
                                    Calculating reward for neuron {:?}:\n\
                                    neuron_reward_shares: {}\n\
                                    rewards_purse_e8s: {}\n\
                                    total_reward_shares: {}\n\
                                    err: {}\n\
                                ",
                                neuron_id,
                                neuron_reward_shares,
                                rewards_purse_e8s,
                                total_reward_shares,
                                err,
                            )
                        });

                        neuron.maturity_e8s_equivalent += reward;
                        distributed_e8s_equivalent += reward;
                        */
                    }
                    Err(e) => println!(
                        "{}Cannot find neuron {}, despite having voted with power {} \
                         in the considered reward period. The reward that should have been \
                         distributed to this neuron is simply skipped, so the total amount \
                         of distributed reward for this period will be lower than the maximum \
                         allowed. Underlying error: {:?}.",
                        log_prefix(),
                        neuron_id,
                        neuron_reward_shares,
                        e
                    ),
                }
            }
        }
        // Freeze distributed_e8s_equivalent, now that we are done handing out rewards.
        let distributed_e8s_equivalent = distributed_e8s_equivalent;
        // Because we used floor to round rewards to integers (and everything is
        // non-negative), it should be that the amount distributed is not more
        // than the original purse.
        debug_assert!(
            i2r(distributed_e8s_equivalent) <= rewards_purse_e8s,
            "rewards distributed ({}) > purse ({})",
            distributed_e8s_equivalent,
            rewards_purse_e8s,
        );

        let now = self.env.now();
        // Settle proposals.
        for pid in considered_proposals.iter() {
            // Before considering a proposal for reward, it must be fully processed --
            // because we're about to clear the ballots, so no further processing will be
            // possible.
            self.process_proposal(pid.id);

            let p = match self.get_proposal_data_mut(*pid) {
                Some(p) => p,
                None => {
                    println!(
                        "{}Cannot find proposal {}, despite it being considered for rewards distribution.",
                        log_prefix(), pid.id
                    );
                    debug_assert!(
                        false,
                        "It appears that proposal {} has been deleted out from under us \
                         while we were distributing rewards. This should never happen. \
                         In production, this would be quietly swept under the rug and \
                         we would continue processing. Current state (Governance):\n{:#?}",
                        pid.id, self.proto,
                    );
                    continue;
                }
            };

            if p.status() == ProposalDecisionStatus::ProposalStatusOpen {
                println!(
                    "{}Proposal {} was considered for reward distribution despite \
                     being open. We will now force the proposal's status to be Rejected.",
                    log_prefix(),
                    pid.id
                );
                debug_assert!(
                    false,
                    "This should be unreachable. Current governance state:\n{:#?}",
                    self.proto,
                );

                // The next two statements put p into the Rejected status. Thus,
                // process_proposal will consider that it has nothing more to do
                // with the p.
                p.decided_timestamp_seconds = now;
                p.latest_tally = Some(Tally {
                    timestamp_seconds: now,
                    yes: 0,
                    no: 0,
                    total: 0,
                });
                debug_assert_eq!(
                    p.status(),
                    ProposalDecisionStatus::ProposalStatusRejected,
                    "Failed to force ProposalData status to become Rejected. p:\n{:#?}",
                    p,
                );
            }

            // This is where the proposal becomes Settled, at least in the eyes
            // of the ProposalData::reward_status method.
            p.reward_event_round = periods_since_genesis;

            // Ballots are used to determine two things:
            //   1. (obviously and primarily) whether to execute the proposal.
            //   2. rewards
            // At this point, we no longer need ballots for either of these
            // things, and since they take up a fair amount of space, we take
            // this opportunity to jettison them.
            p.ballots.clear();
        }

        // Conclude this round of rewards.
        self.proto.latest_reward_event = Some(RewardEvent {
            periods_since_genesis,
            actual_timestamp_seconds: now,
            settled_proposals: considered_proposals,
            distributed_e8s_equivalent,
        })
    }

    /// Checks whether the heap can grow.
    fn check_heap_can_grow(&self) -> Result<(), GovernanceError> {
        match self.env.heap_growth_potential() {
            HeapGrowthPotential::NoIssue => Ok(()),
            HeapGrowthPotential::LimitedAvailability => Err(GovernanceError::new_with_message(
                ErrorType::ResourceExhausted,
                "Heap size too large; governance canister is running is degraded mode.",
            )),
        }
    }

    /// Checks whether new neurons can be added or whether the maximum number of neurons,
    /// as defined in the nervous system parameters, has already been reached.
    fn check_neuron_population_can_grow(&self) -> Result<(), GovernanceError> {
        let max_number_of_neurons = self
            .nervous_system_parameters()
            .max_number_of_neurons
            .expect("NervousSystemParameters must have max_number_of_neurons")
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

    // Gets the raw proposal data as a mut
    fn get_proposal_data_mut(&mut self, pid: impl Into<ProposalId>) -> Option<&mut ProposalData> {
        self.proto.proposals.get_mut(&pid.into().id)
    }

    /// Attempts to get a neuron given a neuron ID and returns the neuron on success
    /// and an error otherwise.
    fn get_neuron_result(&self, nid: &NeuronId) -> Result<&Neuron, GovernanceError> {
        self.proto
            .neurons
            .get(&nid.to_string())
            .ok_or_else(|| Self::neuron_not_found_error(nid))
    }

    /// Attempts to get a neuron as a mut, given a neuron ID and returns the neuron on success
    /// and an error otherwise.
    fn get_neuron_result_mut(&mut self, nid: &NeuronId) -> Result<&mut Neuron, GovernanceError> {
        self.proto
            .neurons
            .get_mut(&nid.to_string())
            .ok_or_else(|| Self::neuron_not_found_error(nid))
    }
}

fn err_if_another_upgrade_is_in_progress(
    id_to_proposal_data: &BTreeMap</* proposal ID */ u64, ProposalData>,
    executing_proposal_id: u64,
) -> Result<(), GovernanceError> {
    let upgrade_action_id: u64 =
        (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();

    for (other_proposal_id, proposal_data) in id_to_proposal_data {
        if *other_proposal_id == executing_proposal_id {
            continue;
        }

        if proposal_data.action != upgrade_action_id {
            continue;
        }

        if proposal_data.status() != ProposalDecisionStatus::ProposalStatusAdopted {
            continue;
        }

        return Err(GovernanceError::new_with_message(
            ErrorType::ResourceExhausted,
            format!(
                "Another upgrade is currently in progress (proposal ID {}). \
                 Please, try again later.",
                other_proposal_id,
            ),
        ));
    }

    Ok(())
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

fn get_neuron_id_from_manage_neuron(
    manage_neuron: &ManageNeuron,
    caller: &PrincipalId,
) -> Result<NeuronId, GovernanceError> {
    if let Some(manage_neuron::Command::ClaimOrRefresh(ClaimOrRefresh {
        by: Some(By::MemoAndController(memo_and_controller)),
    })) = &manage_neuron.command
    {
        return Ok(get_neuron_id_from_memo_and_controller(
            memo_and_controller,
            caller,
        ));
    }

    Ok(NeuronId::from(Governance::bytes_to_subaccount(
        &manage_neuron.subaccount,
    )?))
}

fn get_neuron_id_from_memo_and_controller(
    memo_and_controller: &MemoAndController,
    caller: &PrincipalId,
) -> NeuronId {
    let controller = memo_and_controller.controller.unwrap_or(*caller);
    let memo = memo_and_controller.memo;
    NeuronId::from(ledger::compute_neuron_staking_subaccount(controller, memo))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pb::v1::{
            manage_neuron_response,
            nervous_system_function::{FunctionType, GenericNervousSystemFunction},
            Motion, NeuronPermissionType, ProposalData, ProposalId, Tally, WaitForQuietState,
        },
        types::test_helpers::NativeEnvironment,
    };
    use async_trait::async_trait;
    use ic_canister_client::Sender;
    use ic_nervous_system_common_test_keys::TEST_USER1_KEYPAIR;
    use ic_sns_test_utils::itest_helpers::UserInfo;
    use maplit::btreemap;
    use proptest::prelude::{prop_assert, proptest};
    use std::sync::Arc;

    struct DoNothingLedger {}

    #[async_trait]
    impl Ledger for DoNothingLedger {
        async fn transfer_funds(
            &self,
            _amount_e8s: u64,
            _fee_e8s: u64,
            _from_subaccount: Option<Subaccount>,
            _to: AccountIdentifier,
            _memo: u64,
        ) -> Result<u64, NervousSystemError> {
            unimplemented!();
        }

        async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
            unimplemented!()
        }

        async fn account_balance(
            &self,
            _account: AccountIdentifier,
        ) -> Result<Tokens, NervousSystemError> {
            unimplemented!()
        }
    }

    fn basic_governance_proto() -> GovernanceProto {
        // Test subject.
        let result = GovernanceProto {
            root_canister_id: Some(PrincipalId::try_from(vec![42_u8]).unwrap()),
            ledger_canister_id: Some(PrincipalId::try_from(vec![99_u8]).unwrap()),
            parameters: Some(NervousSystemParameters::with_default_values()),
            ..Default::default()
        };

        ValidGovernanceProto::try_from(result)
            .expect(
                "We have not tried to corrupt the test subject yet but it is already invalid???",
            )
            .into_inner()
    }

    #[tokio::test]
    async fn test_neuron_operations_exclude_one_another() {
        // Step 0: Define helpers.
        struct TestLedger {
            transfer_funds_arrived: Arc<tokio::sync::Notify>,
            transfer_funds_continue: Arc<tokio::sync::Notify>,
        }

        #[async_trait]
        impl Ledger for TestLedger {
            async fn transfer_funds(
                &self,
                _amount_e8s: u64,
                _fee_e8s: u64,
                _from_subaccount: Option<Subaccount>,
                _to: AccountIdentifier,
                _memo: u64,
            ) -> Result<u64, NervousSystemError> {
                self.transfer_funds_arrived.notify_one();
                self.transfer_funds_continue.notified().await;
                Ok(1)
            }

            async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
                unimplemented!()
            }

            async fn account_balance(
                &self,
                _account: AccountIdentifier,
            ) -> Result<Tokens, NervousSystemError> {
                Ok(Tokens::new(1, 0).unwrap())
            }
        }

        let local_set = tokio::task::LocalSet::new(); // Because we are working with !Send data.
        local_set
            .run_until(async move {
                // Step 1: Prepare the world.
                let user = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
                let principal_id = user.sender.get_principal_id();
                // Not sure why user.neuron_id can't be used...
                let neuron_id = crate::pb::v1::NeuronId {
                    id: user.subaccount.to_vec(),
                };

                let mut governance_proto = basic_governance_proto();

                // Step 1.1: Add a neuron (so that we can operate on it).
                governance_proto.neurons.insert(
                    neuron_id.to_string(),
                    Neuron {
                        id: Some(neuron_id.clone()),
                        cached_neuron_stake_e8s: 10_000,
                        permissions: vec![NeuronPermission {
                            principal: Some(principal_id),
                            permission_type: NeuronPermissionType::all(),
                        }],
                        ..Default::default()
                    },
                );

                // Lets us know that a transfer is in progress.
                let transfer_funds_arrived = Arc::new(tokio::sync::Notify::new());

                // Lets us tell ledger that it can proceed with the transfer.
                let transfer_funds_continue = Arc::new(tokio::sync::Notify::new());

                // Step 1.3: Create Governance that we will be sending manage_neuron calls to.
                let mut governance = Governance::new(
                    ValidGovernanceProto::try_from(governance_proto).unwrap(),
                    Box::new(NativeEnvironment::default()),
                    Box::new(TestLedger {
                        transfer_funds_arrived: transfer_funds_arrived.clone(),
                        transfer_funds_continue: transfer_funds_continue.clone(),
                    }),
                );

                // Step 2: Execute code under test.

                // This lets us (later) make a second manage_neuron method call
                // while one is in flight, which is essential for this test.
                let raw_governance = &mut governance as *mut Governance;

                // Step 2.1: Begin an async that is supposed to interfere with a
                // later manage_neuron call.
                let disburse = ManageNeuron {
                    subaccount: user.subaccount.to_vec(),
                    command: Some(manage_neuron::Command::Disburse(manage_neuron::Disburse {
                        amount: None,
                        to_account: Some(
                            AccountIdentifier::new(user.sender.get_principal_id(), None).into(),
                        ),
                    })),
                };
                let disburse_future = {
                    let raw_disburse = &disburse as *const ManageNeuron;
                    let raw_principal_id = &principal_id as *const PrincipalId;
                    tokio::task::spawn_local(unsafe {
                        raw_governance.as_mut().unwrap().manage_neuron(
                            raw_disburse.as_ref().unwrap(),
                            raw_principal_id.as_ref().unwrap(),
                        )
                    })
                };

                transfer_funds_arrived.notified().await;
                // It is now guaranteed that disburse is now in mid flight.

                // Step 2.2: Begin another manage_neuron call.
                let configure = ManageNeuron {
                    subaccount: user.subaccount.to_vec(),
                    command: Some(manage_neuron::Command::Configure(
                        manage_neuron::Configure {
                            operation: Some(
                                manage_neuron::configure::Operation::IncreaseDissolveDelay(
                                    manage_neuron::IncreaseDissolveDelay {
                                        additional_dissolve_delay_seconds: 42,
                                    },
                                ),
                            ),
                        },
                    )),
                };
                let configure_result = unsafe {
                    raw_governance
                        .as_mut()
                        .unwrap()
                        .manage_neuron(&configure, &principal_id)
                        .await
                };

                // Step 3: Inspect results.

                // Assert that configure_result is NeuronLocked.
                match &configure_result.command.as_ref().unwrap() {
                    manage_neuron_response::Command::Error(err) => {
                        assert_eq!(
                            err.error_type,
                            ErrorType::NeuronLocked as i32,
                            "err: {:#?}",
                            err,
                        );
                    }
                    _ => panic!("configure_result: {:#?}", configure_result),
                }

                // Allow disburse to complete.
                transfer_funds_continue.notify_one();
                let disburse_result = disburse_future.await;
                assert!(disburse_result.is_ok(), "{:#?}", disburse_result);
            })
            .await;
    }

    #[test]
    fn test_governance_proto_must_have_root_canister_ids() {
        let mut proto = basic_governance_proto();
        proto.root_canister_id = None;
        assert!(ValidGovernanceProto::try_from(proto).is_err());
    }

    #[test]
    fn test_governance_proto_must_have_ledger_canister_ids() {
        let mut proto = basic_governance_proto();
        proto.ledger_canister_id = None;
        assert!(ValidGovernanceProto::try_from(proto).is_err());
    }

    #[test]
    fn test_governance_proto_must_have_parameters() {
        let mut proto = basic_governance_proto();
        proto.parameters = None;
        assert!(ValidGovernanceProto::try_from(proto).is_err());
    }

    #[test]
    fn test_governance_proto_default_followees_must_exist() {
        let mut proto = basic_governance_proto();

        let neuron_id = NeuronId { id: "A".into() };

        // Populate default_followees with a neuron that does not exist yet.
        let mut function_id_to_followees = BTreeMap::new();
        function_id_to_followees.insert(
            1, // action ID.
            Followees {
                followees: vec![neuron_id.clone()],
            },
        );
        proto.parameters.as_mut().unwrap().default_followees = Some(DefaultFollowees {
            followees: function_id_to_followees,
        });

        // assert that proto is not valid, due to referring to an unknown neuron.
        assert!(ValidGovernanceProto::try_from(proto.clone()).is_err());

        // Create the neuron so that proto is now valid.
        proto.neurons.insert(
            neuron_id.to_string(),
            Neuron {
                id: Some(neuron_id),
                ..Default::default()
            },
        );

        // Assert that proto has become valid.
        ValidGovernanceProto::try_from(proto.clone()).unwrap_or_else(|e| {
            panic!(
                "Still invalid even after adding the required neuron: {:?}: {}",
                proto, e
            )
        });
    }

    #[test]
    fn test_governance_proto_ids_in_nervous_system_functions_match() {
        let mut proto = basic_governance_proto();
        proto.id_to_nervous_system_functions.insert(
            1001,
            NervousSystemFunction {
                id: 1000,
                name: "THIS_IS_DEFECTIVE".to_string(),
                description: None,
                function_type: Some(FunctionType::GenericNervousSystemFunction(
                    GenericNervousSystemFunction {
                        target_canister_id: Some(CanisterId::from_u64(1).get()),
                        target_method_name: Some("test_method".to_string()),
                        validator_canister_id: Some(CanisterId::from_u64(1).get()),
                        validator_method_name: Some("test_validator_method".to_string()),
                    },
                )),
            },
        );
        assert!(ValidGovernanceProto::try_from(proto).is_err());
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

    #[test]
    fn test_disallow_concurrent_upgrade_execution() {
        // Step 1: Prepare the world.
        use ProposalDecisionStatus as Status;

        let upgrade_action_id: u64 =
            (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();

        // Step 1.1: First proposal, which will block the next one.
        let execution_in_progress_proposal = ProposalData {
            action: upgrade_action_id,
            id: Some(1_u64.into()),
            decided_timestamp_seconds: 123,
            latest_tally: Some(Tally {
                yes: 1,
                no: 0,
                total: 1,
                timestamp_seconds: 1,
            }),
            ..Default::default()
        };
        assert_eq!(
            execution_in_progress_proposal.status(),
            Status::ProposalStatusAdopted
        );

        // Step 1.2: Second proposal. This one will be thwarted by the first.
        let to_be_processed_proposal = ProposalData {
            action: upgrade_action_id,
            id: Some(2_u64.into()),
            ballots: btreemap! {
                "neuron 1".to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: 9001,
                    cast_timestamp_seconds: 1,
                },
            },
            wait_for_quiet_state: Some(WaitForQuietState::default()),
            proposal: Some(Proposal {
                title: "Doomed".to_string(),
                action: Some(proposal::Action::UpgradeSnsControlledCanister(
                    UpgradeSnsControlledCanister {
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            to_be_processed_proposal.status(),
            Status::ProposalStatusOpen
        );

        // Step 1.3: Init Governance.
        let mut governance = Governance::new(
            GovernanceProto {
                proposals: btreemap! {
                    1 => execution_in_progress_proposal,
                    2 => to_be_processed_proposal,
                },
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(NativeEnvironment::default()),
            Box::new(DoNothingLedger {}),
        );

        // Step 2: Execute code under test.
        governance.process_proposal(2);

        // Step 2.1: Wait for result.
        let now = std::time::Instant::now;

        let start = now();
        // In practice, the exit condition of the following loop occurs in much
        // less than 1 s (on my Macbook Pro 2019 Intel). The reason for this
        // generous limit is twofold: 1. avoid flakes in CI, while at the same
        // time 2. do not run forever if something goes wrong.
        let give_up = || now() < start + std::time::Duration::from_secs(30);
        let final_proposal_data = loop {
            let result = governance
                .get_proposal(&GetProposal {
                    proposal_id: Some(ProposalId { id: 2 }),
                })
                .result
                .unwrap();
            let proposal_data = match result {
                get_proposal_response::Result::Proposal(p) => p,
                _ => panic!("get_proposal result: {:#?}", result),
            };

            if proposal_data.status().is_final() {
                break proposal_data;
            }

            if give_up() {
                panic!("Proposal took too long to terminate (in the failed state).")
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        };

        // Step 3: Inspect results.
        assert_eq!(
            final_proposal_data.status(),
            Status::ProposalStatusFailed,
            "The second upgrade proposal did not fail. final_proposal_data: {:#?}",
            final_proposal_data,
        );
        assert_eq!(
            final_proposal_data
                .failure_reason
                .as_ref()
                .unwrap()
                .error_type,
            ErrorType::ResourceExhausted as i32,
            "The second upgrade proposal failed, but failure_reason was not as expected. \
             final_proposal_data: {:#?}",
            final_proposal_data,
        );
    }

    #[test]
    fn test_allow_canister_upgrades_while_motion_proposal_execution_is_in_progress() {
        // Step 1: Prepare the world.
        use ProposalDecisionStatus as Status;

        let motion_action_id: u64 = (&Action::Motion(Motion::default())).into();

        let proposal_id = 1_u64;
        let proposal = ProposalData {
            action: motion_action_id,
            id: Some(proposal_id.into()),
            decided_timestamp_seconds: 1,
            latest_tally: Some(Tally {
                yes: 1,
                no: 0,
                total: 1,
                timestamp_seconds: 1,
            }),
            ..Default::default()
        };
        assert_eq!(proposal.status(), Status::ProposalStatusAdopted);

        // Step 2: Run code under test.
        let some_other_proposal_id = 99_u64;
        let result = err_if_another_upgrade_is_in_progress(
            &btreemap! {
                proposal_id => proposal,
            },
            some_other_proposal_id,
        );

        // Step 3: Inspect result.
        assert!(result.is_ok(), "{:#?}", result);
    }

    #[test]
    fn test_allow_canister_upgrades_while_another_upgrade_proposal_is_open() {
        // Step 1: Prepare the world.
        use ProposalDecisionStatus as Status;

        let upgrade_action_id: u64 =
            (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();

        let proposal_id = 1_u64;
        let proposal = ProposalData {
            action: upgrade_action_id,
            id: Some(proposal_id.into()),
            latest_tally: Some(Tally {
                yes: 0,
                no: 0,
                total: 1,
                timestamp_seconds: 1,
            }),
            ..Default::default()
        };
        assert_eq!(proposal.status(), Status::ProposalStatusOpen);

        // Step 2: Run code under test.
        let some_other_proposal_id = 99_u64;
        let result = err_if_another_upgrade_is_in_progress(
            &btreemap! {
                proposal_id => proposal,
            },
            some_other_proposal_id,
        );

        // Step 3: Inspect result.
        assert!(result.is_ok(), "{:#?}", result);
    }

    #[test]
    fn test_allow_canister_upgrades_after_another_upgrade_proposal_has_executed() {
        // Step 1: Prepare the world.
        use ProposalDecisionStatus as Status;

        let upgrade_action_id: u64 =
            (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();

        let proposal_id = 1_u64;
        let proposal = ProposalData {
            action: upgrade_action_id,
            id: Some(proposal_id.into()),
            decided_timestamp_seconds: 1,
            executed_timestamp_seconds: 1,
            latest_tally: Some(Tally {
                yes: 1,
                no: 0,
                total: 1,
                timestamp_seconds: 1,
            }),
            ..Default::default()
        };
        assert_eq!(proposal.status(), Status::ProposalStatusExecuted);

        // Step 2: Run code under test.
        let some_other_proposal_id = 99_u64;
        let result = err_if_another_upgrade_is_in_progress(
            &btreemap! {
                proposal_id => proposal,
            },
            some_other_proposal_id,
        );

        // Step 3: Inspect result.
        assert!(result.is_ok(), "{:#?}", result);
    }

    #[test]
    fn test_allow_canister_upgrades_proposal_does_not_block_itself_but_does_block_others() {
        // Step 1: Prepare the world.
        use ProposalDecisionStatus as Status;

        let upgrade_action_id: u64 =
            (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();

        let proposal_id = 1_u64;
        let proposal = ProposalData {
            action: upgrade_action_id,
            id: Some(proposal_id.into()),
            decided_timestamp_seconds: 1,
            latest_tally: Some(Tally {
                yes: 1,
                no: 0,
                total: 1,
                timestamp_seconds: 1,
            }),
            ..Default::default()
        };
        assert_eq!(proposal.status(), Status::ProposalStatusAdopted);

        let proposals = btreemap! {
            proposal_id => proposal,
        };

        // Step 2 & 3: Run code under test, and inspect results.
        let result = err_if_another_upgrade_is_in_progress(&proposals, proposal_id);
        assert!(result.is_ok(), "{:#?}", result);

        // Other upgrades should be blocked by proposal 1 though.
        let some_other_proposal_id = 99_u64;
        match err_if_another_upgrade_is_in_progress(&proposals, some_other_proposal_id) {
            Ok(_) => panic!("Some other upgrade proposal was not blocked."),
            Err(err) => assert_eq!(
                err.error_type,
                ErrorType::ResourceExhausted as i32,
                "{:#?}",
                err,
            ),
        }
    }
}
