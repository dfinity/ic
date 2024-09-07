#[cfg(feature = "test")]
use crate::pb::v1::{
    AddMaturityRequest, AddMaturityResponse, MintTokensRequest, MintTokensResponse,
};

use crate::{
    canister_control::{
        get_canister_id, perform_execute_generic_nervous_system_function_call,
        upgrade_canister_directly,
    },
    logs::{ERROR, INFO},
    neuron::{
        NeuronState, RemovePermissionsStatus, DEFAULT_VOTING_POWER_PERCENTAGE_MULTIPLIER,
        MAX_LIST_NEURONS_RESULTS,
    },
    pb::{
        sns_root_types::{
            ManageDappCanisterSettingsRequest, ManageDappCanisterSettingsResponse,
            RegisterDappCanistersRequest, RegisterDappCanistersResponse, SetDappControllersRequest,
            SetDappControllersResponse,
        },
        v1::{
            claim_swap_neurons_response::SwapNeuron,
            get_neuron_response, get_proposal_response,
            governance::{
                self,
                neuron_in_flight_command::{self, Command as InFlightCommand},
                MaturityModulation, NeuronInFlightCommand, SnsMetadata, UpgradeInProgress, Version,
            },
            governance_error::ErrorType,
            manage_neuron::{
                self,
                claim_or_refresh::{By, MemoAndController},
                AddNeuronPermissions, ClaimOrRefresh, DisburseMaturity, FinalizeDisburseMaturity,
                RemoveNeuronPermissions,
            },
            manage_neuron_response::{
                DisburseMaturityResponse, MergeMaturityResponse, StakeMaturityResponse,
            },
            neuron::{DissolveState, Followees},
            proposal::Action,
            proposal_data::ActionAuxiliary as ActionAuxiliaryPb,
            transfer_sns_treasury_funds::TransferFrom,
            Account as AccountProto, Ballot, ClaimSwapNeuronsError, ClaimSwapNeuronsRequest,
            ClaimSwapNeuronsResponse, ClaimedSwapNeuronStatus, DefaultFollowees,
            DeregisterDappCanisters, DisburseMaturityInProgress, Empty,
            ExecuteGenericNervousSystemFunction, FailStuckUpgradeInProgressRequest,
            FailStuckUpgradeInProgressResponse, GetMaturityModulationRequest,
            GetMaturityModulationResponse, GetMetadataRequest, GetMetadataResponse, GetMode,
            GetModeResponse, GetNeuron, GetNeuronResponse, GetProposal, GetProposalResponse,
            GetSnsInitializationParametersRequest, GetSnsInitializationParametersResponse,
            Governance as GovernanceProto, GovernanceError, ListNervousSystemFunctionsResponse,
            ListNeurons, ListNeuronsResponse, ListProposals, ListProposalsResponse,
            ManageDappCanisterSettings, ManageLedgerParameters, ManageNeuron, ManageNeuronResponse,
            ManageSnsMetadata, MintSnsTokens, NervousSystemFunction, NervousSystemParameters,
            Neuron, NeuronId, NeuronPermission, NeuronPermissionList, NeuronPermissionType,
            Proposal, ProposalData, ProposalDecisionStatus, ProposalId, ProposalRewardStatus,
            RegisterDappCanisters, RewardEvent, Tally, TransferSnsTreasuryFunds,
            UpgradeSnsControlledCanister, UpgradeSnsToNextVersion, Vote, WaitForQuietState,
        },
    },
    proposal::{
        get_action_auxiliary,
        transfer_sns_treasury_funds_amount_is_small_enough_at_execution_time_or_err,
        validate_and_render_proposal, ValidGenericNervousSystemFunction, MAX_LIST_PROPOSAL_RESULTS,
        MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS,
    },
    sns_upgrade::{
        get_all_sns_canisters, get_running_version, get_upgrade_params, get_wasm, SnsCanisterType,
        UpgradeSnsParams,
    },
    types::{
        function_id_to_proposal_criticality, is_registered_function_id, Environment,
        HeapGrowthPotential, LedgerUpdateLock,
    },
};
use candid::{Decode, Encode};
use dfn_core::api::{spawn, CanisterId};
use ic_base_types::PrincipalId;
use ic_canister_log::log;
use ic_canister_profiler::SpanStats;
use ic_ledger_core::Tokens;
use ic_management_canister_types::{
    CanisterChangeDetails, CanisterInfoRequest, CanisterInfoResponse, CanisterInstallMode,
};
use ic_nervous_system_clients::ledger_client::ICRC1Ledger;
use ic_nervous_system_collections_union_multi_map::UnionMultiMap;
use ic_nervous_system_common::{
    cmc::CMC,
    i2d,
    ledger::{self, compute_distribution_subaccount_bytes},
    NervousSystemError, ONE_DAY_SECONDS,
};
use ic_nervous_system_governance::maturity_modulation::{
    apply_maturity_modulation, MIN_MATURITY_MODULATION_PERMYRIAD,
};
use ic_nervous_system_lock::acquire;
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_constants::LEDGER_CANISTER_ID as NNS_LEDGER_CANISTER_ID;
use ic_protobuf::types::v1::CanisterInstallMode as CanisterInstallModeProto;
use ic_sns_governance_proposal_criticality::ProposalCriticality;
use ic_sns_governance_token_valuation::Valuation;
use icp_ledger::DEFAULT_TRANSFER_FEE as NNS_DEFAULT_TRANSFER_FEE;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use lazy_static::lazy_static;
use maplit::hashset;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::{
    cell::RefCell,
    cmp::Ordering,
    collections::{
        btree_map::{BTreeMap, Entry},
        btree_set::BTreeSet,
        HashMap, HashSet,
    },
    convert::{TryFrom, TryInto},
    ops::Bound::{Excluded, Unbounded},
    str::FromStr,
    string::ToString,
    thread::LocalKey,
};
use strum::IntoEnumIterator;

lazy_static! {
    pub static ref NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER: NervousSystemFunction =
        NervousSystemFunction {
            id: *NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER_ID,
            name: "DELETION_MARKER".to_string(),
            ..Default::default()
        };
    pub static ref NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER_ID: u64 = 0;
}

/// The maximum payload size that will be included in proposals when `list_proposals` is called.
/// That is, when `list_proposals` is called, for each proposal whose payload exceeds
/// this limit, the payload will not be returned in the reply.
pub const EXECUTE_NERVOUS_SYSTEM_FUNCTION_PAYLOAD_LISTING_BYTES_MAX: usize = 1000; // 1 KB

const MAX_HEAP_SIZE_IN_KIB: usize = 4 * 1024 * 1024;
const WASM32_PAGE_SIZE_IN_KIB: usize = 64;
pub const MATURITY_DISBURSEMENT_DELAY_SECONDS: u64 = 7 * 24 * 3600;

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
/// The static MEMO used when calculating the SNS Treasury subaccount.
pub const TREASURY_SUBACCOUNT_NONCE: u64 = 0;

/// Converts bytes to a subaccountpub fn bytes_to_subaccount(bytes: &[u8]) -> Result<icrc_ledger_types::icrc1::account::Subaccount, GovernanceError> {
pub fn bytes_to_subaccount(
    bytes: &[u8],
) -> Result<icrc_ledger_types::icrc1::account::Subaccount, GovernanceError> {
    bytes.try_into().map_err(|_| {
        GovernanceError::new_with_message(ErrorType::PreconditionFailed, "Invalid subaccount")
    })
}

impl NeuronPermissionType {
    /// Returns all the different types of neuron permissions as a vector.
    pub fn all() -> Vec<i32> {
        NeuronPermissionType::iter()
            .map(|permission| permission as i32)
            .collect()
    }
}

impl NeuronPermissionList {
    /// Returns a NeuronPermissionList with all permissions.
    pub fn all() -> Self {
        NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        }
    }

    /// Returns a NeuronPermissionList with all permissions.
    pub fn empty() -> Self {
        NeuronPermissionList {
            permissions: vec![],
        }
    }

    // Returns a NeuronPermission with `self`'s permissions assigned to the given principal.
    pub fn for_principal(self, principal: PrincipalId) -> NeuronPermission {
        NeuronPermission::new(&principal, self.permissions)
    }

    // Returns true if no element in the permission list is not voting-related
    pub fn is_exclusively_voting_related(&self) -> bool {
        let permissions_related_to_voting = Neuron::PERMISSIONS_RELATED_TO_VOTING
            .iter()
            .map(|p| *p as i32)
            .collect::<Vec<_>>();
        self.permissions
            .iter()
            .all(|p| permissions_related_to_voting.contains(p))
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

            let followee_index = index.entry(*function_id).or_default();
            for followee in followees.followees.iter() {
                followee_index
                    .entry(followee.to_string())
                    .or_default()
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
                        followee_set
                            .remove(neuron.id.as_ref().expect("Neuron must have a NeuronId"));
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
        let neuron_ids = index.entry(*principal).or_default();
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
        let neuron_ids = match neuron_ids {
            None => return,
            Some(ids) => ids,
        };
        neuron_ids.remove(neuron_id);
        // If there are no neurons left, remove the entry from the index.
        if neuron_ids.is_empty() {
            index.remove(principal);
        }
    }

    /// Builds an index that maps principalIDs to a set of neurons for which the
    /// principals have some permissions.
    ///
    /// This index is built from the `neurons` in the `Governance` struct, which specify
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
        CanisterId::unchecked_from_principal(self.root_canister_id.expect("No root_canister_id."))
    }

    pub fn ledger_canister_id_or_panic(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(
            self.ledger_canister_id.expect("No ledger_canister_id."),
        )
    }

    pub fn swap_canister_id_or_panic(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.swap_canister_id.expect("No swap_canister_id."))
    }

    /// Returns self.mode, but as an enum, not i32.
    ///
    /// Panics in the following situations:
    ///   1. the conversion is not possible (e.g. self.mode = 0xDeadBeef).
    ///   2. the conversion results in Unspecified.
    ///
    /// In other words, returns either Normal or PreInitializationSwap. (More
    /// valid values could be added later, but that's it as of Aug, 2022.)
    ///
    /// This name does not follow our naming pattern, because "mode" is already
    /// used by prost::Message.
    pub fn get_mode(&self) -> governance::Mode {
        let result = governance::Mode::try_from(self.mode)
            .unwrap_or_else(|_| panic!("Unknown mode ({})", self.mode));

        assert!(
            result != governance::Mode::Unspecified,
            "Mode set to Unspecified",
        );

        result
    }

    /// Gets the current deployed version of the SNS or panics.
    pub fn deployed_version_or_panic(&self) -> Version {
        self.deployed_version
            .as_ref()
            .cloned()
            .expect("No version set in Governance.")
    }

    /// Returns 0 if maturity modulation is disabled (per
    /// nervous_system_parameters.maturity_modulation_disabled). Otherwise,
    /// returns the value in self.maturity_modulation.current_basis_points. If
    /// current_basis_points is missing, returns Err.
    fn effective_maturity_modulation_basis_points(&self) -> Result<i32, GovernanceError> {
        let maturity_modulation_disabled = self
            .parameters
            .as_ref()
            .map(|nervous_system_parameters| {
                nervous_system_parameters
                    .maturity_modulation_disabled
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        if maturity_modulation_disabled {
            return Ok(0);
        }

        self.maturity_modulation
            .as_ref()
            .and_then(|maturity_modulation| maturity_modulation.current_basis_points)
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::Unavailable,
                    "Maturity modulation not known. Retrying later might work. \
                     If this persists, there is probably a problem with retrieving \
                     the maturity modulation value from the Cycles Minting Canister.",
                )
            })
    }
}

/// This follows the following pattern:
/// https://willcrichton.net/rust-api-type-patterns/witnesses.html
#[derive(PartialEq, Debug)]
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

    /// Because enum fields (such as mode) are of type i32, not FooEnum.
    fn valid_mode_or_err(governance_proto: &GovernanceProto) -> Result<governance::Mode, String> {
        let mode = match governance::Mode::try_from(governance_proto.mode).ok() {
            Some(mode) => mode,
            None => {
                return Err(format!(
                    "Not a known governance mode code: {}\n{:#?}",
                    governance_proto.mode, governance_proto
                ));
            }
        };

        if mode == governance::Mode::Unspecified {
            return Err(format!(
                "The mode field must be populated (with something other \
                 than Unspecified): {:#?}",
                governance_proto
            ));
        }

        if mode == governance::Mode::PreInitializationSwap {
            Self::validate_required_field("swap_canister_id", &governance_proto.swap_canister_id)?;
        }

        Ok(mode)
    }

    fn validate_canister_id_field(name: &str, principal_id: PrincipalId) -> Result<(), String> {
        // TODO(NNS1-1992) – CanisterId::try_from always returns `Ok(_)` so this
        // check does nothing.
        match CanisterId::try_from(principal_id) {
            Ok(_) => Ok(()),
            Err(err) => Err(format!(
                "Unable to convert {} PrincipalId to CanisterId: {:#?}",
                name, err,
            )),
        }
    }
}

impl TryFrom<GovernanceProto> for ValidGovernanceProto {
    type Error = String;

    /// Converts GovernanceProto into ValidGovernanceProto (Self).
    ///
    /// If base is not valid, then Err is returned with an explanation.
    fn try_from(base: GovernanceProto) -> Result<Self, Self::Error> {
        let root_canister_id =
            *Self::validate_required_field("root_canister_id", &base.root_canister_id)?;
        let ledger_canister_id =
            *Self::validate_required_field("ledger_canister_id", &base.ledger_canister_id)?;
        let swap_canister_id =
            *Self::validate_required_field("swap_canister_id", &base.swap_canister_id)?;

        Self::validate_canister_id_field("root", root_canister_id)?;
        Self::validate_canister_id_field("ledger", ledger_canister_id)?;
        Self::validate_canister_id_field("swap", swap_canister_id)?;

        Self::valid_mode_or_err(&base)?;
        Self::validate_required_field("parameters", &base.parameters)?.validate()?;
        Self::validate_required_field("sns_metadata", &base.sns_metadata)?.validate()?;
        validate_id_to_nervous_system_functions(&base.id_to_nervous_system_functions)?;
        validate_default_followees(&base)?;
        validate_neurons(&base)?;

        Ok(Self(base))
    }
}

pub fn validate_id_to_nervous_system_functions(
    id_to_nervous_system_functions: &BTreeMap<u64, NervousSystemFunction>,
) -> Result<(), String> {
    for (id, function) in id_to_nervous_system_functions {
        // These entries ensure that ids do not get recycled (after deletion).
        if function == &*NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER {
            continue;
        }

        let validated_function = ValidGenericNervousSystemFunction::try_from(function)?;

        // Require that the key match the value.
        if *id != validated_function.id {
            return Err("At least one entry in id_to_nervous_system_functions \
                 doesn't have a matching id to the map key."
                .to_string());
        }
    }

    Ok(())
}

/// Requires that the neurons identified in base.parameters.default_followees
/// exist (i.e. be in base.neurons).
///
/// Assumes that base.parameters is Some.
///
/// If the validation fails, an Err is returned containing a string that explains why
/// base is invalid.
///
/// TODO NNS1-2169: default followees are not currently supported.
pub fn validate_default_followees(base: &GovernanceProto) -> Result<(), String> {
    base.parameters
        .as_ref()
        .expect("GovernanceProto.parameters is not populated.")
        .default_followees
        .as_ref()
        .ok_or_else(|| "GovernanceProto.parameters.default_followees must be set".to_string())
        .and_then(|default_followees| {
            if default_followees.followees.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "DefaultFollowees.default_followees must be empty, but found {:?}",
                    default_followees.followees
                ))
            }
        })
}

/// Requires that the neurons identified in base.neurons have their
/// voting_power_percentage_multiplier within the expected range of 0 to 100.
///
/// If the validation fails, an Err is returned containing a string that explains why
/// base is invalid.
pub fn validate_neurons(base: &GovernanceProto) -> Result<(), String> {
    for (neuron_id, neuron) in base.neurons.iter() {
        // Since voting_power_percentage_multiplier, only check the upper bound.
        if neuron.voting_power_percentage_multiplier > 100 {
            return Err(format!(
                "Neuron {} has an invalid voting_power_percentage_multiplier ({}). \
                 Expected range is 0 to 100",
                neuron_id, neuron.voting_power_percentage_multiplier
            ));
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
    ledger: Box<dyn ICRC1Ledger>,

    // Implementation of the interface pointing to the NNS's ICP ledger canister
    nns_ledger: Box<dyn ICRC1Ledger>,

    /// Implementation of the interface with the CMC canister.
    cmc: Box<dyn CMC>,

    // Stores information about the instruction usage of various "spans", which
    // map roughly to the execution of a single update call.
    pub profiling_information: &'static LocalKey<RefCell<SpanStats>>,

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

impl Governance {
    pub fn new(
        proto: ValidGovernanceProto,
        env: Box<dyn Environment>,
        ledger: Box<dyn ICRC1Ledger>,
        nns_ledger: Box<dyn ICRC1Ledger>,
        cmc: Box<dyn CMC>,
    ) -> Self {
        let mut proto = proto.into_inner();
        let now = env.now();

        if proto.genesis_timestamp_seconds == 0 {
            proto.genesis_timestamp_seconds = now;

            // Neurons available at genesis should have their timestamp
            // fields set to the genesis timestamp.
            for neuron in proto.neurons.values_mut() {
                neuron.created_timestamp_seconds = now;
                neuron.aging_since_timestamp_seconds = now;
            }
        }

        if proto.latest_reward_event.is_none() {
            // Introduce a dummy reward event to mark the origin of the SNS instance era.
            // This is required to be able to compute accurately the rewards for the
            // very first reward distribution.
            proto.latest_reward_event = Some(RewardEvent {
                actual_timestamp_seconds: now,
                round: 0,
                settled_proposals: vec![],
                distributed_e8s_equivalent: 0,
                end_timestamp_seconds: Some(now),
                rounds_since_last_distribution: Some(0),
                // This value should be considered equivalent to None (allowing
                // the use of unwrap_or_default), but for consistency, we
                // explicitly initialize to 0.
                total_available_e8s_equivalent: Some(0),
            })
        }

        thread_local! {
            static PROFILING_INFORMATION: RefCell<SpanStats> = RefCell::default();
        }

        let mut gov = Self {
            proto,
            env,
            ledger,
            profiling_information: &PROFILING_INFORMATION,
            nns_ledger,
            cmc,
            function_followee_index: BTreeMap::new(),
            principal_to_neuron_ids_index: BTreeMap::new(),
            closest_proposal_deadline_timestamp_seconds: 0,
            latest_gc_timestamp_seconds: 0,
            latest_gc_num_proposals: 0,
        };

        gov.initialize_indices();

        gov
    }

    pub fn get_mode(&self, _: GetMode) -> GetModeResponse {
        GetModeResponse {
            mode: Some(self.proto.mode() as i32),
        }
    }

    pub fn set_mode(&mut self, mode: i32, caller: PrincipalId) {
        let mode =
            governance::Mode::try_from(mode).unwrap_or_else(|_| panic!("Unknown mode: {}", mode));

        if !self.is_swap_canister(caller) {
            panic!("Caller must be the swap canister.");
        }

        // As of Aug, 2022, the only use-case we have for set_mode is to enter
        // Normal mode (from PreInitializationSwap). Therefore, this is here
        // just to make sure we do not proceed with unexpected operations.
        if mode != governance::Mode::Normal {
            panic!("Entering {:?} mode is not allowed.", mode);
        }

        self.proto.mode = mode as i32;
    }

    fn is_swap_canister(&self, id: PrincipalId) -> bool {
        self.proto.swap_canister_id == Some(id)
    }

    // Returns the ids of canisters that cannot be targeted by GenericNervousSystemFunctions.
    pub fn reserved_canister_targets(&self) -> Vec<CanisterId> {
        vec![
            self.env.canister_id(),
            self.proto.root_canister_id_or_panic(),
            self.proto.ledger_canister_id_or_panic(),
            self.proto.swap_canister_id_or_panic(),
            NNS_LEDGER_CANISTER_ID,
            CanisterId::ic_00(),
        ]
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

    /// Computes the NeuronId or returns a GovernanceError if a neuron with this ID already exists.
    fn new_neuron_id(
        &mut self,
        controller: &PrincipalId,
        memo: u64,
    ) -> Result<NeuronId, GovernanceError> {
        let subaccount = ledger::compute_neuron_staking_subaccount_bytes(*controller, memo);
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
                log!(ERROR,
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

    pub fn get_neuron_mut(&mut self, nid: &NeuronId) -> Result<&mut Neuron, GovernanceError> {
        self.proto
            .neurons
            .get_mut(&nid.to_string())
            .ok_or_else(|| Self::neuron_not_found_error(nid))
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
    ///
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
        let transaction_fee_e8s = self.transaction_fee_e8s_or_panic();
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
        let to_account = match disburse.to_account.as_ref() {
            None => Account {
                owner: caller.0,
                subaccount: None,
            },
            Some(ai_pb) => Account::try_from(ai_pb.clone()).map_err(|e| {
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
                    self.governance_minting_account(),
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

        let transaction_fee_e8s = self.transaction_fee_e8s_or_panic();

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
            voting_power_percentage_multiplier: parent_neuron.voting_power_percentage_multiplier,
            source_nns_neuron_id: parent_neuron.source_nns_neuron_id,
            staked_maturity_e8s_equivalent: None,
            auto_stake_maturity: parent_neuron.auto_stake_maturity,
            vesting_period_seconds: None,
            disburse_maturity_in_progress: vec![],
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
                self.neuron_account_id(to_subaccount),
                split.memo,
            )
            .await;

        if let Err(error) = result {
            let error = GovernanceError::from(error);
            // If we've got an error, we assume the transfer didn't happen for
            // some reason. The only state to cleanup is to delete the child
            // neuron, since we haven't mutated the parent yet.
            self.remove_neuron(&child_nid, child_neuron)?;
            log!(
                ERROR,
                "Neuron stake transfer of split_neuron: {:?} \
                     failed with error: {:?}. Neuron can't be staked.",
                child_nid,
                error
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

        neuron.check_authorized(caller, NeuronPermissionType::MergeMaturity)?;

        if merge_maturity.percentage_to_merge > 100 || merge_maturity.percentage_to_merge == 0 {
            return Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    "The percentage of maturity to merge must be a value between 1 and 100 (inclusive)."));
        }

        let transaction_fee_e8s = self.transaction_fee_e8s_or_panic();

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

        let nid = neuron.id.as_ref().expect("Neurons must have an id");
        let subaccount = neuron.subaccount()?;

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
                self.neuron_account_id(subaccount), // The account of the neuron on the ledger
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

    /// Stakes the maturity of a neuron.
    ///
    /// This method allows a neuron controller to stake the currently
    /// existing maturity of a neuron. The caller can choose a percentage
    /// of maturity to merge.
    ///
    /// Pre-conditions:
    /// - The neuron is locked for exclusive use (ALL manage_neuron operation lock the neuron)
    /// - The neuron is controlled by `caller`
    /// - The neuron has some maturity to stake.
    pub fn stake_maturity_of_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        stake_maturity: &manage_neuron::StakeMaturity,
    ) -> Result<StakeMaturityResponse, GovernanceError> {
        let neuron = self.get_neuron_result(id)?.clone();

        let nid = neuron.id.as_ref().expect("Neurons must have an id");

        if !neuron.is_authorized(caller, NeuronPermissionType::StakeMaturity) {
            return Err(GovernanceError::new(ErrorType::NotAuthorized));
        }

        let percentage_to_stake = stake_maturity.percentage_to_stake.unwrap_or(100);

        if percentage_to_stake > 100 || percentage_to_stake == 0 {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "The percentage of maturity to stake must be a value between 0 (exclusive) and 100 (inclusive)."));
        }

        let mut maturity_to_stake = (neuron
            .maturity_e8s_equivalent
            .saturating_mul(percentage_to_stake as u64))
            / 100;

        if maturity_to_stake > neuron.maturity_e8s_equivalent {
            maturity_to_stake = neuron.maturity_e8s_equivalent;
        }

        // Adjust the maturity of the neuron
        let neuron = self
            .get_neuron_result_mut(nid)
            .expect("Expected the neuron to exist");

        neuron.maturity_e8s_equivalent = neuron
            .maturity_e8s_equivalent
            .saturating_sub(maturity_to_stake);

        neuron.staked_maturity_e8s_equivalent = Some(
            neuron
                .staked_maturity_e8s_equivalent
                .unwrap_or(0)
                .saturating_add(maturity_to_stake),
        );

        Ok(StakeMaturityResponse {
            maturity_e8s: neuron.maturity_e8s_equivalent,
            staked_maturity_e8s: neuron.staked_maturity_e8s_equivalent.unwrap_or(0),
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
    pub fn disburse_maturity(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        disburse_maturity: &DisburseMaturity,
    ) -> Result<DisburseMaturityResponse, GovernanceError> {
        let neuron = self.get_neuron_result(id)?;
        neuron.check_authorized(caller, NeuronPermissionType::DisburseMaturity)?;

        // If no account was provided, transfer to the caller's account.
        let to_account: Account = match disburse_maturity.to_account.as_ref() {
            None => Account {
                owner: caller.0,
                subaccount: None,
            },
            Some(account) => Account::try_from(account.clone()).map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    format!(
                        "The given account to disburse the maturity to is invalid due to: {}",
                        e
                    ),
                )
            })?,
        };
        let to_account_proto: AccountProto = AccountProto::from(to_account);

        if disburse_maturity.percentage_to_disburse > 100
            || disburse_maturity.percentage_to_disburse == 0
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "The percentage of maturity to disburse must be a value between 1 and 100 (inclusive)."));
        }

        // The amount to deduct = the amount in the neuron * request.percentage / 100.
        let maturity_to_deduct = neuron
            .maturity_e8s_equivalent
            .checked_mul(disburse_maturity.percentage_to_disburse as u64)
            .expect("Overflow while processing maturity to disburse.")
            .checked_div(100)
            .expect("Error when processing maturity to disburse.")
            as u128;

        let maturity_to_deduct = maturity_to_deduct as u64;

        let transaction_fee_e8s = self.transaction_fee_e8s_or_panic();
        let worst_case_maturity_modulation =
            apply_maturity_modulation(maturity_to_deduct, MIN_MATURITY_MODULATION_PERMYRIAD)
                // Applying maturity modulation is a safe operation.
                // However, in the case that the method fails to apply the equation, return an
                // error instead of throwing a panic.
                .map_err(|err| {
                    GovernanceError::new_with_message(
                        ErrorType::PreconditionFailed,
                        format!(
                            "Could not calculate worst case maturity modulation \
                            and therefore cannot disburse maturity. Err: {}",
                            err
                        ),
                    )
                })?;

        if worst_case_maturity_modulation < transaction_fee_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "If worst case maturity modulation is applied (-5%) then this neuron would \
                     disburse {} e8s, but can't disburse an amount less than the transaction fee \
                     of {} e8s.",
                    worst_case_maturity_modulation, transaction_fee_e8s
                ),
            ));
        }

        let now_seconds = self.env.now();
        let disbursement_in_progress = DisburseMaturityInProgress {
            amount_e8s: maturity_to_deduct,
            timestamp_of_disbursement_seconds: now_seconds,
            account_to_disburse_to: Some(to_account_proto),
            finalize_disbursement_timestamp_seconds: Some(
                now_seconds + MATURITY_DISBURSEMENT_DELAY_SECONDS,
            ),
        };

        // Re-borrow the neuron mutably to update now that the maturity has been
        // deducted and is waiting until the end of the window to modulate and disburse.
        let neuron = self.get_neuron_result_mut(id)?;
        neuron.maturity_e8s_equivalent = neuron
            .maturity_e8s_equivalent
            .saturating_sub(maturity_to_deduct);
        neuron
            .disburse_maturity_in_progress
            .push(disbursement_in_progress);

        Ok(DisburseMaturityResponse {
            // We still populate this field even though it's deprecated, since we cannot remove
            // required fields yet.
            amount_disbursed_e8s: maturity_to_deduct,
            amount_deducted_e8s: Some(maturity_to_deduct),
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
            Some(proposal) => {
                // The proposal has to be adopted before it is executed.
                assert_eq!(proposal.status(), ProposalDecisionStatus::Adopted);
                match result {
                    Ok(_) => {
                        log!(INFO, "Execution of proposal: {} succeeded.", pid);
                        // The proposal was executed 'now'.
                        proposal.executed_timestamp_seconds = self.env.now();
                        // If the proposal was executed it has not failed,
                        // thus we set the failed_timestamp_seconds to zero
                        // (it should already be zero, but let's be defensive).
                        proposal.failed_timestamp_seconds = 0;
                        proposal.failure_reason = None;
                    }
                    Err(error) => {
                        log!(
                            ERROR,
                            "Execution of proposal: {} failed. Reason: {:?}",
                            pid,
                            error
                        );
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
                log!(
                    ERROR,
                    "Proposal {:?} not found when attempt to set execution result to {:?}",
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
            Some(pd) => get_proposal_response::Result::Proposal(pd.limited_for_get_proposal()),
        };

        GetProposalResponse {
            result: Some(proposal_data),
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
    pub fn list_proposals(
        &self,
        request: &ListProposals,
        caller: &PrincipalId,
    ) -> ListProposalsResponse {
        let caller_neurons_set: HashSet<_> = self
            .get_neuron_ids_by_principal(caller)
            .into_iter()
            .map(|neuron_id| neuron_id.to_string())
            .collect();
        let exclude_type: HashSet<u64> = request.exclude_type.iter().cloned().collect();
        let include_reward_status: HashSet<i32> =
            request.include_reward_status.iter().cloned().collect();
        let include_status: HashSet<i32> = request.include_status.iter().cloned().collect();
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
        let limit = if request.limit == 0 || request.limit > MAX_LIST_PROPOSAL_RESULTS {
            MAX_LIST_PROPOSAL_RESULTS
        } else {
            request.limit
        } as usize;
        let props = &self.proto.proposals;
        // Proposals are stored in a sorted map. If 'before_proposal'
        // is provided, grab all proposals before that, else grab the
        // whole range.
        let rng = if let Some(n) = request.before_proposal {
            props.range(..(n.id))
        } else {
            props.range(..)
        };
        // Now reverse the range, filter, and restrict to 'limit'.
        let limited_rng = rng
            .rev()
            .filter(|(_, proposal)| filter_all(proposal))
            .take(limit);

        let proposal_info = limited_rng
            .map(|(_id, proposal_data)| {
                proposal_data.limited_for_list_proposals(&caller_neurons_set)
            })
            .collect();

        // Ignore the keys and clone to a vector.
        ListProposalsResponse {
            proposals: proposal_info,
            include_ballots_by_caller: Some(true),
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
                    .filter(|&f| f != &*NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER)
                    .cloned(),
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

        let proposal_data = match self.proto.proposals.get_mut(&proposal_id) {
            None => return,
            Some(p) => p,
        };

        // Recompute the tally here. It should correctly reflect all votes until
        // the deadline, even after the proposal has been decided.
        if proposal_data.status() == ProposalDecisionStatus::Open
            || proposal_data.accepts_vote(now_seconds)
        {
            proposal_data.recompute_tally(now_seconds);
        }

        // If the status is open
        if proposal_data.status() != ProposalDecisionStatus::Open
            || !proposal_data.can_make_decision(now_seconds)
        {
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

        // A yes decision has been made, execute the proposal!
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
    pub fn process_proposals(&mut self) {
        if self.env.now() < self.closest_proposal_deadline_timestamp_seconds {
            // Nothing to do.
            return;
        }

        let pids = self
            .proto
            .proposals
            .iter()
            .filter(|(_, info)| {
                info.status() == ProposalDecisionStatus::Open || info.accepts_vote(self.env.now())
            })
            .map(|(pid, _)| *pid)
            .collect::<Vec<u64>>();

        for pid in pids {
            self.process_proposal(pid);
        }

        self.closest_proposal_deadline_timestamp_seconds = self
            .proto
            .proposals
            .values()
            .filter(|data| data.status() == ProposalDecisionStatus::Open)
            .map(|proposal_data| {
                proposal_data
                    .wait_for_quiet_state
                    .clone()
                    .map(|w| w.current_deadline_timestamp_seconds)
                    .unwrap_or_else(|| {
                        proposal_data
                            .proposal_creation_timestamp_seconds
                            .saturating_add(proposal_data.initial_voting_period_seconds)
                    })
            })
            .min()
            .unwrap_or(u64::MAX);
    }

    /// Starts execution of the given proposal in the background.
    ///
    /// The given proposal ID specifies the proposal and the `action` specifies
    /// what the proposal should do (basically, function and parameters to be applied).
    fn start_proposal_execution(&mut self, proposal_id: u64, action: Action) {
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
    async fn perform_action(&mut self, proposal_id: u64, action: Action) {
        let result = match action {
            // Execution of Motion proposals is trivial.
            Action::Motion(_) => Ok(()),

            Action::ManageNervousSystemParameters(params) => {
                self.perform_manage_nervous_system_parameters(params)
            }
            Action::UpgradeSnsControlledCanister(params) => {
                self.perform_upgrade_sns_controlled_canister(proposal_id, params)
                    .await
            }
            Action::UpgradeSnsToNextVersion(_) => {
                log!(INFO, "Executing UpgradeSnsToNextVersion action",);
                let upgrade_sns_result =
                    self.perform_upgrade_to_next_sns_version(proposal_id).await;

                // If the upgrade returned `Ok(true)` that means the upgrade completed successfully
                // and the proposal can be marked as "executed". If the upgrade returned `Ok(false)`
                // that means the upgrade has successfully been kicked-off asynchronously, but not
                // completed. Governance's heartbeat logic will continuously check the status of the
                // upgrade and mark the proposal as either executed or failed. So we call `return`
                // in the `Ok(false)` branch so that `set_proposal_execution_status` doesn't get
                // called and set the proposal status prematurely. If the result is `Err`, we do
                // want to set the proposal status, and passing the value through is sufficient.
                match upgrade_sns_result {
                    Ok(true) => Ok(()),
                    Ok(false) => return,
                    Err(e) => Err(e),
                }
            }
            Action::ExecuteGenericNervousSystemFunction(call) => {
                self.perform_execute_generic_nervous_system_function(call)
                    .await
            }
            Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                self.perform_add_generic_nervous_system_function(nervous_system_function)
            }
            Action::RemoveGenericNervousSystemFunction(id) => {
                self.perform_remove_generic_nervous_system_function(id)
            }
            Action::RegisterDappCanisters(register_dapp_canisters) => {
                self.perform_register_dapp_canisters(register_dapp_canisters)
                    .await
            }
            Action::DeregisterDappCanisters(deregister_dapp_canisters) => {
                self.perform_deregister_dapp_canisters(deregister_dapp_canisters)
                    .await
            }
            Action::ManageSnsMetadata(manage_sns_metadata) => {
                self.perform_manage_sns_metadata(manage_sns_metadata)
            }
            Action::TransferSnsTreasuryFunds(transfer) => {
                let valuation =
                    get_action_auxiliary(&self.proto.proposals, ProposalId { id: proposal_id })
                        .and_then(|action_auxiliary| {
                            action_auxiliary.unwrap_transfer_sns_treasury_funds_or_err()
                        });
                self.perform_transfer_sns_treasury_funds(proposal_id, valuation, &transfer)
                    .await
            }
            Action::MintSnsTokens(mint) => self.perform_mint_sns_tokens(mint).await,
            Action::ManageLedgerParameters(manage_ledger_parameters) => {
                self.perform_manage_ledger_parameters(proposal_id, manage_ledger_parameters)
                    .await
            }
            Action::ManageDappCanisterSettings(manage_dapp_canister_settings) => {
                self.perform_manage_dapp_canister_settings(manage_dapp_canister_settings)
                    .await
            }
            // This should not be possible, because Proposal validation is performed when
            // a proposal is first made.
            Action::Unspecified(_) => Err(GovernanceError::new_with_message(
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

        // This validates that it is well-formed, but not the canister targets.
        match ValidGenericNervousSystemFunction::try_from(&nervous_system_function) {
            Ok(valid_function) => {
                let reserved_canisters = self.reserved_canister_targets();
                let target_canister_id = valid_function.target_canister_id;
                let validator_canister_id = valid_function.validator_canister_id;

                if reserved_canisters.contains(&target_canister_id)
                    || reserved_canisters.contains(&validator_canister_id)
                {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::PreconditionFailed,
                        "Cannot add generic nervous system functions that targets sns core canisters, the NNS ledger, or ic00"));
                }
            }
            Err(msg) => {
                return Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    msg,
                ))
            }
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

    /// Registers a list of Dapp canister ids in the root canister.
    async fn perform_register_dapp_canisters(
        &self,
        register_dapp_canisters: RegisterDappCanisters,
    ) -> Result<(), GovernanceError> {
        let payload = candid::Encode!(&RegisterDappCanistersRequest::from(
            register_dapp_canisters.clone()
        ))
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Could not encode RegisterDappCanistersRequest: {err:?}"),
            )
        })?;
        self.env
            .call_canister(
                self.proto.root_canister_id_or_panic(),
                "register_dapp_canisters",
                payload,
            )
            .await
            // Convert to return type.
            .map(|reply| {
                // This line is to ensure we handle the reply properly if it's ever
                // changed to not be empty.
                match candid::Decode!(&reply, RegisterDappCanistersResponse) {
                    Ok(RegisterDappCanistersResponse {}) => {}
                    Err(_) => log!(ERROR, "Could not decode RegisterDappCanistersResponse!"),
                };

                log!(
                    INFO,
                    "Performed register_dapp_canisters, registering the following canisters: {:?}",
                    &register_dapp_canisters.canister_ids
                );
            })
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Canister method call failed: {err:?}"),
                )
            })
    }

    /// Sets the controllers of registered dapp canisters in root.
    /// Dapp canisters can be registered via the register_dapp_canisters proposal.
    async fn perform_deregister_dapp_canisters(
        &self,
        deregister_dapp_canisters: DeregisterDappCanisters,
    ) -> Result<(), GovernanceError> {
        let payload = candid::Encode!(&SetDappControllersRequest::from(
            deregister_dapp_canisters.clone()
        ))
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Could not encode SetDappControllersRequest: {err:?}"),
            )
        })?;
        self.env
            .call_canister(
                self.proto.root_canister_id_or_panic(),
                "set_dapp_controllers",
                payload,
            )
            .await
            // Convert to return type.
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Canister method call failed: {err:?}"),
                )
            })
            // Make sure no canisters' controllers failed to be set.
            .and_then(|reply| {
                // This line is to ensure we handle the reply properly if it's ever
                // changed to not be empty.
                match candid::Decode!(&reply, SetDappControllersResponse) {
                    Ok(SetDappControllersResponse { failed_updates }) => {
                        if failed_updates.is_empty() {
                            log!(
                                INFO,
                                "Deregistered the following dapp canisters: {:?}.",
                                deregister_dapp_canisters.canister_ids
                            );
                            Ok(())
                        } else {
                            let message = format!(
                                "When trying to deregister the following dapp canisters: {:?} \n\
                                The following canisters failed to deregister: {:?}",
                                deregister_dapp_canisters.canister_ids, failed_updates
                            );
                            Err(GovernanceError::new_with_message(
                                ErrorType::External,
                                message,
                            ))
                        }
                    }
                    Err(_) => Err(GovernanceError::new_with_message(
                        ErrorType::External,
                        "Could not decode SetDappControllersResponse".to_string(),
                    )),
                }
            })
    }

    // Make a change to the values of Sns Metadata
    fn perform_manage_sns_metadata(
        &mut self,
        manage_sns_metadata: ManageSnsMetadata,
    ) -> Result<(), GovernanceError> {
        let mut sns_metadata = match &self.proto.sns_metadata {
            Some(sns_metadata) => sns_metadata.clone(),
            None => SnsMetadata {
                logo: None,
                url: None,
                name: None,
                description: None,
            },
        };
        let mut log: String = "Updating the following fields of Sns Metadata: \n".to_string();
        if let Some(new_logo) = manage_sns_metadata.logo {
            sns_metadata.logo = Some(new_logo);
            log += "- Logo";
        }
        if let Some(new_url) = manage_sns_metadata.url {
            log += &format!(
                "Url:\n- old value: {}\n- new value: {}",
                sns_metadata.url.unwrap_or_default(),
                new_url
            );
            sns_metadata.url = Some(new_url);
        }
        if let Some(new_name) = manage_sns_metadata.name {
            log += &format!(
                "Name:\n- old value: {}\n- new value: {}",
                sns_metadata.name.unwrap_or_default(),
                new_name
            );
            sns_metadata.name = Some(new_name);
        }
        if let Some(new_description) = manage_sns_metadata.description {
            log += &format!(
                "Description:\n- old value: {}\n- new value: {}",
                sns_metadata.description.unwrap_or_default(),
                new_description
            );
            sns_metadata.description = Some(new_description);
        }
        log!(INFO, "{}", log);
        self.proto.sns_metadata = Some(sns_metadata);
        Ok(())
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
        let new_params = proposed_params.inherit_from(self.nervous_system_parameters_or_panic());

        log!(
            INFO,
            "Setting Governance nervous system params to: {:?}",
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

    /// Executes a UpgradeSnsControlledCanister proposal by calling the root canister
    /// to upgrade an SNS controlled canister.  This does not upgrade "core" SNS canisters
    /// (i.e. Root, Governance, Ledger, Ledger Archives, or Sale)
    async fn perform_upgrade_sns_controlled_canister(
        &mut self,
        proposal_id: u64,
        upgrade: UpgradeSnsControlledCanister,
    ) -> Result<(), GovernanceError> {
        err_if_another_upgrade_is_in_progress(&self.proto.proposals, proposal_id)?;

        let sns_canisters =
            get_all_sns_canisters(&*self.env, self.proto.root_canister_id_or_panic())
                .await
                .map_err(|e| {
                    GovernanceError::new_with_message(
                        ErrorType::External,
                        format!("Could not get list of SNS canisters from root: {}", e),
                    )
                })?;

        let dapp_canisters: Vec<CanisterId> = sns_canisters
            .dapps
            .iter()
            .map(|x| CanisterId::unchecked_from_principal(*x))
            .collect();

        let target_canister_id = get_canister_id(&upgrade.canister_id)?;
        // Fail if not a registered dapp canister
        if !dapp_canisters.contains(&target_canister_id) {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                format!(
                    "UpgradeSnsControlledCanister can only upgrade dapp canisters that are registered \
                    with the SNS root: see Root::register_dapp_canister. Valid targets are: {:?}",
                    dapp_canisters
                ),
            ));
        }

        let mode = upgrade.mode_or_upgrade() as i32;

        self.upgrade_non_root_canister(
            target_canister_id,
            upgrade.new_canister_wasm,
            upgrade
                .canister_upgrade_arg
                .unwrap_or_else(|| Encode!().unwrap()),
            CanisterInstallMode::try_from(CanisterInstallModeProto::try_from(mode)?)?,
        )
        .await
    }

    async fn upgrade_non_root_canister(
        &mut self,
        target_canister_id: CanisterId,
        wasm: Vec<u8>,
        arg: Vec<u8>,
        mode: CanisterInstallMode,
    ) -> Result<(), GovernanceError> {
        // Serialize upgrade.
        let payload = {
            // We need to stop a canister before we upgrade it. Otherwise it might
            // receive callbacks to calls it made before the upgrade after the
            // upgrade when it might not have the context to parse those usefully.
            //
            // For more details, please refer to the comments above the (definition of the)
            // stop_before_installing field in ChangeCanisterRequest.
            let stop_before_installing = true;

            let change_canister_arg =
                ChangeCanisterRequest::new(stop_before_installing, mode, target_canister_id)
                    .with_wasm(wasm)
                    .with_arg(arg)
                    .with_mode(mode);

            Encode!(&change_canister_arg).unwrap()
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

    /// Return `Ok(true)` if the upgrade was completed successfully, return `Ok(false)` if an
    /// upgrade was successfully kicked-off, but its completion is pending.
    async fn perform_upgrade_to_next_sns_version(
        &mut self,
        proposal_id: u64,
    ) -> Result<bool, GovernanceError> {
        err_if_another_upgrade_is_in_progress(&self.proto.proposals, proposal_id)?;

        let current_version = self.proto.deployed_version_or_panic();
        let root_canister_id = self.proto.root_canister_id_or_panic();

        let UpgradeSnsParams {
            next_version,
            canister_type_to_upgrade,
            new_wasm_hash,
            canister_ids_to_upgrade,
        } = get_upgrade_params(&*self.env, root_canister_id, &current_version)
            .await
            .map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    format!("Could not execute proposal: {}", e),
                )
            })?;

        // SNS Swap is controlled by NNS Governance, so this SNS instance cannot upgrade it.
        // Simply set `deployed_version` to `next_version` version so that other SNS upgrades can
        // be executed, and let the Swap upgrade occur externally (e.g. by someone submitting an
        // NNS proposal).
        if canister_type_to_upgrade == SnsCanisterType::Swap {
            self.proto.deployed_version = Some(next_version);
            return Ok(true);
        }

        let target_wasm = get_wasm(&*self.env, new_wasm_hash.to_vec(), canister_type_to_upgrade)
            .await
            .map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Could not execute proposal: {}", e),
                )
            })?
            .wasm;

        let target_is_root = canister_ids_to_upgrade.contains(&root_canister_id);

        if target_is_root {
            upgrade_canister_directly(
                &*self.env,
                root_canister_id,
                target_wasm,
                Encode!().unwrap(),
            )
            .await?;
        } else {
            for target_canister_id in canister_ids_to_upgrade {
                self.upgrade_non_root_canister(
                    target_canister_id,
                    target_wasm.clone(),
                    Encode!().unwrap(),
                    CanisterInstallMode::Upgrade,
                )
                .await?;
            }
        }

        // A canister upgrade has been successfully kicked-off. Set the pending upgrade-in-progress
        // field so that Governance's heartbeat logic can check on the status of this upgrade.
        self.proto.pending_version = Some(UpgradeInProgress {
            target_version: Some(next_version),
            mark_failed_at_seconds: self.env.now() + 5 * 60,
            checking_upgrade_lock: 0,
            proposal_id,
        });

        log!(
            INFO,
            "Successfully kicked off upgrade for SNS canister {:?}",
            canister_type_to_upgrade,
        );

        Ok(false)
    }

    async fn perform_transfer_sns_treasury_funds(
        &mut self,
        proposal_id: u64, // This is just to control concurrency.
        valuation: Result<Valuation, GovernanceError>,
        transfer: &TransferSnsTreasuryFunds,
    ) -> Result<(), GovernanceError> {
        // Only execute one proposal of this type at a time.
        thread_local! {
            static IN_PROGRESS_PROPOSAL_ID: RefCell<Option<u64>> = const { RefCell::new(None) };
        }
        let release_on_drop = acquire(&IN_PROGRESS_PROPOSAL_ID, proposal_id);
        if let Err(already_in_progress_proposal_id) = release_on_drop {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Another TransferSnsTreasuryFunds proposal (ID = {}) is already in progress.",
                    already_in_progress_proposal_id,
                ),
            ));
        }

        transfer_sns_treasury_funds_amount_is_small_enough_at_execution_time_or_err(
            transfer,
            valuation?,
            self.proto.proposals.values(),
            self.env.now(),
        )?;

        let to = Account {
            owner: transfer
                .to_principal
                .expect("Expected transfer to have a target principal")
                .0,
            subaccount: transfer.to_subaccount.as_ref().map(|s| {
                bytes_to_subaccount(&s.subaccount[..])
                    .expect("Couldn't transform transfer.subaccount to Subaccount")
            }),
        };
        match transfer.from_treasury() {
            TransferFrom::IcpTreasury => self
                .nns_ledger
                .transfer_funds(
                    transfer.amount_e8s,
                    NNS_DEFAULT_TRANSFER_FEE.get_e8s(),
                    None,
                    to,
                    transfer.memo.unwrap_or(0),
                )
                .await
                .map(|_| ())
                .map_err(|e| {
                    GovernanceError::new_with_message(
                        ErrorType::External,
                        format!("Error making ICP treasury transfer: {}", e),
                    )
                }),
            TransferFrom::SnsTokenTreasury => {
                let transaction_fee_e8s = self.transaction_fee_e8s_or_panic();
                // See ic_sns_init::distributions::FractionalDeveloperVotingPower.insert_treasury_accounts
                let treasury_subaccount = compute_distribution_subaccount_bytes(
                    self.env.canister_id().get(),
                    TREASURY_SUBACCOUNT_NONCE,
                );
                self.ledger
                    .transfer_funds(
                        transfer.amount_e8s,
                        transaction_fee_e8s,
                        Some(treasury_subaccount),
                        to,
                        transfer.memo.unwrap_or(0),
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| {
                        GovernanceError::new_with_message(
                            ErrorType::External,
                            format!("Error making SNS Token treasury transfer: {}", e),
                        )
                    })
            }
            TransferFrom::Unspecified => Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Invalid 'from_treasury' in transfer.",
            )),
        }
    }

    async fn perform_mint_sns_tokens(
        &mut self,
        mint: MintSnsTokens,
    ) -> Result<(), GovernanceError> {
        let to = Account {
            owner: mint
                .to_principal
                .ok_or(GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    "Expected mint to have a target principal",
                ))?
                .0,
            subaccount: mint
                .to_subaccount
                .as_ref()
                .map(|s| bytes_to_subaccount(&s.subaccount[..]))
                .transpose()?,
        };
        let amount_e8s = mint.amount_e8s.ok_or(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            "Expected MintSnsTokens to have an an amount_e8s",
        ))?;
        self.ledger
            .transfer_funds(amount_e8s, 0, None, to, mint.memo())
            .await?;
        Ok(())
    }

    async fn perform_manage_ledger_parameters(
        &mut self,
        proposal_id: u64,
        manage_ledger_parameters: ManageLedgerParameters,
    ) -> Result<(), GovernanceError> {
        err_if_another_upgrade_is_in_progress(&self.proto.proposals, proposal_id)?;

        let current_version = self.proto.deployed_version_or_panic();
        let ledger_canister_id = self.proto.ledger_canister_id_or_panic();

        let ledger_canister_info = self.env
            .call_canister(
                CanisterId::ic_00(),
                "canister_info",
                candid::encode_one(
                    CanisterInfoRequest::new(
                        ledger_canister_id,
                        Some(1),
                    )
                ).map_err(|e| GovernanceError::new_with_message(ErrorType::External, format!("Could not execute proposal. Error encoding canister_info request.\n{}", e)))?
            )
            .await
            .map(|b| {
                candid::decode_one::<CanisterInfoResponse>(&b)
                .map_err(|e| GovernanceError::new_with_message(ErrorType::External, format!("Could not execute proposal. Error decoding canister_info response.\n{}", e)))
            })
            .map_err(|err| GovernanceError::new_with_message(ErrorType::External, format!("Canister method call canister_info failed: {:?}", err)))??;

        let ledger_canister_info_version_number_before_upgrade: u64 =
            ledger_canister_info
            .changes()
            .last().ok_or(GovernanceError::new_with_message(ErrorType::External, "Could not execute proposal. Error finding current ledger canister_info version number".to_string()))?
            .canister_version();

        let ledger_wasm = get_wasm(
            &*self.env,
            current_version.ledger_wasm_hash.clone(),
            SnsCanisterType::Ledger,
        )
        .await
        .map_err(|e| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Could not execute proposal. Error getting ledger canister wasm: {}",
                    e
                ),
            )
        })?
        .wasm;

        use ic_icrc1_ledger::{LedgerArgument, UpgradeArgs};
        let ledger_upgrade_arg = candid::encode_one(Some(LedgerArgument::Upgrade(Some(
            UpgradeArgs::from(manage_ledger_parameters.clone()),
        ))))
        .unwrap();

        self.upgrade_non_root_canister(
            ledger_canister_id,
            ledger_wasm,
            ledger_upgrade_arg,
            CanisterInstallMode::Upgrade,
        )
        .await?;

        // If this operation takes 5 minutes, there is very likely a real failure, and other intervention will
        // be required
        let mark_failed_at_seconds = self.env.now() + 5 * 60;

        loop {
            let ledger_canister_info = self.env
                .call_canister(
                    CanisterId::ic_00(),
                    "canister_info",
                    candid::encode_one(
                        CanisterInfoRequest::new(
                            ledger_canister_id,
                            Some(20), // Get enough to ensure we did not miss the relevant change
                        )
                    ).map_err(|e| GovernanceError::new_with_message(ErrorType::External, format!("Could not check if ledger upgrade succeeded. Error encoding canister_info request.\n{}", e)))?
                )
                .await
                .map(|b| {
                    candid::decode_one::<CanisterInfoResponse>(&b)
                        .map_err(|e| GovernanceError::new_with_message(ErrorType::External, format!("Could not check if ledger upgrade succeeded. Error decoding canister_info response.\n{}", e)))
                })
                .map_err(|e| GovernanceError::new_with_message(ErrorType::External, format!("Could not check if ledger upgrade succeeded. Canister method call canister_info failed: {:?}", e)))??;

            for canister_change in ledger_canister_info.changes().iter().rev() {
                if canister_change.canister_version()
                    > ledger_canister_info_version_number_before_upgrade
                {
                    if let CanisterChangeDetails::CanisterCodeDeployment(code_deployment) =
                        canister_change.details()
                    {
                        if let CanisterInstallMode::Upgrade = code_deployment.mode() {
                            if code_deployment.module_hash()[..]
                                == current_version.ledger_wasm_hash[..]
                            {
                                // success
                                // update nervous-system-parameters transaction_fee if the fee is changed.
                                if let Some(nervous_system_parameters) =
                                    self.proto.parameters.as_mut()
                                {
                                    if let Some(transfer_fee) =
                                        manage_ledger_parameters.transfer_fee
                                    {
                                        nervous_system_parameters.transaction_fee_e8s =
                                            Some(transfer_fee);
                                    }
                                }
                                return Ok(());
                            }
                        }
                    }
                }
            }

            if self.env.now() > mark_failed_at_seconds {
                let error = format!(
                    "Upgrade marked as failed at {} seconds from genesis. \
                    Did not find an upgrade in the ledger's canister_info recent_changes.",
                    self.env.now(),
                );
                return Err(GovernanceError::new_with_message(
                    ErrorType::External,
                    error,
                ));
            }
        }
    }

    async fn perform_manage_dapp_canister_settings(
        &self,
        manage_dapp_canister_settings: ManageDappCanisterSettings,
    ) -> Result<(), GovernanceError> {
        let request = ManageDappCanisterSettingsRequest::from(manage_dapp_canister_settings);
        let payload = candid::Encode!(&request).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Could not encode ManageDappCanisterSettings: {err:?}"),
            )
        })?;
        self.env
            .call_canister(
                self.proto.root_canister_id_or_panic(),
                "manage_dapp_canister_settings",
                payload,
            )
            .await
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Canister method call failed: {err:?}"),
                )
            })
            .and_then(
                |reply| match candid::Decode!(&reply, ManageDappCanisterSettingsResponse) {
                    Ok(ManageDappCanisterSettingsResponse { failure_reason }) => failure_reason
                        .map_or(Ok(()), |failure_reason| {
                            Err(GovernanceError::new_with_message(
                                ErrorType::InvalidProposal,
                                format!(
                                    "Failed to manage dapp canister settings: {failure_reason}"
                                ),
                            ))
                        }),
                    Err(error) => Err(GovernanceError::new_with_message(
                        ErrorType::External,
                        format!("Could not decode ManageDappCanisterSettingsResponse: {error}"),
                    )),
                },
            )
    }

    // Returns an option with the NervousSystemParameters
    fn nervous_system_parameters(&self) -> Option<&NervousSystemParameters> {
        self.proto.parameters.as_ref()
    }

    /// Returns the NervousSystemParameters or panics
    fn nervous_system_parameters_or_panic(&self) -> &NervousSystemParameters {
        self.nervous_system_parameters()
            .expect("NervousSystemParameters not present")
    }

    /// Returns the list of permissions that a principal that claims a neuron will have for
    /// that neuron, as defined in the nervous system parameters' neuron_claimer_permissions.
    fn neuron_claimer_permissions_or_panic(&self) -> NeuronPermissionList {
        self.nervous_system_parameters_or_panic()
            .neuron_claimer_permissions
            .as_ref()
            .expect("NervousSystemParameters.neuron_claimer_permissions must be present")
            .clone()
    }

    /// Returns the default followees that a newly claimed neuron will have, as defined in
    /// the nervous system parameters' default_followees.
    /// TODO NNS1-2169: default followees are not currently supported.
    fn default_followees_or_panic(&self) -> DefaultFollowees {
        self.nervous_system_parameters_or_panic()
            .default_followees
            .as_ref()
            .expect("NervousSystemParameters.default_followees must be present")
            .clone()
    }

    /// Returns the ledger's transaction fee as stored in the service nervous parameters.
    fn transaction_fee_e8s_or_panic(&self) -> u64 {
        self.nervous_system_parameters_or_panic()
            .transaction_fee_e8s
            .expect("NervousSystemParameters must have transaction_fee_e8s")
    }

    /// Returns the neuron minimum stake e8s from the nervous system parameters.
    fn neuron_minimum_stake_e8s_or_panic(&self) -> u64 {
        self.nervous_system_parameters_or_panic()
            .neuron_minimum_stake_e8s
            .expect("NervousSystemParameters must have neuron_minimum_stake_e8s")
    }

    fn max_followees_per_function_or_panic(&self) -> u64 {
        self.nervous_system_parameters_or_panic()
            .max_followees_per_function
            .expect("NervousSystemParameters must have max_followees_per_function")
    }

    fn max_number_of_principals_per_neuron_or_panic(&self) -> u64 {
        self.nervous_system_parameters_or_panic()
            .max_number_of_principals_per_neuron
            .expect("NervousSystemParameters must have max_followees_per_function")
    }

    /// Inserts a proposals that has already been validated in the state.
    ///
    /// This is a low-level function that makes no verification whatsoever.
    fn insert_proposal(&mut self, pid: u64, data: ProposalData) {
        let initial_voting_period_seconds = data.initial_voting_period_seconds;

        self.closest_proposal_deadline_timestamp_seconds = std::cmp::min(
            data.proposal_creation_timestamp_seconds + initial_voting_period_seconds,
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
    /// If a proposal is valid it returns the rendering for the Proposal's payload.
    /// If the proposal is invalid it returns a descriptive error.
    async fn validate_and_render_proposal(
        &mut self,
        proposal: &Proposal,
    ) -> Result<(String, Option<ActionAuxiliaryPb>), GovernanceError> {
        if !proposal.allowed_when_resources_are_low() {
            self.check_heap_can_grow()?;
        }

        let reserved_canisters = self.reserved_canister_targets();
        validate_and_render_proposal(proposal, &*self.env, &self.proto, reserved_canisters)
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
        let (rendering, action_auxiliary) = self.validate_and_render_proposal(proposal).await?;

        // This should not panic, because the proposal was just validated.
        let action = proposal.action.as_ref().expect("No action.");

        // These cannot be the target of a ExecuteGenericNervousSystemFunction proposal.
        let disallowed_target_canister_ids = hashset! {
            self.proto.root_canister_id_or_panic(),
            self.proto.ledger_canister_id_or_panic(),
            self.env.canister_id(),
            // TODO add ledger archives
            // TODO add sale (swap) canister here?
        };

        self.mode().allows_proposal_action_or_err(
            action,
            &disallowed_target_canister_ids,
            &self.proto.id_to_nervous_system_functions,
        )?;

        let reject_cost_e8s = self
            .nervous_system_parameters_or_panic()
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
            .nervous_system_parameters_or_panic()
            .neuron_minimum_dissolve_delay_to_vote_seconds
            .expect("NervousSystemParameters must have min_dissolve_delay_for_vote");

        let proposer_dissolve_delay = proposer.dissolve_delay_seconds(now_seconds);
        if proposer_dissolve_delay < min_dissolve_delay_for_vote {
            return Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!(
                        "The proposer's dissolve delay {} is less than the minimum required dissolve delay of {}",
                        proposer_dissolve_delay, min_dissolve_delay_for_vote
                    ),
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

        let nervous_system_parameters = self.nervous_system_parameters_or_panic();

        // Voting power bonus parameters.
        let max_dissolve_delay = nervous_system_parameters
            .max_dissolve_delay_seconds
            .expect("NervousSystemParameters must have max_dissolve_delay_seconds");
        let max_age_bonus = nervous_system_parameters
            .max_neuron_age_for_age_bonus
            .expect("NervousSystemParameters must have max_neuron_age_for_age_bonus");
        let max_dissolve_delay_bonus_percentage = nervous_system_parameters
            .max_dissolve_delay_bonus_percentage
            .expect("NervousSystemParameters must have max_dissolve_delay_bonus_percentage");
        let max_age_bonus_percentage = nervous_system_parameters
            .max_age_bonus_percentage
            .expect("NervousSystemParameters must have max_age_bonus_percentage");

        // Voting duration parameters.
        let voting_duration_parameters =
            action.voting_duration_parameters(nervous_system_parameters);
        let initial_voting_period_seconds = voting_duration_parameters
            .initial_voting_period
            .seconds
            .expect(
                "Unable to determine how long the proposal should initially be open for voting.",
            );
        let wait_for_quiet_deadline_increase_seconds = voting_duration_parameters
            .wait_for_quiet_deadline_increase
            .seconds
            .expect("Unable to determine the wait for quiet deadline increase amount.");

        // Voting power threshold parameters.
        let voting_power_thresholds = action.voting_power_thresholds();
        let minimum_yes_proportion_of_total =
            voting_power_thresholds.minimum_yes_proportion_of_total;
        let minimum_yes_proportion_of_exercised =
            voting_power_thresholds.minimum_yes_proportion_of_exercised;

        for (k, v) in self.proto.neurons.iter() {
            // If this neuron is eligible to vote, record its
            // voting power at the time of proposal creation (now).
            if v.dissolve_delay_seconds(now_seconds) < min_dissolve_delay_for_vote {
                // Not eligible due to dissolve delay.
                continue;
            }
            let power = v.voting_power(
                now_seconds,
                max_dissolve_delay,
                max_age_bonus,
                max_dissolve_delay_bonus_percentage,
                max_age_bonus_percentage,
            );
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
            initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds,
            // Writing these explicitly so that we have to make a conscious decision
            // about what to do when adding a new field to `ProposalData`.
            latest_tally: ProposalData::default().latest_tally,
            decided_timestamp_seconds: ProposalData::default().decided_timestamp_seconds,
            executed_timestamp_seconds: ProposalData::default().executed_timestamp_seconds,
            failed_timestamp_seconds: ProposalData::default().failed_timestamp_seconds,
            failure_reason: ProposalData::default().failure_reason,
            reward_event_round: ProposalData::default().reward_event_round,
            wait_for_quiet_state: ProposalData::default().wait_for_quiet_state,
            reward_event_end_timestamp_seconds: ProposalData::default()
                .reward_event_end_timestamp_seconds,
            minimum_yes_proportion_of_total: Some(minimum_yes_proportion_of_total),
            minimum_yes_proportion_of_exercised: Some(minimum_yes_proportion_of_exercised),
            // This field is on its way to deletion, but before we can do that, we temporarily
            // set it to true. It used to be that this was set based on whether the reward rate
            // is positive, but that was a mistake. That's why we are getting rid of this.
            // TODO(NNS1-2731): Delete this.
            is_eligible_for_rewards: true,
            action_auxiliary,
        };

        proposal_data.wait_for_quiet_state = Some(WaitForQuietState {
            current_deadline_timestamp_seconds: now_seconds
                .saturating_add(initial_voting_period_seconds),
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
            &proposal_id,
            proposer_id,
            Vote::Yes,
            function_id,
            &self.function_followee_index,
            &self.proto.neurons,
            now_seconds,
            &mut proposal_data.ballots,
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
    ///
    /// `function_id` must be a real function ID, not the "catch-all" (pseudo)
    /// function ID, which is used for following.
    fn cast_vote_and_cascade_follow(
        proposal_id: &ProposalId, // As of Nov, 2023 (a2095be), this is only used for logging.
        voting_neuron_id: &NeuronId,
        vote_of_neuron: Vote,
        function_id: u64,
        function_followee_index: &BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>>,
        neurons: &BTreeMap<String, Neuron>,
        // As of Dec, 2023 (52eec5c), the next parameter is only used to populate Ballots. In
        // particular, this has no impact on how the implications of following are deduced.
        now_seconds: u64,
        ballots: &mut BTreeMap<String, Ballot>, // This is ultimately what gets changed.
    ) {
        let fallback_pseudo_function_id = u64::from(&Action::Unspecified(Empty {}));
        assert!(function_id != fallback_pseudo_function_id);

        // This identifies which other neurons might get "triggered" to vote by
        // filling in the current neuron's ballot.
        //
        // By default, followers on the specific function_id are reconsidered,
        // as well as followers have have general "catch-all" following. As an
        // optimization, catch-all followers are not considered when the
        // proposal is not Critical.
        //
        // E.g. if Alice follows Bob on "catch-all", and Bob votes on a
        // TransferSnsTreasuryFunds proposal, then Alice will not be considered
        // a follower of Bob, because the proposal is Critical.
        let neuron_id_to_follower_neuron_ids = {
            let mut members = vec![];
            let mut push_member = |function_id| {
                if let Some(member) = function_followee_index.get(&function_id) {
                    members.push(member);
                }
            };

            push_member(function_id);

            let proposal_criticality = function_id_to_proposal_criticality(function_id);
            match proposal_criticality {
                ProposalCriticality::Normal => push_member(fallback_pseudo_function_id),
                ProposalCriticality::Critical => (), // Do not use catch-all/fallback following.
            }

            UnionMultiMap::new(members)
        };

        // Traverse the follow graph using breadth first search (BFS).

        // Each "tier" in the BFS is listed here. Of course, the first tier just
        // contains the original "triggering" ballot.
        let mut induction_votes = BTreeMap::new();
        induction_votes.insert(voting_neuron_id.to_string(), vote_of_neuron);

        // Each iteration of this loop processes one tier in the BFS.
        //
        // This has to terminate, because if we keep going around in a cycle, that
        // means the same neuron keeps getting swayed, but once a neuron is swayed,
        // it does not matter how its "other" followees vote (i.e. those that have
        // not (directly or indirectly) voted yet). That is, once a neuron is swayed,
        // its vote is "locked in". IOW, swaying is "monotonic".
        while !induction_votes.is_empty() {
            // This will be populated with the followers of neurons in the
            // current BFS tier, who might be swayed to indirectly vote, thus
            // forming the next tier in the BFS.
            let mut follower_neuron_ids = BTreeSet::new();

            // Process the current tier in the BFS.
            for (current_neuron_id, current_new_vote) in &induction_votes {
                let current_ballot = match ballots.get_mut(current_neuron_id) {
                    Some(b) => b,
                    None => {
                        // neuron_id has no (blank) ballot, which means they
                        // were not eligible when the proposal was first
                        // created. This is fairly unusual, but does not
                        // indicate a bug (therefore, no log).
                        continue;
                    }
                };

                // Only fill in "blank" ballots. I.e. those with vote ==
                // Unspecified. This check could just as well be done before
                // current_neuron_id is added to induction_votes.
                if current_ballot.vote != (Vote::Unspecified as i32) {
                    continue;
                }

                // Fill in current_ballot.
                assert_ne!(*current_new_vote, Vote::Unspecified);
                current_ballot.vote = *current_new_vote as i32;
                current_ballot.cast_timestamp_seconds = now_seconds;

                // Take note of the followers of current_neuron_id, and add them
                // to the next "tier" in the BFS.
                if let Some(new_follower_neuron_ids) =
                    neuron_id_to_follower_neuron_ids.get(current_neuron_id)
                {
                    for follower_neuron_id in new_follower_neuron_ids {
                        follower_neuron_ids.insert(follower_neuron_id.clone());
                    }
                }
            }

            // Prepare for the next iteration of the (outer most) loop by
            // constructing the next BFS tier (from follower_neuron_ids).
            induction_votes.clear();
            for follower_neuron_id in follower_neuron_ids {
                let follower_neuron = match neurons.get(&follower_neuron_id.to_string()) {
                    Some(n) => n,
                    None => {
                        // This is a highly suspicious, because currently, we do not
                        // delete neurons, which means that we have an invalid NeuronId
                        // floating around in the system, which indicates that we have a
                        // bug. For now, we deal with that by logging, and pretending like
                        // we did not see follower_neuron_id.
                        log!(
                            ERROR,
                            "Missing neuron {} while trying to record (and cascade) \
                             a vote on proposal {:#?}.",
                            follower_neuron_id,
                            proposal_id,
                        );
                        continue;
                    }
                };

                let follower_vote = follower_neuron.would_follow_ballots(function_id, ballots);
                if follower_vote != Vote::Unspecified {
                    // follower_neuron would be swayed by its followees!
                    //
                    // This is the other (earlier) point at which we could
                    // consider whether a neuron is already locked in, and that
                    // no recursion is needed.
                    induction_votes.insert(follower_neuron_id.to_string(), follower_vote);
                }
            }
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
    /// - the proposal deadline (as extended by wait-for-quiet) has not yet been reached
    fn register_vote(
        &mut self,
        neuron_id: &NeuronId,
        caller: &PrincipalId,
        request: &manage_neuron::RegisterVote,
    ) -> Result<(), GovernanceError> {
        let now_seconds = self.env.now();

        let neuron = self
            .proto
            .neurons
            .get_mut(&neuron_id.to_string())
            .ok_or_else(||
                // The specified neuron is not present.
                GovernanceError::new_with_message(ErrorType::NotFound, "Neuron not found"))?;

        neuron.check_authorized(caller, NeuronPermissionType::Vote)?;
        let proposal_id = request.proposal.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                // InvalidCommand would probably be more apt, but that would
                // be a non-backwards compatible change.
                ErrorType::PreconditionFailed,
                "Registering of vote must include a proposal id.",
            )
        })?;

        let proposal = self.proto.proposals.get_mut(&proposal_id.id).ok_or_else(||
            // Proposal not found.
            GovernanceError::new_with_message(ErrorType::NotFound, "Can't find proposal."))?;
        let action = proposal
            .proposal
            .as_ref()
            .expect("ProposalData must have a proposal")
            .action
            .as_ref()
            .expect("Proposal must have an action");

        let vote = Vote::try_from(request.vote).unwrap_or(Vote::Unspecified);
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

        // Check if the proposal is still open for voting.
        let deadline = proposal.get_deadline_timestamp_seconds();
        if now_seconds > deadline {
            // Deadline has passed, so the proposal cannot be voted on
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Proposal deadline has passed.",
            ));
        }

        // Update ballots.
        let function_id = u64::from(action);
        Governance::cast_vote_and_cascade_follow(
            proposal_id,
            neuron_id,
            vote,
            function_id,
            &self.function_followee_index,
            &self.proto.neurons,
            now_seconds,
            &mut proposal.ballots,
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
            GovernanceError::new_with_message(ErrorType::NotFound, format!("Follower neuron not found: {}", id)))?;

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
                format!(
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
                .or_default();
            // We need to add this neuron as a follower for
            // all followees.
            for followee in &f.followees {
                let all_followers = cache.entry(followee.to_string()).or_default();
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
        let nid = NeuronId::from(ledger::compute_neuron_staking_subaccount_bytes(
            controller, memo,
        ));
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
    /// - the neuron was not created via an NNS Neurons' Fund participation in the
    ///   decentralization swap
    async fn refresh_neuron(&mut self, nid: &NeuronId) -> Result<(), GovernanceError> {
        let now = self.env.now();
        let subaccount = nid.subaccount()?;
        let account = self.neuron_account_id(subaccount);

        // First ensure that the neuron was not created via an NNS Neurons' Fund participation in the
        // decentralization swap
        {
            let neuron = self.get_neuron_result(nid)?;

            if neuron.is_neurons_fund_controlled() {
                return Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    "Cannot refresh an SNS Neuron controlled by the Neurons' Fund",
                ));
            }
        }

        // Get the balance of the neuron from the ledger canister.
        let balance = self.ledger.account_balance(account).await?;

        let min_stake = self
            .nervous_system_parameters_or_panic()
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
                log!(
                    ERROR,
                    "ERROR. Neuron cached stake was inconsistent.\
                     Neuron account: {} has less e8s: {} than the cached neuron stake: {}.\
                     Stake adjusted.",
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
                self.neuron_claimer_permissions_or_panic().permissions,
            )],
            cached_neuron_stake_e8s: 0,
            neuron_fees_e8s: 0,
            created_timestamp_seconds: now,
            aging_since_timestamp_seconds: now,
            followees: self.default_followees_or_panic().followees,
            maturity_e8s_equivalent: 0,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(0)),
            // A neuron created through the `claim_or_refresh` ManageNeuron command will
            // have the default voting power multiplier applied.
            voting_power_percentage_multiplier: DEFAULT_VOTING_POWER_PERCENTAGE_MULTIPLIER,
            source_nns_neuron_id: None,
            staked_maturity_e8s_equivalent: None,
            auto_stake_maturity: None,
            vesting_period_seconds: None,
            disburse_maturity_in_progress: vec![],
        };

        // This also verifies that there are not too many neurons already.
        self.add_neuron(neuron.clone())?;

        // Get the balance of the neuron's subaccount from ledger canister.
        let subaccount = neuron_id.subaccount()?;
        let account = self.neuron_account_id(subaccount);
        let balance = self.ledger.account_balance(account).await?;

        let min_stake = self
            .nervous_system_parameters_or_panic()
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

    /// Attempts to claim a batch of new neurons allocated by the SNS Sale canister.
    ///
    /// Preconditions:
    /// - The caller must be the Sale canister deployed along with this SNS Governance
    ///   canister.
    /// - Each NeuronRecipe's `stake_e8s` is at least neuron_minimum_stake_e8s
    ///   as defined in the `NervousSystemParameters`
    /// - Each NeuronRecipe's `followees` does not exceed max_followees_per_function
    ///   as defined in the `NervousSystemParameters`
    /// - There is available memory in the Governance canister for the newly created
    ///   Neuron.
    /// - The Neuron being claimed must not already exist in Governance.
    ///
    /// Claiming Neurons via this method differs from the primary
    /// `ManageNeuron::ClaimOrRefresh` way of creating neurons for governance. This
    /// method is only callable by the SNS Sale canister associated with this SNS
    /// Governance canister, and claims a batch of neurons instead of just one.
    /// As this is requested by the Sale canister which ensures the correct
    /// transfer of the tokens, this method does not check in the ledger. Additionally,
    /// the dissolve delay is set as part of the neuron creation process, while typically
    /// that is a separate command.
    pub fn claim_swap_neurons(
        &mut self,
        request: ClaimSwapNeuronsRequest,
        caller_principal_id: PrincipalId,
    ) -> ClaimSwapNeuronsResponse {
        let now = self.env.now();

        if !self.is_swap_canister(caller_principal_id) {
            return ClaimSwapNeuronsResponse::new_with_error(ClaimSwapNeuronsError::Unauthorized);
        }

        // Validate NervousSystemParameters and it's underlying parameters.
        match self
            .proto
            .parameters
            .as_ref()
            .ok_or_else(|| "NervousSystemParameters were not present".to_string())
            .and_then(|params| params.validate())
        {
            Ok(_) => (),
            Err(message) => {
                log!(ERROR, "Could not claim_swap_neurons, one or more NervousSystemParameters were not valid. Err: {}", message);
                return ClaimSwapNeuronsResponse::new_with_error(ClaimSwapNeuronsError::Internal);
            }
        }

        // Safe to do with the validation step above
        let neuron_minimum_stake_e8s = self.neuron_minimum_stake_e8s_or_panic();
        let max_followees_per_function = self.max_followees_per_function_or_panic();
        let max_number_of_principals_per_neuron =
            self.max_number_of_principals_per_neuron_or_panic();
        let neuron_claimer_permissions = self.neuron_claimer_permissions_or_panic();

        let mut swap_neurons = vec![];

        let Some(neuron_recipes) = request.neuron_recipes else {
            log!(
                ERROR,
                "Swap called claim_swap_neurons, but did not populate `neuron_recipes`."
            );
            return ClaimSwapNeuronsResponse::new_with_error(ClaimSwapNeuronsError::Internal);
        };

        for neuron_recipe in Vec::<_>::from(neuron_recipes) {
            match neuron_recipe.validate(
                neuron_minimum_stake_e8s,
                max_followees_per_function,
                max_number_of_principals_per_neuron,
            ) {
                Ok(_) => (),
                Err(err) => {
                    log!(ERROR, "Failed to claim Swap Neuron due to {:?}", err);
                    swap_neurons.push(SwapNeuron::from_neuron_recipe(
                        neuron_recipe,
                        ClaimedSwapNeuronStatus::Invalid,
                    ));
                    continue;
                }
            }

            // It's safe to get all fields in NeuronRecipe because of the previous validation.
            let neuron_id = neuron_recipe.get_neuron_id_or_panic();

            // Skip this neuron if it was previously claimed.
            if self.proto.neurons.contains_key(&neuron_id.to_string()) {
                swap_neurons.push(SwapNeuron::from_neuron_recipe(
                    neuron_recipe,
                    ClaimedSwapNeuronStatus::AlreadyExists,
                ));
                continue;
            }

            let neuron = Neuron {
                id: Some(neuron_id.clone()),
                permissions: neuron_recipe
                    .construct_permissions_or_panic(neuron_claimer_permissions.clone()),
                cached_neuron_stake_e8s: neuron_recipe.get_stake_e8s_or_panic(),
                neuron_fees_e8s: 0,
                created_timestamp_seconds: now,
                aging_since_timestamp_seconds: now,
                followees: neuron_recipe.construct_followees(),
                maturity_e8s_equivalent: 0,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                    neuron_recipe.get_dissolve_delay_seconds_or_panic(),
                )),
                voting_power_percentage_multiplier: DEFAULT_VOTING_POWER_PERCENTAGE_MULTIPLIER,
                source_nns_neuron_id: neuron_recipe.source_nns_neuron_id(),
                staked_maturity_e8s_equivalent: None,
                auto_stake_maturity: neuron_recipe.construct_auto_staking_maturity(),
                vesting_period_seconds: None,
                disburse_maturity_in_progress: vec![],
            };

            // Add the neuron to the various data structures and indexes to support neurons. This
            // method may fail if the memory limits of Governance have been reached, which is a
            // recoverable error. The swap canister can retry claiming after GC or upgrades
            // of SNS Governance.
            match self.add_neuron(neuron) {
                Ok(()) => swap_neurons.push(SwapNeuron::from_neuron_recipe(
                    neuron_recipe,
                    ClaimedSwapNeuronStatus::Success,
                )),
                Err(err) => {
                    log!(ERROR, "Failed to claim Swap Neuron due to {:?}", err);
                    swap_neurons.push(SwapNeuron::from_neuron_recipe(
                        neuron_recipe,
                        ClaimedSwapNeuronStatus::MemoryExhausted,
                    ))
                }
            }
        }

        ClaimSwapNeuronsResponse::new(swap_neurons)
    }

    /// Adds a `NeuronPermission` to an already existing Neuron for the given PrincipalId.
    ///
    /// If the PrincipalId doesn't have existing permissions, a new entry will be added for it
    /// with the provided permissions. If a principalId already has permissions for this neuron,
    /// the new permissions will be added to the existing set.
    ///
    /// Preconditions:
    /// - the caller has the permission to change a neuron's access control
    ///   (permission `ManagePrincipals`), or the caller has the permission to
    ///   manage voting-related permissions (permission `ManageVotingPermission`)
    ///   and the permissions being added are voting-related.
    /// - the permissions provided in the request are a subset of neuron_grantable_permissions
    ///   as defined in the nervous system parameters. To see what the current parameters are
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

        neuron
            .check_principal_authorized_to_change_permissions(caller, permissions_to_add.clone())?;

        self.nervous_system_parameters_or_panic()
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
            .nervous_system_parameters_or_panic()
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
    ///   (permission `ManagePrincipals`), or the caller has the permission to
    ///   manage voting-related permissions (permission `ManageVotingPermission`)
    ///   and the permissions being removed are voting-related.
    /// - the PrincipalId exists within the neuron's permissions
    /// - the PrincipalId's NeuronPermission contains the permission_types that are to be removed
    fn remove_neuron_permissions(
        &mut self,
        neuron_id: &NeuronId,
        caller: &PrincipalId,
        remove_neuron_permissions: &RemoveNeuronPermissions,
    ) -> Result<(), GovernanceError> {
        let neuron = self.get_neuron_result(neuron_id)?;

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

        neuron.check_principal_authorized_to_change_permissions(
            caller,
            permissions_to_remove.clone(),
        )?;

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

    /// Returns a governance::Mode, according to self.proto.mode.
    ///
    /// That field is actually an i32, so this has to do some translation.
    ///
    /// If translation is unsuccessful, panics (in non-release builds) or
    /// defaults to Normal (in release builds).
    ///
    /// Similarly, if the translation results in Unspecified, panics (in
    /// non-release builds) or defaults to Normal (in release builds).
    fn mode(&self) -> governance::Mode {
        let result = governance::Mode::try_from(self.proto.mode).unwrap_or_else(|_| {
            debug_assert!(
                false,
                "Governance is in an unknown mode: {}",
                self.proto.mode
            );
            governance::Mode::Normal
        });

        if result != governance::Mode::Unspecified {
            return result;
        }

        debug_assert!(
            false,
            "Governance's mode is not explicitly set. In production, this would default to Normal.",
        );

        governance::Mode::Normal
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
        log!(INFO, "manage_neuron/{}", command.command_name());

        self.mode()
            .allows_manage_neuron_command_or_err(command, self.is_swap_canister(*caller))?;

        self.check_command_is_valid_if_neuron_is_vesting(&neuron_id, command)?;

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
            C::StakeMaturity(m) => self
                .stake_maturity_of_neuron(&neuron_id, caller, m)
                .map(ManageNeuronResponse::stake_maturity_response),
            C::DisburseMaturity(d) => self
                .disburse_maturity(&neuron_id, caller, d)
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

    /// Returns an error if the given neuron is vesting and the given command cannot be called by
    /// a vesting neuron
    fn check_command_is_valid_if_neuron_is_vesting(
        &self,
        neuron_id: &NeuronId,
        command: &manage_neuron::Command,
    ) -> Result<(), GovernanceError> {
        use manage_neuron::{configure::Operation::*, Command::*};

        // If this is a "claim" call, the neuron doesn't exist yet, so we return (because no checks
        // can be made). A "refresh" call can be made on a vesting neuron, so in this case also
        // results in returning Ok.
        if let ClaimOrRefresh(_) = command {
            return Ok(());
        }

        let neuron = self.get_neuron_result(neuron_id)?;

        if !neuron.is_vesting(self.env.now()) {
            return Ok(());
        }

        let err = |op: &str| -> Result<(), GovernanceError> {
            Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!("Neuron {} is vesting and cannot call {}", neuron_id, op),
            ))
        };

        match command {
            Configure(configure) => match configure.operation {
                Some(IncreaseDissolveDelay(_)) => err("IncreaseDissolveDelay"),
                Some(StartDissolving(_)) => err("StartDissolving"),
                Some(StopDissolving(_)) => err("StopDissolving"),
                Some(SetDissolveTimestamp(_)) => err("SetDissolveTimestamp"),
                Some(ChangeAutoStakeMaturity(_)) => Ok(()),
                None => Ok(()),
            },
            Disburse(_) => err("Disburse"),
            Split(_) => err("Split"),
            Follow(_)
            | MakeProposal(_)
            | RegisterVote(_)
            | ClaimOrRefresh(_)
            | MergeMaturity(_)
            | DisburseMaturity(_)
            | AddNeuronPermissions(_)
            | RemoveNeuronPermissions(_)
            | StakeMaturity(_) => Ok(()),
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

    // Disburses any maturity that should be disbursed, unless this is already happening.
    async fn maybe_finalize_disburse_maturity(&mut self) {
        if !self.can_finalize_disburse_maturity() {
            return;
        }

        let maturity_modulation_basis_points =
            match self.proto.effective_maturity_modulation_basis_points() {
                Ok(maturity_modulation_basis_points) => maturity_modulation_basis_points,
                Err(message) => {
                    log!(ERROR, "{}", message.error_message);
                    return;
                }
            };

        self.proto.is_finalizing_disburse_maturity = Some(true);
        let now_seconds = self.env.now();
        // Filter all the neurons that are ready to disburse.
        let neuron_id_and_disbursements: Vec<(NeuronId, DisburseMaturityInProgress)> = self
            .proto
            .neurons
            .values()
            .filter_map(|neuron| {
                let id = match neuron.id.as_ref() {
                    Some(id) => id,
                    None => {
                        log!(
                            ERROR,
                            "NeuronId is not set for neuron. This should never happen. \
                             Cannot disburse."
                        );
                        return None;
                    }
                };
                // The first entry is the oldest one, check whether it can be completed.
                let first_disbursement = neuron.disburse_maturity_in_progress.first()?;
                let finalize_disbursement_timestamp_seconds =
                    match first_disbursement.finalize_disbursement_timestamp_seconds {
                        Some(finalize_disbursement_timestamp_seconds) => {
                            finalize_disbursement_timestamp_seconds
                        }
                        None => {
                            log!(
                                ERROR,
                                "Finalize disbursement timestamp is not set. Cannot disburse."
                            );
                            return None;
                        }
                    };
                if now_seconds >= finalize_disbursement_timestamp_seconds {
                    Some((id.clone(), first_disbursement.clone()))
                } else {
                    None
                }
            })
            .collect();
        for (neuron_id, disbursement) in neuron_id_and_disbursements.into_iter() {
            let maturity_to_disburse_after_modulation_e8s: u64 = match apply_maturity_modulation(
                disbursement.amount_e8s,
                maturity_modulation_basis_points,
            ) {
                Ok(maturity_to_disburse_after_modulation_e8s) => {
                    maturity_to_disburse_after_modulation_e8s
                }
                Err(err) => {
                    log!(
                                    ERROR,
                                    "Could not apply maturity modulation to {:?} for neuron {} due to {:?}, skipping",
                                    disbursement, neuron_id, err
                                );
                    continue;
                }
            };

            let fdm = FinalizeDisburseMaturity {
                amount_to_be_disbursed_e8s: maturity_to_disburse_after_modulation_e8s,
                to_account: disbursement.account_to_disburse_to.clone(),
            };
            let in_flight_command = NeuronInFlightCommand {
                timestamp: self.env.now(),
                command: Some(neuron_in_flight_command::Command::FinalizeDisburseMaturity(
                    fdm,
                )),
            };
            let _neuron_lock = match self.lock_neuron_for_command(&neuron_id, in_flight_command) {
                Ok(neuron_lock) => neuron_lock,
                Err(_) => continue, // if locking fails, try next neuron
            };
            // Do the transfer, this is a minting transfer, from the governance canister's
            // main account (which is also the minting account) to the provided account.
            let account_proto = match disbursement.account_to_disburse_to {
                Some(ref proto) => proto.clone(),
                None => {
                    log!(
                        ERROR,
                        "Invalid DisburseMaturityInProgress-entry {:?} for neuron {}, skipping.",
                        disbursement,
                        neuron_id
                    );
                    continue;
                }
            };
            let to_account = match Account::try_from(account_proto) {
                Ok(account) => account,
                Err(e) => {
                    log!(
                                ERROR,
                                "Failure parsing account of DisburseMaturityInProgress-entry {:?} for neuron {}: {}.",
                                disbursement, neuron_id, e
                            );
                    continue;
                }
            };
            let transfer_result = self
                .ledger
                .transfer_funds(
                    maturity_to_disburse_after_modulation_e8s,
                    0,    // Minting transfers don't pay a fee.
                    None, // This is a minting transfer, no 'from' account is needed
                    to_account,
                    self.env.now(), // The memo(nonce) for the ledger's transaction
                )
                .await;
            match transfer_result {
                Ok(block_index) => {
                    log!(
                                INFO,
                                "Transferring DisburseMaturityInProgress-entry {:?} for neuron {} at block {}.",
                                disbursement, neuron_id, block_index
                            );
                    let neuron = match self.get_neuron_result_mut(&neuron_id) {
                        Ok(neuron) => neuron,
                        Err(e) => {
                            log!(
                                        ERROR,
                                        "Failed updating DisburseMaturityInProgress-entry {:?} for neuron {}: {}.",
                                        disbursement, neuron_id, e
                                    );
                            continue;
                        }
                    };
                    neuron.disburse_maturity_in_progress.remove(0);
                }
                Err(e) => {
                    log!(
                                ERROR,
                                "Failed transferring funds for DisburseMaturityInProgress-entry {:?} for neuron {}: {}.",
                                disbursement, neuron_id, e
                            );
                }
            }
        }
        self.proto.is_finalizing_disburse_maturity = None;
    }

    /// When a neuron is finally dissolved, if there is any staked maturity it is moved to regular maturity
    /// which can be spawned.
    pub(crate) fn maybe_move_staked_maturity(&mut self) {
        let now_seconds = self.env.now();
        // Filter all the neurons that are currently in "dissolved" state and have some staked maturity.
        for neuron in self.proto.neurons.values_mut().filter(|n| {
            n.state(now_seconds) == NeuronState::Dissolved
                && n.staked_maturity_e8s_equivalent.unwrap_or(0) > 0
        }) {
            neuron.maturity_e8s_equivalent = neuron
                .maturity_e8s_equivalent
                .saturating_add(neuron.staked_maturity_e8s_equivalent.unwrap_or(0));
            neuron.staked_maturity_e8s_equivalent = None;
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
        log!(
            INFO,
            "Running GC now at timestamp {} seconds",
            self.latest_gc_timestamp_seconds
        );

        let max_proposals_to_keep_per_action = match self
            .nervous_system_parameters()
            .and_then(|params| params.max_proposals_to_keep_per_action)
        {
            None => {
                log!(
                    ERROR,
                    "NervousSystemParameters must have max_proposals_to_keep_per_action"
                );
                return false;
            }
            Some(max) => max as usize,
        };

        // This data structure contains proposals grouped by action.
        //
        // Proposals are stored in order based on ProposalId, where ProposalIds are assigned in
        // order of creation in the governance canister (i.e. chronologically). The following
        // data structure maintains the same chronological order for proposals in each action's
        // vector.
        let action_to_proposals: HashMap<u64, Vec<u64>> = {
            let mut tmp: HashMap<u64, Vec<u64>> = HashMap::new();
            for (proposal_id, proposal) in self.proto.proposals.iter() {
                tmp.entry(proposal.action).or_default().push(*proposal_id);
            }
            tmp
        };
        // Only keep the latest 'max_proposals_to_keep_per_action'. This is a soft maximum
        // as garbage collection cannot purge un-finalized proposals, and only a subset of proposals
        // at the head of the list are examined.
        // TODO NNS1-1259: Improve "best-effort" garbage collection of proposals
        for (proposal_action, proposals_of_action) in action_to_proposals {
            log!(
                INFO,
                "GC - proposal_type {:#?} max {} current {}",
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
    pub async fn heartbeat(&mut self) {
        self.process_proposals();

        if self.should_check_upgrade_status() {
            self.check_upgrade_status().await;
        }

        let should_distribute_rewards = self.should_distribute_rewards();

        // Getting the total governance token supply from the ledger is expensive enough
        // that we don't want to do it on every call to `heartbeat`. So
        // we only fetch it when it's needed, which is when rewards should be
        // distributed
        if should_distribute_rewards {
            match self.ledger.total_supply().await {
                Ok(supply) => {
                    // Distribute rewards
                    self.distribute_rewards(supply);
                }
                Err(e) => log!(
                    ERROR,
                    "Error when getting total governance token supply: {}",
                    GovernanceError::from(e)
                ),
            }
        }

        if self.should_update_maturity_modulation() {
            self.update_maturity_modulation().await;
        }

        self.maybe_finalize_disburse_maturity().await;

        self.maybe_move_staked_maturity();

        self.maybe_gc();
    }

    fn should_update_maturity_modulation(&self) -> bool {
        // Check if we're already updating the neuron maturity modulation.
        let updated_at_timestamp_seconds = self
            .proto
            .maturity_modulation
            .as_ref()
            .and_then(|maturity_modulation| maturity_modulation.updated_at_timestamp_seconds)
            .unwrap_or_default();

        let age_seconds = self.env.now() - updated_at_timestamp_seconds;
        age_seconds >= ONE_DAY_SECONDS
    }

    async fn update_maturity_modulation(&mut self) {
        if !self.should_update_maturity_modulation() {
            return;
        };

        // Fetch new maturity modulation.
        let maturity_modulation = self.cmc.neuron_maturity_modulation().await;

        // Unwrap response.
        let maturity_modulation = match maturity_modulation {
            Ok(ok) => ok,
            Err(err) => {
                println!(
                    "{}Couldn't update maturity modulation. Error: {}",
                    log_prefix(),
                    err,
                );
                return;
            }
        };

        // Construct new MaturityModulation.
        let new_maturity_modulation = MaturityModulation {
            current_basis_points: Some(maturity_modulation),
            updated_at_timestamp_seconds: Some(self.env.now()),
        };
        println!(
            "{}Updating maturity modulation to {:#?}. Previously: {:#?}",
            log_prefix(),
            new_maturity_modulation,
            self.proto.maturity_modulation
        );

        // Store the new value.
        self.proto.maturity_modulation = Some(new_maturity_modulation);
    }

    /// Returns `true` if enough time has passed since the end of the last reward round.
    ///
    /// The end of the last reward round is recorded in self.latest_reward_event.
    ///
    /// The (current) length of a reward round is specified in
    /// self.nervous_system_parameters.voting_reward_parameters
    fn should_distribute_rewards(&self) -> bool {
        let now = self.env.now();

        let voting_rewards_parameters = match &self
            .nervous_system_parameters_or_panic()
            .voting_rewards_parameters
        {
            None => return false,
            Some(ok) => ok,
        };
        let seconds_since_last_reward_event = now.saturating_sub(
            self.latest_reward_event()
                .end_timestamp_seconds
                .unwrap_or_default(),
        );

        let round_duration_seconds = match voting_rewards_parameters.round_duration_seconds {
            Some(s) => s,
            None => {
                log!(
                    ERROR,
                    "round_duration_seconds unset:\n{:#?}",
                    voting_rewards_parameters,
                );
                return false;
            }
        };

        seconds_since_last_reward_event > round_duration_seconds
    }

    /// Creates a reward event.
    ///
    /// This method:
    /// * collects all proposals in state ReadyToSettle, that is, proposals that
    ///   can no longer accept votes for the purpose of rewards and that have
    ///   not yet been considered in a reward event
    /// * associates those proposals to the new reward event and cleans their ballots
    fn distribute_rewards(&mut self, supply: Tokens) {
        log!(INFO, "distribute_rewards. Supply: {:?}", supply);
        let now = self.env.now();

        // VotingRewardsParameters should always be set,
        // but we check and return early just in case.
        let voting_rewards_parameters = match &self
            .nervous_system_parameters_or_panic()
            .voting_rewards_parameters
        {
            Some(voting_rewards_parameters) => voting_rewards_parameters,
            None => {
                log!(
                    ERROR,
                    "distribute_rewards called even though \
                     voting_rewards_parameters not set.",
                );
                return;
            }
        };

        let round_duration_seconds = match voting_rewards_parameters.round_duration_seconds {
            Some(s) => s,
            None => {
                log!(
                    ERROR,
                    "round_duration_seconds not set:\n{:#?}",
                    voting_rewards_parameters,
                );
                return;
            }
        };
        // This guard is needed, because we'll divide by this amount shortly.
        if round_duration_seconds == 0 {
            // This is important, but emitting this every time will be spammy, because this gets
            // called during heartbeat.
            log!(
                ERROR,
                "round_duration_seconds ({}) is not positive. \
                 Therefore, we cannot calculate voting rewards.",
                round_duration_seconds,
            );
            return;
        }

        let reward_start_timestamp_seconds = self
            .latest_reward_event()
            .end_timestamp_seconds
            .unwrap_or_default();
        let new_rounds_count = now
            .saturating_sub(reward_start_timestamp_seconds)
            .saturating_div(round_duration_seconds);
        if new_rounds_count == 0 {
            // This may happen, in case consider_distributing_rewards was called
            // several times at almost the same time. This is
            // harmless, just abandon.
            return;
        }

        let considered_proposals: Vec<ProposalId> =
            self.ready_to_be_settled_proposal_ids().collect();
        // RewardEvents are generated every time. If there are no proposals to reward, the rewards
        // purse is rolled over via the total_available_e8s_equivalent field.

        // Log if we are about to "backfill" rounds that were missed.
        if new_rounds_count > 1 {
            log!(
                INFO,
                "Some reward distribution should have happened, but were missed. \
                 It is now {}. Whereas, latest_reward_event:\n{:#?}",
                now,
                self.latest_reward_event(),
            );
        }
        let reward_event_end_timestamp_seconds = new_rounds_count
            .saturating_mul(round_duration_seconds)
            .saturating_add(reward_start_timestamp_seconds);

        // What's going on here looks a little complex, but it's just a slightly
        // more advanced version of simple (i.e. non-compounding) interest. The
        // main embellishment is because we are calculating the reward purse
        // over possibly more than one reward round. The possibility of multiple
        // rounds is why we loop over rounds. Otherwise, it boils down to the
        // simple interest formula:
        //
        //   principal * rate * duration
        //
        // Here, the entire token supply is used as the "principal", and the
        // length of a reward round is used as the duration. The reward rate
        // varies from round to round, and is calculated using
        // VotingRewardsParameters::reward_rate_at.
        let rewards_purse_e8s = {
            let mut result = Decimal::from(
                self.latest_reward_event()
                    .e8s_equivalent_to_be_rolled_over(),
            );
            let supply = i2d(supply.get_e8s());

            for i in 1..=new_rounds_count {
                let seconds_since_genesis = round_duration_seconds
                    .saturating_mul(i)
                    .saturating_add(reward_start_timestamp_seconds)
                    .saturating_sub(self.proto.genesis_timestamp_seconds);

                let current_reward_rate = voting_rewards_parameters.reward_rate_at(
                    crate::reward::Instant::from_seconds_since_genesis(i2d(seconds_since_genesis)),
                );

                result += current_reward_rate * voting_rewards_parameters.round_duration() * supply;
            }

            result
        };
        debug_assert!(rewards_purse_e8s >= dec!(0), "{}", rewards_purse_e8s);
        // This will get assembled into the new RewardEvent at the end.
        let total_available_e8s_equivalent = Some(match u64::try_from(rewards_purse_e8s) {
            Ok(ok) => ok,
            Err(err) => {
                log!(
                    ERROR,
                    "Looks like the rewards purse ({}) overflowed u64: {}. \
                     Therefore, we stop the current attempt to distribute voting rewards.",
                    rewards_purse_e8s,
                    err,
                );
                return;
            }
        });

        // Add up reward shares based on voting power that was exercised.
        let mut neuron_id_to_reward_shares: HashMap<NeuronId, Decimal> = HashMap::new();
        for proposal_id in &considered_proposals {
            if let Some(proposal) = self.get_proposal_data(*proposal_id) {
                for (voter, ballot) in &proposal.ballots {
                    #[allow(clippy::blocks_in_conditions)]
                    if !Vote::try_from(ballot.vote)
                        .unwrap_or_else(|_| {
                            println!(
                                "{}Vote::from invoked with unexpected value {}.",
                                log_prefix(),
                                ballot.vote
                            );
                            Vote::Unspecified
                        })
                        .eligible_for_rewards()
                    {
                        continue;
                    }

                    match NeuronId::from_str(voter) {
                        Ok(neuron_id) => {
                            let reward_shares = i2d(ballot.voting_power);
                            *neuron_id_to_reward_shares
                                .entry(neuron_id)
                                .or_insert_with(|| dec!(0)) += reward_shares;
                        }
                        Err(e) => {
                            log!(
                                ERROR,
                                "Could not use voter {} to calculate total_voting_rights \
                                 since it's NeuronId was invalid. Underlying error: {:?}.",
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
        let total_reward_shares: Decimal = neuron_id_to_reward_shares.values().sum();
        debug_assert!(
            total_reward_shares >= dec!(0),
            "total_reward_shares: {} neuron_id_to_reward_shares: {:#?}",
            total_reward_shares,
            neuron_id_to_reward_shares,
        );

        // Because of rounding (and other shenanigans), it is possible that some
        // portion of this amount ends up not being actually distributed.
        let mut distributed_e8s_equivalent = 0_u64;
        // Now that we know the size of the pie (rewards_purse_e8s), and how
        // much of it each neuron is supposed to get (*_reward_shares), we now
        // proceed to actually handing out those rewards.
        if total_reward_shares == dec!(0) {
            log!(
                ERROR,
                "Warning: total_reward_shares is 0. Therefore, we skip increasing \
                 neuron maturity. neuron_id_to_reward_shares: {:#?}",
                neuron_id_to_reward_shares,
            );
        } else {
            for (neuron_id, neuron_reward_shares) in neuron_id_to_reward_shares {
                let neuron: &mut Neuron = match self.get_neuron_result_mut(&neuron_id) {
                    Ok(neuron) => neuron,
                    Err(err) => {
                        log!(
                            ERROR,
                            "Cannot find neuron {}, despite having voted with power {} \
                             in the considered reward period. The reward that should have been \
                             distributed to this neuron is simply skipped, so the total amount \
                             of distributed reward for this period will be lower than the maximum \
                             allowed. Underlying error: {:?}.",
                            neuron_id,
                            neuron_reward_shares,
                            err
                        );
                        continue;
                    }
                };

                // Dividing before multiplying maximizes our chances of success.
                let neuron_reward_e8s =
                    rewards_purse_e8s * (neuron_reward_shares / total_reward_shares);

                // Round down, and convert to u64.
                let neuron_reward_e8s = u64::try_from(neuron_reward_e8s).unwrap_or_else(|err| {
                    panic!(
                        "Calculating reward for neuron {:?}:\n\
                             neuron_reward_shares: {}\n\
                             rewards_purse_e8s: {}\n\
                             total_reward_shares: {}\n\
                             err: {}",
                        neuron_id,
                        neuron_reward_shares,
                        rewards_purse_e8s,
                        total_reward_shares,
                        err,
                    )
                });
                // If the neuron has auto-stake-maturity on, add the new maturity to the
                // staked maturity, otherwise add it to the un-staked maturity.
                if neuron.auto_stake_maturity.unwrap_or(false) {
                    neuron.staked_maturity_e8s_equivalent = Some(
                        neuron.staked_maturity_e8s_equivalent.unwrap_or(0) + neuron_reward_e8s,
                    );
                } else {
                    neuron.maturity_e8s_equivalent += neuron_reward_e8s;
                }
                distributed_e8s_equivalent += neuron_reward_e8s;
            }
        }
        // Freeze distributed_e8s_equivalent, now that we are done handing out rewards.
        let distributed_e8s_equivalent = distributed_e8s_equivalent;
        // Because we used floor to round rewards to integers (and everything is
        // non-negative), it should be that the amount distributed is not more
        // than the original purse.
        debug_assert!(
            i2d(distributed_e8s_equivalent) <= rewards_purse_e8s,
            "rewards distributed ({}) > purse ({})",
            distributed_e8s_equivalent,
            rewards_purse_e8s,
        );

        // This field is deprecated. People should really use end_timestamp_seconds
        // instead. This value can still be used if round duration is not changed.
        let new_reward_event_round = self.latest_reward_event().round + new_rounds_count;
        // Settle proposals.
        for pid in &considered_proposals {
            // Before considering a proposal for reward, it must be fully processed --
            // because we're about to clear the ballots, so no further processing will be
            // possible.
            self.process_proposal(pid.id);

            let p = match self.get_proposal_data_mut(*pid) {
                Some(p) => p,
                None => {
                    log!(ERROR,
                        "Cannot find proposal {}, despite it being considered for rewards distribution.",
                        pid.id
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

            if p.status() == ProposalDecisionStatus::Open {
                log!(
                    ERROR,
                    "Proposal {} was considered for reward distribution despite \
                     being open. We will now force the proposal's status to be Rejected.",
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
                    ProposalDecisionStatus::Rejected,
                    "Failed to force ProposalData status to become Rejected. p:\n{:#?}",
                    p,
                );
            }

            // This is where the proposal becomes Settled, at least in the eyes
            // of the ProposalData::reward_status method.
            p.reward_event_end_timestamp_seconds = Some(reward_event_end_timestamp_seconds);
            p.reward_event_round = new_reward_event_round;

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
            round: new_reward_event_round,
            actual_timestamp_seconds: now,
            settled_proposals: considered_proposals,
            distributed_e8s_equivalent,
            end_timestamp_seconds: Some(reward_event_end_timestamp_seconds),
            rounds_since_last_distribution: Some(new_rounds_count),
            total_available_e8s_equivalent,
        })
    }

    /// Checks if there is a pending upgrade.
    fn should_check_upgrade_status(&self) -> bool {
        self.proto.pending_version.is_some()
    }

    fn can_finalize_disburse_maturity(&self) -> bool {
        let finalizing_disburse_maturity = self.proto.is_finalizing_disburse_maturity;
        finalizing_disburse_maturity.is_none() || !finalizing_disburse_maturity.unwrap()
    }

    /// Checks if pending upgrade is complete and either updates deployed_version
    /// or clears pending_upgrade if beyond the limit.
    async fn check_upgrade_status(&mut self) {
        // This expect is safe because we only call this after checking exactly that condition in
        // should_check_upgrade_status
        let upgrade_in_progress =
            self.proto.pending_version.as_ref().expect(
                "There must be pending_version or should_check_upgrade_status returns false",
            );

        if upgrade_in_progress.target_version.is_none() {
            // If we have an upgrade_in_progress with no target_version, we are in an unexpected
            // situation. We recover to workable state by marking upgrade as failed.

            let msg = "No target_version set for upgrade_in_progress. This should be impossible. \
                Clearing upgrade_in_progress state and marking proposal failed to unblock further upgrades.";
            self.fail_sns_upgrade_to_next_version_proposal(
                upgrade_in_progress.proposal_id,
                GovernanceError::new_with_message(ErrorType::PreconditionFailed, msg),
            );

            return;
        }

        // Pre-checks finished, we now extract needed variables.
        let target_version = upgrade_in_progress.target_version.as_ref().unwrap().clone();
        let mark_failed_at = upgrade_in_progress.mark_failed_at_seconds;
        let proposal_id = upgrade_in_progress.proposal_id;

        // Mark the check as active before async call.
        self.proto
            .pending_version
            .as_mut()
            .unwrap()
            .checking_upgrade_lock += 1;

        let lock = self
            .proto
            .pending_version
            .as_ref()
            .unwrap()
            .checking_upgrade_lock;

        if lock > 1000 {
            let error =
                "Too many attempts to check upgrade without success.  Marking upgrade failed.";

            self.fail_sns_upgrade_to_next_version_proposal(
                proposal_id,
                GovernanceError::new_with_message(ErrorType::External, error),
            );
            return;
        }

        if lock > 1 {
            return;
        }

        let running_version: Result<Version, String> =
            get_running_version(&*self.env, self.proto.root_canister_id_or_panic()).await;

        // Mark the check as inactive after async call.
        self.proto
            .pending_version
            .as_mut()
            .unwrap()
            .checking_upgrade_lock = 0;
        // We cannot panic or we will get stuck with "checking_upgrade_lock" set to true.  We log
        // the issue and return so the next check can be performed.
        let mut running_version = match running_version {
            Ok(r) => r,
            Err(message) => {
                // Always log this, even if we are not yet marking as failed.
                log!(ERROR, "Could not get running version of SNS: {}", message);

                if self.env.now() > mark_failed_at {
                    let error = format!(
                        "Upgrade marked as failed at {} seconds from genesis. \
                             Governance could not determine running version from root: {}. \
                             Setting upgrade to failed to unblock retry.",
                        self.env.now(),
                        message,
                    );
                    self.fail_sns_upgrade_to_next_version_proposal(
                        proposal_id,
                        GovernanceError::new_with_message(ErrorType::External, error),
                    );
                }
                return;
            }
        };

        // In this case, we do not have a running archive, so we just clone the value so the check
        // does not fail on that account.
        if running_version.archive_wasm_hash.is_empty() {
            running_version
                .archive_wasm_hash
                .clone_from(&target_version.archive_wasm_hash);
        }

        let deployed_version = match self.proto.deployed_version.clone() {
            None => {
                let error = format!(
                    "Upgrade marked as failed at {} seconds from genesis. \
                Governance had no recorded deployed_version.  \
                Setting it to currently running version and failing upgrade.",
                    self.env.now(),
                );

                self.proto.deployed_version = Some(running_version);
                self.fail_sns_upgrade_to_next_version_proposal(
                    proposal_id,
                    GovernanceError::new_with_message(ErrorType::PreconditionFailed, error),
                );
                return;
            }
            Some(version) => version,
        };

        let expected_changes = deployed_version.changes_against(&target_version);

        match running_version.version_has_expected_hashes(&expected_changes) {
            Ok(_) => {
                log!(
                    INFO,
                    "Upgrade marked successful at {} from genesis.  New Version: {:?}",
                    self.env.now(),
                    target_version
                );
                self.set_proposal_execution_status(proposal_id, Ok(()));
                self.proto.deployed_version = Some(target_version);
                self.proto.pending_version = None;
            }
            Err(errors) => {
                // We are past mark_failed_at_seconds.
                if self.env.now() > mark_failed_at {
                    let error = format!(
                        "Upgrade marked as failed at {} seconds from genesis. \
                Running system version does not match expected state.\n{:?}",
                        self.env.now(),
                        errors
                    );

                    self.fail_sns_upgrade_to_next_version_proposal(
                        proposal_id,
                        GovernanceError::new_with_message(ErrorType::External, error),
                    );
                }
            }
        }
    }

    // This method sets internal state to remove pending_version and sets the proposal status to
    // an error for an UpgradeSnsToNextVersion actions failure.  This unblocks further upgrade proposals.
    fn fail_sns_upgrade_to_next_version_proposal(
        &mut self,
        proposal_id: u64,
        error: GovernanceError,
    ) {
        log!(ERROR, "{}", error.error_message);
        let result = Err(error);
        self.set_proposal_execution_status(proposal_id, result);
        self.proto.pending_version = None;
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

    /// Fails an upgrade proposal that was Adopted but not Executed or Failed by the deadline.
    pub fn fail_stuck_upgrade_in_progress(
        &mut self,
        _: FailStuckUpgradeInProgressRequest,
    ) -> FailStuckUpgradeInProgressResponse {
        let pending_version = match self.proto.pending_version.as_ref() {
            None => return FailStuckUpgradeInProgressResponse {},
            Some(pending_version) => pending_version,
        };

        // Maybe, we should look at the checking_upgrade_lock field and only
        // proceed if it is false, or the request has force set to true.

        let now = self.env.now();

        if now > pending_version.mark_failed_at_seconds {
            let error = format!(
                "Upgrade marked as failed at {} seconds from UNIX epoch. \
                Governance upgrade was manually aborted by calling fail_stuck_upgrade_in_progress \
                after mark_failed_at_seconds ({}). Setting upgrade to failed to unblock retry.",
                now, pending_version.mark_failed_at_seconds
            );

            self.fail_sns_upgrade_to_next_version_proposal(
                pending_version.proposal_id,
                GovernanceError::new_with_message(ErrorType::External, error),
            );
        }

        FailStuckUpgradeInProgressResponse {}
    }

    /// Checks whether new neurons can be added or whether the maximum number of neurons,
    /// as defined in the nervous system parameters, has already been reached.
    fn check_neuron_population_can_grow(&self) -> Result<(), GovernanceError> {
        let max_number_of_neurons = self
            .nervous_system_parameters_or_panic()
            .max_number_of_neurons
            .expect("NervousSystemParameters must have max_number_of_neurons");

        if (self.proto.neurons.len() as u64) + 1 > max_number_of_neurons {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Cannot add neuron. Max number of neurons reached.",
            ));
        }

        Ok(())
    }

    /// Gets the raw proposal data
    fn get_proposal_data(&self, pid: impl Into<ProposalId>) -> Option<&ProposalData> {
        self.proto.proposals.get(&pid.into().id)
    }

    /// Gets the raw proposal data as a mut
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

    /// Updates a neuron in the list of neurons.
    ///
    /// Preconditions:
    /// - the given `neuron_id` already exists in `self.proto.neurons`
    /// - the permissions are not changed (it's easy to update permissions
    ///   via `manage_neuron` and doing it here would require updating
    ///   `principal_to_neuron_ids_index`)
    /// - the followees are not changed (it's easy to update followees
    ///   via `manage_neuron` and doing it here would require updating
    ///   `function_followee_index`)
    #[cfg(feature = "test")]
    pub fn update_neuron(&mut self, neuron: Neuron) -> Result<(), GovernanceError> {
        let neuron_id = &neuron.id.as_ref().expect("Neuron must have a NeuronId");

        // Must clobber an existing neuron.
        let old_neuron = match self.proto.neurons.get_mut(&neuron_id.to_string()) {
            Some(n) => n,
            None => {
                return Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!(
                        "Cannot update neuron. There is no neuron with id: {}",
                        neuron_id
                    ),
                ));
            }
        };

        // Must NOT clobber permissions.
        if old_neuron.permissions != neuron.permissions {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Cannot update neuron's permissions via update_neuron.".to_string(),
            ));
        }

        // Must NOT clobber followees.
        if old_neuron.followees != neuron.followees {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Cannot update neuron's followees via update_neuron.".to_string(),
            ));
        }

        // Now that neuron has been validated, update old_neuron.
        *old_neuron = neuron;

        Ok(())
    }

    /// Gets the metadata describing the SNS.
    pub fn get_metadata(&self, _request: &GetMetadataRequest) -> GetMetadataResponse {
        let sns_metadata = self
            .proto
            .sns_metadata
            .as_ref()
            .expect("Expected the SnsMetadata to exist");

        GetMetadataResponse {
            logo: sns_metadata.logo.clone(),
            url: sns_metadata.url.clone(),
            name: sns_metadata.name.clone(),
            description: sns_metadata.description.clone(),
        }
    }

    /// Gets the config file used to set up the SNS.
    pub fn get_sns_initialization_parameters(
        &self,
        _request: &GetSnsInitializationParametersRequest,
    ) -> GetSnsInitializationParametersResponse {
        GetSnsInitializationParametersResponse {
            sns_initialization_parameters: self.proto.sns_initialization_parameters.clone(),
        }
    }

    pub fn get_maturity_modulation(
        &self,
        _: GetMaturityModulationRequest,
    ) -> GetMaturityModulationResponse {
        GetMaturityModulationResponse {
            maturity_modulation: self.proto.maturity_modulation.clone(),
        }
    }

    #[cfg(feature = "test")]
    pub fn add_maturity(
        &mut self,
        add_maturity_request: AddMaturityRequest,
    ) -> AddMaturityResponse {
        let AddMaturityRequest { id, amount_e8s } = add_maturity_request;
        let id = id.expect("AddMaturityRequest::id is required");
        let amount_e8s = amount_e8s.expect("AddMaturityRequest::amount_e8s is required");

        // Here, we're getting a mutable reference without a lock, but it's
        // okay because this is is only callable from test code
        let neuron = self.get_neuron_mut(&id).expect("neuron did not exist");

        neuron.maturity_e8s_equivalent = neuron.maturity_e8s_equivalent.saturating_add(amount_e8s);

        AddMaturityResponse {
            new_maturity_e8s: Some(neuron.maturity_e8s_equivalent),
        }
    }

    #[cfg(feature = "test")]
    pub async fn mint_tokens(
        &mut self,
        mint_tokens_request: MintTokensRequest,
    ) -> MintTokensResponse {
        self.ledger
            .transfer_funds(
                mint_tokens_request.amount_e8s(),
                0,    // Minting transfer don't pay a fee
                None, // This is a minting transfer, no 'from' account is needed
                mint_tokens_request
                    .recipient
                    .expect("recipient must be set")
                    .try_into()
                    .unwrap(), // The account of the neuron on the ledger
                self.env.random_u64(), // Random memo(nonce) for the ledger's transaction
            )
            .await
            .unwrap();
        MintTokensResponse {}
    }

    /// Returns the ledger account identifier of the minting account on the ledger canister
    /// (currently an account controlled by the governance canister).
    pub fn governance_minting_account(&self) -> Account {
        Account {
            owner: self.env.canister_id().get().0,
            subaccount: None,
        }
    }

    /// Returns the ledger account identifier of a given neuron, where the neuron is specified by
    /// its subaccount.
    pub fn neuron_account_id(&self, subaccount: Subaccount) -> Account {
        Account {
            owner: self.env.canister_id().get().0,
            subaccount: Some(subaccount),
        }
    }
}

// TODO(NNS1-2835): Remove this const after changes published.
thread_local! {
    static ATTEMPTED_FIXING_MEMORY_ALLOCATIONS: RefCell<bool> = const { RefCell::new(false) };
}

fn err_if_another_upgrade_is_in_progress(
    id_to_proposal_data: &BTreeMap</* proposal ID */ u64, ProposalData>,
    executing_proposal_id: u64,
) -> Result<(), GovernanceError> {
    let upgrade_action_ids: [u64; 3] = [
        (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into(),
        (&Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion::default())).into(),
        (&Action::ManageLedgerParameters(ManageLedgerParameters::default())).into(),
    ];

    for (other_proposal_id, proposal_data) in id_to_proposal_data {
        if *other_proposal_id == executing_proposal_id {
            continue;
        }

        if !upgrade_action_ids.contains(&proposal_data.action) {
            continue;
        }

        if proposal_data.status() != ProposalDecisionStatus::Adopted {
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
#[derive(Copy, Clone, Eq, PartialEq, Debug, candid::CandidType, serde::Deserialize)]
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

    Ok(NeuronId::from(bytes_to_subaccount(
        &manage_neuron.subaccount,
    )?))
}

fn get_neuron_id_from_memo_and_controller(
    memo_and_controller: &MemoAndController,
    caller: &PrincipalId,
) -> NeuronId {
    let controller = memo_and_controller.controller.unwrap_or(*caller);
    let memo = memo_and_controller.memo;
    NeuronId::from(ledger::compute_neuron_staking_subaccount_bytes(
        controller, memo,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pb::v1::{
            governance::SnsMetadata,
            manage_neuron_response,
            nervous_system_function::{FunctionType, GenericNervousSystemFunction},
            neuron, Account as AccountProto, Motion, NeuronPermissionType, ProposalData,
            ProposalId, Tally, UpgradeSnsControlledCanister, UpgradeSnsToNextVersion,
            VotingRewardsParameters, WaitForQuietState,
        },
        reward,
        sns_upgrade::{
            CanisterSummary, GetNextSnsVersionRequest, GetNextSnsVersionResponse,
            GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse, GetWasmRequest,
            GetWasmResponse, SnsCanisterType, SnsVersion, SnsWasm,
        },
        types::test_helpers::NativeEnvironment,
    };
    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use candid::Principal;
    use futures::{join, FutureExt};
    use ic_canister_client_sender::Sender;
    use ic_nervous_system_clients::{
        canister_id_record::CanisterIdRecord,
        canister_status::{
            CanisterStatusResultFromManagementCanister, CanisterStatusResultV2, CanisterStatusType,
        },
    };
    use ic_nervous_system_common::{
        assert_is_err, assert_is_ok, cmc::FakeCmc, ledger::compute_neuron_staking_subaccount_bytes,
        E8, ONE_DAY_SECONDS, START_OF_2022_TIMESTAMP_SECONDS,
    };
    use ic_nervous_system_common_test_keys::{
        TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL, TEST_USER1_KEYPAIR,
    };
    use ic_nns_constants::SNS_WASM_CANISTER_ID;
    use ic_sns_governance_token_valuation::{Token, ValuationFactors};
    use ic_sns_test_utils::itest_helpers::UserInfo;
    use ic_test_utilities_types::ids::canister_test_id;
    use maplit::{btreemap, btreeset};
    use pretty_assertions::assert_eq;
    use proptest::prelude::{prop_assert, proptest};
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, SystemTime},
    };

    mod fail_stuck_upgrade_in_progress_tests;

    struct DoNothingLedger {}

    #[async_trait]
    impl ICRC1Ledger for DoNothingLedger {
        async fn transfer_funds(
            &self,
            _amount_e8s: u64,
            _fee_e8s: u64,
            _from_subaccount: Option<Subaccount>,
            _to: Account,
            _memo: u64,
        ) -> Result<u64, NervousSystemError> {
            unimplemented!();
        }

        async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
            unimplemented!()
        }

        async fn account_balance(&self, _account: Account) -> Result<Tokens, NervousSystemError> {
            unimplemented!()
        }

        fn canister_id(&self) -> CanisterId {
            unimplemented!()
        }
    }

    struct AlwaysSucceedingLedger {}

    #[async_trait]
    impl ICRC1Ledger for AlwaysSucceedingLedger {
        async fn transfer_funds(
            &self,
            _amount_e8s: u64,
            _fee_e8s: u64,
            _from_subaccount: Option<Subaccount>,
            _to: Account,
            _memo: u64,
        ) -> Result<u64, NervousSystemError> {
            Ok(0)
        }

        async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
            Ok(Tokens::default())
        }

        async fn account_balance(&self, _account: Account) -> Result<Tokens, NervousSystemError> {
            Ok(Tokens::default())
        }

        fn canister_id(&self) -> CanisterId {
            CanisterId::from_u64(42)
        }
    }

    fn basic_governance_proto() -> GovernanceProto {
        GovernanceProto {
            root_canister_id: Some(PrincipalId::new_user_test_id(53)),
            ledger_canister_id: Some(PrincipalId::new_user_test_id(228)),
            swap_canister_id: Some(PrincipalId::new_user_test_id(15)),

            parameters: Some(NervousSystemParameters::with_default_values()),
            mode: governance::Mode::Normal as i32,
            sns_metadata: Some(SnsMetadata {
                logo: Some("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string()),
                name: Some("ServiceNervousSystem-Test".to_string()),
                description: Some("A project to spin up a ServiceNervousSystem".to_string()),
                url: Some("https://internetcomputer.org".to_string()),
            }),
            ..Default::default()
        }
    }

    const TRANSITION_ROUND_COUNT: u64 = 42;
    const BASE_VOTING_REWARDS_PARAMETERS: VotingRewardsParameters = VotingRewardsParameters {
        round_duration_seconds: Some(7 * 24 * 60 * 60), // 1 week
        reward_rate_transition_duration_seconds: Some(TRANSITION_ROUND_COUNT * 7 * 24 * 60 * 60), // 42 weeks
        initial_reward_rate_basis_points: Some(200), // 2%
        final_reward_rate_basis_points: Some(100),   // 1%
    };

    lazy_static! {
        static ref A_NEURON_PRINCIPAL_ID: PrincipalId = PrincipalId::new_user_test_id(956560);

        static ref A_NEURON_ID: NeuronId = NeuronId::from(
            compute_neuron_staking_subaccount_bytes(*A_NEURON_PRINCIPAL_ID, /* nonce = */ 0),
        );

        static ref A_NEURON: Neuron = Neuron {
            id: Some(A_NEURON_ID.clone()),
            permissions: vec![NeuronPermission {
                principal: Some(*A_NEURON_PRINCIPAL_ID),
                permission_type: NeuronPermissionType::all(),
            }],
            cached_neuron_stake_e8s: 100 * E8,
            aging_since_timestamp_seconds: START_OF_2022_TIMESTAMP_SECONDS,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(365 * ONE_DAY_SECONDS)),
            voting_power_percentage_multiplier: 100,
            ..Default::default()
        };

        static ref A_MOTION_PROPOSAL: Proposal = Proposal {
            title: "This Proposal is Wunderbar!".to_string(),
            summary: "This will solve all of your problems.".to_string(),
            url: "https://www.example.com/some/path".to_string(),
            action: Some(Action::Motion(Motion {
                motion_text: "See the summary.".to_string(),
            }))
        };

        static ref TEST_ROOT_CANISTER_ID: CanisterId = CanisterId::from(500);
        static ref TEST_GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from(501);
        static ref TEST_LEDGER_CANISTER_ID: CanisterId = CanisterId::from(502);
        static ref TEST_SWAP_CANISTER_ID: CanisterId = CanisterId::from(503);
        static ref TEST_ARCHIVES_CANISTER_IDS: Vec<CanisterId> =
            vec![CanisterId::from(504), CanisterId::from(505)];
        static ref TEST_INDEX_CANISTER_ID: CanisterId = CanisterId::from(506);
        static ref TEST_DAPP_CANISTER_IDS: Vec<CanisterId> = vec![CanisterId::from(600)];
    }

    #[test]
    fn fixtures_are_valid() {
        assert_is_ok!(ValidGovernanceProto::try_from(basic_governance_proto()));
        assert_is_ok!(BASE_VOTING_REWARDS_PARAMETERS.validate());
    }

    #[test]
    fn unspecified_mode_is_invalid() {
        let g = GovernanceProto {
            mode: governance::Mode::Unspecified as i32,
            ..basic_governance_proto()
        };
        assert!(
            ValidGovernanceProto::try_from(g.clone()).is_err(),
            "{:#?}",
            g
        );
    }

    #[test]
    fn garbage_mode_is_invalid() {
        let g = GovernanceProto {
            mode: 0xDEADBEF,
            ..basic_governance_proto()
        };
        assert!(
            ValidGovernanceProto::try_from(g.clone()).is_err(),
            "{:#?}",
            g
        );
    }

    #[tokio::test]
    async fn test_perform_transfer_sns_treasury_funds_execution_fails_when_another_call_is_in_progress(
    ) {
        // Step 0: Define helpers.

        // This expects a transfer_funds call. That call takes 10 ms to complete. This allows us to
        // make concurrent calls to code under test.
        struct StubLedger {}

        #[async_trait]
        impl ICRC1Ledger for StubLedger {
            async fn transfer_funds(
                &self,
                _amount_e8s: u64,
                _fee_e8s: u64,
                _from_subaccount: Option<Subaccount>,
                _to: Account,
                _memo: u64,
            ) -> Result<u64, NervousSystemError> {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Ok(1)
            }

            // The rest are unimplemented.

            async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
                unimplemented!()
            }

            async fn account_balance(
                &self,
                _account: Account,
            ) -> Result<Tokens, NervousSystemError> {
                unimplemented!()
            }

            fn canister_id(&self) -> CanisterId {
                unimplemented!()
            }
        }

        let governance_proto = basic_governance_proto();
        let mut governance = Governance::new(
            ValidGovernanceProto::try_from(governance_proto).unwrap(),
            Box::new(NativeEnvironment::new(None)),
            Box::new(DoNothingLedger {}), // SNS token ledger.
            Box::new(StubLedger {}),      // ICP ledger.
            Box::new(FakeCmc::new()),
        );

        // Step 2: Run code under test.

        // No need to be aware of the particular values in here; they should not affect the outcome
        // of this test.
        let transfer_sns_treasury_funds = TransferSnsTreasuryFunds {
            amount_e8s: 272,
            from_treasury: TransferFrom::IcpTreasury as i32,
            to_principal: Some(PrincipalId::new_user_test_id(181_931_560)),
            to_subaccount: None,
            memo: None,
        };
        let valuation = Valuation {
            token: Token::Icp,
            account: Account {
                owner: Principal::from(PrincipalId::new_user_test_id(104_622_969)),
                subaccount: None,
            },
            timestamp: SystemTime::now(),
            valuation_factors: ValuationFactors {
                tokens: Decimal::from(314),
                icps_per_token: Decimal::from(2),
                xdrs_per_icp: Decimal::from(5),
            },
        };

        // This lets us (later) make a second manage_neuron method call
        // while one is in flight, which is essential for this test.
        let raw_governance = &mut governance as *mut Governance;

        let (result_1, result_2) = join! {
            // Call the code under test with 0 delay.
            governance.perform_transfer_sns_treasury_funds(
                7, // proposal_id,
                Ok(valuation),
                &transfer_sns_treasury_funds,
            ),

            // Make the same call, except this one is delayed by 5 ms. Later, we assert that this
            // fails with the right Err.
            async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                unsafe {
                    raw_governance.as_mut().unwrap().perform_transfer_sns_treasury_funds(
                        7, // proposal_id,
                        Ok(valuation),
                        &transfer_sns_treasury_funds,
                    )
                    .await
                }
            }
        };

        // Step 3: Inspect results.

        // First call works.
        assert_eq!(result_1, Ok(()));

        // Second call fails.
        let err = result_2.unwrap_err();
        let GovernanceError {
            error_type,
            error_message,
        } = &err;

        assert_eq!(
            ErrorType::try_from(*error_type),
            Ok(ErrorType::PreconditionFailed),
            "{:#?}",
            err
        );

        let error_message = error_message.to_lowercase();
        for term in [
            "another",
            "transfersnstreasuryfunds",
            "7",
            "already",
            "in progress",
        ] {
            assert!(error_message.contains(term), "{:#?}", err);
        }
    }

    #[tokio::test]
    async fn test_neuron_operations_exclude_one_another() {
        // Step 0: Define helpers.
        struct TestLedger {
            transfer_funds_arrived: Arc<tokio::sync::Notify>,
            transfer_funds_continue: Arc<tokio::sync::Notify>,
        }

        #[async_trait]
        impl ICRC1Ledger for TestLedger {
            async fn transfer_funds(
                &self,
                _amount_e8s: u64,
                _fee_e8s: u64,
                _from_subaccount: Option<Subaccount>,
                _to: Account,
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
                _account: Account,
            ) -> Result<Tokens, NervousSystemError> {
                Ok(Tokens::new(1, 0).unwrap())
            }

            fn canister_id(&self) -> CanisterId {
                unimplemented!()
            }
        }

        let local_set = tokio::task::LocalSet::new(); // Because we are working with !Send data.
        local_set
            .run_until(async move {
                // Step 1: Prepare the world.
                let user = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
                let principal_id = user.sender.get_principal_id();
                // work around the fact that the type inside UserInfo is not the same as the type in this crate
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
                    Box::<NativeEnvironment>::default(),
                    Box::new(TestLedger {
                        transfer_funds_arrived: transfer_funds_arrived.clone(),
                        transfer_funds_continue: transfer_funds_continue.clone(),
                    }),
                    Box::new(DoNothingLedger {}),
                    Box::new(FakeCmc::new()),
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
                        to_account: Some(AccountProto {
                            owner: Some(user.sender.get_principal_id()),
                            subaccount: None,
                        }),
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
    fn test_governance_proto_must_have_swap_canister_ids() {
        let mut proto = basic_governance_proto();
        proto.swap_canister_id = None;
        assert!(ValidGovernanceProto::try_from(proto).is_err());
    }

    #[test]
    fn test_governance_proto_must_have_parameters() {
        let mut proto = basic_governance_proto();
        proto.parameters = None;
        assert!(ValidGovernanceProto::try_from(proto).is_err());
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
    fn swap_canister_id_is_required_when_mode_is_pre_initialization_swap() {
        let proto = GovernanceProto {
            mode: governance::Mode::PreInitializationSwap as i32,
            swap_canister_id: None,
            ..basic_governance_proto()
        };

        let r = ValidGovernanceProto::try_from(proto.clone());
        match r {
            Ok(_ok) => panic!(
                "Invalid Governance proto, but wasn't rejected: {:#?}",
                proto
            ),
            Err(err) => {
                for key_word in ["swap_canister_id", "populate"] {
                    assert!(
                        err.contains(key_word),
                        "{:#?} not present in the error: {:#?}",
                        key_word,
                        err
                    );
                }
            }
        }
    }

    #[test]
    fn test_governance_proto_neurons_voting_power_multiplier_in_expected_range() {
        let mut proto = basic_governance_proto();
        proto.neurons = btreemap! {
            "A".to_string() => Neuron {
                voting_power_percentage_multiplier: 0,
                ..Default::default()
            },
            "B".to_string() => Neuron {
                voting_power_percentage_multiplier: 50,
                ..Default::default()
            },
            "C".to_string() => Neuron {
                voting_power_percentage_multiplier: 100,
                ..Default::default()
            },
        };
        assert!(ValidGovernanceProto::try_from(proto.clone()).is_ok());
        proto.neurons.insert(
            "D".to_string(),
            Neuron {
                voting_power_percentage_multiplier: 101,
                ..Default::default()
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
        fn test_evaluate_wait_for_quiet_doesnt_shorten_deadline(
            initial_voting_period_seconds in 3600u64..604_800,
            wait_for_quiet_deadline_increase_seconds in 0u64..604_800,
            now_seconds in 0u64..1_000_000,
            old_yes in 0u64..1_000_000,
            old_no in 0u64..1_000_000,
            old_total in 10_000_000u64..100_000_000,
            yes_votes in 0u64..1_000_000,
            no_votes in 0u64..1_000_000,
        ) {
            let proposal_creation_timestamp_seconds = 0; // initial timestamp is always 0
            let mut proposal = ProposalData {
                id: Some(ProposalId { id: 0 }),
                proposal_creation_timestamp_seconds,
                wait_for_quiet_state: Some(WaitForQuietState {
                    current_deadline_timestamp_seconds: initial_voting_period_seconds,
                }),
                initial_voting_period_seconds,
                wait_for_quiet_deadline_increase_seconds,
                ..Default::default()
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
                &old_tally,
                &new_tally,
            );
            let new_deadline = proposal
                .wait_for_quiet_state
                .unwrap()
                .current_deadline_timestamp_seconds;
            prop_assert!(new_deadline >= initial_voting_period_seconds);
        }
    }

    proptest! {
        /// This test ensures that the wait-for-quiet
        /// deadline is increased the correct amount when there is a flip
        /// at the end of a proposal's lifetime.
        #[test]
        fn test_evaluate_wait_for_quiet_flip_at_end(
            initial_voting_period_seconds in 3600u64..604_800,
            wait_for_quiet_deadline_increase_seconds in 0u64..604_800,
            no_votes in 0u64..1_000_000,
            yes_votes_margin in 1u64..1_000_000,
            total in 10_000_000u64..100_000_000,
    ) {
            let now_seconds = initial_voting_period_seconds;
            let mut proposal = ProposalData {
                id: Some(ProposalId { id: 0 }),
                wait_for_quiet_state: Some(WaitForQuietState {
                    current_deadline_timestamp_seconds: initial_voting_period_seconds,
                }),
                initial_voting_period_seconds,
                wait_for_quiet_deadline_increase_seconds,
                ..Default::default()
            };
            let old_tally = Tally {
                timestamp_seconds: now_seconds,
                yes: 0,
                no: no_votes,
                total,
            };
            let new_tally = Tally {
                timestamp_seconds: now_seconds,
                yes: no_votes + yes_votes_margin,
                no: no_votes,
                total,
            };
            proposal.evaluate_wait_for_quiet(
                now_seconds,
                &old_tally,
                &new_tally,
            );
            let new_deadline = proposal
                .wait_for_quiet_state
                .unwrap()
                .current_deadline_timestamp_seconds;
            prop_assert!(new_deadline == initial_voting_period_seconds + wait_for_quiet_deadline_increase_seconds);
        }
    }

    proptest! {
        /// This test ensures that the wait-for-quiet
        /// deadline is increased the correct amount when there is a flip
        /// at any point during of a proposal's lifetime.
        #[test]
        fn test_evaluate_wait_for_quiet_flip(
            initial_voting_period_seconds in 3600u64..604_800,
            wait_for_quiet_deadline_increase_seconds in 0u64..604_800,
            no_votes in 0u64..1_000_000,
            yes_votes_margin in 1u64..1_000_000,
            total in 10_000_000u64..100_000_000,
            time in 0f32..=1f32,
    ) {
            // To make the math easy, we'll do the same trick we did in the previous test, where increase the `adjusted_wait_for_quiet_deadline_increase_seconds`
            // by the smallest time where any flip in the vote will cause a deadline increase.
            let adjusted_wait_for_quiet_deadline_increase_seconds = wait_for_quiet_deadline_increase_seconds + (initial_voting_period_seconds + 1) / 2;
            // We'll also use the `time` parameter to tell us what fraction of the `initial_voting_period_seconds` to test at.
            let now_seconds = (time * initial_voting_period_seconds as f32) as u64;
            let mut proposal = ProposalData {
                id: Some(ProposalId { id: 0 }),
                wait_for_quiet_state: Some(WaitForQuietState {
                    current_deadline_timestamp_seconds: initial_voting_period_seconds,
                }),
                initial_voting_period_seconds,
                wait_for_quiet_deadline_increase_seconds: adjusted_wait_for_quiet_deadline_increase_seconds,
                ..Default::default()
            };
            let old_tally = Tally {
                timestamp_seconds: now_seconds,
                yes: 0,
                no: no_votes,
                total,
            };
            let new_tally = Tally {
                timestamp_seconds: now_seconds,
                yes: no_votes + yes_votes_margin,
                no: no_votes,
                total,
            };
            proposal.evaluate_wait_for_quiet(
                now_seconds,
                &old_tally,
                &new_tally,
            );
            let new_deadline = proposal
                .wait_for_quiet_state
                .unwrap()
                .current_deadline_timestamp_seconds;
            dbg!(new_deadline , initial_voting_period_seconds + wait_for_quiet_deadline_increase_seconds + (now_seconds + 1) / 2);
            prop_assert!(new_deadline == initial_voting_period_seconds + wait_for_quiet_deadline_increase_seconds + (now_seconds + 1) / 2);
        }
    }

    // A helper function to execute each proposal.
    fn execute_proposal(governance: &mut Governance, proposal_id: u64) -> ProposalData {
        governance.process_proposal(proposal_id);

        let now = std::time::Instant::now;

        let start = now();
        // In practice, the exit condition of the following loop occurs in much
        // less than 1 s (on my Macbook Pro 2019 Intel). The reason for this
        // generous limit is twofold: 1. avoid flakes in CI, while at the same
        // time 2. do not run forever if something goes wrong.
        let give_up = || now() < start + std::time::Duration::from_secs(30);

        loop {
            let result = governance
                .get_proposal(&GetProposal {
                    proposal_id: Some(ProposalId { id: proposal_id }),
                })
                .result
                .unwrap();
            let proposal_data = match result {
                get_proposal_response::Result::Proposal(p) => p,
                _ => panic!("get_proposal result: {:#?}", result),
            };

            let upgrade_sns_action_id = 7;

            // If the proposal is an SNS upgrade action, it won't move to the "executed" state in
            // this env (non-canister env), hence return.
            if proposal_data.status().is_final() || proposal_data.action == upgrade_sns_action_id {
                break proposal_data;
            }

            if give_up() {
                panic!("Proposal took too long to terminate (in the failed state).")
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    fn canister_status_for_test(
        module_hash: Vec<u8>,
        status: CanisterStatusType,
    ) -> CanisterStatusResultV2 {
        CanisterStatusResultV2::from(canister_status_from_management_canister_for_test(
            module_hash,
            status,
        ))
    }

    fn canister_status_from_management_canister_for_test(
        module_hash: Vec<u8>,
        status: CanisterStatusType,
    ) -> CanisterStatusResultFromManagementCanister {
        let module_hash = Some(module_hash);

        CanisterStatusResultFromManagementCanister {
            status,
            module_hash,
            ..Default::default()
        }
    }

    #[should_panic]
    #[test]
    fn test_disallow_set_mode_not_normal() {
        // Step 1: Prepare the world, i.e. Governance.
        let mut governance = Governance::new(
            GovernanceProto {
                mode: governance::Mode::Normal as i32,
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::<NativeEnvironment>::default(),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );
        let swap_canister_id = governance.proto.swap_canister_id_or_panic();

        // Step 2: Run code under test.
        governance.set_mode(
            governance::Mode::PreInitializationSwap as i32,
            swap_canister_id.into(),
        );

        // Step 3: Inspect result(s). This is taken care of by #[should_panic]
    }

    #[tokio::test]
    async fn test_disallow_enabling_voting_rewards_while_in_pre_initialization_swap() {
        // Step 1: Prepare the world, i.e. Governance.

        let governance_canister_id = canister_test_id(501);

        let mut env = NativeEnvironment::default();
        env.local_canister_id = Some(governance_canister_id);
        let mut governance = Governance::new(
            GovernanceProto {
                neurons: btreemap! {
                    A_NEURON_ID.to_string() => A_NEURON.clone(),
                },
                mode: governance::Mode::PreInitializationSwap as i32,

                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(NativeEnvironment::new(Some(CanisterId::from_u64(350519)))),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        // Step 2: Run code under test.
        let result = governance
            .make_proposal(
                &A_NEURON_ID,
                &A_NEURON_PRINCIPAL_ID,
                &Proposal {
                    action: Some(Action::ManageNervousSystemParameters(
                        NervousSystemParameters {
                            // The operative data is here. Foils make_proposal.
                            voting_rewards_parameters: Some(BASE_VOTING_REWARDS_PARAMETERS.clone()),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                },
            )
            .await;

        // Step 3: Inspect result(s).
        let err = match result {
            Ok(ok) => panic!("Proposal should have been rejected: {:#?}", ok),
            Err(err) => err,
        };

        let err = err.error_message.to_lowercase();
        assert!(err.contains("mode"), "{:#?}", err);
        assert!(err.contains("vot"), "{:#?}", err);
    }

    #[tokio::test]
    async fn no_new_reward_event_when_there_are_no_new_proposals() {
        // Step 0: Define helper type(s).

        // The main feature this implements is control of perceived time.
        struct DummyEnvironment {
            now: Arc<Mutex<u64>>,
        }

        impl DummyEnvironment {
            fn new(now: Arc<Mutex<u64>>) -> Self {
                Self { now }
            }
        }

        #[async_trait]
        impl Environment for DummyEnvironment {
            fn now(&self) -> u64 {
                *self.now.lock().unwrap()
            }

            fn set_time_warp(&mut self, _new_time_warp: TimeWarp) {
                unimplemented!();
            }

            fn random_u64(&mut self) -> u64 {
                unimplemented!();
            }

            fn random_byte_array(&mut self) -> [u8; 32] {
                unimplemented!();
            }

            async fn call_canister(
                &self,
                _canister_id: CanisterId,
                _method_name: &str,
                _arg: Vec<u8>,
            ) -> Result<
                /* reply: */ Vec<u8>,
                (
                    /* error_code: */ Option<i32>,
                    /* message: */ String,
                ),
            > {
                unimplemented!();
            }

            fn heap_growth_potential(&self) -> HeapGrowthPotential {
                HeapGrowthPotential::NoIssue
            }

            fn canister_id(&self) -> CanisterId {
                CanisterId::from_u64(318680)
            }

            fn canister_version(&self) -> Option<u64> {
                None
            }
        }

        // Step 1: Prepare the world.

        // Step 1.1: Helper.
        let now = Arc::new(Mutex::new(START_OF_2022_TIMESTAMP_SECONDS));

        // Step 1.2: Craft the test subject.
        let mut governance_proto = GovernanceProto {
            neurons: btreemap! {
                A_NEURON_ID.to_string() => A_NEURON.clone(),
            },
            ..basic_governance_proto()
        };
        let voting_rewards_parameters = governance_proto
            .parameters
            .as_mut()
            .unwrap()
            .voting_rewards_parameters
            .as_mut()
            .unwrap();
        *voting_rewards_parameters = VotingRewardsParameters {
            round_duration_seconds: Some(ONE_DAY_SECONDS),
            reward_rate_transition_duration_seconds: Some(1),
            initial_reward_rate_basis_points: Some(101),
            final_reward_rate_basis_points: Some(100),
        };
        let min_reward_rate = i2d(1) / i2d(100);
        let mut governance = Governance::new(
            governance_proto.try_into().unwrap(),
            Box::new(DummyEnvironment::new(now.clone())),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );
        // Step 1.3: Record original last_reward_event. That way, we can detect
        // changes (there aren't supposed to be any).
        let original_latest_reward_event = governance.proto.latest_reward_event.clone();
        assert!(
            original_latest_reward_event.is_some(),
            "{:#?}",
            original_latest_reward_event
        );

        // Step 1.4: Make a proposal.
        let proposal_id = governance
            .make_proposal(&A_NEURON_ID, &A_NEURON_PRINCIPAL_ID, &A_MOTION_PROPOSAL)
            .await
            .unwrap();

        // Step 1.5: Assert pre-condition.
        assert_eq!(
            governance
                .ready_to_be_settled_proposal_ids()
                .collect::<Vec<_>>(),
            vec![]
        );

        // Step 2: Run code under test (to wit, distribute_rewards), which
        // usually updates latest_reward_event, but not this time, because there
        // are no proposals that are ready to settle yet.
        let supply = Tokens::from_e8s(100 * E8);
        governance.distribute_rewards(supply);

        // Step 3: Inspect result(s): No change to latest_reward_event.
        assert_eq!(
            governance.proto.latest_reward_event,
            original_latest_reward_event
        );
        assert_eq!(
            original_latest_reward_event
                .as_ref()
                .unwrap()
                .rounds_since_last_distribution,
            Some(0)
        );

        // Step 4: Repeat, but with a twist: this time, there is indeed a
        // proposal that's ready to settle. Because of this, calling
        // distribute_rewards causes latest_reward_event to update, unlike
        // before.

        // Step 4.1: Advance time so that the proposal we made earlier becomes
        // ready to settle.
        let wait_days = 9;
        *now.lock().unwrap() += ONE_DAY_SECONDS * wait_days;
        assert_eq!(
            governance
                .ready_to_be_settled_proposal_ids()
                .collect::<Vec<_>>(),
            vec![proposal_id]
        );

        // Step 4.2: Call code under test (to wit, distribute_rewards) a second time.
        let supply = Tokens::from_e8s(100 * E8);
        governance.distribute_rewards(supply);

        // Step 4.3: Inspect result(s). This time, latest_reward_event has
        // changed, unlike in step 3.
        assert_ne!(
            governance.proto.latest_reward_event,
            original_latest_reward_event
        );

        // Now that we've seen that latest_reward_event has changed, let's take
        // a closer look at it.
        let final_latest_reward_event = governance.proto.latest_reward_event.as_ref().unwrap();
        assert_eq!(
            final_latest_reward_event.settled_proposals,
            vec![proposal_id]
        );
        assert_eq!(
            final_latest_reward_event.rounds_since_last_distribution,
            Some(wait_days)
        );

        // Inspect the amount distributed in final_latest_reward_event. In
        // principle, we could calculate this exactly, but it's someone
        // complicated, because the reward rate varies. To make this assertion a
        // simpler, we instead calculate a range that the reward amount must
        // fall within. That window is pretty small, and should be sufficient to
        // detect an incorrect implementation of roll over, which is the main
        // thing we are trying to do here.
        let min_distributed_e8s = (i2d(supply.get_e8s()) * i2d(wait_days)
            / *reward::NOMINAL_DAYS_PER_YEAR
            * min_reward_rate)
            .floor();
        // Scale up by 1%, because the max/initial reward rate is exactly this
        // much bigger than the min/final reward rate.
        let max_distributed_e8s = min_distributed_e8s * i2d(101) / i2d(100);
        let distributed_e8s_range = min_distributed_e8s..max_distributed_e8s;
        assert!(
            distributed_e8s_range
                .contains(&i2d(final_latest_reward_event.distributed_e8s_equivalent)),
            "distributed_e8s_range = {:?}\n\
             final_latest_reward_event = {:#?}",
            distributed_e8s_range,
            final_latest_reward_event,
        );

        assert_eq!(
            governance
                .ready_to_be_settled_proposal_ids()
                .collect::<Vec<_>>(),
            vec![]
        );

        let neuron = governance
            .proto
            .neurons
            .get(&A_NEURON_ID.to_string())
            .unwrap();
        assert_eq!(
            neuron.maturity_e8s_equivalent, final_latest_reward_event.distributed_e8s_equivalent,
            "neuron = {:#?}",
            neuron,
        );
    }

    #[test]
    fn two_sns_version_upgrades_cannot_be_concurrent() {
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion::default());
        test_disallow_concurrent_upgrade_execution((&action).into(), action);
    }

    #[test]
    fn two_canister_upgrades_cannot_be_concurrent() {
        let action = Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default());
        test_disallow_concurrent_upgrade_execution((&action).into(), action);
    }

    #[test]
    fn sns_upgrades_block_concurrent_canister_upgrades() {
        let executing_action_id =
            (&Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion::default())).into();
        let action = Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default());
        test_disallow_concurrent_upgrade_execution(executing_action_id, action);
    }

    #[test]
    fn canister_upgrades_block_concurrent_sns_upgrades() {
        let executing_action_id =
            (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion::default());
        test_disallow_concurrent_upgrade_execution(executing_action_id, action);
    }

    #[test]
    fn two_manage_ledger_parameters_proposals_cannot_be_concurrent() {
        let executing_action_id =
            (&Action::ManageLedgerParameters(ManageLedgerParameters::default())).into();
        let action = Action::ManageLedgerParameters(ManageLedgerParameters::default());
        test_disallow_concurrent_upgrade_execution(executing_action_id, action);
    }

    #[test]
    fn manage_ledger_parameters_block_concurrent_sns_upgrades() {
        let executing_action_id =
            (&Action::ManageLedgerParameters(ManageLedgerParameters::default())).into();
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion::default());
        test_disallow_concurrent_upgrade_execution(executing_action_id, action);
    }

    #[test]
    fn manage_ledger_parameters_block_concurrent_canister_upgrades() {
        let executing_action_id =
            (&Action::ManageLedgerParameters(ManageLedgerParameters::default())).into();
        let action = Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default());
        test_disallow_concurrent_upgrade_execution(executing_action_id, action);
    }

    /// A test method to allow testing concurrent upgrades for multiple scenarios
    fn test_disallow_concurrent_upgrade_execution(
        proposal_in_progress_action_id: u64,
        action_to_be_executed: Action,
    ) {
        // Step 1: Prepare the world.
        use ProposalDecisionStatus as Status;

        // Step 1.1: First proposal, which will block the next one.
        let execution_in_progress_proposal = ProposalData {
            action: proposal_in_progress_action_id,
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
        assert_eq!(execution_in_progress_proposal.status(), Status::Adopted);

        // Step 1.2: Second proposal. This one will be thwarted by the first.
        let to_be_processed_proposal = ProposalData {
            action: (&action_to_be_executed).into(),
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
                action: Some(action_to_be_executed),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(to_be_processed_proposal.status(), Status::Open);

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
            Box::<NativeEnvironment>::default(),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
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
            Status::Failed,
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
    fn test_upgrade_sns_to_next_version_for_root() {
        let expected_canister_to_upgrade = SnsCanisterType::Root;
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3, 4],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![6, 7, 8],
        };
        test_upgrade_sns_to_next_version_upgrades_correct_canister(
            next_version,
            vec![1, 2, 3, 4],
            expected_canister_to_upgrade,
        );
    }
    #[test]
    fn test_upgrade_sns_to_next_version_for_governance() {
        let expected_canister_to_upgrade = SnsCanisterType::Governance;
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4, 5],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![6, 7, 8],
        };
        test_upgrade_sns_to_next_version_upgrades_correct_canister(
            next_version,
            vec![2, 3, 4, 5],
            expected_canister_to_upgrade,
        );
    }
    #[test]
    fn test_upgrade_sns_to_next_version_for_ledger() {
        let expected_canister_to_upgrade = SnsCanisterType::Ledger;
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5, 6],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![6, 7, 8],
        };
        test_upgrade_sns_to_next_version_upgrades_correct_canister(
            next_version,
            vec![3, 4, 5, 6],
            expected_canister_to_upgrade,
        );
    }

    #[test]
    fn test_upgrade_sns_to_next_version_for_archive() {
        let expected_canister_to_upgrade = SnsCanisterType::Archive;
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7, 8],
            index_wasm_hash: vec![6, 7, 8],
        };
        test_upgrade_sns_to_next_version_upgrades_correct_canister(
            next_version,
            vec![5, 6, 7, 8],
            expected_canister_to_upgrade,
        );
    }

    #[test]
    fn test_upgrade_sns_to_next_version_for_index() {
        let expected_canister_to_upgrade = SnsCanisterType::Index;
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![6, 7, 8, 9],
        };
        test_upgrade_sns_to_next_version_upgrades_correct_canister(
            next_version,
            vec![6, 7, 8, 9],
            expected_canister_to_upgrade,
        );
    }

    /// This assumes that the current_version is:
    /// SnsVersion {
    ///     root_wasm_hash: vec![1, 2, 3],
    ///     governance_wasm_hash: vec![2, 3, 4],
    ///     ledger_wasm_hash: vec![3, 4, 5],
    ///     swap_wasm_hash: vec![4, 5, 6],
    ///     archive_wasm_hash: vec![5, 6, 7],
    /// }
    /// Any test inputs should only change one canister to a new version
    ///
    /// This also sets a slightly different expectation for upgrading root versus other canisters
    fn test_upgrade_sns_to_next_version_upgrades_correct_canister(
        next_version: SnsVersion,
        expected_wasm_hash_requested: Vec<u8>,
        expected_canister_to_be_upgraded: SnsCanisterType,
    ) {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;

        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});

        // Upgrade Proposal
        let proposal_id = 1;
        let proposal = ProposalData {
            action: (&action).into(),
            id: Some(proposal_id.into()),
            ballots: btreemap! {
                "neuron 1".to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: 9001,
                    cast_timestamp_seconds: 1,
                },
            },
            wait_for_quiet_state: Some(WaitForQuietState::default()),
            proposal: Some(Proposal {
                title: "Upgrade Proposal".to_string(),
                action: Some(action),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(proposal.status(), Status::Open);

        use ProposalDecisionStatus as Status;

        let current_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![6, 7, 8],
        };
        let sns_canister_summary_response = std_sns_canisters_summary_response();
        let env = setup_env_for_sns_upgrade_to_next_version_test(
            &current_version,
            &next_version,
            expected_wasm_hash_requested,
            expected_canister_to_be_upgraded,
            sns_canister_summary_response,
        );

        let assert_required_calls = env.get_assert_required_calls_fn();

        let now = env.now();
        // Init Governance.
        let mut governance = Governance::new(
            GovernanceProto {
                proposals: btreemap! {
                    proposal_id => proposal
                },
                root_canister_id: Some(root_canister_id.get()),
                ledger_canister_id: Some(ledger_canister_id.get()),
                deployed_version: Some(current_version.into()),
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        // When we execute the proposal
        execute_proposal(&mut governance, 1);
        // Then we check things happened as expected
        assert_required_calls();
        assert_eq!(
            governance.proto.pending_version.clone().unwrap(),
            UpgradeInProgress {
                target_version: Some(next_version.into()),
                mark_failed_at_seconds: now + 5 * 60,
                checking_upgrade_lock: 0,
                proposal_id,
            }
        );
        // We do not check the upgrade completion in this test because of limitations
        // with the test infrastructure for Environment
    }

    // Sets up an env that assumes using TEST_*_CANISTER_ID for sns canisters, which can handle requests for SnsUpgradeToNextVersion requests.
    fn setup_env_for_sns_upgrade_to_next_version_test(
        current_version: &SnsVersion,
        next_version: &SnsVersion,
        expected_wasm_hash_requested: Vec<u8>,
        expected_canister_to_be_upgraded: SnsCanisterType,
        sns_canister_summary_response: GetSnsCanistersSummaryResponse,
    ) -> NativeEnvironment {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
        let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;
        let ledger_archive_ids = TEST_ARCHIVES_CANISTER_IDS.clone();
        let index_canister_id = *TEST_INDEX_CANISTER_ID;

        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        env.default_canister_call_response =
            Err((Some(1), "Oh no something was not covered!".to_string()));
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&sns_canister_summary_response).unwrap()),
        );

        env.set_call_canister_response(
            SNS_WASM_CANISTER_ID,
            "get_next_sns_version",
            Encode!(&GetNextSnsVersionRequest {
                current_version: Some(current_version.clone())
            })
            .unwrap(),
            Ok(Encode!(&GetNextSnsVersionResponse {
                next_version: Some(next_version.clone())
            })
            .unwrap()),
        );
        env.set_call_canister_response(
            SNS_WASM_CANISTER_ID,
            "get_wasm",
            Encode!(&GetWasmRequest {
                hash: expected_wasm_hash_requested
            })
            .unwrap(),
            Ok(Encode!(&GetWasmResponse {
                wasm: Some(SnsWasm {
                    wasm: vec![9, 8, 7, 6, 5, 4, 3, 2],
                    canister_type: expected_canister_to_be_upgraded.into(), // Governance
                    proposal_id: None,
                })
            })
            .unwrap()),
        );

        let canisters_to_be_upgraded = match expected_canister_to_be_upgraded {
            SnsCanisterType::Unspecified => {
                panic!("Cannot be unspecified")
            }
            SnsCanisterType::Root => vec![root_canister_id],
            SnsCanisterType::Governance => vec![governance_canister_id],
            SnsCanisterType::Ledger => vec![ledger_canister_id],
            SnsCanisterType::Archive => ledger_archive_ids,
            SnsCanisterType::Swap => {
                panic!("Swap upgrade not supported via SNS (ownership)")
            }
            SnsCanisterType::Index => vec![index_canister_id],
        };

        assert!(!canisters_to_be_upgraded.is_empty());

        if expected_canister_to_be_upgraded != SnsCanisterType::Root {
            // This is the essential call we need to happen in order to know that the correct canister
            // was upgraded.
            for canister_id in canisters_to_be_upgraded {
                env.require_call_canister_invocation(
                    root_canister_id,
                    "change_canister",
                    Encode!(&ChangeCanisterRequest::new(
                        true,
                        CanisterInstallMode::Upgrade,
                        canister_id
                    )
                    .with_wasm(vec![9, 8, 7, 6, 5, 4, 3, 2])
                    .with_arg(Encode!().unwrap()))
                    .unwrap(),
                    // We don't actually look at the response from this call anywhere
                    Some(Ok(Encode!().unwrap())),
                );
            }
        } else {
            // These three are needed for the request to function, but we aren't interested in re-testing
            // canister_control methods here.
            for canister_id in canisters_to_be_upgraded {
                env.set_call_canister_response(
                    CanisterId::ic_00(),
                    "stop_canister",
                    Encode!(&CanisterIdRecord::from(canister_id)).unwrap(),
                    Ok(vec![]),
                );
                env.set_call_canister_response(
                    CanisterId::ic_00(),
                    "canister_status",
                    Encode!(&CanisterIdRecord::from(canister_id)).unwrap(),
                    Ok(Encode!(&canister_status_from_management_canister_for_test(
                        vec![],
                        CanisterStatusType::Stopped,
                    ))
                    .unwrap()),
                );
                env.set_call_canister_response(
                    CanisterId::ic_00(),
                    "start_canister",
                    Encode!(&CanisterIdRecord::from(canister_id)).unwrap(),
                    Ok(vec![]),
                );
                // For root canister, this is the required call that ensures our wiring was correct.
                env.require_call_canister_invocation(
                    CanisterId::ic_00(),
                    "install_code",
                    Encode!(&ic_management_canister_types::InstallCodeArgs {
                        mode: ic_management_canister_types::CanisterInstallMode::Upgrade,
                        canister_id: canister_id.get(),
                        wasm_module: vec![9, 8, 7, 6, 5, 4, 3, 2],
                        arg: Encode!().unwrap(),
                        compute_allocation: None,
                        memory_allocation: None, // local const in install_code()
                        sender_canister_version: None,
                    })
                    .unwrap(),
                    Some(Ok(vec![])),
                );
            }
        }
        env
    }

    fn std_sns_canisters_summary_response() -> GetSnsCanistersSummaryResponse {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
        let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;
        let swap_canister_id = *TEST_SWAP_CANISTER_ID;
        let ledger_archive_ids = TEST_ARCHIVES_CANISTER_IDS.clone();
        let index_canister_id = *TEST_INDEX_CANISTER_ID;
        let dapp_canisters = TEST_DAPP_CANISTER_IDS.clone();

        GetSnsCanistersSummaryResponse {
            root: Some(CanisterSummary {
                status: Some(canister_status_for_test(
                    vec![1, 2, 3],
                    CanisterStatusType::Running,
                )),
                canister_id: Some(root_canister_id.get()),
            }),
            governance: Some(CanisterSummary {
                status: Some(canister_status_for_test(
                    vec![2, 3, 4],
                    CanisterStatusType::Running,
                )),
                canister_id: Some(governance_canister_id.get()),
            }),
            ledger: Some(CanisterSummary {
                status: Some(canister_status_for_test(
                    vec![3, 4, 5],
                    CanisterStatusType::Running,
                )),
                canister_id: Some(ledger_canister_id.get()),
            }),
            swap: Some(CanisterSummary {
                status: Some(canister_status_for_test(
                    vec![4, 5, 6],
                    CanisterStatusType::Running,
                )),
                canister_id: Some(swap_canister_id.get()),
            }),
            dapps: dapp_canisters
                .iter()
                .map(|id| CanisterSummary {
                    status: Some(canister_status_for_test(
                        vec![0, 0, 0],
                        CanisterStatusType::Running,
                    )),
                    canister_id: Some(id.get()),
                })
                .collect(),
            archives: ledger_archive_ids
                .iter()
                .map(|id| CanisterSummary {
                    status: Some(canister_status_for_test(
                        vec![5, 6, 7],
                        CanisterStatusType::Running,
                    )),
                    canister_id: Some(id.get()),
                })
                .collect(),
            index: Some(CanisterSummary {
                status: Some(canister_status_for_test(
                    vec![6, 7, 8],
                    CanisterStatusType::Running,
                )),
                canister_id: Some(index_canister_id.get()),
            }),
        }
    }

    #[test]
    fn test_distribute_rewards_does_not_block_upgrades() {
        // Setup the canister ids for the test
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;

        // Create the environment and add mocked responses from root
        let mut env = NativeEnvironment::new(Some(governance_canister_id));

        let mut canisters_summary_response = std_sns_canisters_summary_response();
        if let Some(ref mut canister_summary) = canisters_summary_response.governance {
            canister_summary.status = Some(canister_status_for_test(
                vec![2, 3, 4],
                CanisterStatusType::Running,
            ));
        }
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&canisters_summary_response).unwrap()),
        );

        // Create the versions that will be used to exercise the test
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![6, 7, 8],
        };

        let current_version = {
            let mut version = next_version.clone();
            version.governance_wasm_hash = vec![1, 1, 1];
            version
        };

        // Create the governance struct with voting reward parameters that require rewards
        // to be distributed once a day. There is no pending version at initialization
        let mut governance = Governance::new(
            GovernanceProto {
                root_canister_id: Some(root_canister_id.get()),
                deployed_version: Some(current_version.clone().into()),
                parameters: Some(NervousSystemParameters {
                    voting_rewards_parameters: Some(VotingRewardsParameters {
                        round_duration_seconds: Some(ONE_DAY_SECONDS),
                        reward_rate_transition_duration_seconds: Some(0),
                        initial_reward_rate_basis_points: Some(250),
                        final_reward_rate_basis_points: Some(250),
                    }),
                    ..NervousSystemParameters::with_default_values()
                }),
                neurons: btreemap! {
                    A_NEURON_ID.to_string() => A_NEURON.clone(),
                },
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(AlwaysSucceedingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        // Get the initial reward event for comparison later
        let initial_reward_event = governance.latest_reward_event();

        // Make a proposal that should settle
        governance
            .make_proposal(&A_NEURON_ID, &A_NEURON_PRINCIPAL_ID, &A_MOTION_PROPOSAL)
            .now_or_never()
            .unwrap()
            .expect("Expected proposal to be submitted");

        // Assert that the rewards should not be distributed, and trigger the periodic tasks to
        // try to distribute them.
        assert!(!governance.should_distribute_rewards());
        governance.heartbeat().now_or_never();

        // Get the latest reward event and assert that its equal to the initial reward event. This
        // puts governance in the state that the OC-SNS was in for NNS1-2105.
        let latest_reward_event = governance.latest_reward_event();
        assert_eq!(initial_reward_event, latest_reward_event);

        // Advance time such that a reward event should be distributed
        governance.env.set_time_warp(TimeWarp {
            delta_s: (ONE_DAY_SECONDS * 5) as i64,
        });

        // Now set the pending_version in Governance such that the period_task to check upgrade
        // status is triggered.
        let mark_failed_at_seconds = governance.env.now() + ONE_DAY_SECONDS;
        governance.proto.pending_version = Some(UpgradeInProgress {
            target_version: Some(next_version.clone().into()),
            mark_failed_at_seconds,
            checking_upgrade_lock: 0,
            proposal_id: 0,
        });

        // Make sure Governance state is correctly set
        assert_eq!(
            governance.proto.pending_version.clone().unwrap(),
            UpgradeInProgress {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds,
                checking_upgrade_lock: 0,
                proposal_id: 0,
            }
        );
        assert_eq!(
            governance.proto.deployed_version.clone().unwrap(),
            current_version.into()
        );

        // Check that both conditions in `heartbeat` will be triggered on this heartbeat
        // and run the tasks.
        assert!(governance.should_distribute_rewards());
        assert!(governance.should_check_upgrade_status());
        governance.heartbeat().now_or_never();

        // These asserts would fail before the change in NNS1-2105. Now, even though
        // there was an attempt to distribute rewards, the status of the upgrade was still checked.
        let latest_reward_event = governance.latest_reward_event();
        assert_ne!(initial_reward_event, latest_reward_event);
        assert!(governance.proto.pending_version.is_none());
        assert_eq!(
            governance.proto.deployed_version.unwrap(),
            next_version.into()
        );
    }

    #[test]
    fn test_check_upgrade_status_fails_if_upgrade_not_finished_in_time() {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![6, 7, 8],
        };

        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        // We set a status that matches our pending version
        let mut canisters_summary_response = std_sns_canisters_summary_response();
        for summary in canisters_summary_response.archives.iter_mut() {
            summary.status = Some(canister_status_for_test(
                vec![1, 1, 1],
                CanisterStatusType::Running,
            ));
        }
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&canisters_summary_response).unwrap()),
        );

        let current_version = {
            let mut version = next_version.clone();
            version.archive_wasm_hash = vec![1, 1, 1];
            version
        };

        let now = env.now();
        let mut governance = Governance::new(
            GovernanceProto {
                root_canister_id: Some(root_canister_id.get()),
                deployed_version: Some(current_version.clone().into()),
                pending_version: Some(UpgradeInProgress {
                    target_version: Some(next_version.clone().into()),
                    mark_failed_at_seconds: now - 1,
                    checking_upgrade_lock: 0,
                    proposal_id: 0,
                }),
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        assert_eq!(
            governance.proto.pending_version.clone().unwrap(),
            UpgradeInProgress {
                target_version: Some(next_version.into()),
                mark_failed_at_seconds: now - 1,
                checking_upgrade_lock: 0,
                proposal_id: 0,
            }
        );
        assert_eq!(
            governance.proto.deployed_version.clone().unwrap(),
            current_version.clone().into()
        );
        // After we run our periodic tasks, the version should be marked as failed because of time
        // constraint.
        governance.heartbeat().now_or_never();

        // A failed deployment is when pending is erased but deployed_version is not updated.
        assert!(governance.proto.pending_version.is_none());
        assert_eq!(
            governance.proto.deployed_version.unwrap(),
            current_version.into()
        );
    }

    #[test]
    fn test_check_upgrade_status_succeeds() {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![6, 7, 8],
        };

        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        // We set a status that matches our pending version
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&std_sns_canisters_summary_response()).unwrap()),
        );

        let current_version = {
            let mut version = next_version.clone();
            version.archive_wasm_hash = vec![1, 1, 1];
            version
        };

        let now = env.now();
        let proposal_id = 12;
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
        let mut governance = Governance::new(
            GovernanceProto {
                root_canister_id: Some(root_canister_id.get()),
                deployed_version: Some(current_version.clone().into()),
                pending_version: Some(UpgradeInProgress {
                    target_version: Some(next_version.clone().into()),
                    mark_failed_at_seconds: now + 5 * 60,
                    checking_upgrade_lock: 0,
                    proposal_id,
                }),
                // we make a proposal that is already decided so that it won't execute again because
                // proposals to upgrade SNS's cannot execute if there's no deployed_version set on Governance state
                proposals: btreemap! {
                    proposal_id => ProposalData {
                        action: (&action).into(),
                        id: Some(proposal_id.into()),
                        ballots: btreemap! {
                        "neuron 1".to_string() => Ballot {
                            vote: Vote::Yes as i32,
                            voting_power: 9001,
                            cast_timestamp_seconds: 1,
                        },
                    },
                    wait_for_quiet_state: Some(WaitForQuietState::default()),
                    decided_timestamp_seconds: now,
                    proposal: Some(Proposal {
                        title: "Upgrade Proposal".to_string(),
                        action: Some(action),
                        ..Default::default()
                    }),
                    latest_tally: Some(Tally {
                        timestamp_seconds: now,
                        yes: 100000000,
                        no: 0,
                        total: 100000000
                    }),
                    ..Default::default()
                }},
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        assert_eq!(
            governance.proto.pending_version.clone().unwrap(),
            UpgradeInProgress {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds: now + 5 * 60,
                checking_upgrade_lock: 0,
                proposal_id,
            }
        );
        assert_eq!(
            governance.proto.deployed_version.clone().unwrap(),
            current_version.into()
        );
        // After we run our periodic tasks, the version should be marked as successful
        governance.heartbeat().now_or_never();

        assert!(governance.proto.pending_version.is_none());
        assert_eq!(
            governance.proto.deployed_version.clone().unwrap(),
            next_version.into()
        );
        // Assert proposal executed
        let proposal = governance.get_proposal(&GetProposal {
            proposal_id: Some(ProposalId { id: proposal_id }),
        });
        let proposal_data = match proposal.result.unwrap() {
            get_proposal_response::Result::Error(e) => {
                panic!("Error: {e:?}")
            }
            get_proposal_response::Result::Proposal(proposal) => proposal,
        };
        assert_ne!(proposal_data.executed_timestamp_seconds, 0);

        assert!(proposal_data.failure_reason.is_none(),);
    }

    #[test]
    fn test_check_upgrade_not_yet_failed_if_canister_summary_errs_and_before_mark_failed_at_time() {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![6, 7, 8],
        };

        let bad_summary = GetSnsCanistersSummaryResponse {
            root: Some(CanisterSummary {
                canister_id: None,
                status: None,
            }),
            ..std_sns_canisters_summary_response()
        };
        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        // We set a status that matches our pending version
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&bad_summary).unwrap()),
        );

        let current_version = {
            let mut version = next_version.clone();
            version.archive_wasm_hash = vec![1, 1, 1];
            version
        };

        let now = env.now();
        let proposal_id = 12;
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
        let mut governance = Governance::new(
            GovernanceProto {
                root_canister_id: Some(root_canister_id.get()),
                deployed_version: Some(current_version.clone().into()),
                pending_version: Some(UpgradeInProgress {
                    target_version: Some(next_version.clone().into()),
                    mark_failed_at_seconds: now + 1,
                    checking_upgrade_lock: 0,
                    proposal_id,
                }),
                // we make a proposal that is already decided so that it won't execute again because
                // proposals to upgrade SNS's cannot execute if there's no deployed_version set on Governance state
                proposals: btreemap! {
                    proposal_id => ProposalData {
                        action: (&action).into(),
                        id: Some(proposal_id.into()),
                        ballots: btreemap! {
                        "neuron 1".to_string() => Ballot {
                            vote: Vote::Yes as i32,
                            voting_power: 9001,
                            cast_timestamp_seconds: 1,
                        },
                    },
                    wait_for_quiet_state: Some(WaitForQuietState::default()),
                    decided_timestamp_seconds: now,
                    proposal: Some(Proposal {
                        title: "Upgrade Proposal".to_string(),
                        action: Some(action),
                        ..Default::default()
                    }),
                    latest_tally: Some(Tally {
                        timestamp_seconds: now,
                        yes: 100000000,
                        no: 0,
                        total: 100000000
                    }),
                    ..Default::default()
                }},
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        assert_eq!(
            governance.proto.pending_version.clone().unwrap(),
            UpgradeInProgress {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds: now + 1,
                checking_upgrade_lock: 0,
                proposal_id,
            }
        );
        assert_eq!(
            governance.proto.deployed_version.clone().unwrap(),
            current_version.into()
        );
        // After we run our periodic tasks, the version should be marked as successful
        governance.heartbeat().now_or_never();

        // We still have pending version
        assert_eq!(
            governance.proto.pending_version.clone().unwrap(),
            UpgradeInProgress {
                target_version: Some(next_version.into()),
                mark_failed_at_seconds: now + 1,
                checking_upgrade_lock: 0,
                proposal_id,
            }
        );

        // Assert proposal not failed or executed
        let proposal = governance.get_proposal(&GetProposal {
            proposal_id: Some(ProposalId { id: proposal_id }),
        });

        let proposal_data = match proposal.result.unwrap() {
            get_proposal_response::Result::Error(e) => {
                panic!("Error: {e:?}")
            }
            get_proposal_response::Result::Proposal(proposal) => proposal,
        };
        assert_eq!(proposal_data.failed_timestamp_seconds, 0);
        assert_eq!(proposal_data.executed_timestamp_seconds, 0);

        assert!(proposal_data.failure_reason.is_none());
    }

    #[test]
    fn test_check_upgrade_fails_if_canister_summary_errs_and_past_mark_failed_at_time() {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![6, 7, 8],
        };

        let bad_summary = GetSnsCanistersSummaryResponse {
            root: Some(CanisterSummary {
                canister_id: None,
                status: None,
            }),
            ..std_sns_canisters_summary_response()
        };
        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        // We set a status that matches our pending version
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&bad_summary).unwrap()),
        );

        let current_version = {
            let mut version = next_version.clone();
            version.archive_wasm_hash = vec![1, 1, 1];
            version
        };

        let now = env.now();
        let proposal_id = 12;
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
        let mut governance = Governance::new(
            GovernanceProto {
                root_canister_id: Some(root_canister_id.get()),
                deployed_version: Some(current_version.clone().into()),
                pending_version: Some(UpgradeInProgress {
                    target_version: Some(next_version.clone().into()),
                    mark_failed_at_seconds: now - 1,
                    checking_upgrade_lock: 0,
                    proposal_id,
                }),
                // we make a proposal that is already decided so that it won't execute again because
                // proposals to upgrade SNS's cannot execute if there's no deployed_version set on Governance state
                proposals: btreemap! {
                    proposal_id => ProposalData {
                        action: (&action).into(),
                        id: Some(proposal_id.into()),
                        ballots: btreemap! {
                        "neuron 1".to_string() => Ballot {
                            vote: Vote::Yes as i32,
                            voting_power: 9001,
                            cast_timestamp_seconds: 1,
                        },
                    },
                    wait_for_quiet_state: Some(WaitForQuietState::default()),
                    decided_timestamp_seconds: now,
                    proposal: Some(Proposal {
                        title: "Upgrade Proposal".to_string(),
                        action: Some(action),
                        ..Default::default()
                    }),
                    latest_tally: Some(Tally {
                        timestamp_seconds: now,
                        yes: 100000000,
                        no: 0,
                        total: 100000000
                    }),
                    ..Default::default()
                }},
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        assert_eq!(
            governance.proto.pending_version.clone().unwrap(),
            UpgradeInProgress {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds: now - 1,
                checking_upgrade_lock: 0,
                proposal_id,
            }
        );
        assert_eq!(
            governance.proto.deployed_version.clone().unwrap(),
            current_version.into()
        );
        // After we run our periodic tasks, the version should be marked as successful
        governance.heartbeat().now_or_never();

        assert!(governance.proto.pending_version.is_none());
        assert_ne!(
            governance.proto.deployed_version.clone().unwrap(),
            next_version.into()
        );

        // Assert proposal failed
        let proposal = governance.get_proposal(&GetProposal {
            proposal_id: Some(ProposalId { id: proposal_id }),
        });
        let proposal_data = match proposal.result.unwrap() {
            get_proposal_response::Result::Error(e) => {
                panic!("Error: {e:?}")
            }
            get_proposal_response::Result::Proposal(proposal) => proposal,
        };
        assert_ne!(proposal_data.failed_timestamp_seconds, 0);

        assert_eq!(
            proposal_data.failure_reason.unwrap(),
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Upgrade marked as failed at {} seconds from genesis. \
                Governance could not determine running version from root: Root had no status. \
                Setting upgrade to failed to unblock retry.",
                    now
                )
            )
        );
    }

    #[test]
    fn test_no_target_version_fails_check_upgrade_status() {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![6, 7, 8],
        };

        let summary = std_sns_canisters_summary_response();
        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        // We set a status that matches our pending version
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&summary).unwrap()),
        );

        let current_version = {
            let mut version = next_version.clone();
            version.archive_wasm_hash = vec![1, 1, 1];
            version
        };

        let now = env.now();
        let proposal_id = 12;
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
        let mut governance = Governance::new(
            GovernanceProto {
                root_canister_id: Some(root_canister_id.get()),
                deployed_version: Some(current_version.into()),
                pending_version: Some(UpgradeInProgress {
                    // This should be impossible due to how it's set, but is the condition of this test
                    target_version: None,
                    mark_failed_at_seconds: now - 1,
                    checking_upgrade_lock: 0,
                    proposal_id,
                }),
                // we make a proposal that is already decided so that it won't execute again because
                // proposals to upgrade SNS's cannot execute if there's no deployed_version set on Governance state
                proposals: btreemap! {
                    proposal_id => ProposalData {
                        action: (&action).into(),
                        id: Some(proposal_id.into()),
                        ballots: btreemap! {
                        "neuron 1".to_string() => Ballot {
                            vote: Vote::Yes as i32,
                            voting_power: 9001,
                            cast_timestamp_seconds: 1,
                        },
                    },
                    wait_for_quiet_state: Some(WaitForQuietState::default()),
                    decided_timestamp_seconds: now,
                    proposal: Some(Proposal {
                        title: "Upgrade Proposal".to_string(),
                        action: Some(action),
                        ..Default::default()
                    }),
                    latest_tally: Some(Tally {
                        timestamp_seconds: now,
                        yes: 100000000,
                        no: 0,
                        total: 100000000
                    }),
                    ..Default::default()
                }},
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        // After we run our periodic tasks, the version should be marked as successful
        governance.heartbeat().now_or_never();

        assert!(governance.proto.pending_version.is_none());
        assert_ne!(
            governance.proto.deployed_version.clone().unwrap(),
            next_version.into()
        );

        // Assert proposal failed
        let proposal = governance.get_proposal(&GetProposal {
            proposal_id: Some(ProposalId { id: proposal_id }),
        });
        let proposal_data = match proposal.result.unwrap() {
            get_proposal_response::Result::Error(e) => {
                panic!("Error: {e:?}")
            }
            get_proposal_response::Result::Proposal(proposal) => proposal,
        };
        assert_ne!(proposal_data.failed_timestamp_seconds, 0);

        assert_eq!(
            proposal_data.failure_reason.unwrap(),
            GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                    "No target_version set for upgrade_in_progress. This should be impossible. \
                        Clearing upgrade_in_progress state and marking proposal failed to unblock further upgrades."
            )
        );
    }

    #[test]
    fn test_check_upgrade_fails_and_sets_deployed_version_if_deployed_version_missing() {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![9, 9, 9],
        };

        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        // We set a status that matches our pending version
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&std_sns_canisters_summary_response()).unwrap()),
        );

        // This is set to the version returned by std_sns_canisters_summary_response()
        // But is different from next_version so we can assert the right result below
        let running_version = {
            let mut version = next_version.clone();
            version.index_wasm_hash = vec![6, 7, 8];
            version
        };

        let now = env.now();
        let proposal_id = 12;
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
        let mut governance = Governance::new(
            GovernanceProto {
                root_canister_id: Some(root_canister_id.get()),
                deployed_version: None,
                pending_version: Some(UpgradeInProgress {
                    target_version: Some(next_version.clone().into()),
                    mark_failed_at_seconds: now + 5 * 60,
                    checking_upgrade_lock: 0,
                    proposal_id,
                }),
                // we make a proposal that is already decided so that it won't execute again because
                // proposals to upgrade SNS's cannot execute if there's no deployed_version set on Governance state
                proposals: btreemap! {
                    proposal_id => ProposalData {
                        action: (&action).into(),
                        id: Some(proposal_id.into()),
                        ballots: btreemap! {
                        "neuron 1".to_string() => Ballot {
                            vote: Vote::Yes as i32,
                            voting_power: 9001,
                            cast_timestamp_seconds: 1,
                        },
                    },
                    wait_for_quiet_state: Some(WaitForQuietState::default()),
                    decided_timestamp_seconds: now,
                    proposal: Some(Proposal {
                        title: "Upgrade Proposal".to_string(),
                        action: Some(action),
                        ..Default::default()
                    }),
                    latest_tally: Some(Tally {
                        timestamp_seconds: now,
                        yes: 100000000,
                        no: 0,
                        total: 100000000
                    }),
                    ..Default::default()
                }},
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        assert_eq!(
            governance.proto.pending_version.clone().unwrap(),
            UpgradeInProgress {
                target_version: Some(next_version.into()),
                mark_failed_at_seconds: now + 5 * 60,
                checking_upgrade_lock: 0,
                proposal_id,
            }
        );

        assert_eq!(governance.proto.deployed_version, None);
        // After we run our periodic tasks, the version should be marked as successful
        governance.heartbeat().now_or_never();

        assert!(governance.proto.pending_version.is_none());
        // This is set to the running version to avoid non-recoverable state
        assert_eq!(
            governance.proto.deployed_version.clone().unwrap(),
            running_version.into()
        );

        // Assert proposal failed
        let proposal = governance.get_proposal(&GetProposal {
            proposal_id: Some(ProposalId { id: proposal_id }),
        });
        let proposal_data = match proposal.result.unwrap() {
            get_proposal_response::Result::Error(e) => {
                panic!("Error: {e:?}")
            }
            get_proposal_response::Result::Proposal(proposal) => proposal,
        };
        assert_ne!(proposal_data.failed_timestamp_seconds, 0);

        assert_eq!(
            proposal_data.failure_reason.unwrap(),
            GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Upgrade marked as failed at {} seconds from genesis. \
                Governance had no recorded deployed_version.  \
                Setting it to currently running version and failing upgrade.",
                    now
                )
            )
        );
    }

    #[test]
    fn test_check_upgrade_can_succeed_if_archives_out_of_sync() {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;

        // Beginning situation is SNS next_version is out of sync with
        // running version in regards to archive
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![9, 9, 9],
            index_wasm_hash: vec![6, 7, 8],
        };

        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        let canisters_summary_response = std_sns_canisters_summary_response();
        // We set a status that matches our pending version
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&canisters_summary_response).unwrap()),
        );

        // Our current version is different than next version by a single field
        // But archive won't match the running version
        let current_version = {
            let mut version = next_version.clone();
            version.governance_wasm_hash = vec![1, 1, 1];
            version
        };

        let now = env.now();
        let proposal_id = 45;
        let mut governance = Governance::new(
            GovernanceProto {
                root_canister_id: Some(root_canister_id.get()),
                deployed_version: Some(current_version.clone().into()),
                pending_version: Some(UpgradeInProgress {
                    target_version: Some(next_version.clone().into()),
                    mark_failed_at_seconds: now + 5 * 60,
                    checking_upgrade_lock: 0,
                    proposal_id,
                }),
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        assert_eq!(
            governance.proto.pending_version.clone().unwrap(),
            UpgradeInProgress {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds: now + 5 * 60,
                checking_upgrade_lock: 0,
                proposal_id,
            }
        );
        assert_eq!(
            governance.proto.deployed_version.clone().unwrap(),
            current_version.into()
        );
        // After we run our periodic tasks, the version should succeed
        governance.heartbeat().now_or_never();

        assert!(governance.proto.pending_version.is_none());
        assert_eq!(
            governance.proto.deployed_version.clone().unwrap(),
            next_version.into()
        );
    }

    #[test]
    fn test_check_upgrade_status_succeeds_if_no_archives_present() {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
        let next_version = SnsVersion {
            root_wasm_hash: vec![1, 2, 3],
            governance_wasm_hash: vec![2, 3, 4],
            ledger_wasm_hash: vec![3, 4, 5],
            swap_wasm_hash: vec![4, 5, 6],
            archive_wasm_hash: vec![5, 6, 7],
            index_wasm_hash: vec![6, 7, 8],
        };

        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        let mut canisters_summary_response = std_sns_canisters_summary_response();
        canisters_summary_response.archives = vec![];
        // We set a status that matches our pending version
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&canisters_summary_response).unwrap()),
        );

        let current_version = {
            let mut version = next_version.clone();
            version.archive_wasm_hash = vec![1, 1, 1];
            version
        };

        let now = env.now();
        let proposal_id = 45;
        let mut governance = Governance::new(
            GovernanceProto {
                root_canister_id: Some(root_canister_id.get()),
                deployed_version: Some(current_version.clone().into()),
                pending_version: Some(UpgradeInProgress {
                    target_version: Some(next_version.clone().into()),
                    mark_failed_at_seconds: now + 5 * 60,
                    checking_upgrade_lock: 0,
                    proposal_id,
                }),
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        assert_eq!(
            governance.proto.pending_version.clone().unwrap(),
            UpgradeInProgress {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds: now + 5 * 60,
                checking_upgrade_lock: 0,
                proposal_id,
            }
        );
        assert_eq!(
            governance.proto.deployed_version.clone().unwrap(),
            current_version.into()
        );
        // After we run our periodic tasks, the version should be marked as successful
        governance.heartbeat().now_or_never();

        assert!(governance.proto.pending_version.is_none());
        assert_eq!(
            governance.proto.deployed_version.unwrap(),
            next_version.into()
        );
    }

    #[test]
    fn test_sns_controlled_canister_upgrade_only_upgrades_dapp_canisters() {
        // Helper to let us create a lot of proposals to test.
        let create_upgrade_proposal = |id: u64, canister_id: CanisterId| {
            let action = Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister {
                canister_id: Some(canister_id.get()),
                // small valid wasm
                new_canister_wasm: vec![0, 0x61, 0x73, 0x6D, 2, 0, 0, 0],
                canister_upgrade_arg: None,
                mode: Some(CanisterInstallModeProto::Upgrade.into()),
            });

            // Upgrade Proposal
            let proposal = ProposalData {
                action: (&action).into(),
                id: Some(id.into()),
                ballots: btreemap! {
                    "neuron 1".to_string() => Ballot {
                        vote: Vote::Yes as i32,
                        voting_power: 9001,
                        cast_timestamp_seconds: 1,
                    },
                },
                wait_for_quiet_state: Some(WaitForQuietState::default()),
                proposal: Some(Proposal {
                    title: "Upgrade Proposal".to_string(),
                    action: Some(action),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert_eq!(proposal.status(), Status::Open);

            proposal
        };

        use ProposalDecisionStatus as Status;

        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
        let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;
        let swap_canister_id = *TEST_SWAP_CANISTER_ID;
        let ledger_archive_ids = TEST_ARCHIVES_CANISTER_IDS.clone();
        let dapp_canisters = TEST_DAPP_CANISTER_IDS.clone();

        // Setup Env to return a response to our canister_call query.
        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&std_sns_canisters_summary_response()).unwrap()),
        );
        // Make all of our proposals and initialize them in Governance
        let dapp_proposal = create_upgrade_proposal(1, dapp_canisters[0]);
        let root_proposal = create_upgrade_proposal(2, root_canister_id);
        let governance_proposal = create_upgrade_proposal(3, governance_canister_id);
        let ledger_proposal = create_upgrade_proposal(4, ledger_canister_id);
        let swap_proposal = create_upgrade_proposal(5, swap_canister_id);
        let ledger_archive_proposal = create_upgrade_proposal(6, ledger_archive_ids[0]);
        let unknown_canister_upgrade_proposal = create_upgrade_proposal(7, canister_test_id(2000));

        // Init Governance.
        let mut governance = Governance::new(
            GovernanceProto {
                proposals: btreemap! {
                    1 => dapp_proposal,
                    2 => root_proposal,
                    3 => governance_proposal,
                    4 => ledger_proposal,
                    5 => swap_proposal,
                    6 => ledger_archive_proposal,
                    7 => unknown_canister_upgrade_proposal
                },
                root_canister_id: Some(root_canister_id.get()),
                ledger_canister_id: Some(ledger_canister_id.get()),
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        // Helper function to assert failures.
        let assert_proposal_failed = |data: ProposalData, proposal_name: &str| {
            assert_eq!(
                data.status(),
                Status::Failed,
                "{} proposal did not fail. final_proposal_data: {:#?}",
                proposal_name,
                data,
            );
            assert_eq!(
                data.failure_reason.as_ref().unwrap().error_type,
                ErrorType::InvalidCommand as i32,
                "{} proposal failed, but failure_reason was not as expected. \
             final_proposal_data: {:#?}",
                proposal_name,
                data,
            );
        };

        // This is the only proposal that should succeed.
        let dapp_upgrade_result = execute_proposal(&mut governance, 1);
        assert_eq!(dapp_upgrade_result.status(), Status::Executed);

        // We assert the rest of the proposals fail.
        assert_proposal_failed(execute_proposal(&mut governance, 2), "Root upgrade");
        assert_proposal_failed(execute_proposal(&mut governance, 3), "Governance upgrade");
        assert_proposal_failed(execute_proposal(&mut governance, 4), "Ledger upgrade");
        assert_proposal_failed(execute_proposal(&mut governance, 5), "Swap upgrade");
        assert_proposal_failed(execute_proposal(&mut governance, 6), "Archive upgrade");
        assert_proposal_failed(
            execute_proposal(&mut governance, 7),
            "Unknown canister upgrade",
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
        assert_eq!(proposal.status(), Status::Adopted);

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
        assert_eq!(proposal.status(), Status::Open);

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
        assert_eq!(proposal.status(), Status::Executed);

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
        assert_eq!(proposal.status(), Status::Adopted);

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

    #[test]
    fn test_add_generic_nervous_system_function_succeeds() {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
        let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;
        let swap_canister_id = *TEST_SWAP_CANISTER_ID;

        let env = NativeEnvironment::new(Some(governance_canister_id));
        let mut governance = Governance::new(
            GovernanceProto {
                proposals: btreemap! {},
                root_canister_id: Some(root_canister_id.get()),
                ledger_canister_id: Some(ledger_canister_id.get()),
                swap_canister_id: Some(swap_canister_id.get()),
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        let valid = NervousSystemFunction {
            id: 1000,
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(CanisterId::from(200).get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::from(100).get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };
        assert_is_ok!(governance.perform_add_generic_nervous_system_function(valid));
    }

    fn default_governance_with_proto(governance_proto: GovernanceProto) -> Governance {
        Governance::new(
            governance_proto
                .try_into()
                .expect("Failed validating governance proto"),
            Box::<NativeEnvironment>::default(),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        )
    }

    fn test_neuron_id(controller: PrincipalId) -> NeuronId {
        NeuronId::from(compute_neuron_staking_subaccount_bytes(controller, 0))
    }

    #[test]
    fn test_stake_maturity_succeeds() {
        // Step 1: Prepare the world and parameters.
        let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
        let neuron_id = test_neuron_id(controller);
        let permission = NeuronPermission {
            principal: Some(controller),
            permission_type: vec![NeuronPermissionType::StakeMaturity as i32],
        };
        let initial_staked_maturity: u64 = 100000;
        let earned_maturity: u64 = 12345;
        let neuron = Neuron {
            id: Some(neuron_id.clone()),
            permissions: vec![permission],
            staked_maturity_e8s_equivalent: Some(initial_staked_maturity),
            maturity_e8s_equivalent: earned_maturity,
            ..Default::default()
        };
        let mut governance_proto = basic_governance_proto();
        governance_proto
            .neurons
            .insert(neuron_id.to_string(), neuron);
        let mut governance = default_governance_with_proto(governance_proto);
        let stake_maturity = manage_neuron::StakeMaturity {
            ..Default::default()
        };

        // Step 2: Run code under test.
        let result = governance.stake_maturity_of_neuron(&neuron_id, &controller, &stake_maturity);

        // Step 3: Inspect result(s).
        assert_is_ok!(result);
        let neuron = governance
            .proto
            .neurons
            .get(&neuron_id.to_string())
            .expect("Missing neuron!");
        assert_eq!(neuron.maturity_e8s_equivalent, 0);
        assert_eq!(
            neuron
                .staked_maturity_e8s_equivalent
                .expect("staked_maturity must be set"),
            initial_staked_maturity + earned_maturity
        );
    }

    #[test]
    fn test_stake_maturity_succeeds_without_initial_stake() {
        // Step 1: Prepare the world and parameters.
        let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
        let neuron_id = test_neuron_id(controller);
        let permission = NeuronPermission {
            principal: Some(controller),
            permission_type: vec![NeuronPermissionType::StakeMaturity as i32],
        };
        let earned_maturity: u64 = 12345;
        let neuron = Neuron {
            id: Some(neuron_id.clone()),
            permissions: vec![permission],
            staked_maturity_e8s_equivalent: None,
            maturity_e8s_equivalent: earned_maturity,
            ..Default::default()
        };
        let mut governance_proto = basic_governance_proto();
        governance_proto
            .neurons
            .insert(neuron_id.to_string(), neuron);
        let mut governance = default_governance_with_proto(governance_proto);
        let stake_maturity = manage_neuron::StakeMaturity {
            ..Default::default()
        };

        // Step 2: Run code under test.
        let result = governance.stake_maturity_of_neuron(&neuron_id, &controller, &stake_maturity);

        // Step 3: Inspect result(s).
        assert_is_ok!(result);
        let neuron = governance
            .proto
            .neurons
            .get(&neuron_id.to_string())
            .expect("Missing neuron!");
        assert_eq!(neuron.maturity_e8s_equivalent, 0);
        assert_eq!(
            neuron
                .staked_maturity_e8s_equivalent
                .expect("staked_maturity must be set"),
            earned_maturity
        );
    }

    #[test]
    fn test_stake_maturity_succeeds_with_partial_percentage() {
        // Step 1: Prepare the world and parameters.
        let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
        let neuron_id = test_neuron_id(controller);
        let permission = NeuronPermission {
            principal: Some(controller),
            permission_type: vec![NeuronPermissionType::StakeMaturity as i32],
        };
        let initial_staked_maturity: u64 = 100000;
        let earned_maturity: u64 = 12345;
        let neuron = Neuron {
            id: Some(neuron_id.clone()),
            permissions: vec![permission],
            staked_maturity_e8s_equivalent: Some(initial_staked_maturity),
            maturity_e8s_equivalent: earned_maturity,
            ..Default::default()
        };
        let mut governance_proto = basic_governance_proto();
        governance_proto
            .neurons
            .insert(neuron_id.to_string(), neuron);
        let mut governance = default_governance_with_proto(governance_proto);
        let partial_percentage = 42;
        let stake_maturity = manage_neuron::StakeMaturity {
            percentage_to_stake: Some(partial_percentage),
        };

        // Step 2: Run code under test.
        let result = governance.stake_maturity_of_neuron(&neuron_id, &controller, &stake_maturity);

        // Step 3: Inspect result(s).
        assert_is_ok!(result);
        let neuron = governance
            .proto
            .neurons
            .get(&neuron_id.to_string())
            .expect("Missing neuron!");
        let expected_newly_staked_maturity =
            earned_maturity.saturating_mul(partial_percentage as u64) / 100;
        assert_eq!(
            neuron.maturity_e8s_equivalent,
            earned_maturity - expected_newly_staked_maturity
        );
        assert_eq!(
            neuron
                .staked_maturity_e8s_equivalent
                .expect("staked_maturity must be set"),
            initial_staked_maturity + expected_newly_staked_maturity
        );
    }

    #[test]
    fn test_stake_maturity_fails_on_non_existing_neuron() {
        // Step 1: Prepare the world and parameters.
        let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
        let neuron_id = test_neuron_id(controller);
        let mut governance = default_governance_with_proto(basic_governance_proto());
        let stake_maturity = manage_neuron::StakeMaturity {
            ..Default::default()
        };

        // Step 2: Run code under test.
        let result = governance.stake_maturity_of_neuron(&neuron_id, &controller, &stake_maturity);

        // Step 3: Inspect result(s).
        assert_matches!(
        result,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == ErrorType::NotFound as i32 && msg.to_lowercase().contains("neuron not found")
        );
    }

    #[test]
    fn test_stake_maturity_fails_if_not_authorized() {
        // Step 1: Prepare the world and parameters.
        let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
        let neuron_id = test_neuron_id(controller);
        let neuron = Neuron {
            id: Some(neuron_id.clone()),
            ..Default::default()
        };
        let mut governance_proto = basic_governance_proto();
        governance_proto
            .neurons
            .insert(neuron_id.to_string(), neuron);
        let mut governance = default_governance_with_proto(governance_proto);
        let stake_maturity = manage_neuron::StakeMaturity {
            ..Default::default()
        };

        // Step 2: Run code under test.
        let result = governance.stake_maturity_of_neuron(&neuron_id, &controller, &stake_maturity);

        // Step 3: Inspect result(s).
        assert_matches!(
        result,
        Err(GovernanceError{error_type: code, error_message: _msg})
            if code == ErrorType::NotAuthorized as i32);
    }

    #[test]
    fn test_stake_maturity_fails_if_invalid_percentage_to_stake() {
        // Step 1: Prepare the world and parameters.
        let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
        let neuron_id = test_neuron_id(controller);
        let permission = NeuronPermission {
            principal: Some(controller),
            permission_type: vec![NeuronPermissionType::StakeMaturity as i32],
        };
        let neuron = Neuron {
            id: Some(neuron_id.clone()),
            permissions: vec![permission],
            ..Default::default()
        };
        let mut governance_proto = basic_governance_proto();
        governance_proto
            .neurons
            .insert(neuron_id.to_string(), neuron);
        let mut governance = default_governance_with_proto(governance_proto);

        for percentage in &[0, 101, 120] {
            let stake_maturity = manage_neuron::StakeMaturity {
                percentage_to_stake: Some(*percentage),
            };

            // Step 2: Run code under test.
            let result =
                governance.stake_maturity_of_neuron(&neuron_id, &controller, &stake_maturity);

            // Step 3: Inspect result(s).
            assert_matches!(
            result,
            Err(GovernanceError{error_type: code, error_message: msg})
                if code == ErrorType::PreconditionFailed as i32 && msg.to_lowercase().contains("percentage of maturity"),
            "Didn't reject invalid percentage_to_stake value {}", percentage
            );
        }
    }

    #[test]
    fn test_move_staked_maturity_on_dissolved_neurons_works() {
        // Step 1: Prepare the world and parameters.
        let controller_1 = *TEST_NEURON_1_OWNER_PRINCIPAL;
        let controller_2 = *TEST_NEURON_2_OWNER_PRINCIPAL;
        let neuron_id_1 = test_neuron_id(controller_1);
        let neuron_id_2 = test_neuron_id(controller_2);
        let regular_maturity: u64 = 1000000;
        let staked_maturity: u64 = 424242;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Dissolved neuron.
        let neuron_1 = Neuron {
            id: Some(neuron_id_1.clone()),
            maturity_e8s_equivalent: regular_maturity,
            staked_maturity_e8s_equivalent: Some(staked_maturity),
            dissolve_state: Some(neuron::DissolveState::WhenDissolvedTimestampSeconds(
                now - 100,
            )),
            ..Default::default()
        };
        // Non-dissolved neuron.
        let neuron_2 = Neuron {
            id: Some(neuron_id_2.clone()),
            maturity_e8s_equivalent: regular_maturity,
            staked_maturity_e8s_equivalent: Some(staked_maturity),
            dissolve_state: Some(neuron::DissolveState::WhenDissolvedTimestampSeconds(
                now + 100,
            )),
            ..Default::default()
        };

        let mut governance_proto = basic_governance_proto();
        governance_proto
            .neurons
            .insert(neuron_id_1.to_string(), neuron_1);
        governance_proto
            .neurons
            .insert(neuron_id_2.to_string(), neuron_2);
        let mut governance = default_governance_with_proto(governance_proto);

        // Step 2: Run code under test.
        governance.maybe_move_staked_maturity();

        // Step 3: Inspect result(s).
        let neuron_1 = governance
            .proto
            .neurons
            .get(&neuron_id_1.to_string())
            .expect("Missing neuron!");
        assert_eq!(
            neuron_1.maturity_e8s_equivalent,
            regular_maturity + staked_maturity
        );
        assert_eq!(neuron_1.staked_maturity_e8s_equivalent.unwrap_or(0), 0);
        let neuron_2 = governance
            .proto
            .neurons
            .get(&neuron_id_2.to_string())
            .expect("Missing neuron!");
        assert_eq!(neuron_2.maturity_e8s_equivalent, regular_maturity);
        assert_eq!(
            neuron_2.staked_maturity_e8s_equivalent,
            Some(staked_maturity)
        );
    }

    struct DisburseMaturityTestSetup {
        pub governance: Governance,
        pub neuron_id: NeuronId,
        pub controller: PrincipalId,
    }

    // Sets up an environment for a disburse-maturity test. The returned
    // setup consists of:
    // - an initialized governance, whose API can be called
    // - an id of a neuron (with the specified maturity) contained in the initialized governance
    // - an id of a principal that controls the neuron
    fn prepare_setup_for_disburse_maturity_tests(
        earned_maturity_e8s: u64,
    ) -> DisburseMaturityTestSetup {
        let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
        let neuron_id = test_neuron_id(controller);
        let permission = NeuronPermission {
            principal: Some(controller),
            permission_type: vec![NeuronPermissionType::DisburseMaturity as i32],
        };
        let neuron = Neuron {
            id: Some(neuron_id.clone()),
            permissions: vec![permission],
            maturity_e8s_equivalent: earned_maturity_e8s,
            ..Default::default()
        };
        let mut governance_proto = GovernanceProto {
            maturity_modulation: Some(MaturityModulation {
                current_basis_points: Some(0), // Neither positive nor negative.
                updated_at_timestamp_seconds: Some(1),
            }),
            ..basic_governance_proto()
        };
        governance_proto
            .neurons
            .insert(neuron_id.to_string(), neuron);
        let governance = default_governance_with_proto(governance_proto);
        DisburseMaturityTestSetup {
            controller,
            neuron_id,
            governance,
        }
    }

    #[test]
    fn test_disburse_maturity_succeeds_to_self() {
        // Step 1: Prepare the world and parameters.
        let earned_maturity_e8s = 1_234_567;
        let mut setup = prepare_setup_for_disburse_maturity_tests(earned_maturity_e8s);

        // Step 2: Run code under test.
        let disburse_maturity = DisburseMaturity {
            percentage_to_disburse: 100,
            to_account: None,
        };
        let result = setup.governance.disburse_maturity(
            &setup.neuron_id,
            &setup.controller,
            &disburse_maturity,
        );

        // Step 3: Inspect result(s).
        let response = result.expect("Operation failed unexpectedly.");
        assert_eq!(response.amount_disbursed_e8s, earned_maturity_e8s);
        let neuron = setup
            .governance
            .proto
            .neurons
            .get(&setup.neuron_id.to_string())
            .expect("Missing neuron!");
        assert_eq!(neuron.maturity_e8s_equivalent, 0);
        assert_eq!(neuron.disburse_maturity_in_progress.len(), 1);
        let in_progress = &neuron.disburse_maturity_in_progress[0];
        assert_eq!(in_progress.amount_e8s, earned_maturity_e8s);
        assert!(
            in_progress.account_to_disburse_to.is_some(),
            "Missing target account for disbursement."
        );
        let target_account_pb = in_progress.account_to_disburse_to.as_ref().unwrap().clone();
        assert_eq!(
            Account::try_from(target_account_pb),
            Ok(Account {
                owner: setup.controller.0,
                subaccount: None
            })
        );
        let d_age = (setup.governance.env.now() as i64)
            - (in_progress.timestamp_of_disbursement_seconds as i64);
        assert!(d_age >= 0, "Disbursement timestamp is in the future");
        assert!(d_age < 10, "Disbursement timestamp is too old");
    }

    #[test]
    fn test_disburse_maturity_succeeds_to_other_account() {
        // Step 1: Prepare the world and parameters.
        let earned_maturity_e8s = 3_456_789;
        let mut setup = prepare_setup_for_disburse_maturity_tests(earned_maturity_e8s);
        let target_principal = *TEST_NEURON_2_OWNER_PRINCIPAL;
        assert_ne!(target_principal, setup.controller);

        // Step 2: Run code under test.
        let disburse_maturity = DisburseMaturity {
            percentage_to_disburse: 100,
            to_account: Some(AccountProto {
                owner: Some(target_principal),
                subaccount: None,
            }),
        };
        let result = setup.governance.disburse_maturity(
            &setup.neuron_id,
            &setup.controller,
            &disburse_maturity,
        );

        // Step 3: Inspect result(s).
        let response = result.expect("Operation failed unexpectedly.");
        assert_eq!(response.amount_disbursed_e8s, earned_maturity_e8s);
        let neuron = setup
            .governance
            .proto
            .neurons
            .get(&setup.neuron_id.to_string())
            .expect("Missing neuron!");
        assert_eq!(neuron.maturity_e8s_equivalent, 0);
        assert_eq!(neuron.disburse_maturity_in_progress.len(), 1);
        let in_progress = &neuron.disburse_maturity_in_progress[0];
        assert_eq!(in_progress.amount_e8s, earned_maturity_e8s);
        assert!(
            in_progress.account_to_disburse_to.is_some(),
            "Missing target account for disbursement."
        );
        let target_account_pb = in_progress.account_to_disburse_to.as_ref().unwrap().clone();
        assert_eq!(
            Account::try_from(target_account_pb),
            Ok(Account {
                owner: target_principal.0,
                subaccount: None
            })
        );
        let d_age = (setup.governance.env.now() as i64)
            - (in_progress.timestamp_of_disbursement_seconds as i64);
        assert!(d_age >= 0, "Disbursement timestamp is in the future");
        assert!(d_age < 10, "Disbursement timestamp is too old");
    }

    #[test]
    fn test_disburse_maturity_succeeds_with_partial_percentage() {
        // Step 1: Prepare the world and parameters.
        let earned_maturity_e8s = 71_112_345;
        let mut setup = prepare_setup_for_disburse_maturity_tests(earned_maturity_e8s);

        // Step 2: Run code under test.
        let partial_percentage = 72;
        let disburse_maturity = DisburseMaturity {
            percentage_to_disburse: partial_percentage,
            to_account: None,
        };
        let result = setup.governance.disburse_maturity(
            &setup.neuron_id,
            &setup.controller,
            &disburse_maturity,
        );

        // Step 3: Inspect result(s).
        let response = result.expect("Operation failed unexpectedly.");
        let expected_disbursing_maturity =
            earned_maturity_e8s.saturating_mul(partial_percentage as u64) / 100;
        assert_eq!(response.amount_disbursed_e8s, expected_disbursing_maturity);
        let neuron = setup
            .governance
            .proto
            .neurons
            .get(&setup.neuron_id.to_string())
            .expect("Missing neuron!");

        assert_eq!(
            neuron.maturity_e8s_equivalent,
            earned_maturity_e8s - expected_disbursing_maturity
        );
        assert_eq!(neuron.disburse_maturity_in_progress.len(), 1);
        let in_progress = &neuron.disburse_maturity_in_progress[0];
        assert_eq!(in_progress.amount_e8s, expected_disbursing_maturity);
        assert!(
            in_progress.account_to_disburse_to.is_some(),
            "Missing target account for disbursement."
        );
        let target_account_pb = in_progress.account_to_disburse_to.as_ref().unwrap().clone();
        assert_eq!(
            Account::try_from(target_account_pb),
            Ok(Account {
                owner: setup.controller.0,
                subaccount: None
            })
        );
        let d_age = (setup.governance.env.now() as i64)
            - (in_progress.timestamp_of_disbursement_seconds as i64);
        assert!(d_age >= 0, "Disbursement timestamp is in the future");
        assert!(d_age < 10, "Disbursement timestamp is too old");
    }

    #[test]
    fn test_disburse_maturity_succeeds_with_multiple_disbursals() {
        // Step 1: Prepare the world and parameters.
        let earned_maturity_e8s = 12345678;
        let mut setup = prepare_setup_for_disburse_maturity_tests(earned_maturity_e8s);

        // Step 2: Run code under test.
        let percentages: Vec<u32> = vec![50, 20, 10];
        for percentage_to_disburse in &percentages {
            let disburse_maturity = DisburseMaturity {
                percentage_to_disburse: *percentage_to_disburse,
                to_account: None,
            };
            let result = setup.governance.disburse_maturity(
                &setup.neuron_id,
                &setup.controller,
                &disburse_maturity,
            );
            assert_is_ok!(result);
        }

        // Step 3: Inspect result(s).
        let neuron = setup
            .governance
            .proto
            .neurons
            .get(&setup.neuron_id.to_string())
            .expect("Missing neuron!");
        assert_eq!(
            neuron.disburse_maturity_in_progress.len(),
            percentages.len()
        );
        let mut remaining_maturity = earned_maturity_e8s;
        for (i, percentage_to_disburse) in percentages.iter().enumerate() {
            let expected_disbursing_maturity =
                remaining_maturity.saturating_mul(*percentage_to_disburse as u64) / 100;
            let in_progress = &neuron.disburse_maturity_in_progress[i];
            println!(
                "i: {}, {}, {}",
                i, percentage_to_disburse, in_progress.amount_e8s
            );
            assert_eq!(
                in_progress.amount_e8s, expected_disbursing_maturity,
                "unexpected disbursing maturity for percentage {}",
                percentage_to_disburse
            );
            remaining_maturity -= expected_disbursing_maturity;
            if i > 0 {
                let prev_in_progress = &neuron.disburse_maturity_in_progress[i - 1];
                assert!(
                    in_progress.timestamp_of_disbursement_seconds
                        >= prev_in_progress.timestamp_of_disbursement_seconds,
                    "disburse_maturity_in_progress is not sorted by the timestamp"
                )
            }
        }
        assert_eq!(neuron.maturity_e8s_equivalent, remaining_maturity);
    }

    #[test]
    fn test_disburse_maturity_fails_on_non_existing_neuron() {
        // Step 1: Prepare the world and parameters.
        let mut setup = prepare_setup_for_disburse_maturity_tests(1000);
        let non_existing_neuron_id = test_neuron_id(*TEST_NEURON_2_OWNER_PRINCIPAL);

        // Step 2: Run code under test.
        let disburse_maturity = DisburseMaturity {
            percentage_to_disburse: 100,
            to_account: None,
        };
        let result = setup.governance.disburse_maturity(
            &non_existing_neuron_id,
            &setup.controller,
            &disburse_maturity,
        );

        // Step 3: Inspect result(s).
        assert_matches!(
        result,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == ErrorType::NotFound as i32 && msg.to_lowercase().contains("neuron not found")
        );
    }

    #[test]
    fn test_disburse_maturity_fails_if_maturity_too_low() {
        // Step 1: Prepare the world and parameters.
        let mut setup = prepare_setup_for_disburse_maturity_tests(1000);

        // Step 2: Run code under test.
        let disburse_maturity = DisburseMaturity {
            percentage_to_disburse: 100,
            to_account: None,
        };
        let result = setup.governance.disburse_maturity(
            &setup.neuron_id,
            &setup.controller,
            &disburse_maturity,
        );

        // Step 3: Inspect result(s).
        assert_matches!(
        result,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == ErrorType::PreconditionFailed as i32 && msg.to_lowercase().contains("can't disburse an amount less than"));
    }

    #[test]
    fn test_disburse_maturity_fails_if_not_authorized() {
        // Step 1: Prepare the world and parameters.
        let mut setup = prepare_setup_for_disburse_maturity_tests(1000000);
        let not_authorized_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;

        // Step 2: Run code under test.
        let disburse_maturity = DisburseMaturity {
            percentage_to_disburse: 100,
            to_account: None,
        };
        let result = setup.governance.disburse_maturity(
            &setup.neuron_id,
            &not_authorized_controller,
            &disburse_maturity,
        );

        // Step 3: Inspect result(s).
        assert_matches!(
        result,
        Err(GovernanceError{error_type: code, error_message: _msg})
            if code == ErrorType::NotAuthorized as i32);
    }

    #[test]
    fn test_disburse_maturity_fails_if_invalid_percentage_to_disburse() {
        // Step 1: Prepare the world and parameters.
        let mut setup = prepare_setup_for_disburse_maturity_tests(1000);

        for percentage in &[0, 101, 120] {
            // Step 2: Run code under test.
            let disburse_maturity = DisburseMaturity {
                percentage_to_disburse: *percentage,
                to_account: None,
            };
            let result = setup.governance.disburse_maturity(
                &setup.neuron_id,
                &setup.controller,
                &disburse_maturity,
            );

            // Step 3: Inspect result(s).
            assert_matches!(
            result,
            Err(GovernanceError{error_type: code, error_message: msg})
                if code == ErrorType::PreconditionFailed as i32 && msg.to_lowercase().contains("percentage of maturity"),
            "Didn't reject invalid percentage_to_disburse value {}", percentage
            );
        }
    }

    struct SplitNeuronTestSetup {
        pub governance: Governance,
        pub neuron_id: NeuronId,
        pub controller: PrincipalId,
    }

    // Sets up an environment for a split-neuron test. The returned
    // setup consists of:
    // - an initialized governance, whose API can be called
    // - an id of a neuron (with the specified stake and maturity) contained in the initialized governance
    // - an id of a principal that controls the neuron
    fn prepare_setup_for_split_neuron_tests(
        stake_e8s: u64,
        maturity_e8s: u64,
    ) -> SplitNeuronTestSetup {
        let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
        let neuron_id = test_neuron_id(controller);
        let permission = NeuronPermission {
            principal: Some(controller),
            permission_type: vec![NeuronPermissionType::Split as i32],
        };
        let neuron = Neuron {
            id: Some(neuron_id.clone()),
            permissions: vec![permission],
            cached_neuron_stake_e8s: stake_e8s,
            maturity_e8s_equivalent: maturity_e8s,
            ..Default::default()
        };
        let mut governance_proto = basic_governance_proto();
        governance_proto
            .neurons
            .insert(neuron_id.to_string(), neuron);
        let canister_id = CanisterId::from_u64(123456);
        let governance = Governance::new(
            governance_proto
                .try_into()
                .expect("Failed validating governance proto"),
            Box::new(NativeEnvironment::new(Some(canister_id))),
            Box::new(AlwaysSucceedingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );
        SplitNeuronTestSetup {
            controller,
            neuron_id,
            governance,
        }
    }

    #[tokio::test]
    async fn test_split_neuron_succeeds() {
        // Step 1: Prepare the world and parameters.
        let stake_e8s = 1_000_000_000_000;
        let split_amount_e8s = stake_e8s / 3;
        let maturity_e8s = 123_456_789;
        let mut setup = prepare_setup_for_split_neuron_tests(stake_e8s, maturity_e8s);
        let orig_neuron = setup
            .governance
            .proto
            .neurons
            .get(&setup.neuron_id.to_string())
            .expect("Missing orig neuron!")
            .clone();
        let split = manage_neuron::Split {
            amount_e8s: split_amount_e8s,
            memo: 42,
        };

        // Step 2: Run code under test.
        let result = setup
            .governance
            .split_neuron(&setup.neuron_id, &setup.controller, &split)
            .await;

        // Step 3: Inspect result(s).
        let child_neuron_id = result.expect("Operation failed unexpectedly.");
        let parent_neuron = setup
            .governance
            .proto
            .neurons
            .get(&setup.neuron_id.to_string())
            .expect("Missing old neuron!");
        assert_eq!(
            parent_neuron.cached_neuron_stake_e8s,
            stake_e8s - split_amount_e8s
        );
        assert_eq!(parent_neuron.maturity_e8s_equivalent, maturity_e8s);
        assert_eq!(parent_neuron.neuron_fees_e8s, orig_neuron.neuron_fees_e8s);
        let child_neuron = setup
            .governance
            .proto
            .neurons
            .get(&child_neuron_id.to_string())
            .expect("Missing new neuron!");
        assert_eq!(
            child_neuron.cached_neuron_stake_e8s,
            split_amount_e8s - setup.governance.transaction_fee_e8s_or_panic()
        );
        assert_eq!(child_neuron.maturity_e8s_equivalent, 0);
        assert!(child_neuron.disburse_maturity_in_progress.is_empty());
        assert_eq!(child_neuron.neuron_fees_e8s, 0);

        let p = parent_neuron;
        let c = child_neuron;
        assert_eq!(p.permissions, c.permissions);
        assert_eq!(p.followees, c.followees);
        assert_eq!(p.dissolve_state, c.dissolve_state);
        assert_eq!(p.source_nns_neuron_id, c.source_nns_neuron_id);
        assert_eq!(p.auto_stake_maturity, c.auto_stake_maturity);
        assert_eq!(
            p.aging_since_timestamp_seconds,
            c.aging_since_timestamp_seconds
        );
        assert_eq!(
            p.voting_power_percentage_multiplier,
            c.voting_power_percentage_multiplier
        );
    }

    #[tokio::test]
    async fn test_split_neuron_fails_if_not_authorized() {
        // Step 1: Prepare the world and parameters.
        let mut setup = prepare_setup_for_split_neuron_tests(1_000_000_000, 100);
        let not_authorized_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;
        let split = manage_neuron::Split {
            amount_e8s: 10_000_000,
            memo: 42,
        };

        // Step 2: Run code under test.
        let result = setup
            .governance
            .split_neuron(&setup.neuron_id, &not_authorized_controller, &split)
            .await;

        // Step 3: Inspect result(s).
        assert_matches!(
        result,
        Err(GovernanceError{error_type: code, error_message: _msg})
            if code == ErrorType::NotAuthorized as i32);
    }

    #[tokio::test]
    async fn test_split_neuron_fails_on_non_existing_neuron() {
        // Step 1: Prepare the world and parameters.
        let mut setup = prepare_setup_for_split_neuron_tests(1_000_000_000, 100);
        let wrong_neuron_id = test_neuron_id(*TEST_NEURON_2_OWNER_PRINCIPAL);
        let split = manage_neuron::Split {
            amount_e8s: 10_000_000,
            memo: 42,
        };

        // Step 2: Run code under test.
        let result = setup
            .governance
            .split_neuron(&wrong_neuron_id, &setup.controller, &split)
            .await;

        // Step 3: Inspect result(s).
        assert_matches!(
        result,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == ErrorType::NotFound as i32 && msg.to_lowercase().contains("neuron not found")
        );
    }

    #[tokio::test]
    async fn test_split_neuron_fails_if_split_amount_too_low() {
        // Step 1: Prepare the world and parameters.
        let mut setup = prepare_setup_for_split_neuron_tests(1_000_000_000, 100);
        let params = setup.governance.nervous_system_parameters_or_panic();
        // The requested amount does not account for transaction fee, so the split should fail.
        let split = manage_neuron::Split {
            amount_e8s: params
                .neuron_minimum_stake_e8s
                .expect("Missing min stake param."),
            memo: 42,
        };
        // Step 2: Run code under test.
        let result = setup
            .governance
            .split_neuron(&setup.neuron_id, &setup.controller, &split)
            .await;

        // Step 3: Inspect result(s).
        assert_matches!(
        result,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == ErrorType::InsufficientFunds as i32&& msg.to_lowercase().contains("minimum split amount"));
    }

    #[tokio::test]
    async fn test_split_neuron_fails_if_remaining_stake_too_low() {
        // Step 1: Prepare the world and parameters.
        let stake_e8s = 10_000_000_000;
        let mut setup = prepare_setup_for_split_neuron_tests(stake_e8s, 100);
        let params = setup.governance.nervous_system_parameters_or_panic();
        // The remaining amount would be below min stake, so the split should fail.
        let split = manage_neuron::Split {
            amount_e8s: stake_e8s + 1
                - params
                    .neuron_minimum_stake_e8s
                    .expect("Missing min stake param."),
            memo: 42,
        };
        // Step 2: Run code under test.
        let result = setup
            .governance
            .split_neuron(&setup.neuron_id, &setup.controller, &split)
            .await;

        // Step 3: Inspect result(s).
        assert_matches!(
        result,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == ErrorType::InsufficientFunds as i32&& msg.to_lowercase().contains("minimum allowed stake"));
    }

    #[tokio::test]
    async fn test_split_neuron_fails_with_repeated_memo() {
        // Step 1: Prepare the world and parameters.
        let mut setup = prepare_setup_for_split_neuron_tests(10_000_000_000, 100);
        let split = manage_neuron::Split {
            amount_e8s: 1_000_000_000,
            memo: 42,
        };

        // Step 2: Run code under test.
        // The first split should succeed.
        let result = setup
            .governance
            .split_neuron(&setup.neuron_id, &setup.controller, &split)
            .await;
        assert!(result.is_ok(), "Error: {}", result.err().unwrap());
        // The second, repeated split should fail.
        let result = setup
            .governance
            .split_neuron(&setup.neuron_id, &setup.controller, &split)
            .await;

        // Step 3: Inspect result(s).
        assert_matches!(
        result,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == ErrorType::PreconditionFailed as i32 && msg.to_lowercase().contains("neuron already exists")
        );
    }

    #[test]
    fn test_add_generic_nervous_system_function_fails_when_restricted() {
        let root_canister_id = *TEST_ROOT_CANISTER_ID;
        let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
        let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;
        let swap_canister_id = *TEST_SWAP_CANISTER_ID;

        let env = NativeEnvironment::new(Some(governance_canister_id));
        let mut governance = Governance::new(
            GovernanceProto {
                proposals: btreemap! {},
                root_canister_id: Some(root_canister_id.get()),
                ledger_canister_id: Some(ledger_canister_id.get()),
                swap_canister_id: Some(swap_canister_id.get()),
                ..basic_governance_proto()
            }
            .try_into()
            .unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );

        let list_that_should_fail = vec![
            root_canister_id,
            governance_canister_id,
            ledger_canister_id,
            swap_canister_id,
            CanisterId::ic_00(),
            NNS_LEDGER_CANISTER_ID,
        ];

        for canister_id in list_that_should_fail {
            assert_adding_generic_nervous_system_function_fails_for_target_and_validator(
                &mut governance,
                canister_id,
            );
        }
    }

    fn assert_adding_generic_nervous_system_function_fails_for_target_and_validator(
        governance: &mut Governance,
        invalid_canister_target: CanisterId,
    ) {
        let nns_function_invalid_validator = NervousSystemFunction {
            id: 1000,
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(invalid_canister_target.get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::from(1).get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };
        let result = governance
            .perform_add_generic_nervous_system_function(nns_function_invalid_validator.clone());
        assert!(
            result.is_err(),
            "function: {:?}\nresult: {:?}",
            nns_function_invalid_validator,
            result
        );

        let nns_function_invalid_target = NervousSystemFunction {
            id: 1000,
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(CanisterId::from(1).get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(invalid_canister_target.get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };
        let result = governance
            .perform_add_generic_nervous_system_function(nns_function_invalid_target.clone());
        assert!(
            result.is_err(),
            "function: {:?}\nresult: {:?}",
            nns_function_invalid_target,
            result
        );
    }

    #[test]
    fn test_effective_maturity_modulation_basis_points() {
        let mut governance_proto = GovernanceProto {
            maturity_modulation: Some(MaturityModulation {
                current_basis_points: Some(42),
                updated_at_timestamp_seconds: Some(1),
            }),
            parameters: Some(NervousSystemParameters {
                maturity_modulation_disabled: None, // Maturity modulation is enabled.
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            governance_proto.effective_maturity_modulation_basis_points(),
            Ok(42),
            "{:#?}",
            governance_proto,
        );

        governance_proto.parameters = Some(NervousSystemParameters {
            maturity_modulation_disabled: Some(false), // Behaves the same as None.
            ..Default::default()
        });

        assert_eq!(
            governance_proto.effective_maturity_modulation_basis_points(),
            Ok(42),
            "{:#?}",
            governance_proto,
        );

        governance_proto.parameters = Some(NervousSystemParameters {
            maturity_modulation_disabled: Some(true), // Causes maturity_modulation to be ignored.
            ..Default::default()
        });

        assert_eq!(
            governance_proto.effective_maturity_modulation_basis_points(),
            Ok(0),
            "{:#?}",
            governance_proto,
        );

        let governance_proto = GovernanceProto {
            maturity_modulation: Some(MaturityModulation {
                current_basis_points: None, // No value yet.
                updated_at_timestamp_seconds: Some(1),
            }),
            parameters: Some(NervousSystemParameters {
                maturity_modulation_disabled: Some(false), // Maturity modulation is enabled.
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = governance_proto.effective_maturity_modulation_basis_points();
        assert_is_err!(result.clone());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ErrorType::Unavailable as i32);
        assert!(err.error_message.contains("retriev"));
    }

    /// Main Narrative:
    ///
    /// 1. There are three neurons. One votes directly. The other two follow the (direct) voter.
    /// 2. The difference between the two follower neurons is what they follow on:
    ///   * catch-all/fallback: This neuron does nothing on critical proposals.
    ///   * TransferSnsTreasuryFunds: This neuron only acts on TransferSnsTreasuryFunds proposals.
    /// 3. There are two proposals that the (direct) voter neuron votes on:
    ///   * Motion: Here, only the first follower neuron follows.
    ///   * TransferSnsTreasuryFunds: Here, only the second follower neuron follows, even though
    ///     the first follower neuron uses catch-all/fallback following.
    ///
    /// What the first follower neuron does is the most interesting, because what we are trying to
    /// demonstrate here is that catch-all/fallback following applies iff the proposal is
    /// normal/non-critical. Whereas, the second follower neuron is there more as a sanity check, to
    /// witness that specific (i.e. non-catch-all/non-fallback) following still happens.
    ///
    /// There is actually a third follower neuron, but this one is even less interesting than the
    /// second. This one is a "super follower" in that this uses a (disjoint) union of the following
    /// of the first two follower neurons.
    ///
    /// There is also a third proposal: a critical proposal, but with a different function ID that
    /// nobody specifically follows. Here, only direct voting causes a ballot to be filled in. This
    /// is another sanity test, which we throw in as a "bonus", because it's pretty cheap to add.
    #[test]
    fn test_cast_vote_and_cascade_follow_critical_vs_normal_proposals() {
        // Step 1: Prepare the world.

        let proposal_id = ProposalId { id: 42 };

        let voting_neuron_id = NeuronId { id: vec![1] };
        let follows_on_catch_all_neuron_id = NeuronId { id: vec![2] };
        let follows_on_transfer_sns_treasury_funds_neuron_id = NeuronId { id: vec![3] };
        let follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id =
            NeuronId { id: vec![4] };

        let non_critical_function_id = u64::from(&Action::Motion(Default::default()));
        let critical_function_id = u64::from(&Action::TransferSnsTreasuryFunds(Default::default()));

        let fallback_pseudo_function_id = u64::from(&Action::Unspecified(Default::default()));
        // This needs to be consistent with neurons (below).
        let function_followee_index = btreemap! {
            fallback_pseudo_function_id => btreemap! {
                voting_neuron_id.to_string() => btreeset! {
                    follows_on_catch_all_neuron_id.clone(),
                    follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.clone(),
                },
            },

            critical_function_id => btreemap! {
                voting_neuron_id.to_string() => btreeset! {
                    follows_on_transfer_sns_treasury_funds_neuron_id.clone(),
                    follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.clone(),
                },
            },
        };

        let voting_neuron = Neuron {
            id: Some(voting_neuron_id.clone()),
            cached_neuron_stake_e8s: E8, // voting power
            ..Default::default()
        };
        let follows_on_catch_all_neuron = Neuron {
            id: Some(follows_on_catch_all_neuron_id.clone()),
            cached_neuron_stake_e8s: E8, // voting power
            followees: btreemap! {
                fallback_pseudo_function_id => Followees {
                    followees: vec![voting_neuron_id.clone()],
                },
            },
            ..Default::default()
        };
        let follows_on_transfer_sns_treasury_funds_neuron = Neuron {
            id: Some(follows_on_transfer_sns_treasury_funds_neuron_id.clone()),
            cached_neuron_stake_e8s: E8, // voting power
            followees: btreemap! {
                critical_function_id => Followees {
                    followees: vec![voting_neuron_id.clone()],
                },
            },
            ..Default::default()
        };
        let follows_on_catch_all_and_transfer_sns_treasury_funds_neuron = Neuron {
            id: Some(follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.clone()),
            cached_neuron_stake_e8s: E8, // voting power
            followees: btreemap! {
                fallback_pseudo_function_id => Followees {
                    followees: vec![voting_neuron_id.clone()],
                },
                critical_function_id => Followees {
                    followees: vec![voting_neuron_id.clone()],
                },
            },
            ..Default::default()
        };
        let neurons = btreemap! {
            voting_neuron_id.to_string()
                => voting_neuron,

            follows_on_catch_all_neuron_id.to_string()
                => follows_on_catch_all_neuron,

            follows_on_transfer_sns_treasury_funds_neuron_id.to_string()
                => follows_on_transfer_sns_treasury_funds_neuron,

            follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.to_string()
                => follows_on_catch_all_and_transfer_sns_treasury_funds_neuron,
        };

        // Step 2: Run code under test.

        // We loop over Votes, because the behavior is "the same" in both cases: under following,
        // the direction of the vote is consistent (it would be a bit insane if voting Yes caused
        // another neuron to vote No, and vice versa).
        for vote_of_neuron in [Vote::Yes, Vote::No] {
            let now_seconds = 123_456_789;

            let empty_ballot = Ballot {
                vote: Vote::Unspecified as i32,
                voting_power: E8,
                cast_timestamp_seconds: now_seconds,
            };
            let filled_in_ballot = Ballot {
                vote: vote_of_neuron as i32,
                ..empty_ballot.clone()
            };

            // Code under test.
            let cast_vote_and_cascade_follow = |function_id| {
                // Give all neurons an empty ballot.
                let mut ballots = [
                    &voting_neuron_id,
                    &follows_on_catch_all_neuron_id,
                    &follows_on_transfer_sns_treasury_funds_neuron_id,
                    &follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id,
                ]
                .into_iter()
                .map(|neuron_id| (neuron_id.to_string(), empty_ballot.clone()))
                .collect::<BTreeMap<String, Ballot>>();

                // voter neuron votes, and the code under test deduces all of the implications of
                // following (or at least, tries to).
                Governance::cast_vote_and_cascade_follow(
                    &proposal_id,
                    &voting_neuron_id,
                    vote_of_neuron,
                    function_id,
                    &function_followee_index,
                    &neurons,
                    now_seconds,
                    &mut ballots,
                );

                ballots
            };

            // Step 2A: Consider following on non-critical proposal. Here catch-all/fallback
            // following should be used.
            let non_critical_ballots = cast_vote_and_cascade_follow(non_critical_function_id);

            // Step 3: Inspect results.

            // Step 3A: Non-critical proposal.
            assert_eq!(
                non_critical_ballots,
                btreemap! {
                    voting_neuron_id.to_string()
                        // Direct vote.
                        => filled_in_ballot.clone(),

                    follows_on_catch_all_neuron_id.to_string()
                        // Thanks to catch-all/fallback following.
                        => filled_in_ballot.clone(),

                    follows_on_transfer_sns_treasury_funds_neuron_id.to_string()
                        // Because this only follows specifically on TransferSnsTreasuryFunds.
                        => empty_ballot.clone(),

                    follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.to_string()
                        // Thanks to catch-all/fallback following, although from just this case, it
                        // is unclear why this happens (you need to look at behavior on many
                        // different proposals to explain the behavior of this neuron).
                        => filled_in_ballot.clone(),
                }
            );

            // Step 2B: Critical proposal following. Here catch-all/fallback following should NOT be
            // used.
            let critical_ballots = cast_vote_and_cascade_follow(critical_function_id);

            // Step 3B: Critical proposal.
            assert_eq!(
                critical_ballots,
                btreemap! {
                    voting_neuron_id.to_string()
                        => filled_in_ballot.clone(),

                    // Perhaps, surprisingly, even though this neuron follows on
                    // "catch-all/fallback", that does not apply here, because the proposal is
                    // "critical".
                    follows_on_catch_all_neuron_id.to_string()
                        => empty_ballot.clone(),

                    // Unsurprisingly, this neuron follows, because it specifically follows on
                    // proposals of this type.
                    follows_on_transfer_sns_treasury_funds_neuron_id.to_string()
                        => filled_in_ballot.clone(),

                    // Even less surprisingly, this also follows for similar reasons.
                    follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.to_string()
                        => filled_in_ballot.clone(),
                }
            );

            // Step 2C: A different critical proposal -> only direct voting happens here.
            let no_following_ballots = cast_vote_and_cascade_follow(u64::from(
                &Action::DeregisterDappCanisters(Default::default()),
            ));
            // Step 3C: A different critical proposal.
            assert_eq!(
                no_following_ballots,
                btreemap! {
                    // Only direct vote.
                    voting_neuron_id.to_string()
                        => filled_in_ballot.clone(),

                    // No following.
                    follows_on_catch_all_neuron_id.to_string()
                        => empty_ballot.clone(),
                    follows_on_transfer_sns_treasury_funds_neuron_id.to_string()
                        => empty_ballot.clone(),
                    // Even this "super follower" doesn't follow here.
                    follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.to_string()
                        => empty_ballot.clone(),
                }
            );
        }
    }
}
