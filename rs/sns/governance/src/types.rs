use crate::{
    following::TOPICS,
    governance::{Governance, NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER, TimeWarp},
    logs::INFO,
    pb::{
        sns_root_types::{
            ManageDappCanisterSettingsRequest, RegisterDappCanistersRequest,
            SetDappControllersRequest, set_dapp_controllers_request::CanisterIds,
        },
        v1::{
            ChunkedCanisterWasm, ClaimSwapNeuronsError, ClaimSwapNeuronsResponse,
            ClaimedSwapNeuronStatus, DefaultFollowees, DeregisterDappCanisters, Empty,
            ExecuteGenericNervousSystemFunction, Followee, GovernanceError,
            ManageDappCanisterSettings, ManageLedgerParameters, ManageNeuronResponse,
            ManageSnsMetadata, MintSnsTokens, Motion, NervousSystemFunction,
            NervousSystemParameters, Neuron, NeuronId, NeuronIds, NeuronPermission,
            NeuronPermissionList, NeuronPermissionType, ProposalId, RegisterDappCanisters,
            RewardEvent, SnsVersion, TransferSnsTreasuryFunds, UpgradeSnsControlledCanister,
            UpgradeSnsToNextVersion, Vote, VotingRewardsParameters,
            claim_swap_neurons_request::{
                NeuronRecipe, NeuronRecipes,
                neuron_recipe::{self, Participant},
            },
            claim_swap_neurons_response::{ClaimSwapNeuronsResult, ClaimedSwapNeurons, SwapNeuron},
            get_neuron_response,
            governance::{
                self, Mode, SnsMetadata, Version,
                neuron_in_flight_command::{self, SyncCommand},
            },
            governance_error::ErrorType,
            manage_neuron,
            manage_neuron_response::{
                self, DisburseMaturityResponse, MergeMaturityResponse, StakeMaturityResponse,
            },
            nervous_system_function::FunctionType,
            neuron::{FolloweesForTopic, TopicFollowees},
            proposal::Action,
        },
    },
    proposal::ValidGenericNervousSystemFunction,
};
use async_trait::async_trait;
use candid::{Decode, Encode};
use ic_base_types::CanisterId;
use ic_canister_log::log;
use ic_crypto_sha2::Sha256;
use ic_icrc1_ledger::UpgradeArgs as LedgerUpgradeArgs;
use ic_ledger_core::tokens::TOKEN_SUBDIVIDABLE_BY;
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInstallModeError, StoredChunksReply,
};
use ic_nervous_system_common::{
    DEFAULT_TRANSFER_FEE, NervousSystemError, ONE_DAY_SECONDS, ONE_MONTH_SECONDS, ONE_YEAR_SECONDS,
    hash_to_hex_string, ledger_validation::MAX_LOGO_LENGTH,
};
use ic_nervous_system_common_validation::validate_url;
use ic_nervous_system_proto::pb::v1::{Duration as PbDuration, Percentage};
use ic_sns_governance_api::format_full_hash;
use ic_sns_governance_proposal_criticality::{ProposalCriticality, VotingDurationParameters};
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue;
use icrc_ledger_types::icrc::metadata_key::MetadataKey;
use lazy_static::lazy_static;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    convert::TryFrom,
    fmt,
};
use strum::IntoEnumIterator;

#[allow(dead_code)]
/// TODO Use to validate the size of the payload 70 KB (for executing
/// SNS functions that are not canister upgrades)
const PROPOSAL_EXECUTE_SNS_FUNCTION_PAYLOAD_BYTES_MAX: usize = 70000;

/// The number of e8s per governance token;
pub const E8S_PER_TOKEN: u64 = TOKEN_SUBDIVIDABLE_BY;

/// The maximum message size for inter-canister calls to a different subnet
/// is 2MiB and thus we restrict the maximum joint size of the canister WASM
/// and argument to 2MB (2,000,000B) to leave some slack for Candid overhead
/// and a few constant-size fields (e.g., compute and memory allocation).
pub const MAX_INSTALL_CODE_WASM_AND_ARG_SIZE: usize = 2_000_000; // 2MB

/// The Governance spec gives each Action a u64 equivalent identifier. This module gives
/// those u64 values a human-readable const variable for use in the SNS.
pub mod native_action_ids {
    use crate::pb::v1::NervousSystemFunction;

    /// Unspecified Action.
    pub const UNSPECIFIED: u64 = 0;

    /// Motion Action.
    pub const MOTION: u64 = 1;

    /// ManageNervousSystemParameters Action.
    pub const MANAGE_NERVOUS_SYSTEM_PARAMETERS: u64 = 2;

    /// UpgradeSnsControlledCanister Action.
    pub const UPGRADE_SNS_CONTROLLED_CANISTER: u64 = 3;

    /// AddGenericNervousSystemFunction Action.
    pub const ADD_GENERIC_NERVOUS_SYSTEM_FUNCTION: u64 = 4;

    /// RemoveGenericNervousSystemFunction Action.
    pub const REMOVE_GENERIC_NERVOUS_SYSTEM_FUNCTION: u64 = 5;

    /// ExecuteGenericNervousSystemFunction Action.
    pub const EXECUTE_GENERIC_NERVOUS_SYSTEM_FUNCTION: u64 = 6;

    /// UpgradeSnsToNextVersion Action.
    pub const UPGRADE_SNS_TO_NEXT_VERSION: u64 = 7;

    /// ManageSnsMetadata Action.
    pub const MANAGE_SNS_METADATA: u64 = 8;

    /// TransferSnsTreasuryFunds Action.
    pub const TRANSFER_SNS_TREASURY_FUNDS: u64 = 9;

    /// RegisterDappCanisters Action.
    pub const REGISTER_DAPP_CANISTERS: u64 = 10;

    /// DeregisterDappCanisters Action.
    pub const DEREGISTER_DAPP_CANISTERS: u64 = 11;

    /// MintSnsTokens Action.
    pub const MINT_SNS_TOKENS: u64 = 12;

    /// ManageLedgerParameters Action.
    pub const MANAGE_LEDGER_PARAMETERS: u64 = 13;

    /// ManageDappCanisterSettings Action.
    pub const MANAGE_DAPP_CANISTER_SETTINGS: u64 = 14;

    /// AdvanceSnsTargetVersion Action.
    pub const ADVANCE_SNS_TARGET_VERSION: u64 = 15;

    /// SetTopicsForCustomProposals Action.
    pub const SET_TOPICS_FOR_CUSTOM_PROPOSALS_ACTION: u64 = 16;

    /// RegisterExtension Action.
    pub const REGISTER_EXTENSION: u64 = 17;

    /// ExecuteExtensionOperation Action.
    pub const EXECUTE_EXTENSION_OPERATION: u64 = 18;

    /// UpgradeExtension Action.
    pub const UPGRADE_EXTENSION: u64 = 19;

    // When adding something to this list, make sure to update the below function.
    pub fn nervous_system_functions() -> Vec<NervousSystemFunction> {
        vec![
            NervousSystemFunction::motion(),
            NervousSystemFunction::manage_nervous_system_parameters(),
            NervousSystemFunction::upgrade_sns_controlled_canister(),
            NervousSystemFunction::add_generic_nervous_system_function(),
            NervousSystemFunction::remove_generic_nervous_system_function(),
            NervousSystemFunction::execute_generic_nervous_system_function(),
            NervousSystemFunction::upgrade_sns_to_next_version(),
            NervousSystemFunction::manage_sns_metadata(),
            NervousSystemFunction::transfer_sns_treasury_funds(),
            NervousSystemFunction::register_dapp_canisters(),
            NervousSystemFunction::deregister_dapp_canisters(),
            NervousSystemFunction::mint_sns_tokens(),
            NervousSystemFunction::manage_ledger_parameters(),
            NervousSystemFunction::manage_dapp_canister_settings(),
            NervousSystemFunction::advance_sns_target_version(),
            NervousSystemFunction::set_topics_for_custom_proposals(),
            NervousSystemFunction::register_extension(),
            NervousSystemFunction::execute_extension_operation(),
            NervousSystemFunction::upgrade_extension(),
        ]
    }
}

impl governance::Mode {
    pub fn allows_manage_neuron_command_or_err(
        &self,
        command: &manage_neuron::Command,
        caller_is_swap_canister: bool,
    ) -> Result<(), GovernanceError> {
        use governance::Mode;
        match self {
            Mode::Unspecified => panic!("Governance's mode is not specified."),
            Mode::Normal => Ok(()),
            Mode::PreInitializationSwap => {
                Self::manage_neuron_command_is_allowed_in_pre_initialization_swap_or_err(
                    command,
                    caller_is_swap_canister,
                )
            }
        }
    }

    fn manage_neuron_command_is_allowed_in_pre_initialization_swap_or_err(
        command: &manage_neuron::Command,
        caller_is_swap_canister: bool,
    ) -> Result<(), GovernanceError> {
        use manage_neuron::Command as C;
        let ok = match command {
            C::Follow(_)
            | C::MakeProposal(_)
            | C::RegisterVote(_)
            | C::AddNeuronPermissions(_)
            | C::RemoveNeuronPermissions(_) => true,

            C::ClaimOrRefresh(_) => caller_is_swap_canister,

            _ => false,
        };

        if ok {
            return Ok(());
        }

        Err(GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            format!(
                "Because governance is currently in PreInitializationSwap mode, \
                 manage_neuron commands of this type are not allowed \
                 (caller_is_swap_canister={caller_is_swap_canister}). command: {command:#?}",
            ),
        ))
    }

    /// Returns Err if the (proposal) action is not allowed by self.
    ///
    ///
    /// # Arguments
    /// * `action` Value in the action field of a Proposal. This function
    ///   determines whether to allow submission of the proposal.
    /// * `disallowed_target_canister_ids`: When the action is a
    ///   ExecuteGenericNervousSystemFunction, the target of the function cannot
    ///   be one of these canisters. Generally, this would contain the ID of the
    ///   (SNS) root, governance, and ledger canisters, but this function does
    ///   not know what role these canisters play. Not used when the action is
    ///   not a EGNSF.
    /// * `id_to_nervous_system_function` From GovernanceProto (from the field
    ///   by the same name). This is used to determine the target of
    ///   ExecuteGenericNervousSystemFunction proposals. Otherwise, this is not
    ///   used.
    pub fn allows_proposal_action_or_err(
        &self,
        action: &Action,
        disallowed_target_canister_ids: &HashSet<CanisterId>,
        id_to_nervous_system_function: &BTreeMap<u64, NervousSystemFunction>,
    ) -> Result<(), GovernanceError> {
        use governance::Mode;
        match self {
            Mode::Normal => Ok(()),

            Mode::PreInitializationSwap => {
                Self::proposal_action_is_allowed_in_pre_initialization_swap_or_err(
                    action,
                    disallowed_target_canister_ids,
                    id_to_nervous_system_function,
                )
            }

            Mode::Unspecified => {
                panic!("Governance's mode is not specified.");
            }
        }
    }

    pub fn functions_disallowed_in_pre_initialization_swap() -> Vec<NervousSystemFunction> {
        vec![
            NervousSystemFunction::manage_nervous_system_parameters(),
            NervousSystemFunction::transfer_sns_treasury_funds(),
            NervousSystemFunction::mint_sns_tokens(),
            NervousSystemFunction::upgrade_sns_controlled_canister(),
            NervousSystemFunction::register_dapp_canisters(),
            NervousSystemFunction::deregister_dapp_canisters(),
        ]
    }

    fn proposal_action_is_allowed_in_pre_initialization_swap_or_err(
        action: &Action,
        disallowed_target_canister_ids: &HashSet<CanisterId>,
        id_to_nervous_system_function: &BTreeMap<u64, NervousSystemFunction>,
    ) -> Result<(), GovernanceError> {
        // ExecuteGenericNervousSystemFunction is special in that it
        // is only disallowed in some cases.
        if let Action::ExecuteGenericNervousSystemFunction(execute) = action {
            return Self::execute_generic_nervous_system_function_is_allowed_in_pre_initialization_swap_or_err(
                    execute,
                    disallowed_target_canister_ids,
                    id_to_nervous_system_function,
                );
        }

        let nervous_system_function = NervousSystemFunction::from(action.clone());

        let is_action_disallowed = Self::functions_disallowed_in_pre_initialization_swap()
            .into_iter()
            .any(|t| t.id == nervous_system_function.id);

        if is_action_disallowed {
            Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Proposal type for {:?} is not allowed while governance is in \
                     PreInitializationSwap ({}) mode.",
                    nervous_system_function,
                    Mode::PreInitializationSwap as i32,
                ),
            ))
        } else {
            Ok(())
        }
    }

    fn execute_generic_nervous_system_function_is_allowed_in_pre_initialization_swap_or_err(
        execute: &ExecuteGenericNervousSystemFunction,
        disallowed_target_canister_ids: &HashSet<CanisterId>,
        id_to_nervous_system_function: &BTreeMap<u64, NervousSystemFunction>,
    ) -> Result<(), GovernanceError> {
        let function_id = execute.function_id;
        let function = id_to_nervous_system_function
            .get(&function_id)
            .ok_or_else(|| {
                // This should never happen in practice, because the caller
                // should have already validated the proposal. This code is just
                // defense in depth.
                GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!(
                        "ExecuteGenericNervousSystemFunction specifies an unknown function ID: \
                         {execute:#?}.\nKnown functions: {id_to_nervous_system_function:#?}",
                    ),
                )
            })?;

        let target_canister_id = ValidGenericNervousSystemFunction::try_from(function)
            .expect("Invalid GenericNervousSystemFunction.")
            .target_canister_id;

        let bad = disallowed_target_canister_ids.contains(&target_canister_id);
        if bad {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "ExecuteGenericNervousSystemFunction proposals targeting {target_canister_id:?} are not allowed while \
                     governance is in PreInitializationSwap mode: {execute:#?}"
                ),
            ));
        }

        Ok(())
    }
}

impl From<&manage_neuron::Command> for neuron_in_flight_command::Command {
    #[rustfmt::skip]
    fn from(src: &manage_neuron::Command) -> neuron_in_flight_command::Command {
        use manage_neuron::Command as S;
        use neuron_in_flight_command::Command as D;
        match src.clone() {
            S::Configure              (x) => D::Configure              (x),
            S::Disburse               (x) => D::Disburse               (x),
            S::Follow                 (x) => D::Follow                 (x),
            S::SetFollowing           (x) => D::SetFollowing           (x),
            S::MakeProposal           (x) => D::MakeProposal           (x),
            S::RegisterVote           (x) => D::RegisterVote           (x),
            S::Split                  (x) => D::Split                  (x),
            S::ClaimOrRefresh         (x) => D::ClaimOrRefreshNeuron   (x),
            S::MergeMaturity          (x) => D::MergeMaturity          (x),
            S::DisburseMaturity       (x) => D::DisburseMaturity       (x),
            S::AddNeuronPermissions   (x) => D::AddNeuronPermissions   (x),
            S::RemoveNeuronPermissions(x) => D::RemoveNeuronPermissions(x),
            S::StakeMaturity          (_) => D::SyncCommand(SyncCommand{}),
        }
    }
}

lazy_static! {
    static ref DEFAULT_NERVOUS_SYSTEM_PARAMETERS: NervousSystemParameters =
        NervousSystemParameters::default();
}

impl Default for &NervousSystemParameters {
    fn default() -> Self {
        &DEFAULT_NERVOUS_SYSTEM_PARAMETERS
    }
}

/// Some constants that define upper bound (ceiling) and lower bounds (floor) for some of
/// the nervous system parameters as well as the default values for the nervous system
/// parameters (until we initialize them). We can't implement Default since it conflicts
/// with PB's.
impl NervousSystemParameters {
    /// This is an upper bound for `max_proposals_to_keep_per_action`. Exceeding it
    /// may cause degradation in the governance canister or the subnet hosting the SNS.
    pub const MAX_PROPOSALS_TO_KEEP_PER_ACTION_CEILING: u32 = 700;

    /// This is an upper bound for `max_number_of_neurons`. Exceeding it may cause
    /// degradation in the governance canister or the subnet hosting the SNS.
    /// See also: `MAX_NEURONS_FOR_DIRECT_PARTICIPANTS`.
    pub const MAX_NUMBER_OF_NEURONS_CEILING: u64 = 200_000;

    /// This is an upper bound for `max_number_of_proposals_with_ballots`. Exceeding
    /// it may cause degradation in the governance canister or the subnet hosting the SNS.
    pub const MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS_CEILING: u64 = 700;

    /// This is an upper bound for `initial_voting_period_seconds`. Exceeding it may cause
    /// degradation in the governance canister or the subnet hosting the SNS.
    pub const INITIAL_VOTING_PERIOD_SECONDS_CEILING: u64 = 30 * ONE_DAY_SECONDS;

    /// This is a lower bound for `initial_voting_period_seconds`. Exceeding it may cause
    /// degradation in the governance canister or the subnet hosting the SNS.
    pub const INITIAL_VOTING_PERIOD_SECONDS_FLOOR: u64 = ONE_DAY_SECONDS;

    /// This is an upper bound for `wait_for_quiet_deadline_increase_seconds`. Exceeding it may cause
    /// degradation in the governance canister or the subnet hosting the SNS.
    pub const WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS_CEILING: u64 = 30 * ONE_DAY_SECONDS;

    /// This is a lower bound for `wait_for_quiet_deadline_increase_seconds`. We're setting it to
    /// 1 instead of 0 because values of 0 are not currently well-tested.
    pub const WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS_FLOOR: u64 = 1;

    /// This is an upper bound for `max_followees_per_function`. Exceeding it may cause
    /// degradation in the governance canister or the subnet hosting the SNS.
    pub const MAX_FOLLOWEES_PER_FUNCTION_CEILING: u64 = 15;

    /// This is an upper bound for `max_number_of_principals_per_neuron`. Exceeding
    /// it may cause may cause degradation in the governance canister or the subnet
    /// hosting the SNS.
    pub const MAX_NUMBER_OF_PRINCIPALS_PER_NEURON_CEILING: u64 = 15;

    /// This is a lower bound for `max_number_of_principals_per_neuron`.
    /// Decreasing it below this number is problematic because SNS Swap assumes
    /// that there are allowed to be at least 5 principals per
    /// neuron during ClaimSwapNeuronsRequest.
    pub const MAX_NUMBER_OF_PRINCIPALS_PER_NEURON_FLOOR: u64 = 5;

    /// This is an upper bound for `max_dissolve_delay_bonus_percentage`. High values
    /// may improve the incentives when voting, but too-high values may also lead
    /// to an over-concentration of voting power. The value used by the NNS is 100.
    pub const MAX_DISSOLVE_DELAY_BONUS_PERCENTAGE_CEILING: u64 = 900;

    /// This is an upper bound for `max_age_bonus_percentage`. High values
    /// may improve the incentives when voting, but too-high values may also lead
    /// to an over-concentration of voting power. The value used by the NNS is 25.
    pub const MAX_AGE_BONUS_PERCENTAGE_CEILING: u64 = 400;

    /// These are the permissions that must be present in
    /// `neuron_claimer_permissions`.
    /// Permissions not in this list can be added after the SNS is created via a
    /// proposal.
    pub const REQUIRED_NEURON_CLAIMER_PERMISSIONS: &'static [NeuronPermissionType] = &[
        // Without this permission, it would be impossible to transfer control
        // of a neuron to a new principal.
        NeuronPermissionType::ManagePrincipals,
        // Without this permission, it would be impossible to vote.
        NeuronPermissionType::Vote,
        // Without this permission, it would be impossible to submit a proposal.
        NeuronPermissionType::SubmitProposal,
    ];

    /// The proportion of "yes votes" as basis points of the total voting power
    /// that is required for the proposal to be adopted. For example, if this field
    /// is 300bp, then the proposal can only be adopted if the number of "yes
    /// votes" is greater than or equal to 3% of the total voting power.
    pub const DEFAULT_MINIMUM_YES_PROPORTION_OF_TOTAL_VOTING_POWER: Percentage =
        Percentage::from_basis_points(300); // 3%

    /// Same as DEFAULT_MINIMUM_YES_PROPORTION_OF_TOTAL_VOTING_POWER, but for "critical" proposals
    pub const CRITICAL_MINIMUM_YES_PROPORTION_OF_TOTAL_VOTING_POWER: Percentage =
        Percentage::from_basis_points(2_000); // 20%

    /// The proportion of "yes votes" as basis points of the exercised voting power
    /// that is required for the proposal to be adopted. For example, if this field
    /// is 5000bp, then the proposal can only be adopted if the number of "yes
    /// votes" is greater than or equal to 50% of the exercised voting power.
    pub const DEFAULT_MINIMUM_YES_PROPORTION_OF_EXERCISED_VOTING_POWER: Percentage =
        Percentage::from_basis_points(5_000); // 50%

    /// Same as DEFAULT_MINIMUM_YES_PROPORTION_OF_EXERCISED_VOTING_POWER, but for "critical" proposals
    pub const CRITICAL_MINIMUM_YES_PROPORTION_OF_EXERCISED_VOTING_POWER: Percentage =
        Percentage::from_basis_points(6_700); // 67%

    pub fn with_default_values() -> Self {
        Self {
            reject_cost_e8s: Some(E8S_PER_TOKEN), // 1 governance token
            neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN), // 1 governance token
            transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
            max_proposals_to_keep_per_action: Some(100),
            initial_voting_period_seconds: Some(4 * ONE_DAY_SECONDS), // 4d
            wait_for_quiet_deadline_increase_seconds: Some(ONE_DAY_SECONDS), // 1d
            default_followees: Some(DefaultFollowees::default()),
            max_number_of_neurons: Some(200_000),
            neuron_minimum_dissolve_delay_to_vote_seconds: Some(6 * ONE_MONTH_SECONDS), // 6m
            max_followees_per_function: Some(15),
            max_dissolve_delay_seconds: Some(8 * ONE_YEAR_SECONDS), // 8y
            max_neuron_age_for_age_bonus: Some(4 * ONE_YEAR_SECONDS), // 4y
            max_number_of_proposals_with_ballots: Some(700),
            neuron_claimer_permissions: Some(Self::default_neuron_claimer_permissions()),
            neuron_grantable_permissions: Some(NeuronPermissionList::default()),
            max_number_of_principals_per_neuron: Some(5),
            voting_rewards_parameters: Some(VotingRewardsParameters::with_default_values()),
            max_dissolve_delay_bonus_percentage: Some(100),
            max_age_bonus_percentage: Some(25),
            maturity_modulation_disabled: Some(false),
            automatically_advance_target_version: Some(true),
        }
    }

    /// Any empty fields of `self` are overwritten with the corresponding fields of `base`.
    pub fn inherit_from(&self, base: &Self) -> Self {
        Self {
            reject_cost_e8s: self.reject_cost_e8s.or(base.reject_cost_e8s),
            neuron_minimum_stake_e8s: self
                .neuron_minimum_stake_e8s
                .or(base.neuron_minimum_stake_e8s),
            transaction_fee_e8s: self.transaction_fee_e8s.or(base.transaction_fee_e8s),
            max_proposals_to_keep_per_action: self
                .max_proposals_to_keep_per_action
                .or(base.max_proposals_to_keep_per_action),
            initial_voting_period_seconds: self
                .initial_voting_period_seconds
                .or(base.initial_voting_period_seconds),
            wait_for_quiet_deadline_increase_seconds: self
                .wait_for_quiet_deadline_increase_seconds
                .or(base.wait_for_quiet_deadline_increase_seconds),
            default_followees: self
                .default_followees
                .clone()
                .or_else(|| base.default_followees.clone()),
            max_number_of_neurons: self.max_number_of_neurons.or(base.max_number_of_neurons),
            neuron_minimum_dissolve_delay_to_vote_seconds: self
                .neuron_minimum_dissolve_delay_to_vote_seconds
                .or(base.neuron_minimum_dissolve_delay_to_vote_seconds),
            max_followees_per_function: self
                .max_followees_per_function
                .or(base.max_followees_per_function),
            max_dissolve_delay_seconds: self
                .max_dissolve_delay_seconds
                .or(base.max_dissolve_delay_seconds),
            max_neuron_age_for_age_bonus: self
                .max_neuron_age_for_age_bonus
                .or(base.max_neuron_age_for_age_bonus),
            max_number_of_proposals_with_ballots: self
                .max_number_of_proposals_with_ballots
                .or(base.max_number_of_proposals_with_ballots),
            neuron_claimer_permissions: self
                .neuron_claimer_permissions
                .clone()
                .or_else(|| base.neuron_claimer_permissions.clone()),
            neuron_grantable_permissions: self
                .neuron_grantable_permissions
                .clone()
                .or_else(|| base.neuron_grantable_permissions.clone()),
            max_number_of_principals_per_neuron: self
                .max_number_of_principals_per_neuron
                .or(base.max_number_of_principals_per_neuron),
            max_dissolve_delay_bonus_percentage: self
                .max_dissolve_delay_bonus_percentage
                .or(base.max_dissolve_delay_bonus_percentage),
            max_age_bonus_percentage: self
                .max_age_bonus_percentage
                .or(base.max_age_bonus_percentage),
            voting_rewards_parameters: self
                .voting_rewards_parameters
                .or(base.voting_rewards_parameters)
                .map(|v| match base.voting_rewards_parameters.as_ref() {
                    None => v,
                    Some(base) => v.inherit_from(base),
                }),
            maturity_modulation_disabled: self
                .maturity_modulation_disabled
                .or(base.maturity_modulation_disabled),
            automatically_advance_target_version: self
                .automatically_advance_target_version
                .or(base.automatically_advance_target_version),
        }
    }

    /// This validates that the `NervousSystemParameters` are well-formed.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_reject_cost_e8s()?;
        self.validate_neuron_minimum_stake_e8s()?;
        self.validate_transaction_fee_e8s()?;
        self.validate_max_proposals_to_keep_per_action()?;
        self.validate_initial_voting_period_seconds()?;
        self.validate_wait_for_quiet_deadline_increase_seconds()?;
        self.validate_default_followees()?;
        self.validate_max_number_of_neurons()?;
        self.validate_neuron_minimum_dissolve_delay_to_vote_seconds()?;
        self.validate_max_followees_per_function()?;
        self.validate_max_dissolve_delay_seconds()?;
        self.validate_max_neuron_age_for_age_bonus()?;
        self.validate_max_number_of_proposals_with_ballots()?;
        self.validate_neuron_claimer_permissions()?;
        self.validate_neuron_grantable_permissions()?;
        self.validate_max_number_of_principals_per_neuron()?;
        self.validate_voting_rewards_parameters()?;
        self.validate_max_dissolve_delay_bonus_percentage()?;
        self.validate_max_age_bonus_percentage()?;

        Ok(())
    }

    /// Validates that the nervous system parameter reject_cost_e8s is well-formed.
    fn validate_reject_cost_e8s(&self) -> Result<u64, String> {
        self.reject_cost_e8s
            .ok_or_else(|| "NervousSystemParameters.reject_cost_e8s must be set".to_string())
    }

    /// Validates that the nervous system parameter neuron_minimum_stake_e8s is well-formed.
    fn validate_neuron_minimum_stake_e8s(&self) -> Result<(), String> {
        let transaction_fee_e8s = self.validate_transaction_fee_e8s()?;

        let neuron_minimum_stake_e8s = self.neuron_minimum_stake_e8s.ok_or_else(|| {
            "NervousSystemParameters.neuron_minimum_stake_e8s must be set".to_string()
        })?;

        if neuron_minimum_stake_e8s <= transaction_fee_e8s {
            Err(format!(
                "NervousSystemParameters.neuron_minimum_stake_e8s ({neuron_minimum_stake_e8s}) must be greater than \
                NervousSystemParameters.transaction_fee_e8s ({neuron_minimum_stake_e8s})"
            ))
        } else {
            Ok(())
        }
    }

    /// Validates that the nervous system parameter transaction_fee_e8s is well-formed.
    fn validate_transaction_fee_e8s(&self) -> Result<u64, String> {
        self.transaction_fee_e8s
            .ok_or_else(|| "NervousSystemParameters.transaction_fee_e8s must be set".to_string())
    }

    /// Validates that the nervous system parameter max_proposals_to_keep_per_action
    /// is well-formed.
    fn validate_max_proposals_to_keep_per_action(&self) -> Result<(), String> {
        let max_proposals_to_keep_per_action =
            self.max_proposals_to_keep_per_action.ok_or_else(|| {
                "NervousSystemParameters.max_proposals_to_keep_per_action must be set".to_string()
            })?;

        // For ProposalId assignment to work, max_proposals_to_keep_per_action must always be
        // greater than 0. If not, garbage collection may remove the latest ProposalId, which is
        // needed when generating the next ProposalId.
        if max_proposals_to_keep_per_action == 0 {
            Err(
                "NervousSystemParameters.max_proposals_to_keep_per_action must be greater than 0"
                    .to_string(),
            )
        } else if max_proposals_to_keep_per_action > Self::MAX_PROPOSALS_TO_KEEP_PER_ACTION_CEILING
        {
            Err(format!(
                "NervousSystemParameters.max_proposals_to_keep_per_action must be less than {}",
                Self::MAX_PROPOSALS_TO_KEEP_PER_ACTION_CEILING
            ))
        } else {
            Ok(())
        }
    }

    /// Validates that the nervous system parameter initial_voting_period_seconds is well-formed.
    fn validate_initial_voting_period_seconds(&self) -> Result<(), String> {
        let initial_voting_period_seconds =
            self.initial_voting_period_seconds.ok_or_else(|| {
                "NervousSystemParameters.initial_voting_period_seconds must be set".to_string()
            })?;

        if initial_voting_period_seconds < Self::INITIAL_VOTING_PERIOD_SECONDS_FLOOR {
            Err(format!(
                "NervousSystemParameters.initial_voting_period_seconds must be greater than {}",
                Self::INITIAL_VOTING_PERIOD_SECONDS_FLOOR
            ))
        } else if initial_voting_period_seconds > Self::INITIAL_VOTING_PERIOD_SECONDS_CEILING {
            Err(format!(
                "NervousSystemParameters.initial_voting_period_seconds must be less than {}",
                Self::INITIAL_VOTING_PERIOD_SECONDS_CEILING
            ))
        } else {
            Ok(())
        }
    }

    /// Validates that the nervous system parameter wait_for_quiet_deadline_increase_seconds is well-formed.
    fn validate_wait_for_quiet_deadline_increase_seconds(&self) -> Result<(), String> {
        let initial_voting_period_seconds =
            self.initial_voting_period_seconds.ok_or_else(|| {
                "NervousSystemParameters.initial_voting_period_seconds must be set".to_string()
            })?;
        let wait_for_quiet_deadline_increase_seconds = self
            .wait_for_quiet_deadline_increase_seconds
            .ok_or_else(|| {
                "NervousSystemParameters.wait_for_quiet_deadline_increase_seconds must be set"
                    .to_string()
            })?;

        if wait_for_quiet_deadline_increase_seconds
            < Self::WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS_FLOOR
        {
            Err(format!(
                "NervousSystemParameters.wait_for_quiet_deadline_increase_seconds must be greater than or equal to {}",
                Self::WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS_FLOOR
            ))
        } else if wait_for_quiet_deadline_increase_seconds
            > Self::WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS_CEILING
        {
            Err(format!(
                "NervousSystemParameters.wait_for_quiet_deadline_increase_seconds must be less than or equal to {}",
                Self::WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS_CEILING
            ))
        // If `wait_for_quiet_deadline_increase_seconds > initial_voting_period_seconds / 2`, any flip (including an initial `yes` vote)
        // will always cause the deadline to be increased. That seems like unreasonable behavior, so we prevent that from being
        // the case.
        } else if wait_for_quiet_deadline_increase_seconds > initial_voting_period_seconds / 2 {
            Err(format!(
                "NervousSystemParameters.wait_for_quiet_deadline_increase_seconds is {}, but must be less than or equal to half the initial voting period, {}",
                initial_voting_period_seconds,
                initial_voting_period_seconds / 2
            ))
        } else {
            Ok(())
        }
    }

    /// Validates that the nervous system parameter default_followees is well-formed.
    /// TODO NNS1-2169: default followees are not currently supported
    fn validate_default_followees(&self) -> Result<(), String> {
        self.default_followees
            .as_ref()
            .ok_or_else(|| "NervousSystemParameters.default_followees must be set".to_string())
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

    /// Validates that the nervous system parameter max_number_of_neurons is well-formed.
    fn validate_max_number_of_neurons(&self) -> Result<(), String> {
        let max_number_of_neurons = self.max_number_of_neurons.ok_or_else(|| {
            "NervousSystemParameters.max_number_of_neurons must be set".to_string()
        })?;

        if max_number_of_neurons > Self::MAX_NUMBER_OF_NEURONS_CEILING {
            Err(format!(
                "NervousSystemParameters.max_number_of_neurons must be less than {}",
                Self::MAX_NUMBER_OF_NEURONS_CEILING
            ))
        } else if max_number_of_neurons == 0 {
            Err("NervousSystemParameters.max_number_of_neurons must be greater than 0".to_string())
        } else {
            Ok(())
        }
    }

    /// Validates that the nervous system parameter
    /// neuron_minimum_dissolve_delay_to_vote_seconds is well-formed.
    fn validate_neuron_minimum_dissolve_delay_to_vote_seconds(&self) -> Result<(), String> {
        let max_dissolve_delay_seconds = self.validate_max_dissolve_delay_seconds()?;

        let neuron_minimum_dissolve_delay_to_vote_seconds = self
            .neuron_minimum_dissolve_delay_to_vote_seconds
            .ok_or_else(|| {
                "NervousSystemParameters.neuron_minimum_dissolve_delay_to_vote_seconds must be set"
                    .to_string()
            })?;

        if neuron_minimum_dissolve_delay_to_vote_seconds > max_dissolve_delay_seconds {
            Err(format!(
                "The minimum dissolve delay to vote ({neuron_minimum_dissolve_delay_to_vote_seconds}) cannot be greater than the max \
                dissolve delay ({max_dissolve_delay_seconds})"
            ))
        } else {
            Ok(())
        }
    }

    /// Validates that the nervous system parameter max_followees_per_function is well-formed.
    fn validate_max_followees_per_function(&self) -> Result<u64, String> {
        let max_followees_per_function = self.max_followees_per_function.ok_or_else(|| {
            "NervousSystemParameters.max_followees_per_function must be set".to_string()
        })?;

        if max_followees_per_function > Self::MAX_FOLLOWEES_PER_FUNCTION_CEILING {
            Err(format!(
                "NervousSystemParameters.max_followees_per_function ({}) cannot be greater than {}",
                max_followees_per_function,
                Self::MAX_FOLLOWEES_PER_FUNCTION_CEILING
            ))
        } else {
            Ok(max_followees_per_function)
        }
    }

    /// Validates that the nervous system parameter max_dissolve_delay_seconds is well-formed.
    fn validate_max_dissolve_delay_seconds(&self) -> Result<u64, String> {
        self.max_dissolve_delay_seconds.ok_or_else(|| {
            "NervousSystemParameters.max_dissolve_delay_seconds must be set".to_string()
        })
    }

    /// Validates that the nervous system parameter max_neuron_age_for_age_bonus is well-formed.
    fn validate_max_neuron_age_for_age_bonus(&self) -> Result<(), String> {
        self.max_neuron_age_for_age_bonus.ok_or_else(|| {
            "NervousSystemParameters.max_neuron_age_for_age_bonus must be set".to_string()
        })?;

        Ok(())
    }

    /// Validates that the nervous system parameter max_number_of_proposals_with_ballots
    /// is well-formed.
    fn validate_max_number_of_proposals_with_ballots(&self) -> Result<(), String> {
        let max_number_of_proposals_with_ballots =
            self.max_number_of_proposals_with_ballots.ok_or_else(|| {
                "NervousSystemParameters.max_number_of_proposals_with_ballots must be set"
                    .to_string()
            })?;

        if max_number_of_proposals_with_ballots == 0 {
            Err(
                "NervousSystemParameters.max_number_of_proposals_with_ballots must be greater than 0"
                    .to_string(),
            )
        } else if max_number_of_proposals_with_ballots
            > Self::MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS_CEILING
        {
            Err(format!(
                "NervousSystemParameters.max_number_of_proposals_with_ballots must be less than {}",
                Self::MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS_CEILING
            ))
        } else {
            Ok(())
        }
    }

    /// Validates that the nervous system parameter neuron_claimer_permissions is well-formed.
    fn validate_neuron_claimer_permissions(&self) -> Result<(), String> {
        let neuron_claimer_permissions =
            self.neuron_claimer_permissions.as_ref().ok_or_else(|| {
                "NervousSystemParameters.neuron_claimer_permissions must be set".to_string()
            })?;

        let neuron_claimer_permissions = neuron_claimer_permissions.clone().try_into().unwrap();

        let required_claimer_permissions = Self::REQUIRED_NEURON_CLAIMER_PERMISSIONS
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();

        let difference = required_claimer_permissions
            .difference(&neuron_claimer_permissions)
            .collect::<Vec<_>>();

        if !difference.is_empty() {
            return Err(format!(
                "NervousSystemParameters.neuron_claimer_permissions is missing the required permissions {difference:?}",
            ));
        }
        Ok(())
    }

    /// Returns the default for the nervous system parameter neuron_claimer_permissions.
    fn default_neuron_claimer_permissions() -> NeuronPermissionList {
        NeuronPermissionList {
            permissions: Self::REQUIRED_NEURON_CLAIMER_PERMISSIONS
                .iter()
                .map(|p| *p as i32)
                .collect(),
        }
    }

    /// Validates that the nervous system parameter neuron_grantable_permissions is well-formed.
    fn validate_neuron_grantable_permissions(&self) -> Result<(), String> {
        self.neuron_grantable_permissions.as_ref().ok_or_else(|| {
            "NervousSystemParameters.neuron_grantable_permissions must be set".to_string()
        })?;

        Ok(())
    }

    /// Validates that the nervous system parameter max_number_of_principals_per_neuron
    /// is well-formed.
    fn validate_max_number_of_principals_per_neuron(&self) -> Result<(), String> {
        let max_number_of_principals_per_neuron =
            self.max_number_of_principals_per_neuron.ok_or_else(|| {
                "NervousSystemParameters.max_number_of_principals_per_neuron must be set"
                    .to_string()
            })?;

        if max_number_of_principals_per_neuron < Self::MAX_NUMBER_OF_PRINCIPALS_PER_NEURON_FLOOR {
            Err(format!(
                "NervousSystemParameters.max_number_of_principals_per_neuron must be greater than or equal to {}",
                Self::MAX_NUMBER_OF_PRINCIPALS_PER_NEURON_FLOOR
            ))
        } else if max_number_of_principals_per_neuron
            > Self::MAX_NUMBER_OF_PRINCIPALS_PER_NEURON_CEILING
        {
            Err(format!(
                "NervousSystemParameters.max_number_of_principals_per_neuron must be at most {}",
                Self::MAX_NUMBER_OF_PRINCIPALS_PER_NEURON_CEILING
            ))
        } else {
            Ok(())
        }
    }

    /// Validates that the nervous system parameter max_dissolve_delay_bonus_percentage
    /// is well-formed.
    fn validate_max_dissolve_delay_bonus_percentage(&self) -> Result<(), String> {
        let max_dissolve_delay_bonus_percentage =
            self.max_dissolve_delay_bonus_percentage.ok_or_else(|| {
                "NervousSystemParameters.max_dissolve_delay_bonus_percentage must be set"
                    .to_string()
            })?;

        if max_dissolve_delay_bonus_percentage > Self::MAX_DISSOLVE_DELAY_BONUS_PERCENTAGE_CEILING {
            Err(format!(
                "NervousSystemParameters.max_dissolve_delay_bonus_percentage must be less than {}",
                Self::MAX_DISSOLVE_DELAY_BONUS_PERCENTAGE_CEILING
            ))
        } else {
            Ok(())
        }
    }

    /// Validates that the nervous system parameter max_age_bonus_percentage
    /// is well-formed.
    fn validate_max_age_bonus_percentage(&self) -> Result<(), String> {
        let max_age_bonus_percentage = self.max_age_bonus_percentage.ok_or_else(|| {
            "NervousSystemParameters.max_age_bonus_percentage must be set".to_string()
        })?;

        if max_age_bonus_percentage > Self::MAX_AGE_BONUS_PERCENTAGE_CEILING {
            Err(format!(
                "NervousSystemParameters.max_age_bonus_percentage must be less than {}",
                Self::MAX_AGE_BONUS_PERCENTAGE_CEILING
            ))
        } else {
            Ok(())
        }
    }

    /// Given a NeuronPermissionList, check whether the provided list can be
    /// granted given the `NervousSystemParameters::neuron_grantable_permissions`.
    /// Format a useful error if not.
    pub fn check_permissions_are_grantable(
        &self,
        neuron_permission_list: &NeuronPermissionList,
    ) -> Result<(), GovernanceError> {
        let mut illegal_permissions = HashSet::new();

        let grantable_permissions: HashSet<&i32> = self
            .neuron_grantable_permissions
            .as_ref()
            .expect("NervousSystemParameters.neuron_grantable_permissions must be present")
            .permissions
            .iter()
            .collect();

        for permission in &neuron_permission_list.permissions {
            if !grantable_permissions.contains(&permission) {
                illegal_permissions.insert(NeuronPermissionType::try_from(*permission).ok());
            }
        }

        if !illegal_permissions.is_empty() {
            return Err(GovernanceError::new_with_message(
                ErrorType::AccessControlList,
                format!(
                    "Cannot grant permissions as one or more permissions is not \
                    allowed to be granted. Illegal Permissions: {illegal_permissions:?}"
                ),
            ));
        }

        Ok(())
    }

    /// The voting_rewards_parameters is considered valid if it is either
    /// unpopulated, or if it is populated with a value that is itself valid
    /// (according to VotingRewardsParameters::validate).
    fn validate_voting_rewards_parameters(&self) -> Result<(), String> {
        let voting_rewards_parameters = self
            .voting_rewards_parameters
            .as_ref()
            .ok_or("NervousSystemParameters.voting_rewards_parameters must be set")?;
        voting_rewards_parameters.validate()
    }
}

impl GovernanceError {
    pub fn new(error_type: ErrorType) -> Self {
        GovernanceError {
            error_type: error_type as i32,
            ..Default::default()
        }
    }

    pub fn new_with_message(error_type: ErrorType, message: impl ToString) -> Self {
        GovernanceError {
            error_type: error_type as i32,
            error_message: message.to_string(),
        }
    }
}

impl fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}: {}", self.error_type(), self.error_message)
    }
}

impl std::error::Error for crate::pb::v1::GovernanceError {}

impl From<NervousSystemError> for GovernanceError {
    fn from(nervous_system_error: NervousSystemError) -> Self {
        GovernanceError {
            error_type: ErrorType::External as i32,
            error_message: nervous_system_error.error_message,
        }
    }
}

impl From<prost::DecodeError> for GovernanceError {
    fn from(decode_error: prost::DecodeError) -> Self {
        GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            format!("Invalid mode for install_code: {decode_error}"),
        )
    }
}

impl From<prost::UnknownEnumValue> for GovernanceError {
    fn from(unknown_enum_value: prost::UnknownEnumValue) -> Self {
        GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            format!("Unknown enum value: {unknown_enum_value}"),
        )
    }
}

impl From<CanisterInstallModeError> for GovernanceError {
    fn from(canister_install_mode_error: CanisterInstallModeError) -> Self {
        GovernanceError {
            error_type: ErrorType::External as i32,
            error_message: format!(
                "Invalid mode for install_code: {}",
                canister_install_mode_error.0
            ),
        }
    }
}

impl Vote {
    /// Returns whether this vote is eligible for voting rewards.
    pub(crate) fn eligible_for_rewards(&self) -> bool {
        match self {
            Vote::Unspecified => false,
            Vote::Yes => true,
            Vote::No => true,
        }
    }

    pub fn opposite(self) -> Self {
        match self {
            Self::Yes => Self::No,
            Self::No => Self::Yes,
            Self::Unspecified => Self::Unspecified,
        }
    }
}

impl NervousSystemFunction {
    pub fn is_native(&self) -> bool {
        matches!(
            self.function_type,
            Some(FunctionType::NativeNervousSystemFunction(_))
        )
    }

    /// The special cases are for:
    /// - `EXECUTE_GENERIC_NERVOUS_SYSTEM_FUNCTION` which wraps custom
    ///   proposals of this SNS While technically being a native function
    /// - `EXECUTE_EXTENSION_OPERATION` which are custom functions for extensions
    ///   which have their own topics defined on the extension operation spec
    pub fn needs_topic(&self) -> bool {
        ![
            native_action_ids::EXECUTE_GENERIC_NERVOUS_SYSTEM_FUNCTION,
            native_action_ids::EXECUTE_EXTENSION_OPERATION,
        ]
        .contains(&self.id)
    }

    fn unspecified() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::UNSPECIFIED,
            name: "All non-critical topics".to_string(),
            description: Some(
                "Catch-all w.r.t to following for non-critical proposals.".to_string(),
            ),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn motion() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::MOTION,
            name: "Motion".to_string(),
            description: Some(
                "Side-effect-less proposals to set general governance direction.".to_string(),
            ),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn manage_nervous_system_parameters() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::MANAGE_NERVOUS_SYSTEM_PARAMETERS,
            name: "Manage nervous system parameters".to_string(),
            description: Some(
                "Proposal to change the core parameters of SNS governance.".to_string(),
            ),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn upgrade_sns_controlled_canister() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::UPGRADE_SNS_CONTROLLED_CANISTER,
            name: "Upgrade SNS controlled canister".to_string(),
            description: Some(
                "Proposal to upgrade the wasm of an SNS controlled canister.".to_string(),
            ),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn add_generic_nervous_system_function() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::ADD_GENERIC_NERVOUS_SYSTEM_FUNCTION,
            name: "Add nervous system function".to_string(),
            description: Some("Proposal to add a new, user-defined, nervous system function: a canister call which can then be executed by proposal.".to_string()),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn remove_generic_nervous_system_function() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::REMOVE_GENERIC_NERVOUS_SYSTEM_FUNCTION,
            name: "Remove nervous system function".to_string(),
            description: Some("Proposal to remove a user-defined nervous system function, which will be no longer executable by proposal.".to_string()),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn execute_generic_nervous_system_function() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::EXECUTE_GENERIC_NERVOUS_SYSTEM_FUNCTION,
            name: "Execute nervous system function".to_string(),
            description: Some("Proposal to execute a user-defined nervous system function, previously added by an AddNervousSystemFunction proposal. A canister call will be made when executed.".to_string()),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn execute_extension_operation() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::EXECUTE_EXTENSION_OPERATION,
            name: "Execute SNS extension operation".to_string(),
            description: Some(
                "Proposal to execute an operation on a registered SNS extension.".to_string(),
            ),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn upgrade_extension() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::UPGRADE_EXTENSION,
            name: "Upgrade SNS extension".to_string(),
            description: Some(
                "Proposal to upgrade the WASM of a registered SNS extension.".to_string(),
            ),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn upgrade_sns_to_next_version() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::UPGRADE_SNS_TO_NEXT_VERSION,
            name: "Upgrade SNS to next version".to_string(),
            description: Some("Proposal to upgrade the WASM of a core SNS canister.".to_string()),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn manage_sns_metadata() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::MANAGE_SNS_METADATA,
            name: "Manage SNS metadata".to_string(),
            description: Some(
                "Proposal to change the metadata associated with an SNS.".to_string(),
            ),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn transfer_sns_treasury_funds() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::TRANSFER_SNS_TREASURY_FUNDS,
            name: "Transfer SNS treasury funds".to_string(),
            description: Some(
                "Proposal to transfer funds from an SNS Governance controlled treasury account"
                    .to_string(),
            ),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn register_dapp_canisters() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::REGISTER_DAPP_CANISTERS,
            name: "Register dapp canisters".to_string(),
            description: Some("Proposal to register a dapp canister with the SNS.".to_string()),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn register_extension() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::REGISTER_EXTENSION,
            name: "Register SNS extension".to_string(),
            description: Some("Proposal to register a new SNS extension.".to_string()),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn deregister_dapp_canisters() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::DEREGISTER_DAPP_CANISTERS,
            name: "Deregister Dapp Canisters".to_string(),
            description: Some(
                "Proposal to deregister a previously-registered dapp canister from the SNS."
                    .to_string(),
            ),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn mint_sns_tokens() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::MINT_SNS_TOKENS,
            name: "Mint SNS tokens".to_string(),
            description: Some("Proposal to mint SNS tokens to a specified recipient.".to_string()),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn manage_ledger_parameters() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::MANAGE_LEDGER_PARAMETERS,
            name: "Manage ledger parameters".to_string(),
            description: Some(
                "Proposal to change some parameters in the ledger canister.".to_string(),
            ),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn manage_dapp_canister_settings() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::MANAGE_DAPP_CANISTER_SETTINGS,
            name: "Manage dapp canister settings".to_string(),
            description: Some(
                "Proposal to change canister settings for some dapp canisters.".to_string(),
            ),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn advance_sns_target_version() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::ADVANCE_SNS_TARGET_VERSION,
            name: "Advance SNS target version".to_string(),
            description: Some("Proposal to advance the target version of this SNS.".to_string()),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }

    fn set_topics_for_custom_proposals() -> NervousSystemFunction {
        NervousSystemFunction {
            id: native_action_ids::SET_TOPICS_FOR_CUSTOM_PROPOSALS_ACTION,
            name: "Set topics for custom proposals".to_string(),
            description: Some("Proposal to set the topics for custom SNS proposals.".to_string()),
            function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
        }
    }
}

impl From<Action> for NervousSystemFunction {
    fn from(action: Action) -> Self {
        match action {
            Action::Unspecified(_) => NervousSystemFunction::unspecified(),
            Action::Motion(_) => NervousSystemFunction::motion(),
            Action::ManageNervousSystemParameters(_) => {
                NervousSystemFunction::manage_nervous_system_parameters()
            }
            Action::UpgradeSnsControlledCanister(_) => {
                NervousSystemFunction::upgrade_sns_controlled_canister()
            }
            Action::AddGenericNervousSystemFunction(_) => {
                NervousSystemFunction::add_generic_nervous_system_function()
            }
            Action::RemoveGenericNervousSystemFunction(_) => {
                NervousSystemFunction::remove_generic_nervous_system_function()
            }

            Action::ExecuteGenericNervousSystemFunction(_) => {
                NervousSystemFunction::execute_generic_nervous_system_function()
            }

            Action::ExecuteExtensionOperation(_) => {
                NervousSystemFunction::execute_extension_operation()
            }

            Action::UpgradeSnsToNextVersion(_) => {
                NervousSystemFunction::upgrade_sns_to_next_version()
            }
            Action::ManageSnsMetadata(_) => NervousSystemFunction::manage_sns_metadata(),
            Action::TransferSnsTreasuryFunds(_) => {
                NervousSystemFunction::transfer_sns_treasury_funds()
            }
            Action::RegisterDappCanisters(_) => NervousSystemFunction::register_dapp_canisters(),
            Action::RegisterExtension(_) => NervousSystemFunction::register_extension(),
            Action::UpgradeExtension(_) => NervousSystemFunction::upgrade_extension(),
            Action::DeregisterDappCanisters(_) => {
                NervousSystemFunction::deregister_dapp_canisters()
            }
            Action::MintSnsTokens(_) => NervousSystemFunction::mint_sns_tokens(),
            Action::ManageLedgerParameters(_) => NervousSystemFunction::manage_ledger_parameters(),
            Action::ManageDappCanisterSettings(_) => {
                NervousSystemFunction::manage_dapp_canister_settings()
            }
            Action::AdvanceSnsTargetVersion(_) => {
                NervousSystemFunction::advance_sns_target_version()
            }
            Action::SetTopicsForCustomProposals(_) => {
                NervousSystemFunction::set_topics_for_custom_proposals()
            }
        }
    }
}

impl manage_neuron::Command {
    pub fn increase_dissolve_delay(additional_dissolve_delay_seconds: u32) -> Self {
        manage_neuron::Command::Configure(manage_neuron::Configure {
            operation: Some(manage_neuron::configure::Operation::IncreaseDissolveDelay(
                manage_neuron::IncreaseDissolveDelay {
                    additional_dissolve_delay_seconds,
                },
            )),
        })
    }

    pub fn start_dissolving() -> Self {
        manage_neuron::Command::Configure(manage_neuron::Configure {
            operation: Some(manage_neuron::configure::Operation::StartDissolving(
                manage_neuron::StartDissolving {},
            )),
        })
    }

    pub fn stop_dissolving() -> Self {
        manage_neuron::Command::Configure(manage_neuron::Configure {
            operation: Some(manage_neuron::configure::Operation::StopDissolving(
                manage_neuron::StopDissolving {},
            )),
        })
    }

    pub fn set_dissolve_timestamp(dissolve_timestamp_seconds: u64) -> Self {
        manage_neuron::Command::Configure(manage_neuron::Configure {
            operation: Some(manage_neuron::configure::Operation::SetDissolveTimestamp(
                manage_neuron::SetDissolveTimestamp {
                    dissolve_timestamp_seconds,
                },
            )),
        })
    }

    pub fn change_auto_stake_maturity(requested_setting_for_auto_stake_maturity: bool) -> Self {
        manage_neuron::Command::Configure(manage_neuron::Configure {
            operation: Some(
                manage_neuron::configure::Operation::ChangeAutoStakeMaturity(
                    manage_neuron::ChangeAutoStakeMaturity {
                        requested_setting_for_auto_stake_maturity,
                    },
                ),
            ),
        })
    }

    /// Returns a string representing what "kind" of command this is.
    pub fn command_name(&self) -> String {
        match self {
            manage_neuron::Command::Configure(_) => "Configure",
            manage_neuron::Command::Disburse(_) => "Disburse",
            manage_neuron::Command::Follow(_) => "Follow",
            manage_neuron::Command::SetFollowing(_) => "SetFollowing",
            manage_neuron::Command::MakeProposal(_) => "MakeProposal",
            manage_neuron::Command::RegisterVote(_) => "RegisterVote",
            manage_neuron::Command::Split(_) => "Split",
            manage_neuron::Command::ClaimOrRefresh(_) => "ClaimOrRefresh",
            manage_neuron::Command::MergeMaturity(_) => "MergeMaturity",
            manage_neuron::Command::DisburseMaturity(_) => "DisburseMaturity",
            manage_neuron::Command::AddNeuronPermissions(_) => "AddNeuronPermissions",
            manage_neuron::Command::RemoveNeuronPermissions(_) => "RemoveNeuronPermissions",
            manage_neuron::Command::StakeMaturity(_) => "StakeMaturity",
        }
        .to_string()
    }
}

impl ManageNeuronResponse {
    pub fn is_err(&self) -> bool {
        matches!(
            &self.command,
            Some(manage_neuron_response::Command::Error(_))
        )
    }

    pub fn err_ref(&self) -> Option<&GovernanceError> {
        match &self.command {
            Some(manage_neuron_response::Command::Error(err)) => Some(err),
            _ => None,
        }
    }

    pub fn err(self) -> Option<GovernanceError> {
        match self.command {
            Some(manage_neuron_response::Command::Error(err)) => Some(err),
            _ => None,
        }
    }

    pub fn is_ok(&self) -> bool {
        !self.is_err()
    }

    pub fn expect(self, msg: &str) -> Self {
        if let Some(manage_neuron_response::Command::Error(err)) = &self.command {
            panic!("{msg}: {err}");
        }
        self
    }

    pub fn error(err: GovernanceError) -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Error(err)),
        }
    }

    pub fn configure_response() -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Configure(
                manage_neuron_response::ConfigureResponse {},
            )),
        }
    }

    pub fn disburse_response(transfer_block_height: u64) -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Disburse(
                manage_neuron_response::DisburseResponse {
                    transfer_block_height,
                },
            )),
        }
    }

    pub fn merge_maturity_response(response: MergeMaturityResponse) -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::MergeMaturity(response)),
        }
    }

    pub fn disburse_maturity_response(response: DisburseMaturityResponse) -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::DisburseMaturity(response)),
        }
    }

    pub fn stake_maturity_response(response: StakeMaturityResponse) -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::StakeMaturity(response)),
        }
    }

    pub fn follow_response() -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Follow(
                manage_neuron_response::FollowResponse {},
            )),
        }
    }

    pub fn set_following_response() -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::SetFollowing(
                manage_neuron_response::SetFollowingResponse {},
            )),
        }
    }

    pub fn make_proposal_response(proposal_id: ProposalId) -> Self {
        let proposal_id = Some(proposal_id);
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::MakeProposal(
                manage_neuron_response::MakeProposalResponse { proposal_id },
            )),
        }
    }

    pub fn register_vote_response() -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::RegisterVote(
                manage_neuron_response::RegisterVoteResponse {},
            )),
        }
    }

    pub fn split_response(created_neuron_id: NeuronId) -> Self {
        let created_neuron_id = Some(created_neuron_id);
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Split(
                manage_neuron_response::SplitResponse { created_neuron_id },
            )),
        }
    }

    pub fn claim_or_refresh_neuron_response(refreshed_neuron_id: NeuronId) -> Self {
        let refreshed_neuron_id = Some(refreshed_neuron_id);
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::ClaimOrRefresh(
                manage_neuron_response::ClaimOrRefreshResponse {
                    refreshed_neuron_id,
                },
            )),
        }
    }

    pub fn add_neuron_permissions_response() -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::AddNeuronPermission(
                manage_neuron_response::AddNeuronPermissionsResponse {},
            )),
        }
    }

    pub fn remove_neuron_permissions_response() -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::RemoveNeuronPermission(
                manage_neuron_response::RemoveNeuronPermissionsResponse {},
            )),
        }
    }
}

impl SnsMetadata {
    /// The maximum number of characters allowed for a SNS url.
    pub const MAX_URL_LENGTH: usize = 512;

    /// The minimum number of characters allowed for a SNS url.
    pub const MIN_URL_LENGTH: usize = 10;

    /// The maximum number of characters allowed for a SNS name.
    pub const MAX_NAME_LENGTH: usize = 255;

    /// The minimum number of characters allowed for a SNS name.
    pub const MIN_NAME_LENGTH: usize = 4;

    /// The maximum number of characters allowed for a SNS description.
    pub const MAX_DESCRIPTION_LENGTH: usize = 2000;

    /// The minimum number of characters allowed for a SNS description.
    pub const MIN_DESCRIPTION_LENGTH: usize = 10;

    /// Validate the SnsMetadata values
    pub fn validate(&self) -> Result<(), String> {
        let url = self.url.as_ref().ok_or("SnsMetadata.url must be set")?;
        Self::validate_url(url)?;

        if let Some(logo) = &self.logo {
            Self::validate_logo(logo)?;
        }

        let name = self.name.as_ref().ok_or("SnsMetadata.name must be set")?;
        Self::validate_name(name)?;

        let description = self
            .description
            .as_ref()
            .ok_or("SnsMetadata.description must be set")?;
        Self::validate_description(description)?;
        Ok(())
    }

    pub fn validate_url(url: &str) -> Result<(), String> {
        validate_url(
            url,
            Self::MIN_URL_LENGTH,
            Self::MAX_URL_LENGTH,
            "SnsMetadata.url",
            None,
        )
    }

    pub fn validate_logo(logo: &str) -> Result<(), String> {
        const PREFIX: &str = "data:image/png;base64,";
        // TODO: Should we check that it's a valid PNG?
        if logo.len() > MAX_LOGO_LENGTH {
            return Err(format!(
                "SnsMetadata.logo must be less than {MAX_LOGO_LENGTH} characters, roughly 256 Kb"
            ));
        }
        if !logo.starts_with(PREFIX) {
            return Err(format!(
                "SnsMetadata.logo must be a base64 encoded PNG, but the provided string does't begin with `{PREFIX}`."
            ));
        }
        if base64::decode(&logo[PREFIX.len()..]).is_err() {
            return Err("Couldn't decode base64 in SnsMetadata.logo".to_string());
        }
        Ok(())
    }

    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.len() > Self::MAX_NAME_LENGTH {
            return Err(format!(
                "SnsMetadata.name must be less than {} characters",
                Self::MAX_NAME_LENGTH
            ));
        } else if name.len() < Self::MIN_NAME_LENGTH {
            return Err(format!(
                "SnsMetadata.name must be greater than {} characters",
                Self::MIN_NAME_LENGTH
            ));
        }
        Ok(())
    }

    pub fn validate_description(description: &str) -> Result<(), String> {
        if description.len() > Self::MAX_DESCRIPTION_LENGTH {
            return Err(format!(
                "SnsMetadata.description must be less than {} characters",
                Self::MAX_DESCRIPTION_LENGTH
            ));
        } else if description.len() < Self::MIN_DESCRIPTION_LENGTH {
            return Err(format!(
                "SnsMetadata.description must be greater than {} characters",
                Self::MIN_DESCRIPTION_LENGTH
            ));
        }
        Ok(())
    }

    pub fn with_default_values_for_testing() -> Self {
        SnsMetadata {
            logo: Some("data:image/png;base64,".to_string()),
            url: Some("https://dfinity.org".to_string()),
            name: Some("SNS-Name".to_string()),
            description: Some("SNS-Description".to_string()),
        }
    }
}

lazy_static! {
    static ref DEFAULT_ACTION: Action = Action::Unspecified(Default::default());
}

impl Default for &Action {
    fn default() -> Self {
        &DEFAULT_ACTION
    }
}

impl Action {
    /// Returns whether proposals with such an action should be allowed to
    /// be submitted when the heap growth potential is low.
    pub(crate) fn allowed_when_resources_are_low(&self) -> bool {
        match self {
            // Due to possible need of an emergency upgrade of the dapp
            Action::UpgradeSnsControlledCanister(_) => true,
            // Due to possible need of an emergency upgrade of the SNS
            Action::UpgradeSnsToNextVersion(_) => true,
            // Due to possible need of emergency functions defined as
            // GenericNervousSystemFunctions
            Action::ExecuteGenericNervousSystemFunction(_) => true,
            _ => false,
        }
    }

    /// Returns the native functions, i.e. the ones that are supported directly by the governance canister.
    pub fn native_functions() -> Vec<NervousSystemFunction> {
        Self::iter().map(NervousSystemFunction::from).collect()
    }

    /// The current set of valid native function ids, for the purposes of following.
    /// See `Proposal`.
    /// See `impl From<&Action> for u64`.
    pub fn native_function_ids() -> Vec<u64> {
        Action::native_functions()
            .into_iter()
            .map(|m| m.id)
            .collect()
    }

    /// Returns a clone of self, except that "large blob fields" are replaced
    /// with a (UTF-8 encoded) textual summary of their contents. See
    /// summarize_blob_field.
    pub(crate) fn limited_for_get_proposal(&self) -> Self {
        match self {
            Action::UpgradeSnsControlledCanister(action) => {
                Action::UpgradeSnsControlledCanister(action.limited_for_get_proposal())
            }
            Action::ExecuteGenericNervousSystemFunction(action) => {
                Action::ExecuteGenericNervousSystemFunction(action.limited_for_get_proposal())
            }
            action => action.clone(),
        }
    }

    /// Returns a clone of self, except that "large blob fields" are cleared.
    pub(crate) fn limited_for_list_proposals(&self) -> Self {
        match self {
            Action::UpgradeSnsControlledCanister(action) => {
                Action::UpgradeSnsControlledCanister(action.limited_for_list_proposals())
            }
            Action::ExecuteGenericNervousSystemFunction(action) => {
                Action::ExecuteGenericNervousSystemFunction(action.limited_for_list_proposals())
            }
            Action::ManageSnsMetadata(action) => {
                Action::ManageSnsMetadata(action.limited_for_list_proposals())
            }
            Action::ManageLedgerParameters(action) => {
                Action::ManageLedgerParameters(action.limited_for_list_proposals())
            }
            action => action.clone(),
        }
    }

    pub(crate) fn voting_duration_parameters(
        &self,
        nervous_system_parameters: &NervousSystemParameters,
        proposal_criticality: ProposalCriticality,
    ) -> VotingDurationParameters {
        let initial_voting_period_seconds = nervous_system_parameters.initial_voting_period_seconds;
        let wait_for_quiet_deadline_increase_seconds =
            nervous_system_parameters.wait_for_quiet_deadline_increase_seconds;

        match proposal_criticality {
            ProposalCriticality::Normal => VotingDurationParameters {
                initial_voting_period: PbDuration {
                    seconds: initial_voting_period_seconds,
                },
                wait_for_quiet_deadline_increase: PbDuration {
                    seconds: wait_for_quiet_deadline_increase_seconds,
                },
            },

            ProposalCriticality::Critical => {
                let initial_voting_period_seconds =
                    initial_voting_period_seconds.unwrap_or_default();
                let wait_for_quiet_deadline_increase_seconds =
                    wait_for_quiet_deadline_increase_seconds.unwrap_or_default();

                VotingDurationParameters {
                    initial_voting_period: PbDuration {
                        seconds: Some(initial_voting_period_seconds.max(5 * ONE_DAY_SECONDS)),
                    },
                    wait_for_quiet_deadline_increase: PbDuration {
                        seconds: Some(wait_for_quiet_deadline_increase_seconds.max(
                            2 * ONE_DAY_SECONDS + ONE_DAY_SECONDS / 2, // 2.5 days
                        )),
                    },
                }
            }
        }
    }
}

impl UpgradeSnsControlledCanister {
    /// Returns a clone of self, except that "large blob fields" are replaced
    /// with a (UTF-8 encoded) textual summary of their contents. See
    /// summarize_blob_field.
    pub(crate) fn limited_for_get_proposal(&self) -> Self {
        Self {
            canister_id: self.canister_id,
            new_canister_wasm: summarize_blob_field(&self.new_canister_wasm),
            canister_upgrade_arg: self
                .canister_upgrade_arg
                .as_ref()
                .map(|blob| summarize_blob_field(blob)),
            mode: self.mode,
            chunked_canister_wasm: self.chunked_canister_wasm.clone(),
        }
    }

    // Returns a clone of self, except that "large blob fields" are cleared.
    pub(crate) fn limited_for_list_proposals(&self) -> Self {
        Self {
            canister_id: self.canister_id,
            canister_upgrade_arg: self.canister_upgrade_arg.clone(),
            mode: self.mode,
            new_canister_wasm: Vec::new(),
            chunked_canister_wasm: self.chunked_canister_wasm.clone(),
        }
    }
}

impl ExecuteGenericNervousSystemFunction {
    /// Returns a clone of self, except that "large blob fields" are replaced
    /// with a (UTF-8 encoded) textual summary of their contents. See
    /// summarize_blob_field.
    pub(crate) fn limited_for_get_proposal(&self) -> Self {
        Self {
            function_id: self.function_id,
            payload: summarize_blob_field(&self.payload),
        }
    }

    /// Returns a clone of self, except that "large blob fields" are cleared.
    pub(crate) fn limited_for_list_proposals(&self) -> Self {
        Self {
            function_id: self.function_id,
            payload: Vec::new(),
        }
    }
}

impl ManageSnsMetadata {
    /// Returns a clone of self, except that the logo is cleared because it can be large.
    pub(crate) fn limited_for_list_proposals(&self) -> Self {
        Self {
            url: self.url.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            logo: None,
        }
    }
}

impl ManageLedgerParameters {
    /// Returns a clone of self, except that the logo is cleared because it can be large.
    pub(crate) fn limited_for_list_proposals(&self) -> Self {
        Self {
            transfer_fee: self.transfer_fee,
            token_name: self.token_name.clone(),
            token_symbol: self.token_symbol.clone(),
            token_logo: None,
        }
    }
}

/// If blob is of length <= 64 (bytes), a copy is returned. Otherwise, a (UTF-8
/// encoded) human-readable textual summary is returned. This summary is
/// guaranteed to be of length > 64. Therefore, it is always possible to
/// disambiguate between direct copying and summary.
fn summarize_blob_field(blob: &[u8]) -> Vec<u8> {
    if blob.len() <= 64 {
        return Vec::from(blob);
    }

    fn format_u8_slice(blob: &[u8]) -> String {
        blob.iter()
            // Hexify each element.
            .map(|elt| format!("{elt:02X?}"))
            // Join them with a space. (To do that, we must first collect them into a Vec.)
            .collect::<Vec<String>>()
            .join(" ")
    }

    Vec::<u8>::from(
        format!(
            "⚠️ NOT THE ORIGINAL CONTENTS OF THIS FIELD ⚠️\n\
             \n\
             The original value had the following properties:\n\
             - Length: {}\n\
             - SHA256 Hash:                {}\n\
             - Leading  32 Bytes (in hex): {}\n\
             - Trailing 32 Bytes (in hex): {}",
            blob.len(),
            format_u8_slice(&Sha256::hash(blob)),
            format_u8_slice(blob.chunks_exact(32).next().unwrap_or(&[])),
            format_u8_slice(blob.rchunks_exact(32).next().unwrap_or(&[])),
        )
        .as_bytes(),
    )
}

// Mapping of action to the unique function id of that action.
impl From<&Action> for u64 {
    fn from(action: &Action) -> Self {
        match action {
            Action::Unspecified(_) => native_action_ids::UNSPECIFIED,
            Action::Motion(_) => native_action_ids::MOTION,
            Action::ManageNervousSystemParameters(_) => {
                native_action_ids::MANAGE_NERVOUS_SYSTEM_PARAMETERS
            }
            Action::UpgradeSnsControlledCanister(_) => {
                native_action_ids::UPGRADE_SNS_CONTROLLED_CANISTER
            }
            Action::UpgradeSnsToNextVersion(_) => native_action_ids::UPGRADE_SNS_TO_NEXT_VERSION,
            Action::AddGenericNervousSystemFunction(_) => {
                native_action_ids::ADD_GENERIC_NERVOUS_SYSTEM_FUNCTION
            }
            Action::RemoveGenericNervousSystemFunction(_) => {
                native_action_ids::REMOVE_GENERIC_NERVOUS_SYSTEM_FUNCTION
            }
            Action::ExecuteGenericNervousSystemFunction(proposal) => proposal.function_id,
            Action::ExecuteExtensionOperation(_) => native_action_ids::EXECUTE_EXTENSION_OPERATION,
            Action::RegisterDappCanisters(_) => native_action_ids::REGISTER_DAPP_CANISTERS,
            Action::RegisterExtension(_) => native_action_ids::REGISTER_EXTENSION,
            Action::UpgradeExtension(_) => native_action_ids::UPGRADE_EXTENSION,
            Action::DeregisterDappCanisters(_) => native_action_ids::DEREGISTER_DAPP_CANISTERS,
            Action::ManageSnsMetadata(_) => native_action_ids::MANAGE_SNS_METADATA,
            Action::TransferSnsTreasuryFunds(_) => native_action_ids::TRANSFER_SNS_TREASURY_FUNDS,
            Action::MintSnsTokens(_) => native_action_ids::MINT_SNS_TOKENS,
            Action::ManageLedgerParameters(_) => native_action_ids::MANAGE_LEDGER_PARAMETERS,
            Action::ManageDappCanisterSettings(_) => {
                native_action_ids::MANAGE_DAPP_CANISTER_SETTINGS
            }
            Action::AdvanceSnsTargetVersion(_) => native_action_ids::ADVANCE_SNS_TARGET_VERSION,
            Action::SetTopicsForCustomProposals(_) => {
                native_action_ids::SET_TOPICS_FOR_CUSTOM_PROPOSALS_ACTION
            }
        }
    }
}

pub fn is_registered_function_id(
    function_id: u64,
    nervous_system_functions: &BTreeMap<u64, NervousSystemFunction>,
) -> bool {
    // Check if the function id is present among the native actions.
    if Action::native_function_ids().contains(&function_id) {
        return true;
    }

    match nervous_system_functions.get(&function_id) {
        None => false,
        Some(function) => function != &*NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER,
    }
}

impl From<ManageLedgerParameters> for LedgerUpgradeArgs {
    fn from(manage_ledger_parameters: ManageLedgerParameters) -> Self {
        let ManageLedgerParameters {
            transfer_fee,
            token_name,
            token_symbol,
            token_logo,
        } = manage_ledger_parameters;

        let metadata = token_logo.map(|token_logo| {
            let key = MetadataKey::ICRC1_LOGO.to_string();
            let value = MetadataValue::Text(token_logo);
            vec![(key, value)]
        });

        LedgerUpgradeArgs {
            transfer_fee: transfer_fee.map(|tf| tf.into()),
            token_name,
            token_symbol,
            metadata,
            ..LedgerUpgradeArgs::default()
        }
    }
}

// This is almost a copy n' paste from NNS. The main difference (as of
// 2023-11-17) is to account for the fact that here in SNS,
// total_available_e8s_equivalent is optional. (Therefore, an extra
// unwrap_or_default call is added.)
impl RewardEvent {
    /// Calculates the total_available_e8s_equivalent in this event that should
    /// be "rolled over" into the next `RewardEvent`.
    ///
    /// Behavior:
    /// - If rewards were distributed for this event, then no available_icp_e8s
    ///   should be rolled over, so this function returns 0.
    /// - Otherwise, this function returns
    ///   `total_available_e8s_equivalent`.
    pub(crate) fn e8s_equivalent_to_be_rolled_over(&self) -> u64 {
        if self.rewards_rolled_over() {
            self.total_available_e8s_equivalent.unwrap_or_default()
        } else {
            0
        }
    }

    // Not copied from NNS: fn rounds_since_last_distribution_to_be_rolled_over

    /// Whether this is a "rollover event", where no rewards were distributed.
    pub(crate) fn rewards_rolled_over(&self) -> bool {
        self.settled_proposals.is_empty()
    }
}

/// Summarizes a RewardEvent. Suitable for logging, because the string is
/// bounded in size.
impl fmt::Display for RewardEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RewardEvent {{ end_timestamp_seconds: {} distributed_e8s_equivalent: {}\
                   actual_timestamp_seconds: {} settled_proposals: <vec of size {}> }})",
            self.end_timestamp_seconds.unwrap_or_default(),
            self.distributed_e8s_equivalent,
            self.actual_timestamp_seconds,
            self.settled_proposals.len(),
            // The `round` field is not shown, because it is deprecated.
        )
    }
}

/// A general trait for the environment in which governance is running.
///
/// See NativeEnvironment for an implementation that is often suitable for tests.
#[async_trait]
pub trait Environment: Send + Sync {
    /// Returns the current time, in seconds since the epoch.
    fn now(&self) -> u64;

    /// An optional feature used in tests to apply a delta to the canister's system timestamp.
    fn set_time_warp(&mut self, _new_time_warp: TimeWarp) {
        panic!("Not implemented.");
    }

    /// Returns a random number.
    ///
    /// This number is the same in all replicas.
    fn insecure_random_u64(&mut self) -> u64;

    /// Calls another canister. The return value indicates whether the call can be successfully
    /// initiated. If initiating the call is successful, the call could later be rejected by the
    /// remote canister. In CanisterEnv (the production implementation of this trait), to
    /// distinguish between whether the remote canister replies or rejects,
    /// set_proposal_execution_status is called (asynchronously). Therefore, the caller of
    /// call_canister should not call set_proposal_execution_status if call_canister returns Ok,
    /// because the call could fail later.
    async fn call_canister(
        &self,
        canister_id: CanisterId,
        method_name: &str,
        arg: Vec<u8>,
    ) -> Result<
        /* reply: */ Vec<u8>,
        (
            /* error_code: */ Option<i32>,
            /* message: */ String,
        ),
    >;

    /// Returns rough information as to how much the heap can grow.
    ///
    /// The intended use case is for the governance canister to avoid
    /// non-essential memory-consuming operations when the potential for heap
    /// growth becomes limited.
    fn heap_growth_potential(&self) -> HeapGrowthPotential;

    /// Returns the PrincipalId of the canister implementing the Environment trait.
    fn canister_id(&self) -> CanisterId;

    /// Returns the canister version of the canister implementing the Environment trait.
    fn canister_version(&self) -> Option<u64>;
}

/// Rough buckets for how much the heap can still grow.
pub enum HeapGrowthPotential {
    /// The heap can grow without issue.
    NoIssue,

    /// The heap can still grow, but not by much.
    LimitedAvailability,
}

/// A lock for a single ongoing update for a single neuron, ensuring that only a single
/// update can happen at a time for a given neuron.
/// Releases the lock when destroyed.
pub struct LedgerUpdateLock {
    pub nid: String,
    pub gov: *mut Governance,
}

impl Drop for LedgerUpdateLock {
    /// Drops the lock on the neuron.
    fn drop(&mut self) {
        // In the case of a panic, the state of the ledger account representing the neuron's stake
        // may be inconsistent with the internal state of governance.  In that case,
        // we want to prevent further operations with that neuron until the issue can be
        // investigated and resolved, which will require code changes.
        if ic_cdk::futures::is_recovering_from_trap() {
            return;
        }
        // It's always ok to dereference the governance when a LedgerUpdateLock
        // goes out of scope. Indeed, in the scope of any Governance method,
        // &self always remains alive. The 'mut' is not an issue, because
        // 'unlock_neuron' will verify that the lock exists.
        let gov: &mut Governance = unsafe { &mut *self.gov };
        gov.unlock_neuron(&self.nid);
    }
}

impl From<u64> for ProposalId {
    fn from(id: u64) -> Self {
        ProposalId { id }
    }
}

impl From<Vec<NeuronId>> for NeuronIds {
    fn from(neuron_ids: Vec<NeuronId>) -> Self {
        NeuronIds { neuron_ids }
    }
}

impl From<NeuronIds> for Vec<NeuronId> {
    fn from(neuron_ids: NeuronIds) -> Self {
        neuron_ids.neuron_ids
    }
}

impl NeuronRecipe {
    pub(crate) fn validate(
        &self,
        neuron_minimum_stake_e8s: u64,
        max_followees_per_function: u64,
        max_number_of_principals_per_neuron: u64,
    ) -> Result<(), String> {
        let mut defects = vec![];

        let Self {
            controller,
            neuron_id,
            stake_e8s,
            dissolve_delay_seconds,
            followees,
            participant,
        } = self;

        if neuron_id.is_none() {
            defects.push("Missing neuron_id".to_string());
        }

        if let Some(stake_e8s) = stake_e8s {
            if *stake_e8s < neuron_minimum_stake_e8s {
                defects.push(format!(
                    "Provided stake_e8s ({stake_e8s}) is less than the required neuron_minimum_stake_e8s({neuron_minimum_stake_e8s})"
                ));
            }
        } else {
            defects.push("Missing stake_e8s".to_string());
        }

        if dissolve_delay_seconds.is_none() {
            defects.push("Missing dissolve_delay_seconds".to_string());
        }

        if let Some(followees) = followees {
            let followees = &followees.neuron_ids;
            if followees.len() as u64 > max_followees_per_function {
                defects.push(format!(
                    "Provided number of followees ({}) exceeds the maximum \
                    number of followees per function ({})",
                    followees.len(),
                    max_followees_per_function
                ));
            }
        } else {
            defects.push("Missing followees".to_string());
        }

        if controller.is_none() {
            defects.push("Missing controller".to_string());
        }

        match participant {
            Some(Participant::Direct(_)) => {}
            Some(Participant::NeuronsFund(neuron_recipe::NeuronsFund {
                nns_neuron_id,
                nns_neuron_controller,
                nns_neuron_hotkeys,
            })) => {
                if nns_neuron_id.is_none() {
                    defects.push("Missing nns_neuron_id for neurons fund participant".to_string());
                }
                if nns_neuron_controller.is_none() {
                    defects.push(
                        "Missing nns_neuron_controller for neurons fund participant".to_string(),
                    );
                }
                if nns_neuron_hotkeys.is_none() {
                    defects.push(
                        "Missing nns_neuron_hotkeys for neurons fund participant".to_string(),
                    );
                }
            }
            None => {
                defects.push("Missing participant type (Direct or Neurons' Fund)".to_string());
            }
        }

        match self.construct_permissions(NeuronPermissionList::default()) {
            Ok(permissions) => {
                if permissions.len() > max_number_of_principals_per_neuron as usize {
                    defects.push(format!(
                        "Neuron recipe would correspond to a neuron with ({}) permissions ({:?}), exceeding the maximum \
                            number of permissions ({})",
                        permissions.len(),
                        permissions,
                        max_number_of_principals_per_neuron
                    ));
                }
            }
            Err(e) => {
                defects.push(e);
            }
        }

        if !defects.is_empty() {
            let participant_info = match participant {
                Some(Participant::Direct(_)) => {
                    format!("direct participant {:?}", self.controller)
                }
                Some(Participant::NeuronsFund(nf)) => {
                    format!("neurons fund participant {:?}", nf.nns_neuron_id)
                }
                None => "unknown participant".to_string(),
            };

            return Err(format!(
                "Could not claim neuron for {} with NeuronId {:?} due to: {}",
                participant_info,
                neuron_id,
                defects.join("\n"),
            ));
        }

        Ok(())
    }

    pub(crate) fn is_neurons_fund_neuron(&self) -> bool {
        matches!(self.participant, Some(Participant::NeuronsFund(_)))
    }

    #[track_caller]
    pub(crate) fn get_dissolve_delay_seconds_or_panic(&self) -> u64 {
        self.dissolve_delay_seconds
            .expect("Expected the dissolve_delay_seconds to be present in NeuronRecipe")
    }

    #[track_caller]
    pub(crate) fn get_stake_e8s_or_panic(&self) -> u64 {
        self.stake_e8s
            .expect("Expected the stake_e8s to be present in NeuronRecipe")
    }

    #[track_caller]
    pub(crate) fn get_neuron_id_or_panic(&self) -> &NeuronId {
        self.neuron_id
            .as_ref()
            .expect("Expected NeuronId to be present in NeuronRecipe")
    }

    pub(crate) fn source_nns_neuron_id(&self) -> Option<u64> {
        match &self.participant {
            Some(Participant::NeuronsFund(neurons_fund)) => {
                neurons_fund.nns_neuron_id.as_ref().cloned()
            }
            _ => None,
        }
    }

    #[track_caller]
    pub(crate) fn construct_permissions_or_panic(
        &self,
        neuron_claimer_permissions: NeuronPermissionList,
    ) -> Vec<NeuronPermission> {
        self.construct_permissions(neuron_claimer_permissions)
            .expect("Failed to construct permissions for neuron")
    }

    pub(crate) fn construct_permissions(
        &self,
        neuron_claimer_permissions: NeuronPermissionList,
    ) -> Result<Vec<NeuronPermission>, String> {
        let mut permissions = vec![];

        let controller = self
            .controller
            .as_ref()
            .ok_or("Expected controller to be present in NeuronRecipe".to_string())?;

        permissions.push(NeuronPermission::new(
            controller,
            neuron_claimer_permissions.permissions,
        ));

        let Some(participant) = &self.participant else {
            return Err("Expected participant to be present in NeuronRecipe".to_string());
        };

        if let Participant::NeuronsFund(neurons_fund_participant) = participant {
            let nns_neuron_controller = neurons_fund_participant.nns_neuron_controller.ok_or(
                "Expected the nns_neuron_controller to be present for NeuronsFundParticipant"
                    .to_string(),
            )?;
            permissions.push(NeuronPermission::new(
                &nns_neuron_controller,
                Neuron::PERMISSIONS_FOR_NEURONS_FUND_NNS_NEURON_CONTROLLER
                    .iter()
                    .map(|p| *p as i32)
                    .collect(),
            ));

            for hotkey in neurons_fund_participant
                .nns_neuron_hotkeys
                .as_ref()
                .ok_or(
                    "Expected the nns_neuron_hotkeys to be present for NeuronsFundParticipant"
                        .to_string(),
                )?
                .principals
                .iter()
            {
                permissions.push(NeuronPermission::new(
                    hotkey,
                    Neuron::PERMISSIONS_FOR_NEURONS_FUND_NNS_NEURON_HOTKEY
                        .iter()
                        .map(|p| *p as i32)
                        .collect(),
                ));
            }
        }

        Ok(permissions)
    }

    pub(crate) fn construct_topic_followees(&self) -> TopicFollowees {
        let Some(followees) = &self.followees else {
            return TopicFollowees::default();
        };

        let followees = &followees.neuron_ids;

        // There's a root neuron without any following set up out of the box.
        if followees.is_empty() {
            return TopicFollowees::default();
        }

        let root_neuron_alias = |followee_neuron_index, num_followees| {
            if num_followees == 1 {
                "Neuron-basket-main".to_string()
            } else {
                // This is not currently used, as each neuron basket has a single root neuron.
                format!("Followee-{followee_neuron_index}")
            }
        };

        // All other neurons follow on all available topics.
        let topic_id_to_followees = TOPICS
            .iter()
            .map(|topic| {
                let topic = i32::from(*topic);
                let num_followees = followees.len();

                let followees = followees
                    .iter()
                    .enumerate()
                    .map(|(followee_neuron_index, followee_neuron_id)| {
                        let alias = Some(root_neuron_alias(followee_neuron_index, num_followees));
                        let neuron_id = Some(followee_neuron_id.clone());

                        Followee { neuron_id, alias }
                    })
                    .collect();

                let followees_per_topic = FolloweesForTopic {
                    followees,
                    topic: Some(topic),
                };

                (topic, followees_per_topic)
            })
            .collect();

        TopicFollowees {
            topic_id_to_followees,
        }
    }

    pub(crate) fn construct_auto_staking_maturity(&self) -> Option<bool> {
        if self.is_neurons_fund_neuron() {
            Some(true)
        } else {
            None
        }
    }
}

impl ClaimSwapNeuronsResponse {
    pub(crate) fn new_with_error(error: ClaimSwapNeuronsError) -> Self {
        ClaimSwapNeuronsResponse {
            claim_swap_neurons_result: Some(ClaimSwapNeuronsResult::Err(error as i32)),
        }
    }

    pub fn new(swap_neurons: Vec<SwapNeuron>) -> Self {
        ClaimSwapNeuronsResponse {
            claim_swap_neurons_result: Some(ClaimSwapNeuronsResult::Ok(ClaimedSwapNeurons {
                swap_neurons,
            })),
        }
    }
}

impl SwapNeuron {
    pub(crate) fn from_neuron_recipe(
        neuron_recipe: NeuronRecipe,
        claimed_swap_neuron_status: ClaimedSwapNeuronStatus,
    ) -> Self {
        SwapNeuron {
            id: neuron_recipe.neuron_id.clone(),
            status: claimed_swap_neuron_status as i32,
        }
    }
}

impl From<Vec<NeuronPermissionType>> for NeuronPermissionList {
    fn from(permissions: Vec<NeuronPermissionType>) -> Self {
        NeuronPermissionList {
            permissions: permissions.into_iter().map(|p| p as i32).collect(),
        }
    }
}

impl From<BTreeSet<NeuronPermissionType>> for NeuronPermissionList {
    fn from(permissions: BTreeSet<NeuronPermissionType>) -> Self {
        NeuronPermissionList {
            permissions: permissions.into_iter().map(|p| p as i32).collect(),
        }
    }
}

impl TryFrom<NeuronPermissionList> for BTreeSet<NeuronPermissionType> {
    type Error = String;

    fn try_from(permissions: NeuronPermissionList) -> Result<Self, Self::Error> {
        permissions
            .permissions
            .into_iter()
            .map(|p| {
                NeuronPermissionType::try_from(p)
                    .map_err(|err| format!("Invalid permission: {p}, err: {err}"))
            })
            .collect()
    }
}

impl TryFrom<NeuronPermissionList> for Vec<NeuronPermissionType> {
    type Error = String;

    fn try_from(permissions: NeuronPermissionList) -> Result<Self, Self::Error> {
        Vec::<Result<NeuronPermissionType, i32>>::from(permissions)
            .into_iter()
            .map(|p| p.map_err(|i| format!("Invalid permission: {i}")))
            .collect()
    }
}

impl From<NeuronPermissionList> for Vec<Result<NeuronPermissionType, i32>> {
    fn from(permissions: NeuronPermissionList) -> Self {
        permissions
            .permissions
            .into_iter()
            .map(|p| NeuronPermissionType::try_from(p).map_err(|_| p))
            .collect()
    }
}

impl fmt::Display for NeuronPermissionList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let permissions = Vec::<Result<NeuronPermissionType, i32>>::from(self.clone())
            .into_iter()
            .map(|p| match p {
                Ok(p) => format!("{p:?}"),
                Err(i) => format!("<Invalid permission ({i})>"),
            })
            .collect::<Vec<_>>()
            .join(", ");

        write!(f, "[{permissions}]")
    }
}

impl get_neuron_response::Result {
    #[track_caller]
    pub fn unwrap(self) -> Neuron {
        match self {
            get_neuron_response::Result::Error(e) => Err(e),
            get_neuron_response::Result::Neuron(n) => Ok(n),
        }
        .unwrap()
    }
}

impl From<RegisterDappCanisters> for RegisterDappCanistersRequest {
    fn from(register_dapp_canisters: RegisterDappCanisters) -> RegisterDappCanistersRequest {
        RegisterDappCanistersRequest {
            canister_ids: register_dapp_canisters.canister_ids,
        }
    }
}

impl From<DeregisterDappCanisters> for SetDappControllersRequest {
    fn from(deregister_dapp_canisters: DeregisterDappCanisters) -> SetDappControllersRequest {
        SetDappControllersRequest {
            canister_ids: Some(CanisterIds {
                canister_ids: deregister_dapp_canisters.canister_ids,
            }),
            controller_principal_ids: deregister_dapp_canisters.new_controllers,
        }
    }
}

impl From<ManageDappCanisterSettings> for ManageDappCanisterSettingsRequest {
    fn from(manage_dapp_canister_settings: ManageDappCanisterSettings) -> Self {
        let ManageDappCanisterSettings {
            canister_ids,
            compute_allocation,
            memory_allocation,
            freezing_threshold,
            reserved_cycles_limit,
            log_visibility,
            wasm_memory_limit,
            wasm_memory_threshold,
        } = manage_dapp_canister_settings;

        ManageDappCanisterSettingsRequest {
            canister_ids,
            compute_allocation,
            memory_allocation,
            freezing_threshold,
            reserved_cycles_limit,
            log_visibility,
            wasm_memory_limit,
            wasm_memory_threshold,
        }
    }
}

impl Motion {
    pub fn new(text: &str) -> Self {
        Motion {
            motion_text: text.to_string(),
        }
    }
}

impl From<Motion> for Action {
    fn from(motion: Motion) -> Action {
        Action::Motion(motion)
    }
}

impl From<NervousSystemParameters> for Action {
    fn from(nervous_system_parameters: NervousSystemParameters) -> Action {
        Action::ManageNervousSystemParameters(nervous_system_parameters)
    }
}

impl From<NervousSystemFunction> for Action {
    fn from(nervous_system_function: NervousSystemFunction) -> Action {
        Action::AddGenericNervousSystemFunction(nervous_system_function)
    }
}

// RemoveGenericNervousSystemFunction not implemented because it takes a u64

impl From<ExecuteGenericNervousSystemFunction> for Action {
    fn from(
        execute_generic_nervous_system_function: ExecuteGenericNervousSystemFunction,
    ) -> Action {
        Action::ExecuteGenericNervousSystemFunction(execute_generic_nervous_system_function)
    }
}

impl From<UpgradeSnsToNextVersion> for Action {
    fn from(upgrade_sns_to_next_version: UpgradeSnsToNextVersion) -> Action {
        Action::UpgradeSnsToNextVersion(upgrade_sns_to_next_version)
    }
}

impl From<TransferSnsTreasuryFunds> for Action {
    fn from(transfer_sns_treasury_funds: TransferSnsTreasuryFunds) -> Action {
        Action::TransferSnsTreasuryFunds(transfer_sns_treasury_funds)
    }
}

impl From<RegisterDappCanisters> for Action {
    fn from(register_dapp_canisters: RegisterDappCanisters) -> Action {
        Action::RegisterDappCanisters(register_dapp_canisters)
    }
}

impl From<DeregisterDappCanisters> for Action {
    fn from(deregister_dapp_canisters: DeregisterDappCanisters) -> Action {
        Action::DeregisterDappCanisters(deregister_dapp_canisters)
    }
}

impl From<MintSnsTokens> for Action {
    fn from(mint_sns_tokens: MintSnsTokens) -> Action {
        Action::MintSnsTokens(mint_sns_tokens)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Wasm {
    Bytes(Vec<u8>),
    Chunked {
        wasm_module_hash: Vec<u8>,
        store_canister_id: CanisterId,
        chunk_hashes_list: Vec<Vec<u8>>,
    },
}

impl TryFrom<ChunkedCanisterWasm> for Wasm {
    type Error = String;

    fn try_from(chunked_canister_wasm: ChunkedCanisterWasm) -> Result<Self, Self::Error> {
        let ChunkedCanisterWasm {
            wasm_module_hash,
            store_canister_id,
            chunk_hashes_list,
        } = chunked_canister_wasm;

        if wasm_module_hash.is_empty() {
            return Err("ChunkedCanisterWasm.wasm_module_hash cannot be empty".to_string());
        }

        let Some(store_canister_id) = store_canister_id else {
            return Err("ChunkedCanisterWasm.store_canister_id cannot be None".to_string());
        };

        let store_canister_id = CanisterId::try_from_principal_id(store_canister_id)
            .map_err(|err| format!("Invalid store_canister_id: {err}"))?;

        Ok(Wasm::Chunked {
            wasm_module_hash,
            store_canister_id,
            chunk_hashes_list,
        })
    }
}

/// Validates that the specified byte sequence meets the following requirements:
/// 1. `new_canister_wasm` starts with Wasm or Gzip magic bytes.
/// 2. Combined length of `new_canister_wasm` and `new_canister_wasm` is within ICP message limits.
fn validate_wasm_bytes(
    new_canister_wasm: &[u8],
    canister_upgrade_arg: &Option<Vec<u8>>,
) -> Result<(), Vec<String>> {
    let mut defects = vec![];

    // https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-module-format
    const RAW_WASM_HEADER: [u8; 4] = [0, 0x61, 0x73, 0x6d];
    const GZIPPED_WASM_HEADER: [u8; 3] = [0x1f, 0x8b, 0x08];

    if new_canister_wasm.len() < 4
        || new_canister_wasm[..4] != RAW_WASM_HEADER[..]
            && new_canister_wasm[..3] != GZIPPED_WASM_HEADER[..]
    {
        defects.push("new_canister_wasm lacks the magic value in its header.".into());
    }

    if new_canister_wasm.len().saturating_add(
        canister_upgrade_arg
            .as_ref()
            .map(|arg| arg.len())
            .unwrap_or_default(),
    ) >= MAX_INSTALL_CODE_WASM_AND_ARG_SIZE
    {
        defects.push(format!(
            "the maximum canister WASM and argument size \
            for UpgradeSnsControlledCanister is {MAX_INSTALL_CODE_WASM_AND_ARG_SIZE} bytes."
        ));
    }

    if !defects.is_empty() {
        return Err(defects);
    }

    Ok(())
}

async fn validate_chunked_wasm(
    env: &dyn Environment,
    wasm_module_hash: &Vec<u8>,
    store_canister_id: CanisterId,
    chunk_hashes_list: &[Vec<u8>],
) -> Result<(), Vec<String>> {
    let mut defects = vec![];

    match chunk_hashes_list {
        [] => {
            let defect = "chunked_canister_wasm.chunk_hashes_list cannot be empty.".to_string();
            defects.push(defect);
        }
        [chunk_hash] if wasm_module_hash != chunk_hash => {
            let defect = format!(
                "chunked_canister_wasm.chunk_hashes_list specifies only one hash ({}), but \
                it differs from chunked_canister_wasm.wasm_module_hash ({}).",
                format_full_hash(chunk_hash),
                format_full_hash(&wasm_module_hash[..]),
            );
            defects.push(defect);
        }
        _ => (),
    }

    let arg = match Encode!(&CanisterIdRecord::from(store_canister_id)) {
        Ok(arg) => arg,
        Err(err) => {
            let defect = format!("Cannot encode stored_chunks arg: {err}");
            defects.push(defect);
            return Err(defects);
        }
    };

    // TODO[NNS1-3550]: Enable stored chunks validation on mainnet.
    #[cfg(feature = "test")]
    let validate_stored_chunks: bool = true;
    #[cfg(not(feature = "test"))]
    let validate_stored_chunks: bool = false;
    if validate_stored_chunks {
        // TODO[NNS1-3550]: Switch this call to best-effort.
        let stored_chunks_response = env
            .call_canister(CanisterId::ic_00(), "stored_chunks", arg)
            .await;

        let stored_chunks_response = match stored_chunks_response {
            Ok(stored_chunks_response) => stored_chunks_response,
            Err(err) => {
                let defect = format!("Cannot call stored_chunks for {store_canister_id}: {err:?}");
                defects.push(defect);
                return Err(defects);
            }
        };

        let stored_chunks_response = match Decode!(&stored_chunks_response, StoredChunksReply) {
            Ok(stored_chunks_response) => stored_chunks_response,
            Err(err) => {
                let defect = format!(
                    "Cannot decode response from calling stored_chunks for {store_canister_id}: {err}"
                );
                defects.push(defect);
                return Err(defects);
            }
        };

        // Finally, check that the expected chunks were successfully uploaded to the store canister.
        let available_chunks = stored_chunks_response
            .0
            .iter()
            .map(|chunk| format_full_hash(&chunk.hash))
            .collect::<BTreeSet<_>>();
        let required_chunks = chunk_hashes_list
            .iter()
            .map(|chunk| format_full_hash(chunk))
            .collect::<BTreeSet<_>>();

        let missing_chunks = required_chunks
            .difference(&available_chunks)
            .cloned()
            .collect::<Vec<_>>();
        if !missing_chunks.is_empty() {
            let defect = format!(
                "{} out of {} expected WASM chunks were not uploaded to the store canister: {}",
                missing_chunks.len(),
                required_chunks.len(),
                missing_chunks.join(", ")
            );
            defects.push(defect);
        }
    }

    if !defects.is_empty() {
        return Err(defects);
    }

    Ok(())
}

impl Wasm {
    /// Returns the list of defects of this Wasm in Err result.
    pub async fn validate(
        &self,
        env: &dyn Environment,
        canister_upgrade_arg: &Option<Vec<u8>>,
    ) -> Result<(), Vec<String>> {
        match self {
            Self::Bytes(bytes) => validate_wasm_bytes(bytes, canister_upgrade_arg),
            Self::Chunked {
                wasm_module_hash,
                store_canister_id,
                chunk_hashes_list,
            } => {
                validate_chunked_wasm(env, wasm_module_hash, *store_canister_id, chunk_hashes_list)
                    .await
            }
        }
    }

    pub fn sha256sum(&self) -> Vec<u8> {
        match self {
            Self::Bytes(bytes) => {
                let mut state = Sha256::new();
                state.write(&bytes[..]);
                state.finish().to_vec()
            }
            Self::Chunked {
                wasm_module_hash, ..
            } => wasm_module_hash.clone(),
        }
    }

    pub fn description(&self) -> String {
        let wasm_module_hash = self.sha256sum();
        let wasm_module_hash = format_full_hash(&wasm_module_hash);

        match self {
            Self::Bytes(bytes) => {
                format!(
                    "Embedded module with {} bytes and SHA256 `{}`.",
                    bytes.len(),
                    wasm_module_hash,
                )
            }
            Self::Chunked {
                wasm_module_hash: _, // computed above
                store_canister_id,
                chunk_hashes_list,
            } => {
                format!(
                    "Remote module stored on canister {} with SHA256 `{}`. \
                     Split into {} chunks:\n  - {}",
                    store_canister_id.get(),
                    wasm_module_hash,
                    chunk_hashes_list.len(),
                    chunk_hashes_list
                        .iter()
                        .map(|chunk_hash| { format!("`{}`", format_full_hash(chunk_hash)) })
                        .collect::<Vec<_>>()
                        .join("\n  - "),
                )
            }
        }
    }
}

impl TryFrom<&UpgradeSnsControlledCanister> for Wasm {
    type Error = String;

    fn try_from(upgrade: &UpgradeSnsControlledCanister) -> Result<Self, Self::Error> {
        const ERR_PREFIX: &str = "Invalid UpgradeSnsControlledCanister";

        match (
            &upgrade.new_canister_wasm[..],
            &upgrade.chunked_canister_wasm,
        ) {
            (
                [],
                Some(ChunkedCanisterWasm {
                    wasm_module_hash,
                    store_canister_id,
                    chunk_hashes_list,
                }),
            ) => {
                let Some(store_canister_id) = store_canister_id else {
                    return Err(format!(
                        "{ERR_PREFIX}.chunked_canister_wasm.store_canister_id must be \
                             specified."
                    ));
                };

                let store_canister_id = CanisterId::try_from_principal_id(*store_canister_id)
                    .map_err(|err| {
                        format!("{ERR_PREFIX}.chunked_canister_wasm.store_canister_id: {err}")
                    })?;

                Ok(Self::Chunked {
                    wasm_module_hash: wasm_module_hash.clone(),
                    store_canister_id,
                    chunk_hashes_list: chunk_hashes_list.clone(),
                })
            }
            (bytes, None) => Ok(Self::Bytes(bytes.to_vec())),
            _ => Err(format!(
                "{ERR_PREFIX}: Either .new_canister_wasm or \
                     .chunked_canister_wasm (but not both) must be specified."
            )),
        }
    }
}

impl TryFrom<&crate::pb::v1::Wasm> for Wasm {
    type Error = String;

    fn try_from(wasm_wrapper: &crate::pb::v1::Wasm) -> Result<Self, Self::Error> {
        let Some(wasm) = &wasm_wrapper.wasm else {
            return Err("wasm.wasm field is required".to_string());
        };

        match wasm {
            crate::pb::v1::wasm::Wasm::Bytes(bytes) => Ok(Self::Bytes(bytes.clone())),
            crate::pb::v1::wasm::Wasm::Chunked(ChunkedCanisterWasm {
                wasm_module_hash,
                store_canister_id,
                chunk_hashes_list,
            }) => {
                let Some(store_canister_id) = store_canister_id else {
                    return Err("wasm.chunked.store_canister_id must be specified.".to_string());
                };
                let store_canister_id = CanisterId::try_from_principal_id(*store_canister_id)
                    .map_err(|err| format!("wasm.chunked.store_canister_id: {err}"))?;
                Ok(Self::Chunked {
                    wasm_module_hash: wasm_module_hash.clone(),
                    store_canister_id,
                    chunk_hashes_list: chunk_hashes_list.clone(),
                })
            }
        }
    }
}

impl UpgradeSnsControlledCanister {
    // Gets the install mode if it is set, otherwise defaults to Upgrade.
    // This function is not called `mode_or_default` because `or_default` usually
    // returns the default value for the type.
    pub fn mode_or_upgrade(&self) -> ic_protobuf::types::v1::CanisterInstallMode {
        self.mode
            .and_then(|mode| ic_protobuf::types::v1::CanisterInstallMode::try_from(mode).ok())
            .unwrap_or(ic_protobuf::types::v1::CanisterInstallMode::Upgrade)
    }
}

impl From<Vec<NeuronRecipe>> for NeuronRecipes {
    fn from(neuron_recipes: Vec<NeuronRecipe>) -> Self {
        NeuronRecipes { neuron_recipes }
    }
}

impl From<NeuronRecipes> for Vec<NeuronRecipe> {
    fn from(neuron_recipes: NeuronRecipes) -> Self {
        neuron_recipes.neuron_recipes
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SnsVersion {{ root:{}, governance:{}, swap:{}, index:{}, ledger:{}, archive:{} }}",
            hash_to_hex_string(&self.root_wasm_hash),
            hash_to_hex_string(&self.governance_wasm_hash),
            hash_to_hex_string(&self.swap_wasm_hash),
            hash_to_hex_string(&self.index_wasm_hash),
            hash_to_hex_string(&self.ledger_wasm_hash),
            hash_to_hex_string(&self.archive_wasm_hash)
        )
    }
}

impl From<Version> for SnsVersion {
    fn from(src: Version) -> Self {
        let Version {
            root_wasm_hash,
            governance_wasm_hash,
            ledger_wasm_hash,
            swap_wasm_hash,
            archive_wasm_hash,
            index_wasm_hash,
        } = src;

        Self {
            root_wasm_hash: Some(root_wasm_hash),
            governance_wasm_hash: Some(governance_wasm_hash),
            ledger_wasm_hash: Some(ledger_wasm_hash),
            swap_wasm_hash: Some(swap_wasm_hash),
            archive_wasm_hash: Some(archive_wasm_hash),
            index_wasm_hash: Some(index_wasm_hash),
        }
    }
}

impl TryFrom<SnsVersion> for Version {
    type Error = String;

    fn try_from(src: SnsVersion) -> Result<Self, Self::Error> {
        let SnsVersion {
            root_wasm_hash: Some(root_wasm_hash),
            governance_wasm_hash: Some(governance_wasm_hash),
            ledger_wasm_hash: Some(ledger_wasm_hash),
            swap_wasm_hash: Some(swap_wasm_hash),
            archive_wasm_hash: Some(archive_wasm_hash),
            index_wasm_hash: Some(index_wasm_hash),
        } = src
        else {
            return Err(
                "Cannot interpret SnsVersion; please specify all the required fields: \
                 {{governance, root, swap, index, ledger, archive}}_wasm_hash."
                    .to_string(),
            );
        };

        Ok(Self {
            governance_wasm_hash,
            root_wasm_hash,
            swap_wasm_hash,
            index_wasm_hash,
            ledger_wasm_hash,
            archive_wasm_hash,
        })
    }
}

pub mod test_helpers {
    use super::*;
    use rand::Rng;
    use std::{
        borrow::BorrowMut,
        collections::HashMap,
        sync::{Arc, RwLock},
    };

    type CanisterCallResult = Result<Vec<u8>, (Option<i32>, String)>;

    /// An implementation of the Environment trait that behaves in a
    /// "reasonable" but not necessarily entirely realistic way (compared to the
    /// real IC) where possible. E.g. the now method returns the current real
    /// time. When there is no "reasonable" behavior, the unimplemented macro is
    /// called.
    ///
    /// The only method that is completely unimplemented is call_canister, since
    /// that is not a native concept on any system other than the IC
    /// itself. canister_id is partially implemented.
    pub struct NativeEnvironment {
        /// When Some, contains the value that the canister_id method returns.
        pub local_canister_id: Option<CanisterId>,

        /// Map of expected calls to a result, where key is hash of arguments (See `compute_call_canister_key`).
        #[allow(clippy::type_complexity)]
        pub canister_calls_map: HashMap<
            (
                ic_base_types::CanisterId,
                std::string::String,
                std::vec::Vec<u8>,
            ),
            CanisterCallResult,
        >,

        // The default response is canister_calls_map doesn't have an entry.  Useful when you only
        // care about specifying a single response for a given test, or alternately want to ensure
        // that any call without a specified response returns an error.
        pub default_canister_call_response: CanisterCallResult,

        /// Calls we require to be made to call_canister in order for the test to succeed.
        /// See `impl Drop for NativeEnvironment`
        #[allow(clippy::type_complexity)]
        pub required_canister_call_invocations: Arc<RwLock<Vec<(CanisterId, String, Vec<u8>)>>>,

        /// The value to be returned by now().
        pub now: u64,
    }

    /// NativeEnvironment is "empty" by default. I.e. the canister_id method
    /// calls unimplemented.
    impl Default for NativeEnvironment {
        fn default() -> Self {
            Self {
                local_canister_id: None,
                canister_calls_map: Default::default(),
                default_canister_call_response: Ok(vec![]),
                required_canister_call_invocations: Arc::new(RwLock::new(vec![])),
                // This needs to be non-zero
                now: Self::DEFAULT_TEST_START_TIMESTAMP_SECONDS,
            }
        }
    }

    impl NativeEnvironment {
        pub const DEFAULT_TEST_START_TIMESTAMP_SECONDS: u64 = 999_111_000_u64;

        pub fn new(local_canister_id: Option<CanisterId>) -> Self {
            Self {
                local_canister_id,
                canister_calls_map: Default::default(),
                default_canister_call_response: Ok(vec![]),
                required_canister_call_invocations: Arc::new(RwLock::new(vec![])),
                now: Self::DEFAULT_TEST_START_TIMESTAMP_SECONDS,
            }
        }

        /// Set the response for a given canister call.  This ensures that we only respond in
        /// a given way if the parameters match what we expect.
        pub fn set_call_canister_response(
            &mut self,
            canister_id: CanisterId,
            method_name: &str,
            arg: Vec<u8>,
            response: CanisterCallResult,
        ) {
            self.canister_calls_map
                .insert((canister_id, method_name.to_string(), arg), response);
        }

        /// Requires that a call will be made (and optionally sets a response)
        ///
        /// See `impl Drop for NativeEnvironment`.
        pub fn require_call_canister_invocation(
            &mut self,
            canister_id: CanisterId,
            method_name: &str,
            arg: Vec<u8>,
            response: Option<CanisterCallResult>,
        ) {
            self.required_canister_call_invocations
                .try_write()
                .unwrap()
                .borrow_mut()
                .push((canister_id, method_name.to_string(), arg.clone()));
            if let Some(res) = response {
                self.set_call_canister_response(canister_id, method_name, arg, res);
            }
        }

        /// Get a function that allows you to assert required calls were made
        /// To avoid Drop impl, you may need to keep governance in scope longer.
        pub fn get_assert_required_calls_fn(&self) -> Box<dyn FnOnce()> {
            let required_calls = Arc::clone(&self.required_canister_call_invocations);
            Box::new(move || {
                let invocations = required_calls.try_read().unwrap().clone();
                // Empty these so we don't panic again during Drop
                required_calls.try_write().unwrap().clear();
                assert!(
                    invocations.is_empty(),
                    "Not all required calls were executed: {invocations:?}"
                );
            })
        }
    }

    /// Used to assert that any post-conditions are true.
    /// A better way is using `get_assert_required_calls_fn` to get a function to make this assert
    /// inside of the test body, as it gives better debug information.  This functions as a fallback
    /// so that tests cannot accidentally pass if that line is removed.
    impl Drop for NativeEnvironment {
        fn drop(&mut self) {
            let invocations = self.required_canister_call_invocations.try_read().unwrap();
            assert!(
                invocations.is_empty(),
                "Not all required calls were executed: {invocations:?}"
            );
        }
    }

    #[async_trait]
    impl Environment for NativeEnvironment {
        fn now(&self) -> u64 {
            self.now
        }

        fn insecure_random_u64(&mut self) -> u64 {
            rand::thread_rng().r#gen()
        }

        async fn call_canister(
            &self,
            canister_id: CanisterId,
            method_name: &str,
            arg: Vec<u8>,
        ) -> CanisterCallResult {
            // Find and remove any required_canister_call_invocations so our assertions work that
            // it was in fact called.
            let invocations = self.required_canister_call_invocations.try_read().unwrap();
            if invocations.contains(&(canister_id, method_name.to_string(), arg.clone())) {
                let index = invocations.iter().position(|(canister, method, arg_)| {
                    canister.get() == canister_id.get() && method.eq(method_name) && arg_ == &arg
                });
                drop(invocations);
                if let Some(index) = index {
                    self.required_canister_call_invocations
                        .try_write()
                        .unwrap()
                        .remove(index);
                }
            }

            let entry = (canister_id, method_name.to_string(), arg.clone());
            match self.canister_calls_map.get(&entry) {
                None => {
                    log!(INFO,
                        "No call_canister entry found for: {:?} {} {:?}.  Using default response: {:?}.",
                        canister_id, method_name, arg, &self.default_canister_call_response
                    );
                    &self.default_canister_call_response
                }
                Some(entry) => entry
            }.clone()
        }

        /// At least in the case of Governance (the only known user of
        /// Environment), this is only used to determine whether to "short
        /// circuit", i.e. return ResourceExhausted instead of doing the "real
        /// work". Most tests do not attempt exercise the special "running out of
        /// memory" condition; therefore, it makes sense for this to always
        /// return NoIssue.
        fn heap_growth_potential(&self) -> crate::types::HeapGrowthPotential {
            HeapGrowthPotential::NoIssue
        }

        fn canister_id(&self) -> CanisterId {
            if let Some(id) = self.local_canister_id {
                return id;
            }

            unimplemented!();
        }

        fn canister_version(&self) -> Option<u64> {
            None
        }

        fn set_time_warp(&mut self, new_time_warp: TimeWarp) {
            self.now += new_time_warp.delta_s as u64
        }
    }
}
#[cfg(test)]
mod tests;
