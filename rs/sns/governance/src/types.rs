use crate::governance::{
    log_prefix, Governance, TimeWarp, NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER,
};
use crate::pb::v1::governance_error::ErrorType;
use crate::pb::v1::manage_neuron_response::{DisburseMaturityResponse, MergeMaturityResponse};
use crate::pb::v1::proposal::Action;
use crate::pb::v1::Empty;
use crate::pb::v1::{
    governance::neuron_in_flight_command, manage_neuron, manage_neuron_response,
    nervous_system_function::FunctionType, DefaultFollowees, GovernanceError, ManageNeuronResponse,
    NervousSystemFunction, NervousSystemParameters, NeuronId, NeuronPermissionList,
    NeuronPermissionType, ProposalId, RewardEvent, Vote,
};

use async_trait::async_trait;

use ic_base_types::CanisterId;
use ic_nervous_system_common::NervousSystemError;
use ledger_canister::{DEFAULT_TRANSFER_FEE, TOKEN_SUBDIVIDABLE_BY};

use std::collections::{BTreeMap, HashSet};
use std::fmt;

pub const ONE_DAY_SECONDS: u64 = 24 * 60 * 60;
pub const ONE_YEAR_SECONDS: u64 = (4 * 365 + 1) * ONE_DAY_SECONDS / 4;
pub const ONE_MONTH_SECONDS: u64 = ONE_YEAR_SECONDS / 12;

#[allow(dead_code)]
/// TODO Use to validate the size of the payload 70 KB (for executing
/// SNS functions that are not canister upgrades)
const PROPOSAL_EXECUTE_SNS_FUNCTION_PAYLOAD_BYTES_MAX: usize = 70000;

/// The number of e8s per governance token;
pub const E8S_PER_TOKEN: u64 = TOKEN_SUBDIVIDABLE_BY;

impl From<&manage_neuron::Command> for neuron_in_flight_command::Command {
    #[rustfmt::skip]
    fn from(src: &manage_neuron::Command) -> neuron_in_flight_command::Command {
        use manage_neuron::Command as S;
        use neuron_in_flight_command::Command as D;
        match src.clone() {
            S::Configure              (x) => D::Configure              (x),
            S::Disburse               (x) => D::Disburse               (x),
            S::Follow                 (x) => D::Follow                 (x),
            S::MakeProposal           (x) => D::MakeProposal           (x),
            S::RegisterVote           (x) => D::RegisterVote           (x),
            S::Split                  (x) => D::Split                  (x),
            S::ClaimOrRefresh         (x) => D::ClaimOrRefreshNeuron   (x),
            S::MergeMaturity          (x) => D::MergeMaturity          (x),
            S::DisburseMaturity       (x) => D::DisburseMaturity       (x),
            S::AddNeuronPermissions   (x) => D::AddNeuronPermissions   (x),
            S::RemoveNeuronPermissions(x) => D::RemoveNeuronPermissions(x),
        }
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
    pub const MAX_NUMBER_OF_NEURONS_CEILING: u64 = 200_000;

    /// This is an upper bound for `max_number_of_proposals_with_ballots`. Exceeding
    /// it may cause degradation in the governance canister or the subnet hosting the SNS.
    pub const MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS_CEILING: u64 = 700;

    /// This is an upper bound for `initial_voting_period`. Exceeding it may cause
    /// degradation in the governance canister or the subnet hosting the SNS.
    pub const INITIAL_VOTING_PERIOD_CEILING: u64 = 30 * ONE_DAY_SECONDS;

    /// This is a lower bound for `initial_voting_period`. Exceeding it may cause
    /// degradation in the governance canister or the subnet hosting the SNS.
    pub const INITIAL_VOTING_PERIOD_FLOOR: u64 = ONE_DAY_SECONDS;

    /// This is an upper bound for `max_followees_per_function`. Exceeding it may cause
    /// degradation in the governance canister or the subnet hosting the SNS.
    pub const MAX_FOLLOWEES_PER_FUNCTION_CEILING: u64 = 15;

    /// This is an upper bound for `max_number_of_principals_per_neuron`. Exceeding
    /// it may cause may cause degradation in the governance canister or the subnet
    /// hosting the SNS.
    pub const MAX_NUMBER_OF_PRINCIPALS_PER_NEURON_CEILING: u64 = 15;

    pub fn with_default_values() -> Self {
        Self {
            reject_cost_e8s: Some(E8S_PER_TOKEN), // 1 governance token
            neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN), // 1 governance token
            transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
            max_proposals_to_keep_per_action: Some(100),
            initial_voting_period: Some(4 * ONE_DAY_SECONDS), // 4d
            default_followees: Some(DefaultFollowees::default()),
            max_number_of_neurons: Some(200_000),
            neuron_minimum_dissolve_delay_to_vote_seconds: Some(6 * ONE_MONTH_SECONDS), // 6m
            max_followees_per_function: Some(15),
            max_dissolve_delay_seconds: Some(8 * ONE_YEAR_SECONDS), // 8y
            max_neuron_age_for_age_bonus: Some(4 * ONE_YEAR_SECONDS), // 4y
            reward_distribution_period_seconds: Some(ONE_DAY_SECONDS), // 1d
            max_number_of_proposals_with_ballots: Some(700),
            neuron_claimer_permissions: Some(Self::default_neuron_claimer_permissions()),
            neuron_grantable_permissions: Some(NeuronPermissionList::default()),
            max_number_of_principals_per_neuron: Some(5),
        }
    }

    /// Any empty fields of `self` are overwritten with the corresponding fields of `base`.
    pub fn inherit_from(&self, base: &Self) -> Self {
        let mut new_params = self.clone();
        new_params.reject_cost_e8s = self.reject_cost_e8s.or(base.reject_cost_e8s);
        new_params.neuron_minimum_stake_e8s = self
            .neuron_minimum_stake_e8s
            .or(base.neuron_minimum_stake_e8s);
        new_params.transaction_fee_e8s = self.transaction_fee_e8s.or(base.transaction_fee_e8s);
        new_params.max_proposals_to_keep_per_action = self
            .max_proposals_to_keep_per_action
            .or(base.max_proposals_to_keep_per_action);
        new_params.initial_voting_period =
            self.initial_voting_period.or(base.initial_voting_period);
        new_params.default_followees = self
            .default_followees
            .clone()
            .or_else(|| base.default_followees.clone());
        new_params.max_number_of_neurons =
            self.max_number_of_neurons.or(base.max_number_of_neurons);
        new_params.neuron_minimum_dissolve_delay_to_vote_seconds = self
            .neuron_minimum_dissolve_delay_to_vote_seconds
            .or(base.neuron_minimum_dissolve_delay_to_vote_seconds);
        new_params.max_followees_per_function = self
            .max_followees_per_function
            .or(base.max_followees_per_function);
        new_params.max_dissolve_delay_seconds = self
            .max_dissolve_delay_seconds
            .or(base.max_dissolve_delay_seconds);
        new_params.max_neuron_age_for_age_bonus = self
            .max_neuron_age_for_age_bonus
            .or(base.max_neuron_age_for_age_bonus);
        new_params.reward_distribution_period_seconds = self
            .reward_distribution_period_seconds
            .or(base.reward_distribution_period_seconds);
        new_params.max_number_of_proposals_with_ballots = self
            .max_number_of_proposals_with_ballots
            .or(base.max_number_of_proposals_with_ballots);
        new_params.neuron_claimer_permissions = self
            .neuron_claimer_permissions
            .clone()
            .or_else(|| base.neuron_claimer_permissions.clone());
        new_params.neuron_grantable_permissions = self
            .neuron_grantable_permissions
            .clone()
            .or_else(|| base.neuron_grantable_permissions.clone());
        new_params.max_number_of_principals_per_neuron = self
            .max_number_of_principals_per_neuron
            .or(base.max_number_of_principals_per_neuron);

        new_params
    }

    /// This validates that the `NervousSystemParameters` are well-formed.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_reject_cost_e8s()?;
        self.validate_neuron_minimum_stake_e8s()?;
        self.validate_transaction_fee_e8s()?;
        self.validate_max_proposals_to_keep_per_action()?;
        self.validate_initial_voting_period()?;
        self.validate_default_followees()?;
        self.validate_max_number_of_neurons()?;
        self.validate_neuron_minimum_dissolve_delay_to_vote_seconds()?;
        self.validate_max_followees_per_function()?;
        self.validate_max_dissolve_delay_seconds()?;
        self.validate_max_neuron_age_for_age_bonus()?;
        self.validate_reward_distribution_period_seconds()?;
        self.validate_max_number_of_proposals_with_ballots()?;
        self.validate_neuron_claimer_permissions()?;
        self.validate_neuron_grantable_permissions()?;
        self.validate_max_number_of_principals_per_neuron()?;

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
                "NervousSystemParameters.neuron_minimum_stake_e8s ({}) must be greater than \
                NervousSystemParameters.transaction_fee_e8s ({})",
                neuron_minimum_stake_e8s, neuron_minimum_stake_e8s
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

    /// Validates that the nervous system parameter initial_voting_period is well-formed.
    fn validate_initial_voting_period(&self) -> Result<(), String> {
        let initial_voting_period = self.initial_voting_period.ok_or_else(|| {
            "NervousSystemParameters.initial_voting_period must be set".to_string()
        })?;

        if initial_voting_period < Self::INITIAL_VOTING_PERIOD_FLOOR {
            Err(format!(
                "NervousSystemParameters.initial_voting_period must be greater than {}",
                Self::INITIAL_VOTING_PERIOD_FLOOR
            ))
        } else if initial_voting_period > Self::INITIAL_VOTING_PERIOD_CEILING {
            Err(format!(
                "NervousSystemParameters.initial_voting_period must be less than {}",
                Self::INITIAL_VOTING_PERIOD_CEILING
            ))
        } else {
            Ok(())
        }
    }

    /// Validates that the nervous system parameter default_followees is well-formed.
    fn validate_default_followees(&self) -> Result<(), String> {
        let default_followees = self
            .default_followees
            .as_ref()
            .ok_or_else(|| "NervousSystemParameters.default_followees must be set".to_string())?;

        let max_followees_per_function = self.validate_max_followees_per_function()?;

        if default_followees.followees.len() > max_followees_per_function as usize {
            return Err(format!(
                "NervousSystemParameters.default_followees must have size less than {}",
                max_followees_per_function
            ));
        }

        Ok(())
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
                "The minimum dissolve delay to vote ({}) cannot be greater than the max \
                dissolve delay ({})",
                neuron_minimum_dissolve_delay_to_vote_seconds, max_dissolve_delay_seconds
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

    /// Validates that the nervous system parameter reward_distribution_period_seconds
    /// is well-formed.
    fn validate_reward_distribution_period_seconds(&self) -> Result<(), String> {
        self.reward_distribution_period_seconds.ok_or_else(|| {
            "NervousSystemParameters.reward_distribution_period_seconds must be set".to_string()
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

        if !neuron_claimer_permissions
            .permissions
            .contains(&(NeuronPermissionType::ManagePrincipals as i32))
        {
            return Err("NervousSystemParameters.neuron_claimer_permissions must contain NeuronPermissionType::ManagePrincipals".to_string());
        }

        Ok(())
    }

    /// Returns the default for the nervous system parameter neuron_claimer_permissions.
    fn default_neuron_claimer_permissions() -> NeuronPermissionList {
        NeuronPermissionList {
            permissions: vec![NeuronPermissionType::ManagePrincipals as i32],
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

        if max_number_of_principals_per_neuron == 0 {
            Err(
                "NervousSystemParameters.max_number_of_principals_per_neuron must be greater than 0"
                    .to_string(),
            )
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
                illegal_permissions.insert(NeuronPermissionType::from_i32(*permission));
            }
        }

        if !illegal_permissions.is_empty() {
            return Err(GovernanceError::new_with_message(
                ErrorType::ErrorAccessControlList,
                format!(
                    "Cannot grant permissions as one or more permissions is not \
                    allowed to be granted. Illegal Permissions: {:?}",
                    illegal_permissions
                ),
            ));
        }

        Ok(())
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

impl From<NervousSystemError> for GovernanceError {
    fn from(nervous_system_error: NervousSystemError) -> Self {
        GovernanceError {
            error_type: ErrorType::External as i32,
            error_message: nervous_system_error.error_message,
        }
    }
}

/// Converts a Vote integer enum value into a typed enum value.
impl From<i32> for Vote {
    fn from(vote_integer: i32) -> Vote {
        match Vote::from_i32(vote_integer) {
            Some(v) => v,
            None => {
                println!(
                    "{}Vote::from invoked with unexpected value {}.",
                    log_prefix(),
                    vote_integer
                );
                Vote::Unspecified
            }
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
}

impl NervousSystemFunction {
    pub fn is_native(&self) -> bool {
        matches!(
            self.function_type,
            Some(FunctionType::NativeNervousSystemFunction(_))
        )
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
            panic!("{}: {}", msg, err);
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

    pub fn follow_response() -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Follow(
                manage_neuron_response::FollowResponse {},
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

impl Action {
    /// Returns whether proposals with such an action should be allowed to
    /// be submitted when the heap growth potential is low.
    pub(crate) fn allowed_when_resources_are_low(&self) -> bool {
        match self {
            Action::UpgradeSnsControlledCanister(_) => true,
            // TODO This line is just to avoid triggering clippy::match-like-matches-macro.
            // Once we have more cases, it can be deleted (along with this comment).
            Action::Motion(_) => false,
            _ => false,
        }
    }

    // Returns the native functions, i.e. the ones that are supported directly by the governance canister.
    pub fn native_functions() -> Vec<NervousSystemFunction> {
        vec![
            NervousSystemFunction {
                id: 0,
                name: "Unspecified".to_string(),
                description: Some(
                    "Catch-all w.r.t to following for all types of proposals.".to_string(),
                ),
                function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
            },
            NervousSystemFunction {
                id: 1,
                name: "Motion".to_string(),
                description: Some(
                    "Side-effect-less proposals to set general governance direction.".to_string(),
                ),
                function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
            },
            NervousSystemFunction {
                id: 2,
                name: "Manage nervous system parameters".to_string(),
                description: Some(
                    "Proposal to change the core parameters of SNS governance.".to_string(),
                ),
                function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
            },
            NervousSystemFunction {
                id: 3,
                name: "Upgrade SNS controlled canister".to_string(),
                description: Some(
                    "Proposal to upgrade the wasm of an SNS controlled canister.".to_string(),
                ),
                function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
            },
            NervousSystemFunction {
                id: 4,
                name: "Add nervous system function".to_string(),
                description: Some(
                    "Proposal to add a new, user-defined, nervous system function:\
                     a canister call which can then be executed by proposal."
                        .to_string(),
                ),
                function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
            },
            NervousSystemFunction {
                id: 5,
                name: "Remove nervous system function".to_string(),
                description: Some(
                    "Proposal to remove a user-defined nervous system function,\
                     which will be no longer executable by proposal."
                        .to_string(),
                ),
                function_type: Some(FunctionType::NativeNervousSystemFunction(Empty {})),
            },
        ]
    }

    // The current set of valid native function ids, for the purposes of following.
    // See `Proposal`.
    // See `impl From<&Action> for u64`.
    pub fn native_function_ids() -> Vec<u64> {
        Action::native_functions()
            .into_iter()
            .map(|m| m.id)
            .collect()
    }
}

// Mapping of action to the unique function id of that action.
//
// When adding/removing an action here, also add/remove from
// `Action::native_actions_metadata()`.
impl From<&Action> for u64 {
    fn from(action: &Action) -> Self {
        match action {
            Action::Unspecified(_) => 0,
            Action::Motion(_) => 1,
            Action::ManageNervousSystemParameters(_) => 2,
            Action::UpgradeSnsControlledCanister(_) => 3,
            Action::AddGenericNervousSystemFunction(_) => 4,
            Action::RemoveGenericNervousSystemFunction(_) => 5,
            Action::ExecuteGenericNervousSystemFunction(proposal) => proposal.function_id,
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

/// Summarizes a RewardEvent. Suitable for logging, because the string is
/// bounded in size.
impl fmt::Display for RewardEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RewardEvent {{ periods_since_genesis: {} distributed_e8s_equivalent: {}\
                   actual_timestamp_seconds: {} settled_proposals: <vec of size {}> }})",
            self.periods_since_genesis,
            self.distributed_e8s_equivalent,
            self.actual_timestamp_seconds,
            self.settled_proposals.len()
        )
    }
}

/// A general trait for the environment in which governance is running.
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
    fn random_u64(&mut self) -> u64;

    /// Returns a random byte array with 32 bytes.
    ///
    /// This byte array is the same in all replicas.
    fn random_byte_array(&mut self) -> [u8; 32];

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
        // It's always ok to dereference the governance when a LedgerUpdateLock
        // goes out of scope. Indeed, in the scope of any Governance method,
        // &self always remains alive. The 'mut' is not an issue, because
        // 'unlock_neuron' will verify that the lock exists.
        let gov: &mut Governance = unsafe { &mut *self.gov };
        gov.unlock_neuron(&self.nid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::v1::neuron::Followees;
    use maplit::btreemap;

    #[test]
    fn test_nervous_system_parameters_validate() {
        let invalid_params = vec![
            NervousSystemParameters {
                neuron_minimum_stake_e8s: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                transaction_fee_e8s: Some(100),
                neuron_minimum_stake_e8s: Some(10),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                transaction_fee_e8s: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_proposals_to_keep_per_action: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_proposals_to_keep_per_action: Some(0),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_proposals_to_keep_per_action: Some(
                    NervousSystemParameters::MAX_PROPOSALS_TO_KEEP_PER_ACTION_CEILING + 1,
                ),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                initial_voting_period: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                initial_voting_period: Some(
                    NervousSystemParameters::INITIAL_VOTING_PERIOD_FLOOR - 1,
                ),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                initial_voting_period: Some(
                    NervousSystemParameters::INITIAL_VOTING_PERIOD_CEILING + 1,
                ),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_followees_per_function: Some(0),
                default_followees: Some(DefaultFollowees {
                    followees: btreemap! {12 => Followees { followees: vec![NeuronId { id: vec![] }] }},
                }),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                default_followees: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_number_of_neurons: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_number_of_neurons: Some(0),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_number_of_neurons: Some(
                    NervousSystemParameters::MAX_NUMBER_OF_NEURONS_CEILING + 1,
                ),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                neuron_minimum_dissolve_delay_to_vote_seconds: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_dissolve_delay_seconds: Some(10),
                neuron_minimum_dissolve_delay_to_vote_seconds: Some(20),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_followees_per_function: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_followees_per_function: Some(
                    NervousSystemParameters::MAX_FOLLOWEES_PER_FUNCTION_CEILING + 1,
                ),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_dissolve_delay_seconds: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_neuron_age_for_age_bonus: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                reward_distribution_period_seconds: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_number_of_proposals_with_ballots: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_number_of_proposals_with_ballots: Some(0),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_number_of_proposals_with_ballots: Some(
                    NervousSystemParameters::MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS_CEILING + 1,
                ),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                neuron_claimer_permissions: Some(NeuronPermissionList {
                    permissions: vec![NeuronPermissionType::Vote as i32],
                }),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                neuron_claimer_permissions: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                neuron_grantable_permissions: None,
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_number_of_principals_per_neuron: Some(0),
                ..NervousSystemParameters::with_default_values()
            },
            NervousSystemParameters {
                max_number_of_principals_per_neuron: Some(1000),
                ..NervousSystemParameters::with_default_values()
            },
        ];

        for params in invalid_params {
            assert!(params.validate().is_err());
        }

        assert!(NervousSystemParameters::with_default_values()
            .validate()
            .is_ok());
    }

    #[test]
    fn test_inherit_from() {
        let default_params = NervousSystemParameters::with_default_values();
        let followees = DefaultFollowees {
            followees: btreemap! { 1 => Followees { followees: vec![] } },
        };

        let proposed_params = NervousSystemParameters {
            transaction_fee_e8s: Some(124),
            max_number_of_neurons: Some(566),
            max_number_of_proposals_with_ballots: Some(9801),
            default_followees: Some(followees.clone()),
            ..Default::default()
        };

        let new_params = proposed_params.inherit_from(&default_params);
        let expected_params = NervousSystemParameters {
            transaction_fee_e8s: Some(124),
            max_number_of_neurons: Some(566),
            max_number_of_proposals_with_ballots: Some(9801),
            default_followees: Some(followees),
            ..default_params
        };

        assert_eq!(new_params, expected_params);
    }

    /// Test that the nervous system parameter default_followees can be cleared by
    /// inheriting an empty default_followees.
    #[test]
    fn test_inherit_from_inherits_default_followees() {
        let default_params = NervousSystemParameters::with_default_values();
        let followees = DefaultFollowees {
            followees: btreemap! { 1 => Followees { followees: vec![] } },
        };

        let proposed_params = NervousSystemParameters {
            default_followees: Some(DefaultFollowees {
                followees: btreemap! {},
            }),
            ..Default::default()
        };

        let current_params = NervousSystemParameters {
            default_followees: Some(followees),
            ..default_params.clone()
        };

        let new_params = proposed_params.inherit_from(&current_params);
        let expected_params = NervousSystemParameters {
            default_followees: Some(DefaultFollowees {
                followees: btreemap! {},
            }),
            ..default_params
        };

        assert_eq!(new_params, expected_params);
    }
}
