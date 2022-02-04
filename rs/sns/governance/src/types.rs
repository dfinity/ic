use crate::governance::{Governance, LOG_PREFIX};
use crate::pb::v1::governance_error::ErrorType;
use crate::pb::v1::manage_neuron_response::MergeMaturityResponse;
use crate::pb::v1::proposal::Action;
use crate::pb::v1::{
    manage_neuron_response, ExecuteNervousSystemFunction, GovernanceError, ManageNeuronResponse,
    NervousSystemParameters, NeuronId, ProposalId, RewardEvent, Tally, Vote,
};
use ic_base_types::CanisterId;
use ledger_canister::{
    AccountIdentifier, Subaccount, Tokens, DEFAULT_TRANSFER_FEE, TOKEN_SUBDIVIDABLE_BY,
};
use std::fmt;

use async_trait::async_trait;

pub const ONE_DAY_SECONDS: u64 = 24 * 60 * 60;
pub const ONE_YEAR_SECONDS: u64 = (4 * 365 + 1) * ONE_DAY_SECONDS / 4;
pub const ONE_MONTH_SECONDS: u64 = ONE_YEAR_SECONDS / 12;

#[allow(dead_code)]
// TODO Use to validate the size of the payload 70 KB (for executing
// SNS functions that are not canister upgrades)
const PROPOSAL_EXECUTE_SNS_FUNCTION_PAYLOAD_BYTES_MAX: usize = 70000;

/// The number of e8s per governance token;
pub const E8S_PER_TOKEN: u64 = TOKEN_SUBDIVIDABLE_BY;

// The default values for network economics (until we initialize it).
// Can't implement Default since it conflicts with Prost's.
impl NervousSystemParameters {
    pub fn with_default_values() -> Self {
        Self {
            reject_cost_e8s: Some(E8S_PER_TOKEN),          // 1 ICP
            neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN), // 1 ICP
            transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
            max_proposals_to_keep_per_action: Some(100),
            initial_voting_period: Some(2 * ONE_DAY_SECONDS),
            default_followees: std::collections::HashMap::new(),
            max_number_of_neurons: Some(200_000),
            neuron_minimum_dissolve_delay_to_vote_seconds: Some(6 * ONE_MONTH_SECONDS),
            max_followees_per_action: Some(15),
            max_dissolve_delay_seconds: Some(8 * ONE_YEAR_SECONDS),
            max_neuron_age_for_age_bonus: Some(4 * ONE_YEAR_SECONDS),
            reward_distribution_period_seconds: Some(ONE_DAY_SECONDS),
            max_number_of_proposals_with_ballots: Some(700),
        }
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

/// Converts a Vote integer enum value into a typed enum value.
impl From<i32> for Vote {
    fn from(vote_integer: i32) -> Vote {
        match Vote::from_i32(vote_integer) {
            Some(v) => v,
            None => {
                println!(
                    "{}Vote::from invoked with unexpected value {}.",
                    LOG_PREFIX, vote_integer
                );
                Vote::Unspecified
            }
        }
    }
}

impl Vote {
    /// Returns whether this vote is eligible for voting reward.
    pub(crate) fn eligible_for_rewards(&self) -> bool {
        match self {
            Vote::Unspecified => false,
            Vote::Yes => true,
            Vote::No => true,
        }
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
            panic!("{}: {:?}", msg, err);
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
}

impl Action {
    /// Returns whether proposals with such an action should be allowed to
    /// be submitted when the heap growth potential is low.
    pub(crate) fn allowed_when_resources_are_low(&self) -> bool {
        // TODO match id's that we want to allow
        false
    }

    /// Returns whether a provided action is a valid [Action].
    /// This is to prevent memory attacks due to keying on
    /// u64
    pub fn is_valid_action(_action: u64) -> bool {
        todo!()
    }

    pub fn from_u64(_action: u64) -> Option<Action> {
        todo!()
    }

    pub fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        todo!()
    }
}

impl From<&Action> for u64 {
    fn from(action: &Action) -> Self {
        match action {
            Action::Unspecified(_) => 0,
            Action::Motion(_) => 1,
            Action::ManageNervousSystemParameters(_) => 2,
            Action::UpgradeSnsControlledCanister(_) => 3,
            Action::ExecuteNervousSystemFunction(_) => 4,
        }
    }
}

impl Tally {
    /// Returns true if this tally corresponds to an adopted proposal.
    ///
    /// A proposal is adopted if and only if the voting power for `yes`
    /// is strictly greater than 1/2 of the total voting power -- counting
    /// neurons that are eligible to vote, but did not.
    pub(crate) fn is_absolute_majority_for_yes(&self) -> bool {
        self.yes > self.total - self.yes
    }
}

/// Summarizes a RewardEvent. Suitable for logging, because the string is
/// bounded in size.
impl fmt::Display for RewardEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RewardEvent {{ day_after_genesis: {} distributed_e8s_equivalent: {}\
                   actual_timestamp_seconds: {} settled_proposals: <vec of size {}> }})",
            self.day_after_genesis,
            self.distributed_e8s_equivalent,
            self.actual_timestamp_seconds,
            self.settled_proposals.len()
        )
    }
}

/// A general trait for the environment in which governance is running.
pub trait Environment: Send + Sync {
    /// Returns the current time, in seconds since the epoch.
    fn now(&self) -> u64;

    /// Returns a random number.
    ///
    /// This number is the same in all replicas.
    fn random_u64(&mut self) -> u64;

    /// Returns a random byte array with 32 bytes.
    ///
    /// This number is the same in all replicas.
    fn random_byte_array(&mut self) -> [u8; 32];

    /// Executes a `ExecuteNervousSystemFunction`. The standard implementation
    /// is expected to call out to another canister and eventually report
    /// the result back
    fn execute_sns_external_proposal(
        &self,
        proposal_id: u64,
        update: &ExecuteNervousSystemFunction,
    ) -> Result<(), GovernanceError>;

    /// Returns rough information as to how much the heap can grow.
    ///
    /// The intended use case is for the governance canister to avoid
    /// non-essential memory-consuming operations when the potential for heap
    /// growth becomes limited.
    fn heap_growth_potential(&self) -> HeapGrowthPotential;

    /// Returns the PrincipalId of the canister.
    fn canister_id(&self) -> CanisterId;
}

pub struct EmptyEnvironment {}

/// Not Implemented
/// For use in defaults
impl Environment for EmptyEnvironment {
    fn now(&self) -> u64 {
        unimplemented!()
    }

    fn random_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        unimplemented!()
    }

    fn execute_sns_external_proposal(
        &self,
        _proposal_id: u64,
        _update: &ExecuteNervousSystemFunction,
    ) -> Result<(), GovernanceError> {
        unimplemented!()
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        unimplemented!()
    }

    fn canister_id(&self) -> CanisterId {
        unimplemented!()
    }
}

/// Rough buckets for how much the heap can still grow.
pub enum HeapGrowthPotential {
    /// The heap can grow without issue.
    NoIssue,

    /// The heap can still grow, but not by much.
    LimitedAvailability,
}

#[async_trait]
pub trait Ledger: Send + Sync {
    /// Transfers funds from one of this canister's subaccount to a
    /// subaccount of of the provided principal.
    ///
    /// Returns the block height at which the transfer was recorded.
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: AccountIdentifier,
        memo: u64,
    ) -> Result<u64, GovernanceError>;

    async fn total_supply(&self) -> Result<Tokens, GovernanceError>;

    async fn account_balance(&self, account: AccountIdentifier) -> Result<Tokens, GovernanceError>;
}

pub struct EmptyLedger {}

#[async_trait]
impl Ledger for EmptyLedger {
    async fn transfer_funds(
        &self,
        _amount_e8s: u64,
        _fee_e8s: u64,
        _from_subaccount: Option<Subaccount>,
        _to: AccountIdentifier,
        _memo: u64,
    ) -> Result<u64, GovernanceError> {
        unimplemented!()
    }

    async fn total_supply(&self) -> Result<Tokens, GovernanceError> {
        unimplemented!()
    }

    async fn account_balance(
        &self,
        _account: AccountIdentifier,
    ) -> Result<Tokens, GovernanceError> {
        unimplemented!()
    }
}

/// A single ongoing update for a single neuron.
/// Releases the lock when destroyed.
pub struct LedgerUpdateLock {
    pub nid: u64,
    pub gov: *mut Governance,
}

impl Drop for LedgerUpdateLock {
    fn drop(&mut self) {
        // It's always ok to dereference the governance when a LedgerUpdateLock
        // goes out of scope. Indeed, in the scope of any Governance method,
        // &self always remains alive. The 'mut' is not an issue, because
        // 'unlock_neuron' will verify that the lock exists.
        let gov: &mut Governance = unsafe { &mut *self.gov };
        gov.unlock_neuron(self.nid);
    }
}
