#![allow(deprecated)]
use crate::{
    are_nf_fund_proposals_disabled, are_performance_based_rewards_enabled, decoder_config,
    governance::{
        merge_neurons::{
            build_merge_neurons_response, calculate_merge_neurons_effect,
            validate_merge_neurons_before_commit,
        },
        split_neuron::{SplitNeuronEffect, calculate_split_neuron_effect},
    },
    heap_governance_data::{
        HeapGovernanceData, XdrConversionRate, initialize_governance, reassemble_governance_proto,
        split_governance_proto,
    },
    is_comprehensive_neuron_list_enabled, is_neuron_follow_restrictions_enabled,
    is_self_describing_proposal_actions_enabled,
    neuron::{DissolveStateAndAge, Neuron, NeuronBuilder, Visibility},
    neuron_data_validation::{NeuronDataValidationSummary, NeuronDataValidator},
    neuron_store::{
        MAX_NEURON_PAGE_SIZE, NeuronMetrics, NeuronStore, approve_genesis_kyc,
        metrics::NeuronSubsetMetrics, prune_some_following,
    },
    neurons_fund::{
        NeuronsFund, NeuronsFundNeuronPortion, NeuronsFundSnapshot,
        PolynomialNeuronsFundParticipation, SwapParticipationLimits,
    },
    node_provider_rewards::{
        DateRangeFilter, latest_node_provider_rewards, list_node_provider_rewards,
        record_node_provider_rewards,
    },
    pb::{
        self,
        proposal_conversions::{ProposalDisplayOptions, proposal_data_to_info},
        v1::{
            ArchivedMonthlyNodeProviderRewards, Ballot, BlessAlternativeGuestOsVersion,
            CreateServiceNervousSystem, Followees, FulfillSubnetRentalRequest,
            GetNeuronsFundAuditInfoRequest, GetNeuronsFundAuditInfoResponse,
            Governance as GovernanceProto, GovernanceError, InstallCode, KnownNeuron,
            ListKnownNeuronsResponse, ManageNeuron, MonthlyNodeProviderRewards, Motion,
            NetworkEconomics, NeuronState, NeuronsFundAuditInfo, NeuronsFundData,
            NeuronsFundParticipation as NeuronsFundParticipationPb,
            NeuronsFundSnapshot as NeuronsFundSnapshotPb, NnsFunction, NodeProvider, Proposal,
            ProposalData, ProposalRewardStatus, ProposalStatus, RestoreAgingSummary, RewardEvent,
            RewardNodeProvider, RewardNodeProviders, SettleNeuronsFundParticipationRequest,
            SettleNeuronsFundParticipationResponse, StopOrStartCanister, Tally, Topic,
            UpdateCanisterSettings, UpdateNodeProvider, Vote, VotingPowerEconomics,
            WaitForQuietState, archived_monthly_node_provider_rewards,
            create_service_nervous_system::LedgerParameters,
            get_neurons_fund_audit_info_response,
            governance::{
                GovernanceCachedMetrics, NeuronInFlightCommand,
                governance_cached_metrics::NeuronSubsetMetrics as NeuronSubsetMetricsPb,
                neuron_in_flight_command::{Command as InFlightCommand, SyncCommand},
            },
            governance_error::ErrorType,
            manage_neuron::{
                self, ClaimOrRefresh, Command, NeuronIdOrSubaccount, SetFollowing,
                claim_or_refresh::{By, MemoAndController},
                set_following::FolloweesForTopic,
            },
            maturity_disbursement::Destination,
            neurons_fund_snapshot::NeuronsFundNeuronPortion as NeuronsFundNeuronPortionPb,
            proposal::Action,
            reward_node_provider::{RewardMode, RewardToAccount},
            settle_neurons_fund_participation_request,
            settle_neurons_fund_participation_response::{
                self, NeuronsFundNeuron as NeuronsFundNeuronPb,
            },
            swap_background_information,
        },
    },
    proposals::{
        ValidProposalAction,
        call_canister::CallCanister,
        execute_nns_function::{ValidExecuteNnsFunction, ValidNnsFunction},
        sum_weighted_voting_power,
    },
    storage::{VOTING_POWER_SNAPSHOTS, with_voting_history_store, with_voting_history_store_mut},
};
use async_trait::async_trait;
use candid::{Decode, Encode};
use chrono::NaiveDate;
use cycles_minting_canister::{IcpXdrConversionRate, IcpXdrConversionRateCertifiedResponse};
use disburse_maturity::initiate_maturity_disbursement;
#[cfg(not(target_arch = "wasm32"))]
use futures::FutureExt;
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::println;
#[cfg(target_arch = "wasm32")]
use ic_cdk::spawn;
use ic_nervous_system_canisters::cmc::CMC;
use ic_nervous_system_canisters::ledger::IcpLedger;
use ic_nervous_system_common::{
    NervousSystemError, ONE_DAY_SECONDS, ONE_MONTH_SECONDS, ONE_YEAR_SECONDS, ledger,
};
use ic_nervous_system_governance::maturity_modulation::apply_maturity_modulation;
use ic_nervous_system_proto::pb::v1::{GlobalTimeOfDay, Principals};
use ic_nervous_system_rate_limits::{
    InMemoryRateLimiter, RateLimiter, RateLimiterConfig, RateLimiterError,
};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID,
    NODE_REWARDS_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance_api::{
    self as api, CreateServiceNervousSystem as ApiCreateServiceNervousSystem,
    GetNeuronIndexRequest, GetPendingProposalsRequest, ListNeuronVotesRequest, ListNeurons,
    ListNeuronsResponse, ListProposalInfoRequest, ListProposalInfoResponse, ManageNeuronResponse,
    NeuronIndexData, NeuronInfo, NeuronVote, NeuronVotes, ProposalInfo,
    manage_neuron_response::{self, StakeMaturityResponse},
    proposal_validation::{
        validate_proposal_summary, validate_proposal_title, validate_proposal_url,
    },
    subnet_rental::SubnetRentalRequest,
};
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
};
use ic_node_rewards_canister_api::providers_rewards::{
    GetNodeProvidersRewardsRequest, GetNodeProvidersRewardsResponse,
};
use ic_node_rewards_canister_api::{DateUtc, RewardsCalculationAlgorithmVersion};
use ic_protobuf::registry::dc::v1::AddOrRemoveDataCentersProposalPayload;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_swap::pb::v1::{self as sns_swap_pb, Lifecycle, NeuronsFundParticipationConstraints};
use ic_sns_wasm::pb::v1::{
    DeployNewSnsRequest, DeployNewSnsResponse, ListDeployedSnsesRequest, ListDeployedSnsesResponse,
};
use ic_stable_structures::{Storable, storable::Bound};
use ic_types::Time;
use icp_ledger::{AccountIdentifier, Subaccount, TOKEN_SUBDIVIDABLE_BY, Tokens};
use itertools::Itertools;
use maplit::hashmap;
use registry_canister::mutations::do_add_node_operator::AddNodeOperatorPayload;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    cmp::{Ordering, max},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    convert::{TryFrom, TryInto},
    fmt,
    future::Future,
    ops::RangeInclusive,
    string::ToString,
    sync::Arc,
    time::{Duration, SystemTime},
};

pub mod disburse_maturity;
mod ledger_helper;
mod merge_neurons;
mod split_neuron;
pub mod test_data;
#[cfg(test)]
mod tests;
pub mod voting_power_snapshots;

#[cfg(feature = "canbench-rs")]
mod benches;

#[macro_use]
pub mod tla_macros;
#[cfg(feature = "tla")]
pub mod tla;

use crate::reward::distribution::RewardsDistribution;
use crate::storage::with_voting_state_machines_mut;
#[cfg(feature = "tla")]
pub use tla::{
    CLAIM_NEURON_DESC, DISBURSE_MATURITY_DESC, DISBURSE_NEURON_DESC, DISBURSE_TO_NEURON_DESC,
    InstrumentationState, MERGE_NEURONS_DESC, REFRESH_NEURON_DESC, SPAWN_NEURON_DESC,
    SPAWN_NEURONS_DESC, SPLIT_NEURON_DESC, TLA_INSTRUMENTATION_STATE, TLA_TRACES_LKEY,
    TLA_TRACES_MUTEX, ToTla, tla_update_method,
};

// 70 KB (for executing NNS functions that are not canister upgrades)
const PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX: usize = 70000;

// When wait for quiet is used, a proposal does not need to reach absolute
// majority to be accepted. However there is a minimum amount of votes needed
// for a simple majority to be enough. This minimum is expressed as a ratio of
// the total possible votes for the proposal.
const MIN_NUMBER_VOTES_FOR_PROPOSAL_RATIO: f64 = 0.03;

// Parameter of the wait for quiet algorithm. This is the maximum amount the
// deadline can be delayed on each vote.
pub const WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS: u64 = 2 * ONE_DAY_SECONDS;

// 1 KB - maximum payload size of NNS function calls to keep in listing of
// proposals
pub const EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX: usize = 1000;
// 10 KB
pub const PROPOSAL_MOTION_TEXT_BYTES_MAX: usize = 10000;

// The minimum neuron dissolve delay (set when a neuron is first claimed)
pub const INITIAL_NEURON_DISSOLVE_DELAY: u64 = 7 * ONE_DAY_SECONDS;

// The maximum dissolve delay allowed for a neuron.
pub const MAX_DISSOLVE_DELAY_SECONDS: u64 = 8 * ONE_YEAR_SECONDS;

// The age of a neuron that saturates the age bonus for the voting power
// computation.
pub const MAX_NEURON_AGE_FOR_AGE_BONUS: u64 = 4 * ONE_YEAR_SECONDS;

/// The maximum number of followees each neuron can establish for each topic.
pub const MAX_FOLLOWEES_PER_TOPIC: usize = 15;

/// The maximum number of recent ballots to keep, per neuron.
pub const MAX_NEURON_RECENT_BALLOTS: usize = 100;

/// The desired period for reward distribution events.
///
/// No two consecutive reward events will happen with less then this duration in
/// between. A reward distribution event will take place as soon as possible
/// once this duration has passed since the last one. Therefore, this is a
/// "desired" period: the actual distribution cannot be guaranteed to be
/// perfectly periodic, and inter-reward-events duration are expected to exceed
/// this desired period by a few seconds.
pub const REWARD_DISTRIBUTION_PERIOD_SECONDS: u64 = ONE_DAY_SECONDS;

/// The maximum number of neurons supported.
pub const MAX_NUMBER_OF_NEURONS: usize = 500_000;

// Spawning is exempted from rate limiting, so we don't need large of a limit here.
pub const MAX_SUSTAINED_NEURONS_PER_HOUR: u64 = 15;

pub const MINIMUM_SECONDS_BETWEEN_ALLOWANCE_INCREASE: u64 = 3600 / MAX_SUSTAINED_NEURONS_PER_HOUR;

/// The maximum number of neurons that can be created in a spike. Note that such rate of neuron
/// creation is not sustainable as the allowance will be exhausted after creating this many neurons
/// in a short period of time, and the allowance will only be increased according to
/// `MINIMUM_SECONDS_BETWEEN_ALLOWANCE_INCREASE`.
pub const MAX_NEURON_CREATION_SPIKE: u64 = MAX_SUSTAINED_NEURONS_PER_HOUR * 20;

/// The maximum number results returned by the method `list_proposals`.
pub const MAX_LIST_PROPOSAL_RESULTS: u32 = 100;

/// The maximum number of neurons returned by `list_neurons`
pub const MAX_LIST_NEURONS_RESULTS: usize = 500;

const MAX_LIST_NODE_PROVIDER_REWARDS_RESULTS: usize = 24;

/// The max number of unsettled proposals -- that is proposals for which ballots
/// are still stored.
pub const MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS: usize = 200;

/// The max number of open manage neuron proposals.
pub const MAX_NUMBER_OF_OPEN_MANAGE_NEURON_PROPOSALS: usize = 10_000;

/// Max number of hot key for each neuron.
pub const MAX_NUM_HOT_KEYS_PER_NEURON: usize = 10;

const MAX_HEAP_SIZE_IN_KIB: usize = 4 * 1024 * 1024;
const WASM32_PAGE_SIZE_IN_KIB: usize = 64;

/// Max number of wasm32 pages for the heap after which we consider that there
/// is a risk to the ability to grow the heap.
///
/// This is 7/8 of the maximum number of pages. This corresponds to 3.5 GiB.
pub const HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES: usize =
    MAX_HEAP_SIZE_IN_KIB / WASM32_PAGE_SIZE_IN_KIB * 7 / 8;

pub(crate) const LOG_PREFIX: &str = "[Governance] ";

/// The number of seconds between automated Node Provider reward events
/// Currently 1/12 of a year: 2629800 = 86400 * 365.25 / 12
pub const NODE_PROVIDER_REWARD_PERIOD_SECONDS: u64 = 2629800;

const VALID_MATURITY_MODULATION_BASIS_POINTS_RANGE: RangeInclusive<i32> = -500..=500;

/// Maximum allowed number of Neurons' Fund participants that may participate in an SNS swap. Given
/// the maximum number of SNS neurons per swap participant (a.k.a. neuron basket count), this
/// constant can be used to obtain an upper bound for the number of SNS neurons created for the
/// Neurons' Fund participants. See also `MAX_SNS_NEURONS_PER_BASKET`. In addition, this constant
/// also affects the upperbound of instructions needed to draw/refund maturity from/to the Neurons'
/// Fund, so before increasing this constant, the impact on the instructions used by
/// `CreateServiceNervousSystem` proposal execution also needs to be evaluated (currently, each
/// neuron takes ~120K instructions to draw/refund maturity, so the total is ~600M).
pub const MAX_NEURONS_FUND_PARTICIPANTS: u64 = 5_000;

/// A key for the neuron rate limiter, to make sure all add_neuron operations are limited
/// in the same limit.
const NEURON_RATE_LIMITER_KEY: &str = "ADD_NEURON";

impl GovernanceError {
    pub fn new(error_type: ErrorType) -> Self {
        Self {
            error_type: error_type as i32,
            ..Default::default()
        }
    }

    pub fn new_with_message(error_type: ErrorType, message: impl ToString) -> Self {
        Self {
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
        Self {
            error_type: ErrorType::External as i32,
            error_message: nervous_system_error.error_message,
        }
    }
}

impl From<RateLimiterError> for GovernanceError {
    fn from(value: RateLimiterError) -> Self {
        let message = match value {
            RateLimiterError::NotEnoughCapacity => {
                "Reached maximum number of neurons that can be created in this hour. \
                    Please wait and try again later."
                    .to_string()
            }
            RateLimiterError::InvalidArguments(e) => format!("Rate Limit Error: {e}"),
            RateLimiterError::MaxReservationsReached => {
                "Reached maximum number of neuron creation reservations.  This should not happen."
                    .to_string()
            }
            RateLimiterError::ReservationNotFound => "Rate limit reservation could not be \
                committed because rate limiter has no record of it."
                .to_string(),
        };

        GovernanceError::new_with_message(ErrorType::Unavailable, message)
    }
}

impl From<NeuronsFundNeuronPortion> for NeuronsFundNeuronPortionPb {
    fn from(neuron: NeuronsFundNeuronPortion) -> Self {
        #[allow(deprecated)] // TODO(NNS1-3198): Remove
        Self {
            nns_neuron_id: Some(neuron.id),
            amount_icp_e8s: Some(neuron.amount_icp_e8s),
            maturity_equivalent_icp_e8s: Some(neuron.maturity_equivalent_icp_e8s),
            controller: Some(neuron.controller),
            is_capped: Some(neuron.is_capped),
            hotkeys: neuron.hotkeys,
        }
    }
}

impl From<NeuronsFundNeuronPortion> for NeuronsFundNeuronPb {
    fn from(neuron: NeuronsFundNeuronPortion) -> Self {
        Self {
            nns_neuron_id: Some(neuron.id.id),
            amount_icp_e8s: Some(neuron.amount_icp_e8s),
            controller: Some(neuron.controller),
            hotkeys: Some(Principals::from(neuron.hotkeys.clone())),
            is_capped: Some(neuron.is_capped),
        }
    }
}

impl From<Result<NeuronsFundSnapshot, GovernanceError>> for SettleNeuronsFundParticipationResponse {
    fn from(result: Result<NeuronsFundSnapshot, GovernanceError>) -> Self {
        let result = match result {
            Ok(neurons_fund_snapshot) => {
                let neurons_fund_neuron_portions = neurons_fund_snapshot
                    .into_vec()
                    .into_iter()
                    .map(Into::<NeuronsFundNeuronPb>::into)
                    .collect();
                settle_neurons_fund_participation_response::Result::Ok(
                    settle_neurons_fund_participation_response::Ok {
                        neurons_fund_neuron_portions,
                    },
                )
            }
            Err(error) => settle_neurons_fund_participation_response::Result::Err(error),
        };
        Self {
            result: Some(result),
        }
    }
}

impl From<Result<NeuronsFundAuditInfo, GovernanceError>> for GetNeuronsFundAuditInfoResponse {
    fn from(result: Result<NeuronsFundAuditInfo, GovernanceError>) -> Self {
        let result = match result {
            Ok(neurons_fund_audit_info) => get_neurons_fund_audit_info_response::Result::Ok(
                get_neurons_fund_audit_info_response::Ok {
                    neurons_fund_audit_info: Some(neurons_fund_audit_info),
                },
            ),
            Err(error) => get_neurons_fund_audit_info_response::Result::Err(error),
        };
        GetNeuronsFundAuditInfoResponse {
            result: Some(result),
        }
    }
}

impl Vote {
    /// Returns whether this vote is eligible for voting reward.
    pub fn eligible_for_rewards(&self) -> bool {
        match self {
            Vote::Unspecified => false,
            Vote::Yes => true,
            Vote::No => true,
        }
    }
}

impl ManageNeuron {
    pub fn get_neuron_id_or_subaccount(
        &self,
    ) -> Result<Option<NeuronIdOrSubaccount>, GovernanceError> {
        match (self.id.as_ref(), self.neuron_id_or_subaccount.as_ref()) {
            (Some(_), Some(_)) => Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Both id and neuron_id_or_subaccount fields are set",
            )),
            (None, None) => Ok(None),
            (None, Some(id)) => Ok(Some(id.clone())),
            (Some(nid), None) => Ok(Some(NeuronIdOrSubaccount::NeuronId(*nid))),
        }
    }
}

impl Command {
    fn allowed_when_resources_are_low(&self) -> bool {
        match self {
            // Only making proposals and registering votes are needed to pass proposals.
            // Therefore we should disallow others when resources are low.
            Command::RegisterVote(_) => true,
            Command::MakeProposal(_) => true,
            _ => false,
        }
    }
}

impl Proposal {
    /// If this is a [ManageNeuron] proposal, this returns the ID of
    /// the managed neuron.
    pub fn managed_neuron(&self) -> Option<NeuronIdOrSubaccount> {
        if let Some(Action::ManageNeuron(manage_neuron_action)) = &self.action {
            manage_neuron_action
                .get_neuron_id_or_subaccount()
                .expect("Validation of managed neuron failed")
        } else {
            None
        }
    }

    /// String value representing the action type of the proposal used in governance canister metrics.
    pub(crate) fn action_type(&self) -> String {
        if let Some(action) = &self.action {
            let action_name = action.as_str_name();

            if let Action::ExecuteNnsFunction(m) = action {
                let nns_function_name =
                    if let Ok(nns_function) = NnsFunction::try_from(m.nns_function) {
                        nns_function.as_str_name()
                    } else {
                        println!(
                            "{}ERROR: Unknown NnsFunction: {}",
                            LOG_PREFIX, m.nns_function
                        );
                        NnsFunction::Unspecified.as_str_name()
                    };
                return format!("{action_name}-{nns_function_name}");
            }
            action_name.to_string()
        } else {
            println!("{}ERROR: No action -> no action type.", LOG_PREFIX);
            "NO_ACTION".to_string()
        }
    }
}

impl Action {
    /// String value of the enum field names.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// and safe for programmatic use.
    pub(crate) fn as_str_name(&self) -> &'static str {
        match self {
            Action::ManageNeuron(_) => "ACTION_MANAGE_NEURON",
            Action::ManageNetworkEconomics(_) => "ACTION_MANAGE_NETWORK_ECONOMICS",
            Action::Motion(_) => "ACTION_MOTION",
            Action::ApproveGenesisKyc(_) => "ACTION_APPROVE_GENESIS_KYC",
            Action::AddOrRemoveNodeProvider(_) => "ACTION_ADD_OR_REMOVE_NODE_PROVIDER",
            Action::RewardNodeProvider(_) => "ACTION_REWARD_NODE_PROVIDER",
            Action::RewardNodeProviders(_) => "ACTION_REWARD_NODE_PROVIDERS",
            Action::SetDefaultFollowees(_) => "ACTION_SET_DEFAULT_FOLLOWEES",
            Action::RegisterKnownNeuron(_) => "ACTION_REGISTER_KNOWN_NEURON",
            Action::DeregisterKnownNeuron(_) => "ACTION_DEREGISTER_KNOWN_NEURON",
            Action::SetSnsTokenSwapOpenTimeWindow(_) => {
                "ACTION_SET_SNS_TOKEN_SWAP_OPEN_TIME_WINDOW"
            }
            Action::OpenSnsTokenSwap(_) => "ACTION_OPEN_SNS_TOKEN_SWAP",
            Action::CreateServiceNervousSystem(_) => "ACTION_CREATE_SERVICE_NERVOUS_SYSTEM",
            Action::ExecuteNnsFunction(_) => "ACTION_EXECUTE_NNS_FUNCTION",
            Action::InstallCode(_) => "ACTION_CHANGE_CANISTER",
            Action::StopOrStartCanister(_) => "ACTION_STOP_OR_START_CANISTER",
            Action::UpdateCanisterSettings(_) => "ACTION_UPDATE_CANISTER_SETTINGS",
            Action::FulfillSubnetRentalRequest(_) => "ACTION_FULFILL_SUBNET_RENTAL_REQUEST",
            Action::BlessAlternativeGuestOsVersion(_) => {
                "ACTION_BLESS_ALTERNATIVE_GUEST_OS_VERSION"
            }
        }
    }
}

impl ProposalData {
    /// Compute the 'status' of a proposal. See [ProposalStatus] for
    /// more information.
    pub fn status(&self) -> ProposalStatus {
        if self.decided_timestamp_seconds == 0 {
            ProposalStatus::Open
        } else if self.is_accepted() {
            if self.executed_timestamp_seconds > 0 {
                ProposalStatus::Executed
            } else if self.failed_timestamp_seconds > 0 {
                ProposalStatus::Failed
            } else {
                ProposalStatus::Adopted
            }
        } else {
            ProposalStatus::Rejected
        }
    }

    /// Whether this proposal is restricted, that is, whether neuron voting
    /// eligibility depends on the content of this proposal.
    pub fn is_manage_neuron(&self) -> bool {
        self.topic() == Topic::NeuronManagement
    }

    pub fn reward_status(
        &self,
        now_seconds: u64,
        voting_period_seconds: u64,
    ) -> ProposalRewardStatus {
        if self.is_manage_neuron() {
            return ProposalRewardStatus::Ineligible;
        }
        match self.reward_event_round {
            0 => {
                if self.accepts_vote(now_seconds, voting_period_seconds) {
                    ProposalRewardStatus::AcceptVotes
                } else {
                    ProposalRewardStatus::ReadyToSettle
                }
            }
            _ => ProposalRewardStatus::Settled,
        }
    }

    pub fn get_deadline_timestamp_seconds(&self, voting_period_seconds: u64) -> u64 {
        if let Some(wait_for_quiet_state) = &self.wait_for_quiet_state {
            wait_for_quiet_state.current_deadline_timestamp_seconds
        } else {
            self.proposal_timestamp_seconds
                .saturating_add(voting_period_seconds)
        }
    }

    /// Returns true if votes are still accepted for this proposal and
    /// false otherwise.
    ///
    /// For voting reward purposes, votes may be accepted even after a
    /// decision has been made on a proposal. Such votes will not
    /// affect the decision on the proposal, but they affect the
    /// voting rewards of the voting neuron.
    ///
    /// This, this method can return true even if the proposal is
    /// already decided.
    pub fn accepts_vote(&self, now_seconds: u64, voting_period_seconds: u64) -> bool {
        // Naive version of the wait-for-quiet mechanics. For now just tests
        // that the proposal duration is smaller than the threshold, which
        // we're just currently setting as seconds.
        //
        // Wait for quiet is meant to be able to decide proposals without
        // quorum. The tally must have been done above already.
        //
        // If the wait for quit threshold is unset (0), then proposals can
        // accept votes forever.
        now_seconds < self.get_deadline_timestamp_seconds(voting_period_seconds)
    }

    /// Returns true if the proposal has unprocessed votes in the state machine.
    pub fn has_unprocessed_votes(&self) -> bool {
        with_voting_state_machines_mut(|vsm| vsm.machine_has_votes_to_process(self.id.unwrap()))
    }

    pub fn evaluate_wait_for_quiet(
        &mut self,
        now_seconds: u64,
        voting_period_seconds: u64,
        old_tally: &Tally,
        new_tally: &Tally,
    ) {
        let wait_for_quiet_state = match self.wait_for_quiet_state.as_mut() {
            Some(wait_for_quiet_state) => wait_for_quiet_state,
            None => return,
        };

        // Don't evaluate wait for quiet if there is already a decision, or the
        // deadline has been met. The deciding amount for yes and no are
        // slightly different, because yes needs a majority to succeed, while
        // no only needs a tie.
        let current_deadline = wait_for_quiet_state.current_deadline_timestamp_seconds;
        let deciding_amount_yes = new_tally.total / 2 + 1;
        let deciding_amount_no = new_tally.total.div_ceil(2);
        if new_tally.yes >= deciding_amount_yes
            || new_tally.no >= deciding_amount_no
            || now_seconds > current_deadline
        {
            return;
        }

        // Returns whether the vote has turned, i.e. if the vote is now yes, when it was
        // previously no, or if the vote is now no if it was previously yes.
        fn vote_has_turned(old_tally: &Tally, new_tally: &Tally) -> bool {
            (old_tally.yes > old_tally.no && new_tally.yes <= new_tally.no)
                || (old_tally.yes <= old_tally.no && new_tally.yes > new_tally.no)
        }
        if !vote_has_turned(old_tally, new_tally) {
            return;
        }

        // The required_margin reflects the proposed deadline extension to be
        // made beyond the current moment, so long as that extends beyond the
        // current wait-for-quiet deadline. We calculate the required_margin a
        // bit indirectly here so as to keep with unsigned integers, but the
        // idea is:
        //
        //     W + (voting_period - elapsed) / 2
        //
        // Thus, while we are still within the original voting period, we add
        // to W, but once we are beyond that window, we subtract from W until
        // reaching the limit where required_margin remains at zero. This
        // occurs when:
        //
        //     elapsed = voting_period + 2 * W
        //
        // As an example, given that W = 12h, if the initial voting_period is
        // 24h then the maximum deadline will be 48h.
        //
        // The required_margin ends up being a linearly decreasing value,
        // starting at W + voting_period / 2 and reducing to zero at the
        // furthest possible deadline. When the vote does not flip, we do not
        // update the deadline, and so there is a chance of ending prior to
        // the extreme limit. But each time the vote flips, we "re-enter" the
        // linear progression according to the elapsed time.
        //
        // This means that whenever there is a flip, the deadline is always
        // set to the current time plus the required_margin, which places us
        // along the a linear path that was determined by the starting
        // variables.
        let elapsed_seconds = now_seconds.saturating_sub(self.proposal_timestamp_seconds);
        let required_margin = WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS
            .saturating_add(voting_period_seconds / 2)
            .saturating_sub(elapsed_seconds / 2);
        let new_deadline = std::cmp::max(
            current_deadline,
            now_seconds.saturating_add(required_margin),
        );

        if new_deadline != current_deadline {
            println!(
                "{}Updating WFQ deadline for proposal: {:?}. Old: {}, New: {}, Ext: {}",
                LOG_PREFIX,
                self.id.unwrap(),
                current_deadline,
                new_deadline,
                new_deadline - current_deadline
            );

            wait_for_quiet_state.current_deadline_timestamp_seconds = new_deadline;
        }
    }

    /// This is an expensive operation.
    pub fn recompute_tally(&mut self, now_seconds: u64, voting_period_seconds: u64) {
        // Tally proposal
        let mut yes = 0;
        let mut no = 0;
        let mut undecided = 0;
        for ballot in self.ballots.values() {
            let lhs: &mut u64 = if let Ok(vote) = Vote::try_from(ballot.vote) {
                match vote {
                    Vote::Unspecified => &mut undecided,
                    Vote::Yes => &mut yes,
                    Vote::No => &mut no,
                }
            } else {
                &mut undecided
            };
            *lhs = (*lhs).saturating_add(ballot.voting_power)
        }

        // It is validated in `make_proposal` that the total does not
        // exceed u64::MAX: the `saturating_add` is just a precaution.
        let total = yes.saturating_add(no).saturating_add(undecided);

        let new_tally = Tally {
            timestamp_seconds: now_seconds,
            yes,
            no,
            total,
        };

        // Every time the tally changes, (possibly) update the wait-for-quiet
        // dynamic deadline.
        if let Some(old_tally) = self.latest_tally {
            if new_tally.yes == old_tally.yes
                && new_tally.no == old_tally.no
                && new_tally.total == old_tally.total
            {
                return;
            }

            self.evaluate_wait_for_quiet(
                now_seconds,
                voting_period_seconds,
                &old_tally,
                &new_tally,
            );
        }

        self.latest_tally = Some(new_tally);
    }

    /// Returns true if a proposal meets the conditions to be accepted. The
    /// result is only meaningful if the deadline has passed.
    pub fn is_accepted(&self) -> bool {
        if let Some(tally) = self.latest_tally.as_ref() {
            if self.wait_for_quiet_state.is_none() {
                tally.is_absolute_majority_for_yes()
            } else {
                (tally.yes as f64 >= tally.total as f64 * MIN_NUMBER_VOTES_FOR_PROPOSAL_RATIO)
                    && tally.yes > tally.no
            }
        } else {
            false
        }
    }

    /// Returns true if a decision may be made right now to adopt or
    /// reject this proposal. The proposal must be tallied prior to
    /// calling this method.
    pub(crate) fn can_make_decision(&self, now_seconds: u64, voting_period_seconds: u64) -> bool {
        if let Some(tally) = &self.latest_tally {
            // A proposal is adopted if strictly more than half of the
            // votes are 'yes' and rejected if at least half of the votes
            // are 'no'. The conditions are described as below to avoid
            // overflow. In the absence of overflow, the below is
            // equivalent to (2 * yes > total) || (2 * no >= total).
            let majority =
                (tally.yes > tally.total - tally.yes) || (tally.no >= tally.total - tally.no);
            let can_accept_votes = self.accepts_vote(now_seconds, voting_period_seconds);
            let votes_still_processing = self.has_unprocessed_votes();
            let polls_open_or_still_counting = can_accept_votes || votes_still_processing;
            let expired = !polls_open_or_still_counting;

            // NOTE: expired is not exactly the right concept in the case where votes are still
            // processing.
            let decision_reason = match (majority, expired) {
                (true, true) => Some("majority and expiration"),
                (true, false) => Some("majority"),
                (false, true) => Some("expiration"),
                (false, false) => None,
            };
            if let Some(reason) = decision_reason {
                println!(
                    "{}Proposal {} decided, thanks to {}. Tally at decision time: {:?}",
                    LOG_PREFIX,
                    self.id
                        .map_or("unknown".to_string(), |i| format!("{}", i.id)),
                    reason,
                    tally
                );
                return true;
            }
        }
        false
    }

    fn set_swap_lifecycle_by_settle_neurons_fund_participation_request_type(
        &mut self,
        result: &SwapResult,
    ) {
        let lifecycle = match result {
            SwapResult::Committed { .. } => Lifecycle::Committed,
            SwapResult::Aborted => Lifecycle::Aborted,
        };
        self.set_sns_token_swap_lifecycle(lifecycle);
    }

    fn get_neurons_fund_data_or_err(&self) -> Result<&NeuronsFundData, GovernanceError> {
        let Some(neurons_fund_data) = self.neurons_fund_data.as_ref() else {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!("Neurons Fund data not found ({:?}).", self.id),
            ));
        };
        Ok(neurons_fund_data)
    }

    fn mut_neurons_fund_data_or_err(&mut self) -> Result<&mut NeuronsFundData, GovernanceError> {
        let Some(neurons_fund_data) = self.neurons_fund_data.as_mut() else {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!("Neurons Fund data not found ({:?}).", self.id),
            ));
        };
        Ok(neurons_fund_data)
    }
}

#[cfg(test)]
mod test_wait_for_quiet {
    use crate::pb::v1::{ProposalData, Tally, WaitForQuietState};
    use ic_nns_common::pb::v1::ProposalId;
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
            let proposal_timestamp_seconds = 0; // initial timestamp is always 0
            let mut proposal = ProposalData {
                id: Some(ProposalId { id: 0 }),
                proposal_timestamp_seconds,
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

impl ProposalStatus {
    /// Return true if this status is 'final' in the sense that no
    /// further state transitions are possible.
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            ProposalStatus::Rejected | ProposalStatus::Executed | ProposalStatus::Failed
        )
    }
}

impl ProposalRewardStatus {
    /// Return true if this reward status is 'final' in the sense that
    /// no further state transitions are possible.
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            ProposalRewardStatus::Settled | ProposalRewardStatus::Ineligible
        )
    }
}

impl Topic {
    pub const MIN: Topic = Topic::Unspecified;
    // A unit test will fail if this value does not stay up to date (e.g. when a new value is
    // added).
    pub const MAX: Topic = Topic::ServiceNervousSystemManagement;

    /// When voting rewards are distributed, the voting power of
    /// neurons voting on proposals are weighted by this amount. The
    /// weights are designed to encourage active participation from
    /// neuron holders.
    pub fn reward_weight(&self) -> f64 {
        match self {
            // We provide higher voting rewards for neuron holders
            // who vote on Governance and SnsAndCommunityFund proposals.
            Topic::Governance => 20.0,
            Topic::SnsAndCommunityFund => 20.0,
            // Lower voting rewards for exchange rate proposals.
            Topic::ExchangeRate => 0.01,
            // Other topics are unit weighted. Typically a handful of
            // proposals per day (excluding weekends).
            _ => 1.0,
        }
    }
}

impl Storable for Topic {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned((*self as i32).to_le_bytes().to_vec())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self::try_from(i32::from_le_bytes(bytes.as_ref().try_into().unwrap()))
            .expect("Failed to read i32 as Topic")
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: std::mem::size_of::<u32>() as u32,
        is_fixed_size: true,
    };
}

impl Tally {
    /// Returns true if this tally corresponds to an adopted proposal.
    ///
    /// A proposal is adopted if and only if the voting power for `yes`
    /// is strictly greater than 1/2 of the total voting power -- counting
    /// neurons that are eligible to vote, but did not.
    fn is_absolute_majority_for_yes(&self) -> bool {
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
                   actual_timestamp_seconds: {} settled_proposals: <vec of size {}>\
                   total_available_e8s_equivalent: {} }})",
            self.day_after_genesis,
            self.distributed_e8s_equivalent,
            self.actual_timestamp_seconds,
            self.settled_proposals.len(),
            self.total_available_e8s_equivalent,
        )
    }
}

#[derive(Debug)]
pub enum RngError {
    RngNotInitialized,
}

impl From<RngError> for GovernanceError {
    fn from(e: RngError) -> Self {
        match e {
            RngError::RngNotInitialized => GovernanceError::new_with_message(
                ErrorType::Unavailable,
                "Rng not initialized.  Try again later.".to_string(),
            ),
        }
    }
}

pub trait RandomnessGenerator: Send + Sync {
    /// Returns a random number.
    ///
    /// This number is the same in all replicas.
    fn random_u64(&mut self) -> Result<u64, RngError>;

    /// Returns a random byte array with 32 bytes.
    ///
    /// This number is the same in all replicas.
    fn random_byte_array(&mut self) -> Result<[u8; 32], RngError>;

    // Seed the random number generator.
    fn seed_rng(&mut self, seed: [u8; 32]);

    // Get the current RNG seed (used in pre-upgrade)
    fn get_rng_seed(&self) -> Option<[u8; 32]>;
}

/// A general trait for the environment in which governance is running.
#[async_trait]
pub trait Environment: Send + Sync {
    /// Returns the current time, in seconds since the epoch.
    fn now(&self) -> u64;

    fn now_system_time(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.now())
    }

    #[cfg(any(test, feature = "test"))]
    fn set_time_warp(&self, _new_time_warp: TimeWarp) {
        panic!("Not implemented.");
    }

    /// Executes a `ValidExecuteNnsFunction`. The standard implementation is
    /// expected to call out to another canister and eventually report the
    /// result back
    ///
    /// See also call_candid_method.
    fn execute_nns_function(
        &self,
        proposal_id: u64,
        update: &ValidExecuteNnsFunction,
    ) -> Result<(), GovernanceError>;

    /// Returns rough information as to how much the heap can grow.
    ///
    /// The intended use case is for the governance canister to avoid
    /// non-essential memory-consuming operations when the potential for heap
    /// growth becomes limited.
    fn heap_growth_potential(&self) -> HeapGrowthPotential;

    /// Basically, the same as ic_cdk::api::call_raw.
    async fn call_canister_method(
        &self,
        target: CanisterId,
        method_name: &str,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)>;
}

/// Rough buckets for how much the heap can still grow.
pub enum HeapGrowthPotential {
    /// The heap can grow without issue.
    NoIssue,

    /// The heap can still grow, but not by much.
    LimitedAvailability,
}

/// The `Governance` canister implements the full public interface of the
/// IC's governance system.
pub struct Governance {
    /// The Governance Protobuf which contains all persistent state of
    /// the IC's governance system except for neurons. Needs to be stored and
    /// retrieved on upgrades after being reassembled along with neurons.
    pub heap_data: HeapGovernanceData,

    /// Stores all neurons and related data.
    pub neuron_store: NeuronStore,

    /// Implementation of Environment to make unit testing easier.
    pub env: Arc<dyn Environment>,

    /// Implementation of the interface with the Ledger canister.
    ledger: Arc<dyn IcpLedger>,

    /// Implementation of the interface with the CMC canister.
    cmc: Arc<dyn CMC>,

    /// Implementation of a randomness generator
    randomness: Box<dyn RandomnessGenerator>,

    /// Timestamp, in seconds since the unix epoch, until which no proposal
    /// needs to be processed.
    closest_proposal_deadline_timestamp_seconds: u64,

    /// The time of the latest "garbage collection" - when obsolete
    /// proposals were cleaned up.
    pub latest_gc_timestamp_seconds: u64,

    /// The number of proposals after the last time GC was run.
    pub latest_gc_num_proposals: usize,

    /// For validating neuron related data.
    neuron_data_validator: NeuronDataValidator,

    rate_limiter: InMemoryRateLimiter<String>,
}

pub fn governance_minting_account() -> AccountIdentifier {
    AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), None)
}

pub fn neuron_subaccount(subaccount: Subaccount) -> AccountIdentifier {
    AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(subaccount))
}

#[derive(Debug)]
pub enum SwapResult {
    Aborted,
    Committed {
        sns_governance_canister_id: PrincipalId,
        total_direct_participation_icp_e8s: u64,
        total_neurons_fund_participation_icp_e8s: u64,
    },
}

impl TryFrom<settle_neurons_fund_participation_request::Result> for SwapResult {
    type Error = String;

    fn try_from(
        swap_result_pb: settle_neurons_fund_participation_request::Result,
    ) -> Result<Self, Self::Error> {
        use settle_neurons_fund_participation_request::Result;
        match swap_result_pb {
            Result::Committed(committed) => {
                let sns_governance_canister_id =
                    committed.sns_governance_canister_id.ok_or_else(|| {
                        "Committed.sns_governance_canister_id must be specified".to_string()
                    })?;
                let total_direct_participation_icp_e8s = committed
                    .total_direct_participation_icp_e8s
                    .ok_or_else(|| {
                        "Committed.total_direct_participation_icp_e8s must be specified".to_string()
                    })?;
                let total_neurons_fund_participation_icp_e8s = committed
                    .total_neurons_fund_participation_icp_e8s
                    .ok_or_else(|| {
                        "Committed.total_neurons_fund_participation_icp_e8s must be specified"
                            .to_string()
                    })?;
                Ok(SwapResult::Committed {
                    sns_governance_canister_id,
                    total_direct_participation_icp_e8s,
                    total_neurons_fund_participation_icp_e8s,
                })
            }
            Result::Aborted(_) => Ok(SwapResult::Aborted),
        }
    }
}

#[derive(Debug)]
pub struct ValidatedSettleNeuronsFundParticipationRequest {
    pub request_str: String,
    pub nns_proposal_id: ProposalId,
    pub swap_result: SwapResult,
}

impl TryFrom<SettleNeuronsFundParticipationRequest>
    for ValidatedSettleNeuronsFundParticipationRequest
{
    type Error = GovernanceError;

    /// Collect defects of a SettleNeuronsFundParticipationRequest request into Err,
    /// or return validated data in the Ok case.
    fn try_from(request: SettleNeuronsFundParticipationRequest) -> Result<Self, Self::Error> {
        // Validate request.nns_proposal_id
        let validated_proposal_id = {
            if let Some(id) = request.nns_proposal_id {
                Ok(ProposalId { id })
            } else {
                Err(vec!["Request.nns_proposal_id is unspecified.".to_string()])
            }
        };
        let request_str = format!("{:#?}", &request);
        // Validate request.result
        let swap_result = if let Some(result) = request.result {
            SwapResult::try_from(result).map_err(|err| vec![err])
        } else {
            Err(vec![
                "Request.result is unspecified (must be either Committed or Aborted).".to_string(),
            ])
        };
        // Compose the validated results
        match (validated_proposal_id, swap_result) {
            (Ok(nns_proposal_id), Ok(swap_result)) => Ok(Self {
                request_str,
                nns_proposal_id,
                swap_result,
            }),
            (Ok(_), Err(proposal_type_defects)) => Err(proposal_type_defects),
            (Err(proposal_id_defects), Ok(_)) => Err(proposal_id_defects),
            (Err(proposal_id_defects), Err(proposal_type_defects)) => {
                let defects = proposal_id_defects
                    .into_iter()
                    .chain(proposal_type_defects)
                    .collect();
                Err(defects)
            }
        }
            .map_err(|defects| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    format!(
                        "SettleNeuronsFundParticipation is invalid for the following reason(s):\n  - {}",
                        defects.join("\n  - "),
                    ),
                )
            })
    }
}

/// This function is used to spawn a future in a way that is compatible with both the WASM and
/// non-WASM environments that are used for testing.  This only actually spawns in the case where
/// the WASM is running in the IC, or has some other source of asynchrony.  Otherwise, it
/// immediately executes.s
fn spawn_in_canister_env(future: impl Future<Output = ()> + Sized + 'static) {
    #[cfg(target_arch = "wasm32")]
    {
        spawn(future);
    }
    // This is needed for tests
    #[cfg(not(target_arch = "wasm32"))]
    {
        future
            .now_or_never()
            .expect("Future could not execute in non-WASM environment");
    }
}

fn new_rate_limiter() -> InMemoryRateLimiter<String> {
    RateLimiter::new_in_memory(RateLimiterConfig {
        add_capacity_amount: 1,
        add_capacity_interval: Duration::from_secs(MINIMUM_SECONDS_BETWEEN_ALLOWANCE_INCREASE),
        max_capacity: MAX_NEURON_CREATION_SPIKE,
        // It should not be possible to have more than MAX_NEURON_CREATION_SPIKE_RESERVATIONS
        // because there is only one reservation space being used.
        // But we don't want to hit that error, so we add an extra one.
        max_reservations: MAX_NEURON_CREATION_SPIKE + 1,
    })
}

impl Governance {
    /// Creates a new Governance instance with uninitialized fields. The canister should only have
    /// such state before the state is recovered from the stable memory in post_upgrade or
    /// initialized in init. In any other case, the `Governance` object should be initialized with
    /// either `new` or `new_restored`.
    pub fn new_uninitialized(
        env: Arc<dyn Environment>,
        ledger: Arc<dyn IcpLedger>,
        cmc: Arc<dyn CMC>,
        randomness: Box<dyn RandomnessGenerator>,
    ) -> Self {
        Self {
            heap_data: HeapGovernanceData::default(),
            neuron_store: NeuronStore::new(BTreeMap::new()),
            env,
            ledger,
            cmc,
            randomness,
            closest_proposal_deadline_timestamp_seconds: 0,
            latest_gc_timestamp_seconds: 0,
            latest_gc_num_proposals: 0,
            neuron_data_validator: NeuronDataValidator::new(),
            rate_limiter: new_rate_limiter(),
        }
    }

    /// Initializes Governance for the first time from init payload. When restoring after an upgrade
    /// with its persisted state, `Governance::new_restored` should be called instead.
    pub fn new(
        initial_governance: api::Governance,
        env: Arc<dyn Environment>,
        ledger: Arc<dyn IcpLedger>,
        cmc: Arc<dyn CMC>,
        randomness: Box<dyn RandomnessGenerator>,
    ) -> Self {
        let (neurons, heap_governance_proto) = initialize_governance(initial_governance, env.now());

        Self {
            heap_data: heap_governance_proto,
            neuron_store: NeuronStore::new(neurons),
            env,
            ledger,
            cmc,
            randomness,
            closest_proposal_deadline_timestamp_seconds: 0,
            latest_gc_timestamp_seconds: 0,
            latest_gc_num_proposals: 0,
            neuron_data_validator: NeuronDataValidator::new(),
            rate_limiter: new_rate_limiter(),
        }
    }

    /// Restores Governance after an upgrade from its persisted state.
    pub fn new_restored(
        governance_proto: GovernanceProto,
        env: Arc<dyn Environment>,
        ledger: Arc<dyn IcpLedger>,
        cmc: Arc<dyn CMC>,
        mut randomness: Box<dyn RandomnessGenerator>,
    ) -> Self {
        let (heap_governance_proto, maybe_rng_seed) = split_governance_proto(governance_proto);

        // Carry over the previous rng seed to avoid race conditions in handling queued ingress
        // messages that may require a functioning RNG.
        if let Some(rng_seed) = maybe_rng_seed {
            randomness.seed_rng(rng_seed);
        }

        Self {
            heap_data: heap_governance_proto,
            neuron_store: NeuronStore::new_restored(),
            env,
            ledger,
            cmc,
            randomness,
            closest_proposal_deadline_timestamp_seconds: 0,
            latest_gc_timestamp_seconds: 0,
            latest_gc_num_proposals: 0,
            neuron_data_validator: NeuronDataValidator::new(),
            rate_limiter: new_rate_limiter(),
        }
    }

    /// After calling this method, the proto and neuron_store (the heap neurons at least)
    /// becomes unusable, so it should only be called in pre_upgrade once.
    pub fn take_heap_proto(&mut self) -> GovernanceProto {
        let heap_governance_proto = std::mem::take(&mut self.heap_data);
        let rng_seed = self.randomness.get_rng_seed();
        reassemble_governance_proto(heap_governance_proto, rng_seed)
    }

    pub fn seed_rng(&mut self, seed: [u8; 32]) {
        self.randomness.seed_rng(seed);
    }

    /// Validates that the underlying protobuf is well formed.
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if self.heap_data.economics.is_none() {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                "Network economics was not found",
            ));
        }

        self.validate_default_followees(&self.heap_data.default_followees)?;

        Ok(())
    }

    // Returns whether the proposed default following is valid by making
    // sure that the referred-to neurons exist.
    fn validate_default_followees(
        &self,
        proposed: &HashMap<i32, Followees>,
    ) -> Result<(), GovernanceError> {
        for followees in proposed.values() {
            for followee in &followees.followees {
                if !self.neuron_store.contains(*followee) {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::NotFound,
                        "One or more of the neurons proposed to become \
                         the new default followees don't exist.",
                    ));
                }
            }
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test"))]
    pub fn set_time_warp(&mut self, new_time_warp: TimeWarp) {
        // This is not very DRY, because we have to keep a couple copies of TimeWarp in sync.
        // However, trying to share one copy of TimeWarp seems difficult. Seems like you would have
        // to use Arc<Mutex<...>>, and clone that. The problem there is that you then run the risk
        // of failing to lock the Mutex, which is a giant can of worms that our punny human brains
        // are not good at getting right.
        self.env.set_time_warp(new_time_warp);
        self.neuron_store.set_time_warp(new_time_warp);
    }

    fn transaction_fee(&self) -> u64 {
        self.economics().transaction_fee_e8s
    }

    fn neuron_not_found_error(nid: &NeuronId) -> GovernanceError {
        GovernanceError::new_with_message(ErrorType::NotFound, format!("Neuron not found: {nid:?}"))
    }

    fn no_neuron_for_subaccount_error(subaccount: &[u8]) -> GovernanceError {
        GovernanceError::new_with_message(
            ErrorType::NotFound,
            format!("No neuron found for subaccount {subaccount:?}"),
        )
    }

    fn bytes_to_subaccount(bytes: &[u8]) -> Result<icp_ledger::Subaccount, GovernanceError> {
        bytes.try_into().map_err(|_| {
            GovernanceError::new_with_message(ErrorType::PreconditionFailed, "Invalid subaccount")
        })
    }

    fn find_neuron_id(&self, find_by: &NeuronIdOrSubaccount) -> Result<NeuronId, GovernanceError> {
        match find_by {
            NeuronIdOrSubaccount::NeuronId(neuron_id) => {
                if self.neuron_store.contains(*neuron_id) {
                    Ok(*neuron_id)
                } else {
                    Err(Self::neuron_not_found_error(neuron_id))
                }
            }
            NeuronIdOrSubaccount::Subaccount(subaccount) => self
                .neuron_store
                .get_neuron_id_for_subaccount(Self::bytes_to_subaccount(subaccount)?)
                .ok_or_else(|| Self::no_neuron_for_subaccount_error(subaccount)),
        }
    }

    pub fn with_neuron<R>(
        &self,
        nid: &NeuronId,
        map: impl FnOnce(&Neuron) -> R,
    ) -> Result<R, GovernanceError> {
        Ok(self.neuron_store.with_neuron(nid, map)?)
    }

    pub fn with_neuron_by_neuron_id_or_subaccount<R>(
        &self,
        find_by: &NeuronIdOrSubaccount,
        f: impl FnOnce(&Neuron) -> R,
    ) -> Result<R, GovernanceError> {
        let neuron_id = self.find_neuron_id(find_by)?;
        self.with_neuron(&neuron_id, f)
    }

    pub fn with_neuron_mut<R>(
        &mut self,
        neuron_id: &NeuronId,
        f: impl FnOnce(&mut Neuron) -> R,
    ) -> Result<R, GovernanceError> {
        Ok(self.neuron_store.with_neuron_mut(neuron_id, f)?)
    }

    /// Updates a neuron in the list of neurons.
    ///
    /// Preconditions:
    /// - the given `neuron` already exists in `self.neuron_store.neurons`
    #[cfg(feature = "test")]
    pub fn update_neuron(&mut self, neuron: api::Neuron) -> Result<(), GovernanceError> {
        // Converting from API type to internal type.
        let new_neuron = Neuron::try_from(neuron).expect("Neuron must be valid");

        self.with_neuron_mut(&new_neuron.id(), |old_neuron| {
            let subaccount = old_neuron.subaccount();
            if new_neuron.subaccount() != subaccount {
                return Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!("Cannot change the subaccount {subaccount} of a neuron."),
                ));
            }
            *old_neuron = new_neuron;
            Ok(())
        })?
    }

    /// Add a neuron to the list of neurons.
    ///
    /// Fails under the following conditions:
    /// - the maximum number of neurons has been reached, or
    /// - the given `neuron_id` already exists in `self.neuron_store.neurons`, or
    /// - the neuron's controller `PrincipalId` is not self-authenticating.
    pub(crate) fn add_neuron(
        &mut self,
        neuron_id: u64,
        neuron: Neuron,
    ) -> Result<(), GovernanceError> {
        if neuron_id == 0 {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Cannot add neuron with ID zero".to_string(),
            ));
        }
        {
            let neuron_real_id = neuron.id().id;
            if neuron_real_id != neuron_id {
                return Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!(
                        "The neuron's ID {neuron_real_id} does not match the provided ID {neuron_id}"
                    ),
                ));
            }
        }

        // New neurons are not allowed when the heap is too large.
        self.check_heap_can_grow()?;

        if self.neuron_store.len() + 1 > MAX_NUMBER_OF_NEURONS {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Cannot add neuron. Max number of neurons reached.",
            ));
        }
        if self.neuron_store.contains(NeuronId { id: neuron_id }) {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!("Cannot add neuron. There is already a neuron with id: {neuron_id:?}"),
            ));
        }

        self.neuron_store.add_neuron(neuron)?;

        Ok(())
    }

    /// Remove a neuron from the list of neurons.
    ///
    /// Fail if the given `neuron_id` doesn't exist in `self.neuron_store`.
    /// Caller should make sure neuron.id = Some(NeuronId {id: neuron_id}).
    fn remove_neuron(&mut self, neuron: Neuron) -> Result<(), GovernanceError> {
        let neuron_id = neuron.id();
        if !self.neuron_store.contains(neuron_id) {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!("Cannot remove neuron. Can't find a neuron with id: {neuron_id:?}"),
            ));
        }
        self.neuron_store.remove_neuron(&neuron_id);

        Ok(())
    }

    /// TODO(NNS1-2499): inline this.
    /// Return the Neuron IDs of all Neurons that have `principal` as their
    /// controller or as one of their hot keys.
    pub fn get_neuron_ids_by_principal(&self, principal_id: &PrincipalId) -> BTreeSet<NeuronId> {
        self.neuron_store
            .get_neuron_ids_readable_by_caller(*principal_id)
    }

    /// Return the union of `followees` with the set of Neuron IDs of all
    /// Neurons that directly follow the `followees` w.r.t. the
    /// topic `NeuronManagement`.
    pub fn get_managed_neuron_ids_for(&self, followees: Vec<NeuronId>) -> Vec<NeuronId> {
        // Tap into the neuron followee index for followers of level zero neurons.
        let mut managed: Vec<NeuronId> = followees.clone();
        for followee in followees {
            managed.extend(
                self.neuron_store
                    .get_followers_by_followee_and_topic(followee, Topic::NeuronManagement),
            )
        }

        managed
    }

    /// See `ListNeurons`.
    pub fn list_neurons(
        &self,
        list_neurons: &ListNeurons,
        caller: PrincipalId,
    ) -> ListNeuronsResponse {
        let now = self.env.now();

        let ListNeurons {
            neuron_ids,
            include_neurons_readable_by_caller,
            include_empty_neurons_readable_by_caller,
            include_public_neurons_in_full_neurons,
            page_number,
            page_size,
            neuron_subaccounts,
        } = list_neurons;

        let page_number = page_number.unwrap_or(0);
        let page_size = page_size
            .unwrap_or(MAX_LIST_NEURONS_RESULTS as u64)
            .min(MAX_LIST_NEURONS_RESULTS as u64);

        let include_empty_neurons_readable_by_caller =
            include_empty_neurons_readable_by_caller.unwrap_or(false);
        let include_public_neurons_in_full_neurons =
            include_public_neurons_in_full_neurons.unwrap_or(false);

        // This just includes (the ID of) neurons where the caller is controller
        // or hotkey. Whereas, this does NOT include neurons that are
        //
        //     1. public, nor
        //
        //     2. can be targetted by a ManageNeuron proposal that the caller is
        //        allowed to make or vote on (by virtue of following on then
        //        NeuronManagement topic). In other words, caller can vote with
        //        (another) neuron M, and the neuron follows M on the
        //        NeuronManagement topic.
        let mut implicitly_requested_neuron_ids = if *include_neurons_readable_by_caller {
            if include_empty_neurons_readable_by_caller {
                self.get_neuron_ids_by_principal(&caller)
                    .into_iter()
                    .collect()
            } else {
                self.neuron_store
                    .get_non_empty_neuron_ids_readable_by_caller(caller)
            }
        } else {
            BTreeSet::new()
        };

        let mut neurons_by_subaccount: BTreeSet<NeuronId> = neuron_subaccounts
            .as_ref()
            .map(|subaccounts| {
                subaccounts
                    .iter()
                    .flat_map(|neuron_subaccount| {
                        Self::bytes_to_subaccount(&neuron_subaccount.subaccount)
                            .ok()
                            .and_then(|subaccount| {
                                self.neuron_store.get_neuron_id_for_subaccount(subaccount)
                            })
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Concatenate (explicit and implicit)-ly included neurons.
        let mut requested_neuron_ids: BTreeSet<NeuronId> =
            neuron_ids.iter().map(|id| NeuronId { id: *id }).collect();
        requested_neuron_ids.append(&mut implicitly_requested_neuron_ids);
        requested_neuron_ids.append(&mut neurons_by_subaccount);

        // These will be assembled into the final result.
        let mut neuron_infos = hashmap![];
        let mut full_neurons = vec![];

        let chunks: Vec<Vec<NeuronId>> = requested_neuron_ids
            .into_iter()
            .chunks(page_size as usize)
            .into_iter()
            .map(|chunk| chunk.collect())
            .collect();

        let total_pages_available = Some(chunks.len() as u64);

        let empty = Vec::new();
        let current_page = chunks.get(page_number as usize).unwrap_or(&empty);

        // Populate the above two neuron collections.
        for neuron_id in current_page {
            // Ignore when a neuron is not found. It is not guaranteed that a
            // neuron will be found, because some of the elements in
            // requested_neuron_ids are supplied by the caller.
            let _ignore_when_neuron_not_found = self.with_neuron(neuron_id, |neuron| {
                // Populate neuron_infos.
                let neuron_info = neuron.get_neuron_info(self.voting_power_economics(), now, caller, true);
                neuron_infos.insert(neuron_id.id, neuron_info);

                // Populate full_neurons.
                let let_caller_read_full_neuron =
                    // (Caller can vote with neuron if it is the controller or a hotkey of the neuron.)
                    neuron.is_authorized_to_vote(&caller)
                        || self.neuron_store.can_principal_vote_on_proposals_that_target_neuron(caller, neuron)
                        // neuron is public, and the caller requested that
                        // public neurons be included (in full_neurons).
                        || (include_public_neurons_in_full_neurons
                            && neuron.visibility() == Visibility::Public
                        );
                if let_caller_read_full_neuron {
                    full_neurons.push(neuron.clone().into_api(now, self.voting_power_economics(), true));
                }
            });
        }

        // Assemble final result.
        ListNeuronsResponse {
            neuron_infos,
            full_neurons,
            total_pages_available,
        }
    }

    /// Returns a list of known neurons, neurons that have been given a name.
    pub fn list_known_neurons(&self) -> ListKnownNeuronsResponse {
        // This should be migrated to known neuron index before migrating any neuron to stable storage.
        let known_neurons: Vec<KnownNeuron> = self
            .neuron_store
            .list_known_neuron_ids()
            .into_iter()
            // Flat map to discard neuron_not_found errors here, which we cannot handle here
            // and indicates a problem with NeuronStore
            .flat_map(|neuron_id| {
                self.neuron_store
                    .with_neuron(&neuron_id, |n| KnownNeuron {
                        id: Some(n.id()),
                        known_neuron_data: n.known_neuron_data().cloned(),
                    })
                    .map_err(|e| {
                        println!(
                            "Error while listing known neurons.  Neuron disappeared: {:?}",
                            e
                        );
                        e
                    })
            })
            .collect();

        ListKnownNeuronsResponse { known_neurons }
    }

    pub fn list_neuron_votes(
        &self,
        request: ListNeuronVotesRequest,
    ) -> Result<NeuronVotes, GovernanceError> {
        let ListNeuronVotesRequest {
            neuron_id,
            before_proposal,
            limit,
        } = request;
        let neuron_id = neuron_id.ok_or(GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            "Neuron ID is required",
        ))?;
        // For now, we only support listing votes for known neurons. In the future when we record
        // votes for all neurons, we can enhance this to check the caller if the neuron is not a
        // known neuron.
        if !self.neuron_store.is_known_neuron(neuron_id) {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Neuron is not a known neuron",
            ));
        }

        let votes = with_voting_history_store(|voting_history| {
            voting_history.list_neuron_votes(neuron_id, before_proposal, limit)
        });
        let votes = votes
            .into_iter()
            .map(|(proposal_id, vote)| NeuronVote {
                proposal_id: Some(proposal_id),
                vote: Some(vote.into()),
            })
            .collect();

        let all_finalized_before_proposal =
            self.heap_data.proposals.iter().find_map(|(id, proposal)| {
                if proposal.ballots.is_empty() {
                    None
                } else {
                    Some(ProposalId { id: *id })
                }
            });

        Ok(NeuronVotes {
            votes: Some(votes),
            all_finalized_before_proposal,
        })
    }

    /// Claim the neurons supplied by the GTC on behalf of `new_controller`
    ///
    /// For each neuron ID in `neuron_ids`, check that the corresponding neuron
    /// exists in `self.neuron_store.neurons` and the neuron's controller is the GTC.
    /// If the neuron is in the expected state, set the neuron's controller to
    /// `new_controller` and set other fields (e.g.
    /// `created_timestamp_seconds`).
    pub fn claim_gtc_neurons(
        &mut self,
        caller: &PrincipalId,
        new_controller: PrincipalId,
        neuron_ids: Vec<NeuronId>,
    ) -> Result<(), GovernanceError> {
        if caller != GENESIS_TOKEN_CANISTER_ID.get_ref() {
            return Err(GovernanceError::new(ErrorType::NotAuthorized));
        }

        let ids_are_valid = neuron_ids.iter().all(|id| {
            self.with_neuron(id, |neuron| {
                neuron.controller() == *GENESIS_TOKEN_CANISTER_ID.get_ref()
            })
            .unwrap_or(false)
        });

        if !ids_are_valid {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "At least one supplied NeuronId either does not have an associated Neuron \
                or the associated Neuron is not controlled by the GTC",
            ));
        }

        let now = self.env.now();
        for neuron_id in neuron_ids {
            self.with_neuron_mut(&neuron_id, |neuron| {
                neuron.created_timestamp_seconds = now;
                neuron.set_controller(new_controller)
            })
            .unwrap();
        }

        Ok(())
    }

    /// Transfer a GTC neuron to a recipient neuron.
    ///
    /// This will transfer the stake of the donor neuron to the recipient
    /// neuron, and perform a ledger transfer from the donor neuron's
    /// sub-account to the recipient neuron's sub-account. The donor neuron
    /// will then be deleted.
    pub async fn transfer_gtc_neuron(
        &mut self,
        caller: &PrincipalId,
        donor_neuron_id: &NeuronId,
        recipient_neuron_id: &NeuronId,
    ) -> Result<(), GovernanceError> {
        if caller != GENESIS_TOKEN_CANISTER_ID.get_ref() {
            return Err(GovernanceError::new(ErrorType::NotAuthorized));
        }

        let (is_donor_controlled_by_gtc, donor_subaccount, donor_cached_neuron_stake_e8s) = self
            .with_neuron(donor_neuron_id, |donor_neuron| {
                let is_donor_controlled_by_gtc =
                    donor_neuron.controller() == *GENESIS_TOKEN_CANISTER_ID.get_ref();
                let donor_subaccount = donor_neuron.subaccount();
                let donor_cached_neuron_stake_e8s = donor_neuron.cached_neuron_stake_e8s;
                (
                    is_donor_controlled_by_gtc,
                    donor_subaccount,
                    donor_cached_neuron_stake_e8s,
                )
            })?;
        let recipient_subaccount = self.with_neuron(recipient_neuron_id, |recipient_neuron| {
            recipient_neuron.subaccount()
        })?;

        if !is_donor_controlled_by_gtc {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Donor neuron is not controlled by the GTC",
            ));
        }

        let transaction_fee = self.transaction_fee();

        let recipient_account_identifier = neuron_subaccount(recipient_subaccount);

        let transfer_amount_doms = donor_cached_neuron_stake_e8s - transaction_fee;

        let _ = self
            .ledger
            .transfer_funds(
                transfer_amount_doms,
                transaction_fee,
                Some(donor_subaccount),
                recipient_account_identifier,
                0,
            )
            .await?;

        let donor_neuron = self.with_neuron(donor_neuron_id, |neuron| neuron.clone())?;
        self.remove_neuron(donor_neuron)?;

        self.with_neuron_mut(recipient_neuron_id, |recipient_neuron| {
            recipient_neuron.cached_neuron_stake_e8s += transfer_amount_doms;
        })?;

        Ok(())
    }

    /// Disburse the stake of a neuron.
    ///
    /// This causes the stake of a neuron to be disbursed to the provided
    /// principal (and optional subaccount). If `amount` is provided then
    /// that amount is disbursed.
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
    /// - The caller is the controller of the the neuron.
    /// - The neuron's state is `Dissolved` at the current timestamp.
    #[cfg_attr(feature = "tla", tla_update_method(DISBURSE_NEURON_DESC.clone(), tla_snapshotter!()))]
    pub async fn disburse_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        disburse: &manage_neuron::Disburse,
    ) -> Result<u64, GovernanceError> {
        let transaction_fee_e8s = self.transaction_fee();

        let (
            is_neuron_controlled_by_caller,
            neuron_state,
            is_neuron_kyc_verified,
            neuron_subaccount,
            fees_amount_e8s,
            neuron_minted_stake_e8s,
        ) = self.with_neuron(id, |neuron| {
            (
                neuron.is_controlled_by(caller),
                neuron.state(self.env.now()),
                neuron.kyc_verified,
                neuron.subaccount(),
                neuron.neuron_fees_e8s,
                neuron.minted_stake_e8s(),
            )
        })?;

        if !is_neuron_controlled_by_caller {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                format!(
                    "Caller '{:?}' is not authorized to control neuron '{}'.",
                    caller, id.id
                ),
            ));
        }

        if neuron_state != NeuronState::Dissolved {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Neuron {} has NOT been dissolved. It is in state {:?}",
                    id.id, neuron_state
                ),
            ));
        }

        if !is_neuron_kyc_verified {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!("Neuron {} is not kyc verified.", id.id),
            ));
        }

        // If no account was provided, transfer to the caller's account.
        let to_account: AccountIdentifier = match disburse.to_account.as_ref() {
            None => AccountIdentifier::new(*caller, None),
            Some(ai_pb) => AccountIdentifier::try_from(ai_pb).map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    format!("The recipient's subaccount is invalid due to: {e}"),
                )
            })?,
        };

        // Calculate the amount to transfer, and adjust the cached stake,
        // accordingly. Make sure no matter what the user disburses we still
        // take the fees into account.
        //
        // Note that the implementation of minted_stake_e8s() is effectively:
        //   neuron.cached_neuron_stake_e8s.saturating_sub(neuron.neuron_fees_e8s)
        // So there is symmetry here in that we are subtracting
        // fees_amount_e8s from both sides of this `map_or`.
        let mut disburse_amount_e8s = disburse
            .amount
            .as_ref()
            .map_or(neuron_minted_stake_e8s, |a| {
                a.e8s.saturating_sub(fees_amount_e8s)
            });

        // Subtract the transaction fee from the amount to disburse since it'll
        // be deducted from the source (the neuron's) account.
        if disburse_amount_e8s > transaction_fee_e8s {
            disburse_amount_e8s -= transaction_fee_e8s
        }

        // Add the neuron's id to the set of neurons with ongoing ledger updates.
        let now = self.env.now();
        let _neuron_lock = self.lock_neuron_for_command(
            id.id,
            NeuronInFlightCommand {
                timestamp: now,
                command: Some(InFlightCommand::Disburse(disburse.clone())),
            },
        )?;

        // We need to do 2 transfers:
        // 1 - Burn the neuron management fees.
        // 2 - Transfer the the disbursed amount to the target account

        // Transfer 1 - burn the fees, but only if the value exceeds the cost of
        // a transaction fee, as the ledger doesn't support burn transfers for
        // an amount less than the transaction fee.
        if fees_amount_e8s > transaction_fee_e8s {
            let now = self.env.now();
            tla_log_label!("DisburseNeuron_Fee");
            tla_log_locals! {
                fees_amount: fees_amount_e8s,
                neuron_id: id.id,
                to_account: tla::account_to_tla(to_account),
                disburse_amount: disburse_amount_e8s
            };
            let _result = self
                .ledger
                .transfer_funds(
                    fees_amount_e8s,
                    0, // Burning transfers don't pay a fee.
                    Some(neuron_subaccount),
                    governance_minting_account(),
                    now,
                )
                .await?;
        }

        self.with_neuron_mut(id, |neuron| {
            // Update the stake and the fees to reflect the burning above.
            if neuron.cached_neuron_stake_e8s > fees_amount_e8s {
                neuron.cached_neuron_stake_e8s -= fees_amount_e8s;
            } else {
                neuron.cached_neuron_stake_e8s = 0;
            }
            neuron.neuron_fees_e8s = 0;
        })
        .expect("Expected the parent neuron to exist");

        // Transfer 2 - Disburse to the chosen account. This may fail if the
        // user told us to disburse more than they had in their account (but
        // the burn still happened).
        let now = self.env.now();

        tla_log_label!("DisburseNeuron_Stake");
        tla_log_locals! {
            fees_amount: fees_amount_e8s,
            neuron_id: id.id,
            to_account: tla::account_to_tla(to_account),
            disburse_amount: disburse_amount_e8s
        };

        let block_height = self
            .ledger
            .transfer_funds(
                disburse_amount_e8s,
                transaction_fee_e8s,
                Some(neuron_subaccount),
                to_account,
                now,
            )
            .await?;

        self.with_neuron_mut(id, |neuron| {
            let to_deduct = disburse_amount_e8s + transaction_fee_e8s;
            // The transfer was successful we can change the stake of the neuron.
            neuron.cached_neuron_stake_e8s =
                neuron.cached_neuron_stake_e8s.saturating_sub(to_deduct);
        })
        .expect("Expected the parent neuron to exist");

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
    /// - The caller is the controller of the neuron.
    /// - The parent neuron is not already undergoing ledger updates.
    /// - The parent neuron is not spawning.
    /// - The staked amount minus amount to split is more than the minimum
    ///   stake.
    /// - The amount to split minus the transfer fee is more than the minimum
    ///   stake.
    #[cfg_attr(feature = "tla", tla_update_method(SPLIT_NEURON_DESC.clone(), tla_snapshotter!()))]
    pub async fn split_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        split: &manage_neuron::Split,
    ) -> Result<NeuronId, GovernanceError> {
        // New neurons are not allowed when the heap is too large.
        self.check_heap_can_grow()?;

        let neuron_limit_reservation = self.rate_limiter.try_reserve(
            self.env.now_system_time(),
            NEURON_RATE_LIMITER_KEY.to_string(),
            1,
        )?;

        let &manage_neuron::Split {
            amount_e8s: split_amount_e8s,
            memo,
        } = split;

        let min_stake = self
            .heap_data
            .economics
            .as_ref()
            .expect("Governance must have economics.")
            .neuron_minimum_stake_e8s;

        let transaction_fee_e8s = self.transaction_fee();

        // Get the neuron and clone to appease the borrow checker.
        // We'll get a mutable reference when we need to change it later.
        let parent_neuron = self.with_neuron(id, |neuron| neuron.clone())?;
        let minted_stake_e8s = parent_neuron.minted_stake_e8s();

        if parent_neuron.state(self.env.now()) == NeuronState::Spawning {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Can't perform operation on neuron: Neuron is spawning.",
            ));
        }

        if !parent_neuron.is_controlled_by(caller) {
            return Err(GovernanceError::new(ErrorType::NotAuthorized));
        }

        if split_amount_e8s < min_stake + transaction_fee_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!(
                    "Trying to split a neuron with argument {} e8s. This is too little: \
                      at the minimum, one needs the minimum neuron stake, which is {} e8s, \
                      plus the transaction fee, which is {}. Hence the minimum split amount is {}.",
                    split_amount_e8s,
                    min_stake,
                    transaction_fee_e8s,
                    min_stake + transaction_fee_e8s
                ),
            ));
        }

        if minted_stake_e8s < min_stake + split_amount_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!(
                    "Trying to split {} e8s out of neuron {}. \
                     This is not allowed, because the parent has stake {} e8s. \
                     If the requested amount was subtracted from it, there would be less than \
                     the minimum allowed stake, which is {} e8s. ",
                    split_amount_e8s, id.id, minted_stake_e8s, min_stake
                ),
            ));
        }

        let created_timestamp_seconds = self.env.now();
        let child_nid = self.neuron_store.new_neuron_id(&mut *self.randomness)?;

        let from_subaccount = parent_neuron.subaccount();

        let to_subaccount_bytes = if let Some(memo) = memo {
            ledger::compute_neuron_split_subaccount_bytes(parent_neuron.controller(), memo)
        } else {
            self.randomness.random_byte_array()?
        };
        let to_subaccount = Subaccount(to_subaccount_bytes);

        // Make sure there isn't already a neuron with the same sub-account.
        if self.neuron_store.has_neuron_with_subaccount(to_subaccount) {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "There is already a neuron with the same subaccount.",
            ));
        }

        let in_flight_command = NeuronInFlightCommand {
            timestamp: created_timestamp_seconds,
            command: Some(InFlightCommand::Split(*split)),
        };

        let staked_amount = split_amount_e8s - transaction_fee_e8s;

        // Make sure the parent neuron is not already undergoing a ledger
        // update.
        let _parent_lock = self.lock_neuron_for_command(id.id, in_flight_command.clone())?;

        // Before we do the transfer, we need to save the neuron in the map
        // otherwise a trap after the transfer is successful but before this
        // method finishes would cause the funds to be lost.
        // However the new neuron is not yet ready to be used as we can't know
        // whether the transfer will succeed, so we temporarily set the
        // stake to 0 and only change it after the transfer is successful.
        let child_neuron = NeuronBuilder::new(
            child_nid,
            to_subaccount,
            *caller,
            parent_neuron.dissolve_state_and_age(),
            created_timestamp_seconds,
        )
        .with_hot_keys(parent_neuron.hot_keys.clone())
        .with_followees(parent_neuron.followees.clone())
        .with_kyc_verified(parent_neuron.kyc_verified)
        .with_auto_stake_maturity(parent_neuron.auto_stake_maturity.unwrap_or(false))
        .with_not_for_profit(parent_neuron.not_for_profit)
        .with_joined_community_fund_timestamp_seconds(
            parent_neuron.joined_community_fund_timestamp_seconds,
        )
        .with_neuron_type(parent_neuron.neuron_type)
        .build();

        // Add the child neuron to the set of neurons undergoing ledger updates.
        let _child_lock = self.lock_neuron_for_command(child_nid.id, in_flight_command.clone())?;

        // We need to add the "embryo neuron" to the governance proto only after
        // acquiring the lock. Indeed, in case there is already a pending
        // command, we return without state rollback. If we had already created
        // the embryo, it would not be garbage collected.
        self.add_neuron(child_nid.id, child_neuron.clone())?;

        // Do the transfer for the parent first, to avoid double spending.
        self.neuron_store.with_neuron_mut(id, |parent_neuron| {
            parent_neuron.cached_neuron_stake_e8s = parent_neuron
                .cached_neuron_stake_e8s
                .checked_sub(split_amount_e8s)
                .expect("Subtracting neuron stake underflows");
        })?;

        let now = self.env.now();
        tla_log_locals! { sn_amount : split_amount_e8s, sn_child_neuron_id: child_nid.id, sn_parent_neuron_id: id.id, sn_child_account_id: tla::account_to_tla(neuron_subaccount(to_subaccount)) };
        let result: Result<u64, NervousSystemError> = self
            .ledger
            .transfer_funds(
                staked_amount,
                transaction_fee_e8s,
                Some(from_subaccount),
                neuron_subaccount(to_subaccount),
                now,
            )
            .await;

        if let Err(error) = result {
            let error = GovernanceError::from(error);

            // Refund the parent neuron if the ledger call somehow failed.
            self.neuron_store
                .with_neuron_mut(id, |parent_neuron| {
                    parent_neuron.cached_neuron_stake_e8s = parent_neuron
                        .cached_neuron_stake_e8s
                        .checked_add(split_amount_e8s)
                        .expect("Neuron stake overflows");
                })
                .expect("Expected the parent neuron to exist");

            // If we've got an error, we assume the transfer didn't happen for
            // some reason. The only state to cleanup is to delete the child
            // neuron, since we haven't mutated the parent yet.
            self.remove_neuron(child_neuron)?;
            println!(
                "Neuron stake transfer of split_neuron: {:?} \
                     failed with error: {:?}. Neuron can't be staked.",
                child_nid, error
            );
            return Err(error);
        }

        // Commit the usage from reservation now that we are not going to remove the neuron
        if self
            .rate_limiter
            .commit(self.env.now_system_time(), neuron_limit_reservation)
            .is_err()
        {
            println!(
                "{LOG_PREFIX}Warning: Failed to commit rate limiter reservation. This may indicate a bug in the reservation system."
            );
        }

        // Read the maturity and staked maturity again after the ledger call, to avoid stale values.
        let (parent_maturity_e8s, parent_staked_maturity_e8s) = self
            .neuron_store
            .with_neuron(id, |neuron| {
                (
                    neuron.maturity_e8s_equivalent,
                    neuron.staked_maturity_e8s_equivalent.unwrap_or(0),
                )
            })
            .expect("Expected the parent neuron to exist");

        // Calculates the maturity and staked maturity to transfer to the child. The parent stake is
        // the value before the ledger call, which is OK because it's used for calculating the
        // proportion of the split.
        let SplitNeuronEffect {
            transfer_maturity_e8s,
            transfer_staked_maturity_e8s,
        } = calculate_split_neuron_effect(
            split_amount_e8s,
            minted_stake_e8s,
            parent_maturity_e8s,
            parent_staked_maturity_e8s,
        );

        // Decrease maturity and staked maturity of the parent neuron.
        self.with_neuron_mut(id, |parent_neuron| {
            parent_neuron.maturity_e8s_equivalent = parent_neuron
                .maturity_e8s_equivalent
                .checked_sub(transfer_maturity_e8s)
                .expect("Maturity underflows");
            let new_staked_maturity = parent_neuron
                .staked_maturity_e8s_equivalent
                .unwrap_or(0)
                .checked_sub(transfer_staked_maturity_e8s)
                .expect("Staked maturity underflows");
            parent_neuron.staked_maturity_e8s_equivalent = if new_staked_maturity > 0 {
                Some(new_staked_maturity)
            } else {
                None
            };
        })
        .expect("Expected the parent neuron to exist");

        // Increase stake, maturity and staked maturity of the child neuron.
        self.with_neuron_mut(&child_nid, |child_neuron| {
            child_neuron.cached_neuron_stake_e8s = child_neuron
                .cached_neuron_stake_e8s
                .checked_add(staked_amount)
                .expect("Stake overflows");
            child_neuron.maturity_e8s_equivalent = child_neuron
                .maturity_e8s_equivalent
                .checked_add(transfer_maturity_e8s)
                .expect("Maturity overflows");
            let new_staked_maturity = child_neuron
                .staked_maturity_e8s_equivalent
                .unwrap_or(0)
                .checked_add(transfer_staked_maturity_e8s)
                .expect("Staked maturity overflows");
            child_neuron.staked_maturity_e8s_equivalent = if new_staked_maturity > 0 {
                Some(new_staked_maturity)
            } else {
                None
            };
        })
        .expect("Expected the child neuron to exist");

        Ok(child_nid)
    }

    /// Merge one neuron (the "source" provided by the Merge argument) into
    /// another (the "target" specified by the 'id').
    ///
    /// The source neuron's stake, maturity and age are moved into the target.
    /// Any fees the source neuron are burned before the transfer occurs.
    ///
    /// On success the target neuron contains all the stake, maturity and age
    /// of both neurons. The source neuron has 0 stake, 0 maturity and 0 age.
    /// Current fees are not affected in either neuron. The dissolve delay of
    /// the target neuron is the greater of the dissolve delay of the two,
    /// while the source remains unchanged.
    ///
    /// See `MergeNeuronsError` for possible errors.
    ///
    /// Considerations:
    /// - If the stake of the source neuron is bigger than the transaction fee
    ///   it will be merged into the stake of the target neuron; if it is less
    ///   than the transaction fee, the maturity of the source neuron will
    ///   still be merged into the maturity of the target neuron.
    #[cfg_attr(feature = "tla", tla_update_method(MERGE_NEURONS_DESC.clone(), tla_snapshotter!()))]
    pub async fn merge_neurons(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        merge: &manage_neuron::Merge,
    ) -> Result<ManageNeuronResponse, GovernanceError> {
        let now = self.env.now();
        let in_flight_command = NeuronInFlightCommand {
            timestamp: now,
            command: Some(InFlightCommand::Merge(*merge)),
        };

        // Step 1: calculates the effect of the merge.
        let effect = calculate_merge_neurons_effect(
            id,
            merge,
            caller,
            &self.neuron_store,
            self.transaction_fee(),
            now,
        )?;

        // Step 2: additional validation for the execution.
        validate_merge_neurons_before_commit(
            &effect.source_neuron_id(),
            &effect.target_neuron_id(),
            caller,
            &self.neuron_store,
            &self.heap_data.proposals,
        )?;

        // Step 3: Locking the neurons.
        let _target_lock =
            self.lock_neuron_for_command(effect.source_neuron_id().id, in_flight_command.clone())?;
        let _source_lock =
            self.lock_neuron_for_command(effect.target_neuron_id().id, in_flight_command.clone())?;

        // Step 4: burn neuron fees if needed.
        if let Some(source_burn_fees) = effect.source_burn_fees() {
            tla_log_locals! {
                source_neuron_id: effect.source_neuron_id().id,
                target_neuron_id: effect.target_neuron_id().id,
                fees_amount: effect.source_burn_fees().map_or(0, |f| f.amount_e8s),
                amount_to_target: effect.stake_transfer().map_or(0, |t| t.amount_to_target_e8s)
            }
            tla_log_label!("MergeNeurons_Burn");

            source_burn_fees
                .burn_neuron_fees_with_ledger(&*self.ledger, &mut self.neuron_store, now)
                .await?;
        }

        // Step 5: transfer the stake if needed.
        if let Some(stake_transfer) = effect.stake_transfer() {
            tla_log_locals! {
                source_neuron_id: effect.source_neuron_id().id,
                target_neuron_id: effect.target_neuron_id().id,
                fees_amount: effect.source_burn_fees().map_or(0, |f| f.amount_e8s),
                amount_to_target: effect.stake_transfer().map_or(0, |t| t.amount_to_target_e8s)
            }
            tla_log_label!("MergeNeurons_Stake");

            stake_transfer
                .transfer_neuron_stake_with_ledger(&*self.ledger, &mut self.neuron_store, now)
                .await?;
        }

        // Step 6: applying the internal effect of the merge.
        let source_neuron = self
            .neuron_store
            .with_neuron_mut(&effect.source_neuron_id(), |source| {
                effect.source_effect().apply(source);
                source.clone()
            })
            .expect("Expected the source neuron to exist");
        let target_neuron = self
            .neuron_store
            .with_neuron_mut(&effect.target_neuron_id(), |target| {
                effect.target_effect().apply(target);
                target.clone()
            })
            .expect("Expected the target neuron to exist");

        // Step 7: builds the response.
        Ok(ManageNeuronResponse::merge_response(
            build_merge_neurons_response(
                &source_neuron,
                &target_neuron,
                self.voting_power_economics(),
                now,
                *caller,
            ),
        ))
    }

    pub fn simulate_manage_neuron(
        &self,
        caller: &PrincipalId,
        manage_neuron: ManageNeuron,
    ) -> ManageNeuronResponse {
        let id = match self.neuron_id_from_manage_neuron(&manage_neuron) {
            Ok(id) => id,
            Err(e) => return ManageNeuronResponse::error(e),
        };

        match manage_neuron.command {
            Some(Command::Merge(merge)) => self
                .simulate_merge_neurons(&id, caller, merge)
                .unwrap_or_else(ManageNeuronResponse::error),
            Some(_) => ManageNeuronResponse::error(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Simulating manage_neuron is not supported for this request type",
            )),
            None => ManageNeuronResponse::error(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "No Command given in simulate_manage_neuron request",
            )),
        }
    }

    fn simulate_merge_neurons(
        &self,
        id: &NeuronId,
        caller: &PrincipalId,
        merge: manage_neuron::Merge,
    ) -> Result<ManageNeuronResponse, GovernanceError> {
        let now = self.env.now();

        // Step 1: calculates the effect of the merge.
        let effect = calculate_merge_neurons_effect(
            id,
            &merge,
            caller,
            &self.neuron_store,
            self.transaction_fee(),
            now,
        )?;

        // Step 2: reads the neurons.
        let mut source_neuron = self
            .neuron_store
            .with_neuron(&effect.source_neuron_id(), |neuron| neuron.clone())?;
        let mut target_neuron = self
            .neuron_store
            .with_neuron(&effect.target_neuron_id(), |neuron| neuron.clone())?;

        // Step 3: applies the effect of the merge.
        if let Some(source_burn_fees) = effect.source_burn_fees() {
            source_burn_fees.burn_neuron_fees_without_ledger(&mut source_neuron);
        }
        if let Some(stake_transfer) = effect.stake_transfer() {
            stake_transfer
                .transfer_neuron_stake_without_ledger(&mut source_neuron, &mut target_neuron);
        }
        effect.source_effect().apply(&mut source_neuron);
        effect.target_effect().apply(&mut target_neuron);

        // Step 4: builds the response.
        Ok(ManageNeuronResponse::merge_response(
            build_merge_neurons_response(
                &source_neuron,
                &target_neuron,
                self.voting_power_economics(),
                now,
                *caller,
            ),
        ))
    }

    /// Spawn an neuron from an existing neuron's maturity.
    ///
    /// This creates a new neuron and moves some of the existing neuron's maturity
    /// to the new neuron's maturity. The newly created neuron is in spawning state
    /// and the time when it will be spawn is defined according to the NetworkEconomics.
    ///
    /// Pre-conditions:
    /// - The parent neuron exists.
    /// - The caller is the controller of the neuron.
    /// - The controller of the spawned neuron is self-authenticating.
    /// - The parent neuron is not already undergoing ledger updates.
    /// - The parent neuron is not spawning itself.
    /// - The maturity to move to the new neuron must be such that, with every maturity modulation, at least
    ///   NetworkEconomics::neuron_minimum_spawn_stake_e8s are created when the maturity is spawn.
    #[cfg_attr(feature = "tla", tla_update_method(SPAWN_NEURON_DESC.clone(), tla_snapshotter!()))]
    pub fn spawn_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        spawn: &manage_neuron::Spawn,
    ) -> Result<NeuronId, GovernanceError> {
        // New neurons are not allowed when the heap is too large.
        self.check_heap_can_grow()?;

        let parent_neuron = self.with_neuron(id, |neuron| neuron.clone())?;

        if parent_neuron.state(self.env.now()) == NeuronState::Spawning {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Can't perform operation on neuron: Target neuron is spawning.",
            ));
        }

        if !parent_neuron.is_controlled_by(caller) {
            return Err(GovernanceError::new(ErrorType::NotAuthorized));
        }

        let percentage: u32 = spawn.percentage_to_spawn.unwrap_or(100);
        if percentage > 100 || percentage == 0 {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "The percentage of maturity to spawn must be a value between 1 and 100 (inclusive).",
            ));
        }

        let maturity_to_spawn = parent_neuron
            .maturity_e8s_equivalent
            .checked_mul(percentage as u64)
            .expect("Overflow while processing maturity to spawn.");
        let maturity_to_spawn = maturity_to_spawn.checked_div(100).unwrap();

        // Validate that if a child neuron controller was provided, it is a valid
        // principal.
        let child_controller = if let Some(child_controller) = &spawn.new_controller {
            *child_controller
        } else {
            parent_neuron.controller()
        };

        let economics = self
            .heap_data
            .economics
            .as_ref()
            .expect("Governance does not have NetworkEconomics")
            .clone();

        // Check if the least possible stake this neuron would be spawned with
        // is more than the minimum neuron stake.
        let least_possible_stake = (maturity_to_spawn as f64 * (1f64 - 0.05)) as u64;

        if least_possible_stake < economics.neuron_minimum_stake_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                "There isn't enough maturity to spawn a new neuron due to worst case maturity modulation.",
            ));
        }

        let child_nid = self.neuron_store.new_neuron_id(&mut *self.randomness)?;

        // use provided sub-account if any, otherwise generate a random one.
        let to_subaccount = match spawn.nonce {
            None => Subaccount(self.randomness.random_byte_array()?),
            Some(nonce_val) => {
                ledger::compute_neuron_staking_subaccount(child_controller, nonce_val)
            }
        };

        // Make sure there isn't already a neuron with the same sub-account.
        if self.neuron_store.has_neuron_with_subaccount(to_subaccount) {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "There is already a neuron with the same subaccount.",
            ));
        }

        let created_timestamp_seconds = self.env.now();
        let dissolve_and_spawn_at_timestamp_seconds =
            created_timestamp_seconds + economics.neuron_spawn_dissolve_delay_seconds;

        // Lock both parent and child neurons so that it cannot interleave with other async
        // operations on those neurons and spawn doesn't happen while the parent is in a corrupted
        // state.
        let in_flight_command = NeuronInFlightCommand {
            timestamp: created_timestamp_seconds,
            command: Some(InFlightCommand::SyncCommand(SyncCommand {})),
        };
        let _parent_lock = self.lock_neuron_for_command(id.id, in_flight_command.clone())?;
        let _child_lock = self.lock_neuron_for_command(child_nid.id, in_flight_command.clone())?;

        let child_neuron = NeuronBuilder::new(
            child_nid,
            to_subaccount,
            child_controller,
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: dissolve_and_spawn_at_timestamp_seconds,
            },
            created_timestamp_seconds,
        )
        .with_spawn_at_timestamp_seconds(dissolve_and_spawn_at_timestamp_seconds)
        .with_hot_keys(parent_neuron.hot_keys.clone())
        .with_followees(parent_neuron.followees.clone())
        .with_kyc_verified(parent_neuron.kyc_verified)
        .with_maturity_e8s_equivalent(maturity_to_spawn)
        .build();

        // `add_neuron` will verify that `child_neuron.controller` `is_self_authenticating()`, so we don't need to check it here.
        self.add_neuron(child_nid.id, child_neuron)?;

        // Get the parent neuron again, but this time mutable references.
        self.with_neuron_mut(id, |parent_neuron| {
            // Reset the parent's maturity.
            parent_neuron.maturity_e8s_equivalent -= maturity_to_spawn;
        })
        .expect("Neuron not found");

        Ok(child_nid)
    }

    /// Returns an error indicating MergeMaturity is no longer a valid action.
    /// Can be removed after October 2024, along with corresponding code.
    pub fn merge_maturity_removed_error<T>() -> Result<T, GovernanceError> {
        Err(GovernanceError::new_with_message(
            ErrorType::InvalidCommand,
            "The command MergeMaturity is no longer available, as this functionality was \
            superseded by StakeMaturity. Use StakeMaturity instead.",
        ))
    }

    /// Stakes the maturity of a neuron.
    ///
    /// This method allows a neuron controller to stake the currently
    /// existing maturity of a neuron. The caller can choose a percentage
    /// of maturity to merge.
    ///
    /// Pre-conditions:
    /// - The neuron is controlled by `caller`
    /// - The neuron has some maturity to stake.
    /// - The neuron is not in spawning state.
    pub fn stake_maturity_of_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        stake_maturity: &manage_neuron::StakeMaturity,
    ) -> Result<StakeMaturityResponse, GovernanceError> {
        let (neuron_state, is_neuron_controlled_by_caller, neuron_maturity_e8s_equivalent) =
            self.with_neuron(id, |neuron| {
                (
                    neuron.state(self.env.now()),
                    neuron.is_controlled_by(caller),
                    neuron.maturity_e8s_equivalent,
                )
            })?;

        if neuron_state == NeuronState::Spawning {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Can't perform operation on neuron: Neuron is spawning.",
            ));
        }

        if !is_neuron_controlled_by_caller {
            return Err(GovernanceError::new(ErrorType::NotAuthorized));
        }

        let percentage_to_stake = stake_maturity.percentage_to_stake.unwrap_or(100);

        if percentage_to_stake > 100 || percentage_to_stake == 0 {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "The percentage of maturity to stake must be a value between 0 (exclusive) and 100 (inclusive).",
            ));
        }

        let mut maturity_to_stake =
            (neuron_maturity_e8s_equivalent.saturating_mul(percentage_to_stake as u64)) / 100;

        if maturity_to_stake > neuron_maturity_e8s_equivalent {
            // In case we have some bug, clamp maturity_to_stake by available maturity.
            maturity_to_stake = neuron_maturity_e8s_equivalent;
            println!(
                "{}WARNING: a portion of maturity ({}% * {} = {}) should not be larger than its entirety {}",
                LOG_PREFIX,
                percentage_to_stake,
                neuron_maturity_e8s_equivalent,
                maturity_to_stake,
                neuron_maturity_e8s_equivalent
            );
        }

        let now = self.env.now();
        let in_flight_command = NeuronInFlightCommand {
            timestamp: now,
            command: Some(InFlightCommand::SyncCommand(SyncCommand {})),
        };

        // Lock the neuron so that we're sure that we are not staking the maturity in the middle of another ongoing operation.
        let _neuron_lock = self.lock_neuron_for_command(id.id, in_flight_command)?;

        // Adjust the maturity of the neuron
        let response = self
            .with_neuron_mut(id, |neuron| {
                neuron.maturity_e8s_equivalent = neuron
                    .maturity_e8s_equivalent
                    .saturating_sub(maturity_to_stake);

                neuron.staked_maturity_e8s_equivalent = Some(
                    neuron
                        .staked_maturity_e8s_equivalent
                        .unwrap_or(0)
                        .saturating_add(maturity_to_stake),
                );
                let staked_maturity_e8s = neuron.staked_maturity_e8s_equivalent.unwrap_or(0);

                StakeMaturityResponse {
                    maturity_e8s: neuron.maturity_e8s_equivalent,
                    staked_maturity_e8s,
                }
            })
            .expect("Expected the neuron to exist");

        Ok(response)
    }

    /// Disburse part of the stake of a neuron into a new neuron, possibly
    /// owned by someone else and with a different dissolve delay.
    ///
    /// The parent neuron's stake is decreased by the amount specified in
    /// DisburseToNeuron, while the child neuron is created with a stake
    /// equal to that amount, minus the transfer fee.
    ///
    /// The child neuron doesn't inherit any of the properties of the parent
    /// neuron, except its following and whether it's a genesis neuron.
    ///
    /// On success returns the newly created neuron's id.
    ///
    /// Preconditions:
    /// - The parent neuron exists
    /// - The caller is the controller of the neuron
    /// - The parent neuron is not already undergoing ledger updates.
    /// - The parent neuron is not in spawning state.
    /// - The parent neuron's state is `Dissolved` at the current timestamp.
    /// - The staked amount minus amount to split is more than the minimum
    ///   stake.
    /// - The amount to split minus the transfer fee is more than the minimum
    ///   stake.
    #[cfg_attr(feature = "tla", tla_update_method(DISBURSE_TO_NEURON_DESC.clone(), tla_snapshotter!()))]
    pub async fn disburse_to_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        disburse_to_neuron: &manage_neuron::DisburseToNeuron,
    ) -> Result<NeuronId, GovernanceError> {
        let neuron_limit_reservation = self.rate_limiter.try_reserve(
            self.env.now_system_time(),
            NEURON_RATE_LIMITER_KEY.to_string(),
            1,
        )?;

        let economics = self
            .heap_data
            .economics
            .as_ref()
            .expect("Governance must have economics.")
            .clone();

        let created_timestamp_seconds = self.env.now();
        let transaction_fee_e8s = self.transaction_fee();

        let parent_neuron = self.with_neuron(id, |neuron| neuron.clone())?;
        let parent_nid = parent_neuron.id();

        if parent_neuron.state(self.env.now()) == NeuronState::Spawning {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Can't perform operation on neuron: Neuron is spawning.",
            ));
        }

        if !parent_neuron.is_controlled_by(caller) {
            return Err(GovernanceError::new(ErrorType::NotAuthorized));
        }

        let min_stake = economics.neuron_minimum_stake_e8s;
        if disburse_to_neuron.amount_e8s < min_stake + transaction_fee_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!(
                    "Called `disburse_to_neuron` with `amount` argument {} e8s. This is too little: \
                      at the minimum, one needs the minimum neuron stake, which is {} e8s, \
                      plus the transaction fee, which is {}. Hence the minimum disburse amount is {}.",
                    disburse_to_neuron.amount_e8s,
                    min_stake,
                    transaction_fee_e8s,
                    min_stake + transaction_fee_e8s
                ),
            ));
        }

        if parent_neuron.minted_stake_e8s()
            < economics.neuron_minimum_stake_e8s + disburse_to_neuron.amount_e8s
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!(
                    "Trying to disburse {} e8s out of neuron {}. \
                     This is not allowed, because the parent has stake {} e8s. \
                     If the requested amount was subtracted from it, there would be less than \
                     the minimum allowed stake, which is {} e8s. ",
                    disburse_to_neuron.amount_e8s,
                    parent_nid.id,
                    parent_neuron.minted_stake_e8s(),
                    min_stake
                ),
            ));
        }

        let state = parent_neuron.state(created_timestamp_seconds);
        if state != NeuronState::Dissolved {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Neuron {} has NOT been dissolved. It is in state {:?}",
                    id.id, state
                ),
            ));
        }

        if !parent_neuron.kyc_verified {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!("Neuron is not kyc verified: {}", id.id),
            ));
        }

        // Validate that if a child neuron controller was provided, it is a valid
        // principal.
        let child_controller = disburse_to_neuron.new_controller.ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Must specify a new controller for disburse to neuron.",
            )
        })?;

        let child_nid = self.neuron_store.new_neuron_id(&mut *self.randomness)?;
        let from_subaccount = parent_neuron.subaccount();

        // The account is derived from the new owner's principal so it can be found by
        // the owner on the ledger. There is no need to length-prefix the
        // principal since the nonce is constant length, and so there is no risk
        // of ambiguity.
        let to_subaccount = Subaccount(ledger::compute_neuron_disburse_subaccount_bytes(
            child_controller,
            disburse_to_neuron.nonce,
        ));

        // Make sure there isn't already a neuron with the same sub-account.
        if self.neuron_store.has_neuron_with_subaccount(to_subaccount) {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "There is already a neuron with the same subaccount.",
            ));
        }

        let in_flight_command = NeuronInFlightCommand {
            timestamp: created_timestamp_seconds,
            command: Some(InFlightCommand::DisburseToNeuron(
                disburse_to_neuron.clone(),
            )),
        };

        // Make sure the parent neuron is not already undergoing a ledger update.
        let _parent_lock =
            self.lock_neuron_for_command(parent_nid.id, in_flight_command.clone())?;

        let dissolve_delay_seconds = std::cmp::min(
            disburse_to_neuron.dissolve_delay_seconds,
            MAX_DISSOLVE_DELAY_SECONDS,
        );

        let dissolve_state_and_age = if dissolve_delay_seconds > 0 {
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: created_timestamp_seconds,
            }
        } else {
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: created_timestamp_seconds,
            }
        };

        // Before we do the transfer, we need to save the neuron in the map
        // otherwise a trap after the transfer is successful but before this
        // method finishes would cause the funds to be lost.
        // However the new neuron is not yet ready to be used as we can't know
        // whether the transfer will succeed, so we temporarily set the
        // stake to 0 and only change it after the transfer is successful.
        let child_neuron = NeuronBuilder::new(
            child_nid,
            to_subaccount,
            child_controller,
            dissolve_state_and_age,
            created_timestamp_seconds,
        )
        .with_followees(self.heap_data.default_followees.clone())
        .with_kyc_verified(parent_neuron.kyc_verified)
        .build();

        self.add_neuron(child_nid.id, child_neuron.clone())?;

        // Add the child neuron to the set of neurons undergoing ledger updates.
        let _child_lock = self.lock_neuron_for_command(child_nid.id, in_flight_command.clone())?;

        let staked_amount = disburse_to_neuron.amount_e8s - transaction_fee_e8s;

        // Do the transfer from the parent neuron's subaccount to the child neuron's
        // subaccount.
        let memo = created_timestamp_seconds;

        tla_log_locals! {
            parent_neuron_id: parent_nid.id,
            disburse_amount: disburse_to_neuron.amount_e8s,
            child_neuron_id: child_nid.id,
            child_account_id: tla::account_to_tla(neuron_subaccount(to_subaccount))
        };
        let result: Result<u64, NervousSystemError> = self
            .ledger
            .transfer_funds(
                staked_amount,
                transaction_fee_e8s,
                Some(from_subaccount),
                neuron_subaccount(to_subaccount),
                memo,
            )
            .await;

        if let Err(error) = result {
            let error = GovernanceError::from(error);
            // If we've got an error, we assume the transfer didn't happen for
            // some reason. The only state to cleanup is to delete the child
            // neuron, since we haven't mutated the parent yet.
            self.remove_neuron(child_neuron)?;
            println!(
                "Neuron minting transfer of to neuron: {:?}\
                                  failed with error: {:?}. Neuron can't be staked.",
                child_nid, error
            );
            return Err(error);
        }

        // Commit the reservation now that the neuron can no longer be deleted.
        if self
            .rate_limiter
            .commit(self.env.now_system_time(), neuron_limit_reservation)
            .is_err()
        {
            println!(
                "{LOG_PREFIX}Warning: Failed to commit rate limiter reservation. This may indicate a bug in the reservation system."
            );
        }

        // Get the neurons again, but this time mutable references.
        self.with_neuron_mut(id, |parent_neuron| {
            // Update the state of the parent and child neurons.
            parent_neuron.cached_neuron_stake_e8s -= disburse_to_neuron.amount_e8s;
        })
        .expect("Neuron not found");

        self.with_neuron_mut(&child_nid, |child_neuron| {
            child_neuron.cached_neuron_stake_e8s = staked_amount;
        })
        .expect("Expected the child neuron to exist");

        Ok(child_nid)
    }

    #[cfg_attr(feature = "tla", tla_update_method(DISBURSE_MATURITY_DESC.clone(), tla_snapshotter!()))]
    fn disburse_maturity(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        disburse_maturity: &manage_neuron::DisburseMaturity,
    ) -> Result<u64, GovernanceError> {
        self.check_heap_can_grow()?;

        let now_seconds = self.env.now();

        let in_flight_command = NeuronInFlightCommand {
            timestamp: now_seconds,
            command: Some(InFlightCommand::SyncCommand(SyncCommand {})),
        };

        // Lock the neuron so that we're sure that we are not disbursing the maturity in the middle
        // of another ongoing operation.
        let _neuron_lock = self.lock_neuron_for_command(id.id, in_flight_command)?;

        initiate_maturity_disbursement(
            &mut self.neuron_store,
            caller,
            id,
            disburse_maturity,
            now_seconds,
        )
        .map_err(GovernanceError::from)
    }

    fn set_following(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        set_following: &manage_neuron::SetFollowing,
    ) -> Result<(), GovernanceError> {
        // Start with original following of the neuron.
        let (neuron, mut topic_to_followees) = self.with_neuron(
            id,
            |neuron| -> Result<(Neuron, HashMap</* topic */ i32, Followees>), GovernanceError> {
                set_following.validate(caller, neuron)?;

                Ok((neuron.clone(), neuron.followees.clone()))
            },
        )??;

        // Modify new_followees according to set_following.
        let SetFollowing { topic_following } = set_following;
        for FolloweesForTopic { topic, followees } in topic_following {
            let topic = topic.unwrap_or_default();
            let followees = followees.clone();

            topic_to_followees = modify_followees(
                &self.neuron_store,
                &neuron,
                &topic_to_followees,
                topic,
                Followees { followees },
            )?;
        }

        // Commit new_followees to the neuron.
        let now_seconds = self.env.now();
        self.with_neuron_mut(id, |neuron| {
            neuron.followees = topic_to_followees;
            neuron.refresh_voting_power(now_seconds);
        })?;

        Ok(())
    }

    /// Set the status of a proposal that is 'being executed' to
    /// 'executed' or 'failed' depending on the value of 'success'.
    ///
    /// The proposal ID 'pid' is taken as a raw integer to avoid
    /// lifetime issues.
    pub fn set_proposal_execution_status(&mut self, pid: u64, result: Result<(), GovernanceError>) {
        match self.heap_data.proposals.get_mut(&pid) {
            Some(proposal_data) => {
                // The proposal has to be adopted before it is executed.
                assert_eq!(proposal_data.status(), ProposalStatus::Adopted);
                match result {
                    Ok(_) => {
                        println!(
                            "{}Execution of proposal: {} succeeded. (Proposal title: {:?})",
                            LOG_PREFIX,
                            pid,
                            proposal_data
                                .proposal
                                .as_ref()
                                .and_then(|proposal| proposal.title.clone())
                        );
                        // The proposal was executed 'now'.
                        proposal_data.executed_timestamp_seconds = self.env.now();
                        // If the proposal previously failed to be
                        // executed, it is no longer that case that the
                        // proposal failed to be executed.
                        proposal_data.failed_timestamp_seconds = 0;
                        proposal_data.failure_reason = None;
                    }
                    Err(error) => {
                        println!(
                            "{}Execution of proposal: {} failed. Reason: {:?} (Proposal title: {:?})",
                            LOG_PREFIX,
                            pid,
                            error,
                            proposal_data
                                .proposal
                                .as_ref()
                                .and_then(|proposal| proposal.title.clone())
                        );
                        // Only update the failure timestamp is there is
                        // not yet any report of success in executing this
                        // proposal. If success already has been reported,
                        // it may be that the failure is reported after
                        // the success, e.g., due to a retry.
                        if proposal_data.executed_timestamp_seconds == 0 {
                            proposal_data.failed_timestamp_seconds = self.env.now();
                            proposal_data.failure_reason = Some(error);
                        }
                    }
                }
            }
            None => {
                // The proposal ID was not found. Something is wrong:
                // just log this information to aid debugging.
                println!(
                    "{}Proposal {:?} not found when attempt to set execution result to {:?}",
                    LOG_PREFIX, pid, result
                );
            }
        }
    }

    /// Returns the neuron info for a given neuron `id`. This method
    /// does not require authorization, so the `NeuronInfo` of a
    /// neuron is accessible to any caller.
    pub fn get_neuron_info(
        &self,
        id: &NeuronId,
        requester: PrincipalId,
    ) -> Result<NeuronInfo, GovernanceError> {
        let now = self.env.now();
        self.with_neuron(id, |neuron| {
            neuron.get_neuron_info(self.voting_power_economics(), now, requester, false)
        })
    }

    /// Returns a paginated list of neurons.
    /// The list has an exclusive lower bound on the neuron id, and a maximum
    /// number of neurons to be returned.
    /// The number of neurons to be returned is capped by `MAX_NEURON_PAGE_SIZE`.
    pub fn get_neuron_index(
        &self,
        req: GetNeuronIndexRequest,
        requester: PrincipalId,
    ) -> Result<NeuronIndexData, GovernanceError> {
        if !is_comprehensive_neuron_list_enabled() {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Comprehensive neuron list is not enabled.",
            ));
        }

        let now = self.env.now();

        let exclusive_start_neuron_id = req.exclusive_start_neuron_id.unwrap_or(NeuronId { id: 0 });

        let page_size = req
            .page_size
            .unwrap_or(MAX_NEURON_PAGE_SIZE)
            .min(MAX_NEURON_PAGE_SIZE);

        let neurons = self.neuron_store.list_all_neurons_paginated(
            exclusive_start_neuron_id,
            page_size,
            requester,
            now,
            self.voting_power_economics(),
        );

        Ok(NeuronIndexData { neurons })
    }

    /// Returns the neuron info for a neuron identified by id or subaccount.
    /// This method does not require authorization, so the `NeuronInfo` of a
    /// neuron is accessible to any caller.
    pub fn get_neuron_info_by_id_or_subaccount(
        &self,
        find_by: &NeuronIdOrSubaccount,
        requester: PrincipalId,
    ) -> Result<NeuronInfo, GovernanceError> {
        self.with_neuron_by_neuron_id_or_subaccount(find_by, |neuron| {
            neuron.get_neuron_info(
                self.voting_power_economics(),
                self.env.now(),
                requester,
                false,
            )
        })
    }

    /// Returns the complete neuron data for a given neuron `id` or
    /// `subaccount` after checking that the `caller` is authorized. The
    /// neuron's controller and hot keys are authorized, as are the
    /// controllers and hot keys of any neurons that are listed as followees
    /// of the requested neuron on the `ManageNeuron` topic.
    pub fn get_full_neuron_by_id_or_subaccount(
        &self,
        by: &NeuronIdOrSubaccount,
        caller: &PrincipalId,
    ) -> Result<api::Neuron, GovernanceError> {
        let neuron_id = self.find_neuron_id(by)?;
        self.get_full_neuron(&neuron_id, caller)
    }

    /// Returns the complete neuron data for a given neuron `id` after
    /// checking that the `caller` is authorized. The neuron's
    /// controller and hot keys are authorized, as are the controllers
    /// and hot keys of any neurons that are listed as followees of
    /// the requested neuron on the `ManageNeuron` topic.
    pub fn get_full_neuron(
        &self,
        id: &NeuronId,
        caller: &PrincipalId,
    ) -> Result<api::Neuron, GovernanceError> {
        let native_neuron = self
            .neuron_store
            .get_full_neuron(*id, *caller)
            .map_err(GovernanceError::from)?;

        let now_seconds = self.env.now();
        let voting_power_economics = self.voting_power_economics();
        Ok(native_neuron.into_api(now_seconds, voting_power_economics, false))
    }

    // Returns the set of currently registered node providers.
    pub fn get_node_providers(&self) -> &[NodeProvider] {
        &self.heap_data.node_providers
    }

    pub fn latest_reward_event(&self) -> &RewardEvent {
        self.heap_data
            .latest_reward_event
            .as_ref()
            .expect("Invariant violation! There should always be a latest_reward_event.")
    }

    /// Tries to get a proposal given a proposal id
    ///
    /// - The proposal's ballots only show votes from neurons that the
    ///   caller either controls or is a registered hot key for.
    pub fn get_proposal_info(
        &self,
        caller: &PrincipalId,
        pid: impl Into<ProposalId>,
    ) -> Option<ProposalInfo> {
        let now_seconds = self.env.now();
        let caller_neurons = self.get_neuron_ids_by_principal(caller);
        let voting_period_seconds = self.voting_period_seconds();
        self.heap_data
            .proposals
            .get(&pid.into().id)
            .map(|proposal_data| {
                proposal_data_to_info(
                    proposal_data,
                    ProposalDisplayOptions::for_get_proposal_info(),
                    &caller_neurons,
                    now_seconds,
                    voting_period_seconds,
                )
            })
    }

    /// Tries to get the Neurons' Fund participation data for an SNS Swap created via given proposal.
    ///
    /// - The returned structure is anomymized w.r.t. NNS neuron IDs.
    pub fn get_neurons_fund_audit_info(
        &self,
        request: GetNeuronsFundAuditInfoRequest,
    ) -> Result<NeuronsFundAuditInfo, GovernanceError> {
        let proposal_id = request.nns_proposal_id.ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "nns_proposal_id is not specified.",
            )
        })?;
        let proposal_data =
            self.get_proposal_data_or_err(&proposal_id, "get_neurons_fund_audit_info")?;
        let action = proposal_data
            .proposal
            .as_ref()
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!("Proposal data for {proposal_id:?} is missing the `proposal` field."),
                )
            })?
            .action
            .as_ref()
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!("Proposal data for {proposal_id:?} is missing `proposal.action`.",),
                )
            })?;
        if !matches!(action, Action::CreateServiceNervousSystem(_)) {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!("Proposal {proposal_id:?} is not of type CreateServiceNervousSystem.",),
            ));
        }
        let neurons_fund_data = proposal_data.get_neurons_fund_data_or_err()?;
        let initial_neurons_fund_participation = neurons_fund_data
            .initial_neurons_fund_participation
            .as_ref()
            .map(NeuronsFundParticipationPb::anonymized);
        let final_neurons_fund_participation = neurons_fund_data
            .final_neurons_fund_participation
            .as_ref()
            .map(NeuronsFundParticipationPb::anonymized);
        let neurons_fund_refunds = neurons_fund_data
            .neurons_fund_refunds
            .as_ref()
            .map(NeuronsFundSnapshotPb::anonymized);
        Ok(NeuronsFundAuditInfo {
            initial_neurons_fund_participation,
            final_neurons_fund_participation,
            neurons_fund_refunds,
        })
    }

    /// Gets all open proposals
    ///
    /// - The proposals' ballots only show votes from neurons that the
    ///   caller either controls or is a registered hot key for.
    ///
    /// - Proposals with `ExecuteNnsFunction` as action have their
    ///   `payload` cleared if larger than
    ///   EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX. The caller can
    ///   retrieve dropped payloads by calling `get_proposal_info` for
    ///   each proposal of interest.
    pub fn get_pending_proposals(
        &self,
        caller: &PrincipalId,
        req: Option<GetPendingProposalsRequest>,
    ) -> Vec<ProposalInfo> {
        let now = self.env.now();
        let caller_neurons = self.get_neuron_ids_by_principal(caller);
        let return_self_describing_action = is_self_describing_proposal_actions_enabled()
            && req
                .and_then(|r| r.return_self_describing_action)
                .unwrap_or(false);
        self.heap_data
            .proposals
            .values()
            .filter(|data| data.status() == ProposalStatus::Open)
            .map(|data| {
                proposal_data_to_info(
                    data,
                    ProposalDisplayOptions::for_get_pending_proposals(
                        return_self_describing_action,
                    ),
                    &caller_neurons,
                    now,
                    self.voting_period_seconds(),
                )
            })
            .collect()
    }

    // Gets the raw proposal data
    pub fn get_proposal_data(&self, pid: impl Into<ProposalId>) -> Option<&ProposalData> {
        self.heap_data.proposals.get(&pid.into().id)
    }

    fn mut_proposal_data(&mut self, pid: impl Into<ProposalId>) -> Option<&mut ProposalData> {
        self.heap_data.proposals.get_mut(&pid.into().id)
    }

    fn mut_proposal_data_and_neuron_store(
        &mut self,
        proposal_id: &ProposalId,
    ) -> (Option<&mut ProposalData>, &mut NeuronStore) {
        (
            self.heap_data.proposals.get_mut(&proposal_id.id),
            &mut self.neuron_store,
        )
    }

    /// Return true if the 'info' proposal is visible to some of the neurons in
    /// 'caller_neurons'.
    fn proposal_is_visible_to_neurons(
        &self,
        info: &ProposalData,
        caller_neurons: &BTreeSet<NeuronId>,
    ) -> bool {
        // Is 'info' a manage neuron proposal?
        if let Some(ref managed_id) = info.proposal.as_ref().and_then(|x| x.managed_neuron()) {
            // mgr_ids: &Vec<NeuronId>
            if let Ok(mgr_ids) = self.with_neuron_by_neuron_id_or_subaccount(managed_id, |neuron| {
                neuron.neuron_managers()
            }) {
                // Find one ID in the list of manager IDs that is also
                // in 'caller_neurons'.
                if mgr_ids.iter().any(|x| caller_neurons.contains(x)) {
                    // If such an ID is found, the caller is
                    // permitted to list this proposal.
                    return true;
                }
                // 'caller' not authorized
                false
            } else {
                // This proposal is 'managed', but we cannot find out
                // by whom - don't show.
                false
            }
        } else {
            // This proposal is is not 'managed' - fine to show in all lists.
            true
        }
    }

    /// Returns the proposals info of proposals with proposal ID less
    /// than `before_proposal` (exclusive), returning at most `limit` proposal
    /// infos. If `before_proposal` is not provided, start from the highest
    /// available proposal ID (inclusive).
    ///
    /// As proposal IDs are assigned sequentially, this retrieves up to
    /// `limit` proposals older (in terms of creation) than a specific
    /// proposal. This can be used to paginate through proposals, as follows:
    ///
    /// `
    /// let mut lst = gov.list_proposals(ListProposalInfoRequest {});
    /// while !lst.empty() {
    ///   /* do stuff with lst */
    ///   lst = gov.list_proposals(ListProposalInfoRequest {
    ///     before_proposal: lst.last().and_then(|x|x.id)
    ///   });
    /// }
    /// `
    ///
    /// - A proposal with restricted voting is included only if the
    ///   caller is allowed to vote on the proposal.
    ///
    /// - The proposals' ballots only show votes from neurons that the
    ///   caller either controls or is a registered hot key for.
    ///
    /// - Proposals with `ExecuteNnsFunction` as action have their
    ///   `payload` cleared if larger than
    ///   EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX.  The caller can
    ///   retrieve dropped payloads by calling `get_proposal_info` for
    ///   each proposal of interest.
    ///
    /// - If `omit_large_fields` is set to true, some "large fields" such as
    ///   CreateServiceNervousSystem's logo and token_logo are omitted (set to
    ///   none) from each proposal before returning. This is useful when these
    ///   fields would cause the message to exceed the maximum message size.
    ///   Consider using this field and then calling `get_proposal_info` for each
    ///   proposal of interest.
    pub fn list_proposals(
        &self,
        caller: &PrincipalId,
        req: ListProposalInfoRequest,
    ) -> ListProposalInfoResponse {
        let exclude_topic: HashSet<i32> = req.exclude_topic.iter().cloned().collect();
        let include_reward_status: HashSet<i32> =
            req.include_reward_status.iter().cloned().collect();
        let include_status: HashSet<i32> = req.include_status.iter().cloned().collect();
        let caller_neurons = self.get_neuron_ids_by_principal(caller);
        let return_self_describing_action = is_self_describing_proposal_actions_enabled()
            && req.return_self_describing_action.unwrap_or(false);
        let now = self.env.now();
        let proposal_matches_request = |data: &ProposalData| -> bool {
            let topic = data.topic();
            let voting_period_seconds = self.voting_period_seconds()(topic);
            // Filter out proposals by topic.
            if exclude_topic.contains(&(topic as i32)) {
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
            // Filter out proposals by the visibility of the caller principal
            // when include_all_manage_neuron_proposals is false. When
            // include_all_manage_neuron_proposals is true the proposal is
            // always included.
            req.include_all_manage_neuron_proposals.unwrap_or(false)
                || self.proposal_is_visible_to_neurons(data, &caller_neurons)
        };
        let limit = if req.limit == 0 || req.limit > MAX_LIST_PROPOSAL_RESULTS {
            MAX_LIST_PROPOSAL_RESULTS
        } else {
            req.limit
        } as usize;
        let proposals = &self.heap_data.proposals;
        // Proposals are stored in a sorted map. If 'before_proposal'
        // is provided, grab all proposals before that, else grab the
        // whole range.
        let proposals = if let Some(n) = req.before_proposal {
            proposals.range(..(n.id))
        } else {
            proposals.range(..)
        };
        // Now reverse the range, filter, and restrict to 'limit'.
        let proposals = proposals
            .rev()
            .filter(|(_, x)| proposal_matches_request(x))
            .take(limit)
            .map(|(_, proposal_data)| {
                proposal_data_to_info(
                    proposal_data,
                    ProposalDisplayOptions::for_list_proposals(
                        req.omit_large_fields.unwrap_or_default(),
                        return_self_describing_action,
                    ),
                    &caller_neurons,
                    now,
                    self.voting_period_seconds(),
                )
            })
            .collect();
        ListProposalInfoResponse {
            proposal_info: proposals,
        }
    }

    // This is slow, because it scans all proposals.
    pub fn ready_to_be_settled_proposal_ids(
        &self,
        as_of_timestamp_seconds: u64,
    ) -> impl Iterator<Item = ProposalId> + '_ {
        self.heap_data
            .proposals
            .iter()
            .filter(move |(_, proposal)| {
                let topic = proposal.topic();
                let voting_period_seconds = self.voting_period_seconds()(topic);
                let reward_status =
                    proposal.reward_status(as_of_timestamp_seconds, voting_period_seconds);

                reward_status == ProposalRewardStatus::ReadyToSettle
            })
            .map(|(k, _)| ProposalId { id: *k })
    }

    /// Rounds now downwards to nearest multiple of REWARD_DISTRIBUTION_PERIOD_SECONDS after genesis
    fn most_recent_fully_elapsed_reward_round_end_timestamp_seconds(&self) -> u64 {
        let now = self.env.now();
        let genesis_timestamp_seconds = self.heap_data.genesis_timestamp_seconds;

        if genesis_timestamp_seconds > now {
            println!(
                "{}WARNING: genesis is in the future: {} vs. now = {})",
                LOG_PREFIX, genesis_timestamp_seconds, now,
            );
            return 0;
        }

        (now - genesis_timestamp_seconds) // Duration since genesis (in seconds).
            / REWARD_DISTRIBUTION_PERIOD_SECONDS // This is where the truncation happens. Whole number of rounds.
            * REWARD_DISTRIBUTION_PERIOD_SECONDS // Convert back into seconds.
            + self.heap_data.genesis_timestamp_seconds // Convert from duration to back to instant.
    }

    pub fn num_ready_to_be_settled_proposals(&self) -> usize {
        self.ready_to_be_settled_proposal_ids(self.env.now())
            .count()
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
    pub fn process_proposal(&mut self, proposal_id: u64) {
        let now_seconds = self.env.now();
        // Due to Rust lifetime issues, we must extract a closure that
        // computes the voting period from a topic before we borrow
        // `self.heap_data` mutably.
        let voting_period_seconds_fn = self.voting_period_seconds();

        let proposal = match self.heap_data.proposals.get_mut(&proposal_id) {
            Some(p) => p,
            None => {
                println!(
                    "{}Cannot find proposal {} when trying to process it.",
                    LOG_PREFIX, proposal_id
                );
                return;
            }
        };
        let topic = proposal.topic();
        let voting_period_seconds = voting_period_seconds_fn(topic);

        if proposal.status() != ProposalStatus::Open {
            return;
        }

        if !proposal.can_make_decision(now_seconds, voting_period_seconds) {
            return;
        }
        // This marks the proposal as no longer open.
        proposal.decided_timestamp_seconds = now_seconds;
        if !proposal.is_accepted() {
            return;
        }

        // Stops borrowing proposal before mutating neurons.
        let action = proposal.proposal.as_ref().and_then(|x| x.action.clone());

        // The proposal was adopted, return the rejection fee for non-ManageNeuron
        // proposals.
        if !proposal.is_manage_neuron()
            && let Some(nid) = proposal.proposer
        {
            let rejection_cost = proposal.reject_cost_e8s;
            self.with_neuron_mut(&nid, |neuron| {
                if neuron.neuron_fees_e8s >= rejection_cost {
                    neuron.neuron_fees_e8s -= rejection_cost;
                }
            })
            .ok();
        }

        match ValidProposalAction::try_from(action) {
            Ok(valid_action) => {
                self.start_proposal_execution(proposal_id, &valid_action);
            }
            Err(e) => {
                // This should not happen as the proposal was validated when it was created. The
                // only way it can happen is that some validation is added after the proposal was
                // created.
                self.set_proposal_execution_status(
                    proposal_id,
                    Err(GovernanceError::new_with_message(
                        ErrorType::PreconditionFailed,
                        format!("Invalid proposal action: {}", e),
                    )),
                );
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
            .heap_data
            .proposals
            .iter()
            .filter(|(_, info)| info.status() == ProposalStatus::Open)
            .map(|(pid, _)| *pid)
            .collect::<Vec<u64>>();

        for pid in pids {
            self.process_proposal(pid);
        }

        self.closest_proposal_deadline_timestamp_seconds =
            self.compute_closest_proposal_deadline_timestamp_seconds();
    }

    /// Computes the timestamp of the earliest open proposal's deadline
    pub fn compute_closest_proposal_deadline_timestamp_seconds(&self) -> u64 {
        self.heap_data
            .proposals
            .values()
            .filter(|data| data.status() == ProposalStatus::Open)
            .map(|data| {
                let voting_period = self.voting_period_seconds()(data.topic());
                data.get_deadline_timestamp_seconds(voting_period)
            })
            .min()
            .unwrap_or(u64::MAX)
    }

    /// Starts execution of the given proposal in the background.
    fn start_proposal_execution(&mut self, pid: u64, action: &ValidProposalAction) {
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
        //
        // See "Recommendations for Using `unsafe` in the Governance canister" in canister.rs
        let governance: &'static mut Governance = unsafe { std::mem::transmute(self) };
        spawn_in_canister_env(governance.perform_action(pid, action.clone()));
    }

    /// Mints node provider rewards to a neuron or to a ledger account.
    async fn mint_reward_to_neuron_or_account(
        &mut self,
        np_principal: &PrincipalId,
        reward: &RewardNodeProvider,
    ) -> Result<(), GovernanceError> {
        let now = self.env.now();
        match reward.reward_mode.as_ref() {
            None => Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Reward node provider proposal must have a reward mode.",
            )),
            Some(RewardMode::RewardToNeuron(reward_to_neuron)) => {
                let to_subaccount = Subaccount(self.randomness.random_byte_array()?);
                let _block_height = self
                    .ledger
                    .transfer_funds(
                        reward.amount_e8s,
                        0, // Minting transfers don't pay transaction fees.
                        None,
                        neuron_subaccount(to_subaccount),
                        now,
                    )
                    .await?;
                let nid = self.neuron_store.new_neuron_id(&mut *self.randomness)?;
                let dissolve_delay_seconds = std::cmp::min(
                    reward_to_neuron.dissolve_delay_seconds,
                    MAX_DISSOLVE_DELAY_SECONDS,
                );

                let dissolve_state_and_age = if dissolve_delay_seconds > 0 {
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds,
                        aging_since_timestamp_seconds: now,
                    }
                } else {
                    DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: now,
                    }
                };

                // Transfer successful.
                let neuron = NeuronBuilder::new(
                    nid,
                    to_subaccount,
                    *np_principal,
                    dissolve_state_and_age,
                    now,
                )
                .with_followees(self.heap_data.default_followees.clone())
                .with_cached_neuron_stake_e8s(reward.amount_e8s)
                .with_kyc_verified(true)
                .build();

                self.add_neuron(nid.id, neuron)
            }
            Some(RewardMode::RewardToAccount(reward_to_account)) => {
                // We are not creating a neuron, just transferring funds.
                let to_account = match &reward_to_account.to_account {
                    Some(to_account) => AccountIdentifier::try_from(to_account).map_err(|e| {
                        GovernanceError::new_with_message(
                            ErrorType::InvalidCommand,
                            format!("The recipient's subaccount is invalid due to: {e}"),
                        )
                    })?,
                    None => AccountIdentifier::new(*np_principal, None),
                };

                self.ledger
                    .transfer_funds(
                        reward.amount_e8s,
                        0, // Minting transfers don't pay transaction fees.
                        None,
                        to_account,
                        now,
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| {
                        GovernanceError::new_with_message(
                            ErrorType::PreconditionFailed,
                            format!(
                                "Couldn't perform minting transfer: {}",
                                GovernanceError::from(e)
                            ),
                        )
                    })
            }
        }
    }

    async fn reward_node_provider_helper(
        &mut self,
        reward: &RewardNodeProvider,
    ) -> Result<(), GovernanceError> {
        if let Some(node_provider) = &reward.node_provider {
            if let Some(np_principal) = &node_provider.id {
                if !self
                    .heap_data
                    .node_providers
                    .iter()
                    .any(|np| np.id == node_provider.id)
                {
                    Err(GovernanceError::new_with_message(
                        ErrorType::NotFound,
                        format!("Node provider with id {np_principal} not found."),
                    ))
                } else {
                    // Check that the amount to distribute is not above
                    // than the maximum set in network economics.
                    let maximum_node_provider_rewards_e8s =
                        self.economics().maximum_node_provider_rewards_e8s;
                    if reward.amount_e8s > maximum_node_provider_rewards_e8s {
                        Err(GovernanceError::new_with_message(
                            ErrorType::PreconditionFailed,
                            format!(
                                "Proposed reward {} greater than maximum {}",
                                reward.amount_e8s, maximum_node_provider_rewards_e8s
                            ),
                        ))
                    } else {
                        self.mint_reward_to_neuron_or_account(np_principal, reward)
                            .await
                    }
                }
            } else {
                Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    "Node provider has no ID.",
                ))
            }
        } else {
            Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Proposal was missing the node provider.",
            ))
        }
    }

    /// Rewards a node provider.
    async fn reward_node_provider(&mut self, pid: u64, reward: &RewardNodeProvider) {
        let result = self.reward_node_provider_helper(reward).await;
        self.set_proposal_execution_status(pid, result);
    }

    /// Mint and transfer the specified Node Provider rewards
    async fn reward_node_providers(
        &mut self,
        rewards: &[RewardNodeProvider],
    ) -> Result<(), GovernanceError> {
        let mut result = Ok(());

        for reward in rewards {
            let reward_result = self.reward_node_provider_helper(reward).await;
            if reward_result.is_err() {
                println!(
                    "Rewarding {:?} failed. Reason: {:}",
                    reward,
                    reward_result.clone().unwrap_err()
                );
            }
            result = result.or(reward_result);
        }

        result
    }

    /// Execute a RewardNodeProviders proposal
    async fn reward_node_providers_from_proposal(
        &mut self,
        pid: u64,
        reward_nps: RewardNodeProviders,
    ) {
        let result = if reward_nps.use_registry_derived_rewards == Some(true) {
            self.mint_monthly_node_provider_rewards().await
        } else {
            self.reward_node_providers(&reward_nps.rewards).await
        };

        self.set_proposal_execution_status(pid, result);
    }

    /// Return `true` if `NODE_PROVIDER_REWARD_PERIOD_SECONDS` has passed since the last monthly
    /// node provider reward event
    fn is_time_to_mint_monthly_node_provider_rewards(&self) -> bool {
        match &self.heap_data.most_recent_monthly_node_provider_rewards {
            None => false,
            Some(recent_rewards) => {
                self.env.now().saturating_sub(recent_rewards.timestamp)
                    >= NODE_PROVIDER_REWARD_PERIOD_SECONDS
            }
        }
    }

    /// Mint and transfer monthly node provider rewards.
    ///
    /// This also returns Ok when another call is in progress. In this case, Ok
    /// is returned IMMEDIATELY, i.e. does not wait until the work is actually
    /// done before returnning.
    async fn mint_monthly_node_provider_rewards(&mut self) -> Result<(), GovernanceError> {
        // Return immediately if another call is already in progress.
        thread_local! {
            static LOCK: RefCell<Option<u64>> = const { RefCell::new(None) };
        }
        let release_on_drop = ic_nervous_system_lock::acquire(&LOCK, self.env.now());
        if let Err(earlier_call_start_timestamp) = release_on_drop {
            // Log, but not too frequently (at most once every 5 minutes).
            thread_local! {
                static LAST_LOGGED_UNAVAILABLE_TIMESTAMP_SECONDS: RefCell<u64> = const { RefCell::new(0) };
            }
            let time_since_logged_seconds = LAST_LOGGED_UNAVAILABLE_TIMESTAMP_SECONDS
                .with(|t| self.env.now().saturating_sub(*t.borrow()));
            if time_since_logged_seconds > 5 * 60 {
                println!(
                    "{}Another mint_monthly_node_provider_rewards call (started at \
                     {} seconds since the UNIX epoch) is already in progress.",
                    LOG_PREFIX, earlier_call_start_timestamp,
                );
                LAST_LOGGED_UNAVAILABLE_TIMESTAMP_SECONDS.with(|t| {
                    *t.borrow_mut() = self.env.now();
                });
            }

            return Ok(());
        }

        let monthly_node_provider_rewards = if are_performance_based_rewards_enabled() {
            self.get_node_providers_rewards().await?
        } else {
            self.get_monthly_node_provider_rewards().await?
        };

        let _ = self
            .reward_node_providers(&monthly_node_provider_rewards.rewards)
            .await;
        self.update_most_recent_monthly_node_provider_rewards(monthly_node_provider_rewards);

        // Commit the minting status by making a canister call.
        let _unused_canister_status_response = self
            .env
            .call_canister_method(
                GOVERNANCE_CANISTER_ID,
                "get_build_metadata",
                Encode!().unwrap_or_default(),
            )
            .await;

        Ok(())
    }

    fn update_most_recent_monthly_node_provider_rewards(
        &mut self,
        most_recent_rewards: MonthlyNodeProviderRewards,
    ) {
        record_node_provider_rewards(most_recent_rewards.clone());
        self.heap_data.most_recent_monthly_node_provider_rewards = Some(most_recent_rewards);
    }

    pub fn list_node_provider_rewards(
        &self,
        date_filter: Option<DateRangeFilter>,
    ) -> Vec<MonthlyNodeProviderRewards> {
        list_node_provider_rewards(MAX_LIST_NODE_PROVIDER_REWARDS_RESULTS, date_filter)
            .into_iter()
            .map(|archived| match archived.version {
                Some(archived_monthly_node_provider_rewards::Version::Version1(v1)) => {
                    v1.rewards.unwrap()
                }
                _ => panic!("Should not be possible!"),
            })
            .collect()
    }

    pub fn get_most_recent_monthly_node_provider_rewards(
        &self,
    ) -> Option<MonthlyNodeProviderRewards> {
        let archived = latest_node_provider_rewards();

        match archived {
            None => self
                .heap_data
                .most_recent_monthly_node_provider_rewards
                .clone(),
            Some(ArchivedMonthlyNodeProviderRewards {
                version:
                    Some(archived_monthly_node_provider_rewards::Version::Version1(
                        archived_monthly_node_provider_rewards::V1 { rewards },
                    )),
            }) => rewards,
            Some(_) => panic!("Should not be possible!"),
        }
    }

    fn next_start_date_node_providers_rewards(&self) -> DateUtc {
        if let Some(rewards) = self.get_most_recent_monthly_node_provider_rewards() {
            if let Some(end_date) = rewards.end_date {
                // Case 1a: end_date exists → next start date is the day after
                let naive_date =
                    NaiveDate::from_ymd(end_date.year as i32, end_date.month, end_date.day);
                return DateUtc::from(naive_date.succ());
            }

            // Case 1b: end_date is None → fall back to the timestamp of the reward
            return DateUtc::from_unix_timestamp_seconds(rewards.timestamp);
        }

        // Case 2: No previous rewards → default start date
        // This is only used for test environments where there are no previous rewards.
        let default_ts = Time::from_nanos_since_unix_epoch(ic_cdk::api::time())
            .as_secs_since_unix_epoch()
            .saturating_sub(NODE_PROVIDER_REWARD_PERIOD_SECONDS);

        DateUtc::from_unix_timestamp_seconds(default_ts)
    }

    async fn perform_action(&mut self, pid: u64, action: ValidProposalAction) {
        match action {
            ValidProposalAction::ManageNeuron(mgmt) => {
                // An adopted neuron management command is executed
                // with the privileges of the controller of the
                // neuron.
                match mgmt.get_neuron_id_or_subaccount() {
                    Ok(Some(ref managed_neuron_id)) => {
                        if let Ok(controller) = self.with_neuron_by_neuron_id_or_subaccount(
                            managed_neuron_id,
                            |managed_neuron| managed_neuron.controller(),
                        ) {
                            let result = self.manage_neuron(&controller, &mgmt).await;
                            match result.command {
                                Some(manage_neuron_response::Command::Error(err)) => {
                                    let err = GovernanceError::from(err);
                                    self.set_proposal_execution_status(pid, Err(err))
                                }
                                _ => self.set_proposal_execution_status(pid, Ok(())),
                            };
                        } else {
                            self.set_proposal_execution_status(
                                pid,
                                Err(GovernanceError::new_with_message(
                                    ErrorType::NotAuthorized,
                                    "Couldn't execute manage neuron proposal.\
                                        The neuron was not found.",
                                )),
                            );
                        }
                    }
                    Ok(None) => {
                        self.set_proposal_execution_status(
                            pid,
                            Err(GovernanceError::new_with_message(
                                ErrorType::NotFound,
                                "Couldn't execute manage neuron proposal.\
                                          The neuron was not found.",
                            )),
                        );
                    }
                    Err(e) => self.set_proposal_execution_status(pid, Err(e)),
                }
            }
            ValidProposalAction::ManageNetworkEconomics(network_economics) => {
                self.perform_manage_network_economics(pid, network_economics);
            }
            // A motion is not executed, just recorded for posterity.
            ValidProposalAction::Motion(_) => {
                self.set_proposal_execution_status(pid, Ok(()));
            }
            ValidProposalAction::ExecuteNnsFunction(m) => {
                // This will eventually set the proposal execution
                // status.
                match self.env.execute_nns_function(pid, &m) {
                    Ok(()) => {
                        // The status will be set as a result of this
                        // call. We don't set it now.
                    }
                    Err(_) => {
                        self.set_proposal_execution_status(
                            pid,
                            Err(GovernanceError::new_with_message(
                                ErrorType::External,
                                "Couldn't execute NNS function through proposal",
                            )),
                        );
                    }
                }
            }
            ValidProposalAction::ApproveGenesisKyc(proposal) => {
                let result = self.approve_genesis_kyc(&proposal.principals);
                self.set_proposal_execution_status(pid, result);
            }
            ValidProposalAction::AddOrRemoveNodeProvider(proposal) => {
                let result = proposal.execute(&mut self.heap_data.node_providers);
                self.set_proposal_execution_status(pid, result);
            }
            ValidProposalAction::RewardNodeProvider(ref reward) => {
                self.reward_node_provider(pid, reward).await;
            }
            ValidProposalAction::RewardNodeProviders(proposal) => {
                self.reward_node_providers_from_proposal(pid, proposal)
                    .await;
            }
            ValidProposalAction::RegisterKnownNeuron(register_request) => {
                let result = register_request.execute(&mut self.neuron_store);
                self.set_proposal_execution_status(pid, result);
            }
            ValidProposalAction::DeregisterKnownNeuron(deregister_request) => {
                let result = deregister_request.execute(&mut self.neuron_store);
                self.set_proposal_execution_status(pid, result);
            }
            ValidProposalAction::CreateServiceNervousSystem(ref create_service_nervous_system) => {
                self.create_service_nervous_system(pid, create_service_nervous_system)
                    .await;
            }
            ValidProposalAction::InstallCode(install_code) => {
                self.perform_install_code(pid, install_code).await;
            }
            ValidProposalAction::StopOrStartCanister(stop_or_start) => {
                self.perform_stop_or_start_canister(pid, stop_or_start)
                    .await;
            }
            ValidProposalAction::UpdateCanisterSettings(update_settings) => {
                self.perform_update_canister_settings(pid, update_settings)
                    .await;
            }
            ValidProposalAction::FulfillSubnetRentalRequest(fulfill_subnet_rental_request) => {
                self.perform_fulfill_subnet_rental_request(pid, fulfill_subnet_rental_request)
                    .await
            }
            ValidProposalAction::BlessAlternativeGuestOsVersion(
                bless_alternative_guest_os_version,
            ) => self.perform_bless_alternative_guest_os_version(
                pid,
                bless_alternative_guest_os_version,
            ),
        }
    }

    fn perform_manage_network_economics(
        &mut self,
        proposal_id: u64,
        proposed_network_economics: NetworkEconomics,
    ) {
        let result = self.perform_manage_network_economics_impl(proposed_network_economics);
        self.set_proposal_execution_status(proposal_id, result);
    }

    /// Only call this from perform_manage_network_economics.
    fn perform_manage_network_economics_impl(
        &mut self,
        proposed_network_economics: NetworkEconomics,
    ) -> Result<(), GovernanceError> {
        let new_network_economics = self
            .economics()
            .apply_changes_and_validate(&proposed_network_economics)
            .map_err(|defects| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    format!(
                        "The resulting NetworkEconomics is invalid for the following reason(s):\
                         \n  - {}",
                        defects.join("\n  - "),
                    ),
                )
            })?;

        self.heap_data.economics = Some(new_network_economics);
        Ok(())
    }

    async fn perform_install_code(&mut self, proposal_id: u64, install_code: InstallCode) {
        let result = self.perform_call_canister(proposal_id, install_code).await;
        self.set_proposal_execution_status(proposal_id, result);
    }

    async fn perform_stop_or_start_canister(
        &mut self,
        proposal_id: u64,
        stop_or_start: StopOrStartCanister,
    ) {
        let result = self.perform_call_canister(proposal_id, stop_or_start).await;
        self.set_proposal_execution_status(proposal_id, result);
    }

    async fn perform_update_canister_settings(
        &mut self,
        proposal_id: u64,
        update_settings: UpdateCanisterSettings,
    ) {
        let result = self
            .perform_call_canister(proposal_id, update_settings)
            .await;
        self.set_proposal_execution_status(proposal_id, result);
    }

    async fn perform_fulfill_subnet_rental_request(
        &mut self,
        proposal_id: u64,
        fulfill_subnet_rental_request: FulfillSubnetRentalRequest,
    ) {
        let result = fulfill_subnet_rental_request
            .execute(ProposalId { id: proposal_id }, &self.env)
            .await;
        self.set_proposal_execution_status(proposal_id, result);
    }

    fn perform_bless_alternative_guest_os_version(
        &mut self,
        proposal_id: u64,
        bless_alternative_guest_os_version: BlessAlternativeGuestOsVersion,
    ) {
        let result = bless_alternative_guest_os_version.execute();
        self.set_proposal_execution_status(proposal_id, result);
    }

    async fn perform_call_canister(
        &mut self,
        proposal_id: u64,
        call_canister: impl CallCanister,
    ) -> Result<(), GovernanceError> {
        let (canister_id, function) = call_canister.canister_and_function()?;
        let payload = call_canister.payload()?;

        let response = self
            .env
            .call_canister_method(canister_id, function, payload)
            .await;

        match response {
            Ok(_) => Ok(()),
            Err((code, message)) => Err(GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Error calling external canister for proposal {proposal_id}. Rejection code: {code:?} message: {message}"
                ),
            )),
        }
    }

    fn set_sns_token_swap_lifecycle_to_open(proposal_data: &mut ProposalData) {
        let lifecycle = &mut proposal_data.sns_token_swap_lifecycle;
        match lifecycle {
            None => {
                *lifecycle = Some(sns_swap_pb::Lifecycle::Open as i32);
            }
            Some(lifecycle) => {
                // This can happen if swap calls `settle_neurons_fund_participation` (and that gets
                // fully processed) before the await returns on the call to the Swap's `open`
                // endpoint. This is highly unusual, as it means enough direct swap participants
                // managed to participate while the `execute_create_service_nervous_system_proposal`
                // function was running.
                println!(
                    "{}WARNING: The sns_token_swap_lifecycle field in a ProposalData of {:?} \
                     has unexpectedly been already set to {:?}. Leaving the field as-is.",
                    LOG_PREFIX, proposal_data.id, lifecycle,
                );
            }
        }
    }

    async fn create_service_nervous_system(
        &mut self,
        proposal_id: u64,
        create_service_nervous_system: &CreateServiceNervousSystem,
    ) {
        let result = self
            .do_create_service_nervous_system(proposal_id, create_service_nervous_system)
            .await;
        self.set_proposal_execution_status(proposal_id, result);
    }

    async fn do_create_service_nervous_system(
        &mut self,
        proposal_id: u64,
        create_service_nervous_system: &CreateServiceNervousSystem,
    ) -> Result<(), GovernanceError> {
        // Get the current time of proposal execution.
        let current_timestamp_seconds = self.env.now();

        let swap_parameters = create_service_nervous_system
            .swap_parameters
            .as_ref()
            .ok_or(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "missing field swap_parameters",
            ))?;

        let proposal_id = ProposalId { id: proposal_id };
        let (initial_neurons_fund_participation_snapshot, neurons_fund_participation_constraints) =
            if swap_parameters.neurons_fund_participation.unwrap_or(false) {
                let (
                    initial_neurons_fund_participation_snapshot,
                    neurons_fund_participation_constraints,
                ) = self
                    .draw_maturity_from_neurons_fund(&proposal_id, create_service_nervous_system)?;
                (
                    initial_neurons_fund_participation_snapshot,
                    Some(neurons_fund_participation_constraints),
                )
            } else {
                self.record_neurons_fund_participation_not_requested(&proposal_id)?;
                (NeuronsFundSnapshot::empty(), None)
            };

        let random_swap_start_time = self.randomly_pick_swap_start();
        let create_service_nervous_system = create_service_nervous_system.clone();

        self.execute_create_service_nervous_system_proposal(
            create_service_nervous_system,
            neurons_fund_participation_constraints,
            current_timestamp_seconds,
            proposal_id,
            random_swap_start_time,
            initial_neurons_fund_participation_snapshot,
        )
        .await
    }

    // This function is public as it is used in various tests, also outside this crate.
    fn make_sns_init_payload(
        create_service_nervous_system: CreateServiceNervousSystem,
        neurons_fund_participation_constraints: Option<NeuronsFundParticipationConstraints>,
        current_timestamp_seconds: u64,
        proposal_id: ProposalId,
        random_swap_start_time: GlobalTimeOfDay,
    ) -> Result<SnsInitPayload, String> {
        let (swap_start_timestamp_seconds, swap_due_timestamp_seconds) = {
            let start_time = create_service_nervous_system
                .swap_parameters
                .as_ref()
                .and_then(|swap_parameters| swap_parameters.start_time);

            let duration = create_service_nervous_system
                .swap_parameters
                .as_ref()
                .and_then(|swap_parameters| swap_parameters.duration);

            CreateServiceNervousSystem::swap_start_and_due_timestamps(
                start_time.unwrap_or(random_swap_start_time),
                duration.unwrap_or_default(),
                current_timestamp_seconds,
            )
        }?;

        let sns_init_payload = SnsInitPayload::try_from(ApiCreateServiceNervousSystem::from(
            create_service_nervous_system,
        ))?;

        Ok(SnsInitPayload {
            neurons_fund_participation_constraints,
            nns_proposal_id: Some(proposal_id.id),
            swap_start_timestamp_seconds: Some(swap_start_timestamp_seconds),
            swap_due_timestamp_seconds: Some(swap_due_timestamp_seconds),
            ..sns_init_payload
        })
    }

    async fn execute_create_service_nervous_system_proposal(
        &mut self,
        create_service_nervous_system: CreateServiceNervousSystem,
        neurons_fund_participation_constraints: Option<NeuronsFundParticipationConstraints>,
        current_timestamp_seconds: u64,
        proposal_id: ProposalId,
        random_swap_start_time: GlobalTimeOfDay,
        initial_neurons_fund_participation_snapshot: NeuronsFundSnapshot,
    ) -> Result<(), GovernanceError> {
        let is_start_time_unspecified = create_service_nervous_system
            .swap_parameters
            .as_ref()
            .map(|swap_parameters| swap_parameters.start_time.is_none())
            .unwrap_or(false);

        // Step 1.1: Convert proposal into SnsInitPayload.
        let sns_init_payload = Self::make_sns_init_payload(
            create_service_nervous_system,
            neurons_fund_participation_constraints,
            current_timestamp_seconds,
            proposal_id,
            random_swap_start_time,
        )
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "Failed to convert CreateServiceNervousSystem proposal to SnsInitPayload: {err}",
                ),
            )
        })?;

        // Step 1.2: Validate the SnsInitPayload.
        sns_init_payload.validate_post_execution().map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Failed to validate SnsInitPayload: {err}"),
            )
        })?;

        // If the test configuration is active (implying we are not running in
        // production), and the start time has not been specified,
        // we want the swap to start immediately. Otherwise, each test would take
        // at least 24h.
        #[cfg(feature = "test")]
        let sns_init_payload = if is_start_time_unspecified {
            SnsInitPayload {
                swap_start_timestamp_seconds: Some(self.env.now()),
                ..sns_init_payload
            }
        } else {
            sns_init_payload
        };
        #[cfg(not(feature = "test"))]
        if is_start_time_unspecified {
            println!(
                "{}The swap's start time for proposal {:?} is unspecified, \
                so a random time of {:?} will be used.",
                LOG_PREFIX, proposal_id, random_swap_start_time,
            );
        }

        // Step 2 (main): Call deploy_new_sns method on the SNS_WASM canister.
        // Do NOT return Err right away using the ? operator, because we must refund maturity to the
        // Neurons' Fund before returning.
        let mut deploy_new_sns_response: Result<DeployNewSnsResponse, GovernanceError> =
            call_deploy_new_sns(&self.env, sns_init_payload).await;

        // Step 3: React to response from deploy_new_sns (Ok or Err).

        // Step 3.1: If the call was not successful, issue refunds (and then, return).
        if let Err(err) = &mut deploy_new_sns_response {
            let refund_result = self.refund_maturity_to_neurons_fund(
                &proposal_id,
                initial_neurons_fund_participation_snapshot,
            );
            err.error_message += &format!(" refund result: {refund_result:#?}");
        }
        let deploy_new_sns_response = deploy_new_sns_response?;

        // Step 3.2: Otherwise, deploy_new_sns was successful. Record this fact for latter
        // settlement.
        let proposal_data = self.mut_proposal_data_or_err(
            &proposal_id,
            "in execute_create_service_nervous_system_proposal",
        )?;
        Self::set_sns_token_swap_lifecycle_to_open(proposal_data);

        // subnet_id and canisters fields in deploy_new_sns_response are not
        // used. Would probably make sense to stick them on the
        // ProposalData.
        println!("deploy_new_sns succeeded: {:#?}", deploy_new_sns_response);
        Ok(())
    }

    /// Mark all Neurons controlled by the given principals as having passed
    /// KYC verification
    pub fn approve_genesis_kyc(
        &mut self,
        principals: &[PrincipalId],
    ) -> Result<(), GovernanceError> {
        approve_genesis_kyc(&mut self.neuron_store, principals)
    }

    fn validate_manage_neuron_proposal(
        &self,
        manage_neuron: &ManageNeuron,
    ) -> Result<(), GovernanceError> {
        let managed_id = manage_neuron
            .get_neuron_id_or_subaccount()?
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    "Proposal must include a neuron to manage.",
                )
            })?;

        let command = manage_neuron.command.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "A manage neuron action must have a command",
            )
        })?;

        let controller = self
            .with_neuron_by_neuron_id_or_subaccount(&managed_id, |managed_neuron| {
                managed_neuron.controller()
            })?;

        // Early exit for deprecated commands.
        if let Command::MergeMaturity(_) = command {
            return Self::merge_maturity_removed_error();
        }

        // Below we make sure the manage neuron proposal is not too large. Otherwise they can occupy
        // a lot of space due to its low fee (0.01 ICP) and high limit of open proposals (100K).
        //
        // TODO: consolidate the validation logic with the `manage_neuron` implementation.
        match command {
            // We could implement more complicated logic to check its encoded size, or treat each
            // type of proposal differently, but in the hotfix we simply disable it.
            Command::MakeProposal(_) => {
                return Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    "Cannot issue a make proposal command through a proposal",
                ));
            }
            // DisburseMaturity contains a subaccount which can be unbounded without checking. This
            // command is not implemented yet, and before we implement it we should also validate
            // its subaccount.
            Command::DisburseMaturity(disburse_maturity) => {
                let destination = Destination::try_new(
                    &disburse_maturity.to_account,
                    &disburse_maturity.to_account_identifier,
                    controller,
                );
                if destination.is_err() {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::InvalidCommand,
                        "The disburse destination is invalid",
                    ));
                }
            }
            // Similar to DisburseMaturity, Disburse has a blob as the ICP account address. A
            // successful conversion should indicate that the blob does not contain a large amount
            // of data.
            Command::Disburse(disburse) => {
                if let Some(to_account) = &disburse.to_account
                    && AccountIdentifier::try_from(to_account).is_err()
                {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::InvalidCommand,
                        "The to_account field is invalid",
                    ));
                }
            }
            Command::Follow(follow) => {
                if follow.followees.len() > MAX_FOLLOWEES_PER_TOPIC {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::InvalidCommand,
                        format!(
                            "Too many followees: {} (max: {})",
                            follow.followees.len(),
                            MAX_FOLLOWEES_PER_TOPIC
                        ),
                    ));
                }
            }
            Command::SetFollowing(set_following) => {
                set_following.validate_intrinsically()?;
            }
            _ => {}
        };

        let is_managed_neuron_not_for_profit = self
            .with_neuron_by_neuron_id_or_subaccount(&managed_id, |managed_neuron| {
                managed_neuron.not_for_profit
            })?;

        // Only not-for-profit neurons can issue disburse/split/disburse-to-neuron
        // commands through a proposal.
        if !is_managed_neuron_not_for_profit {
            match command {
                Command::Disburse(_) => {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::NotAuthorized,
                        "Cannot issue a disburse command through a proposal",
                    ));
                }
                Command::DisburseToNeuron(_) => {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::NotAuthorized,
                        "Cannot issue a disburse to neuron command through a proposal",
                    ));
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// This verifies the following:
    ///
    ///     1. When the changes are applied, the resulting NetworkEconomics is
    ///        valid. See NetworkEconomics::validate.
    ///
    /// Since self.heap_data.economics can be different when a proposal is
    /// executed (compared to when it is created), this should be performed both
    /// at proposal creation time AND execution time.
    ///
    /// Note that it is not considered "invalid" when the "modified" result is
    /// the same as the original (i.e. setting F to V even though the current
    /// value of F is ALREADY V). This is because such a proposal is not
    /// actually harmful to the system; just maybe confusing to users.
    fn validate_manage_network_economics(
        &self,
        // (Note that this is the value associated with ManageNetworkEconomics,
        // not the resulting NetworkEconomics.)
        proposed_network_economics: &NetworkEconomics,
    ) -> Result<(), GovernanceError> {
        // It maybe does not make sense to be able to set transaction_fee_e8s
        // via proposal. What we probably want instead is to fetch this value
        // from ledger.

        self.economics()
            .apply_changes_and_validate(proposed_network_economics)
            .map_err(|defects| {
                let message = format!(
                    "The resulting settings would not be valid for the \
                     following reason(s):\n\
                     - {}",
                    defects.join("\n  - "),
                );

                GovernanceError::new_with_message(ErrorType::InvalidProposal, message)
            })?;

        Ok(())
    }

    pub(crate) fn economics(&self) -> &NetworkEconomics {
        self.heap_data
            .economics
            .as_ref()
            .expect("NetworkEconomics not present")
    }

    pub fn voting_power_economics(&self) -> &VotingPowerEconomics {
        let result = self
            .heap_data
            .economics
            .as_ref()
            .and_then(|economics| economics.voting_power_economics.as_ref());

        match result {
            Some(ok) => ok,
            None => {
                println!(
                    "{}ERROR: Falling back to default VotingPowerEconomics.",
                    LOG_PREFIX
                );
                &VotingPowerEconomics::DEFAULT
            }
        }
    }

    pub fn neuron_minimum_dissolve_delay_to_vote_seconds(&self) -> u64 {
        self.voting_power_economics()
            .neuron_minimum_dissolve_delay_to_vote_seconds
            .unwrap_or(VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS)
    }

    /// The proposal id of the next proposal.
    fn next_proposal_id(&self) -> u64 {
        // Correctness is based on the following observations:
        // * Proposal GC never removes the proposal with highest ID.
        // * The proposal map is a BTreeMap, so the proposals are ordered by id.
        self.heap_data
            .proposals
            .iter()
            .next_back()
            .map_or(1, |(k, _)| k + 1)
    }

    fn validate_proposal(
        &self,
        proposal: &Proposal,
    ) -> Result<ValidProposalAction, GovernanceError> {
        validate_proposal_title(&proposal.title)?;
        validate_proposal_summary(&proposal.summary)?;
        validate_proposal_url(&proposal.url)?;

        let action = ValidProposalAction::try_from(proposal.action.clone()).map_err(|e| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Invalid action: {}", e),
            )
        })?;

        self.validate_proposal_action(&action)?;

        Ok(action)
    }

    /// Validates a proposal action against the current state of the governance canister.
    /// TODO(NNS1-4272) move intrinsic validations into the conversion from Action to
    /// ValidProposalAction, and rename this function to validate_proposal_action_against_state.
    fn validate_proposal_action(
        &self,
        action: &ValidProposalAction,
    ) -> Result<(), GovernanceError> {
        // TODO: Jira ticket NNS1-3555
        #[allow(non_local_definitions)]
        impl From<String> for GovernanceError {
            fn from(message: String) -> Self {
                Self::new_with_message(ErrorType::InvalidProposal, message)
            }
        }
        match action {
            ValidProposalAction::ExecuteNnsFunction(execute_nns_function) => {
                self.validate_execute_nns_function(execute_nns_function)
            }
            ValidProposalAction::Motion(motion) => validate_motion(motion),
            ValidProposalAction::CreateServiceNervousSystem(create_service_nervous_system) => {
                self.validate_create_service_nervous_system(create_service_nervous_system)
            }
            ValidProposalAction::ManageNeuron(manage_neuron) => {
                self.validate_manage_neuron_proposal(manage_neuron)
            }
            ValidProposalAction::ManageNetworkEconomics(network_economics) => {
                self.validate_manage_network_economics(network_economics)
            }

            ValidProposalAction::AddOrRemoveNodeProvider(add_or_remove_node_provider) => {
                add_or_remove_node_provider.validate(&self.heap_data.node_providers)
            }
            ValidProposalAction::ApproveGenesisKyc(_)
            | ValidProposalAction::RewardNodeProvider(_)
            | ValidProposalAction::RewardNodeProviders(_) => Ok(()),
            ValidProposalAction::RegisterKnownNeuron(register_known_neuron) => {
                register_known_neuron.validate(&self.neuron_store)
            }
            ValidProposalAction::InstallCode(install_code) => install_code.validate(),
            ValidProposalAction::StopOrStartCanister(stop_or_start) => stop_or_start.validate(),
            ValidProposalAction::UpdateCanisterSettings(update_settings) => {
                update_settings.validate()
            }
            ValidProposalAction::FulfillSubnetRentalRequest(fulfill_subnet_rental_request) => {
                fulfill_subnet_rental_request.validate()
            }
            ValidProposalAction::DeregisterKnownNeuron(deregister_known_neuron) => {
                deregister_known_neuron.validate(&self.neuron_store)
            }
            ValidProposalAction::BlessAlternativeGuestOsVersion(
                bless_alternative_guest_os_version,
            ) => bless_alternative_guest_os_version.validate(),
        }
    }

    fn validate_execute_nns_function(
        &self,
        update: &ValidExecuteNnsFunction,
    ) -> Result<(), GovernanceError> {
        let invalid_proposal_error = |error_message: String| -> GovernanceError {
            GovernanceError::new_with_message(ErrorType::InvalidProposal, error_message)
        };

        // Check payload size limits
        if !update.can_have_large_payload()
            && update.payload.len() > PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX
        {
            return Err(invalid_proposal_error(format!(
                "The maximum NNS function payload size in a proposal action is {} bytes, this payload is: {} bytes",
                PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX,
                update.payload.len(),
            )));
        }

        // Validate specific payloads based on the nns_function type
        match update.nns_function {
            ValidNnsFunction::SubnetRentalRequest => {
                self.validate_subnet_rental_proposal(&update.payload)
                    .map_err(invalid_proposal_error)?;
            }
            ValidNnsFunction::AssignNoid => {
                Self::validate_assign_noid_payload(&update.payload, &self.heap_data.node_providers)
                    .map_err(invalid_proposal_error)?;
            }
            ValidNnsFunction::AddOrRemoveDataCenters => {
                Self::validate_add_or_remove_data_centers_payload(&update.payload)
                    .map_err(invalid_proposal_error)?;
            }
            _ => {}
        };

        Ok(())
    }

    fn validate_subnet_rental_proposal(&self, payload: &[u8]) -> Result<(), String> {
        // Must be able to parse the payload.
        if let Err(e) = Decode!([decoder_config()]; &payload, SubnetRentalRequest) {
            return Err(format!("Invalid SubnetRentalRequest: {e}"));
        }

        // No concurrent subnet rental requests are allowed.
        let other_proposal_ids = self.select_nonfinal_proposal_ids(|action| {
            let Action::ExecuteNnsFunction(execute_nns_function) = action else {
                return false;
            };

            execute_nns_function.nns_function == NnsFunction::SubnetRentalRequest as i32
        });
        if !other_proposal_ids.is_empty() {
            return Err(format!(
                "There is another open SubnetRentalRequest proposal: {other_proposal_ids:?}",
            ));
        }

        Ok(())
    }

    fn validate_assign_noid_payload(
        payload: &[u8],
        node_providers: &[NodeProvider],
    ) -> Result<(), String> {
        let decoded_payload = match Decode!([decoder_config()]; &payload, AddNodeOperatorPayload) {
            Ok(payload) => payload,
            Err(e) => {
                return Err(format!(
                    "The payload could not be decoded into a AddNodeOperatorPayload: {e}"
                ));
            }
        };

        if decoded_payload.node_provider_principal_id.is_none() {
            return Err("The payload's node_provider_principal_id field was None".to_string());
        }

        let is_registered = node_providers
            .iter()
            .any(|np| np.id.unwrap() == decoded_payload.node_provider_principal_id.unwrap());
        if !is_registered {
            return Err("The node provider specified in the payload is not registered".to_string());
        }

        Ok(())
    }

    fn validate_add_or_remove_data_centers_payload(payload: &[u8]) -> Result<(), String> {
        let decoded_payload = match Decode!([decoder_config()]; payload, AddOrRemoveDataCentersProposalPayload)
        {
            Ok(payload) => payload,
            Err(e) => {
                return Err(format!(
                    "The payload could not be decoded into a AddOrRemoveDataCentersProposalPayload: {e}"
                ));
            }
        };

        decoded_payload
            .validate()
            .map_err(|e| format!("The given AddOrRemoveDataCentersProposalPayload is invalid: {e}"))
    }

    fn validate_create_service_nervous_system(
        &self,
        create_service_nervous_system: &CreateServiceNervousSystem,
    ) -> Result<(), GovernanceError> {
        // Must be able to convert to a valid SnsInitPayload.
        let conversion_result = SnsInitPayload::try_from(ApiCreateServiceNervousSystem::from(
            create_service_nervous_system.clone(),
        ));

        let validated = conversion_result.map_err(|e| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Invalid CreateServiceNervousSystem: {e}"),
            )
        })?;

        if are_nf_fund_proposals_disabled()
            && validated.neurons_fund_participation.unwrap_or_default()
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "Invalid CreateServiceNervousSystem: NeuronsFundParticipation is not currently allowed \
                as decided by motion proposal 135970: https://dashboard.internetcomputer.org/proposal/135970.",
            ));
        }

        // Must be unique.
        #[allow(unused_variables)]
        let other_proposal_ids = self.select_nonfinal_proposal_ids(|action| {
            matches!(action, Action::CreateServiceNervousSystem(_))
        });

        #[cfg(not(feature = "test"))]
        if !other_proposal_ids.is_empty() {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "There is another open CreateServiceNervousSystem proposal: {:?}",
                    other_proposal_ids,
                ),
            ));
        }

        // All requirements met.
        Ok(())
    }

    fn select_nonfinal_proposal_ids(&self, action_predicate: impl Fn(&Action) -> bool) -> Vec<u64> {
        self.heap_data
            .proposals
            .values()
            .filter_map(|proposal_data| {
                // Disregard proposals that are in a final (or Unspecified) state.
                match proposal_data.status() {
                    ProposalStatus::Open | ProposalStatus::Adopted => (),
                    ProposalStatus::Rejected
                    | ProposalStatus::Executed
                    | ProposalStatus::Failed => {
                        return None;
                    }
                    ProposalStatus::Unspecified => {
                        println!(
                            "{}ERROR: ProposalData had Unspecified status: {:#?}",
                            LOG_PREFIX, proposal_data
                        );
                        return None;
                    }
                };

                // Unpack proposal.
                let action = match &proposal_data.proposal {
                    Some(Proposal {
                        action: Some(action),
                        ..
                    }) => action,

                    // Ignore proposals with no action.
                    _ => {
                        println!(
                            "{}ERROR: ProposalData had no action: {:#?}",
                            LOG_PREFIX, proposal_data
                        );
                        return None;
                    }
                };

                // Evaluate selection criterion.
                if action_predicate(action) {
                    proposal_data.id.map(|id| id.id)
                } else {
                    None
                }
            })
            .collect()
    }

    pub async fn make_proposal(
        &mut self,
        proposer_id: &NeuronId,
        caller: &PrincipalId,
        proposal: &Proposal,
    ) -> Result<ProposalId, GovernanceError> {
        let now_seconds = self.env.now();

        let action = self.validate_proposal(proposal)?;

        if !action.allowed_when_resources_are_low() {
            self.check_heap_can_grow()?;
        }

        // At this point, the topic should be valid because the proposal was just validated, but we
        // exit on error anyway and check for Topic::Unspecified, just to be safe.
        let topic = action.topic()?;
        if topic == Topic::Unspecified {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "Topic is unspecified. This should never happen.",
            ));
        }

        let self_describing_action =
            if is_self_describing_proposal_actions_enabled() && cfg!(target_arch = "wasm32") {
                // TODO(NNS1-4271): handle the error case when the self-describing action is fully
                // implemented.
                action.to_self_describing(self.env.clone()).await.ok()
            } else {
                None
            };

        // Before actually modifying anything, we first make sure that
        // the neuron is allowed to make this proposal and create the
        // electoral roll.
        //
        // Find the proposing neuron.
        let (
            is_proposer_authorized_to_vote,
            proposer_dissolve_delay_seconds,
            proposer_minted_stake_e8s,
        ) = self.with_neuron(proposer_id, |neuron| {
            (
                neuron.is_authorized_to_vote(caller),
                neuron.dissolve_delay_seconds(now_seconds),
                neuron.minted_stake_e8s(),
            )
        })?;

        // Check that the caller is authorized, i.e., either the
        // controller or a registered hot key.
        if !is_proposer_authorized_to_vote {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                "Caller not authorized to propose.",
            ));
        }

        let proposal_submission_fee = self.proposal_submission_fee(proposal)?;

        let reject_cost_e8s = self.reject_cost_e8s(proposal)?;

        // If the current stake of this neuron is less than the cost
        // of having a proposal rejected, the neuron cannot make the proposal -
        // because the proposal may be rejected.
        if proposer_minted_stake_e8s < proposal_submission_fee {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!(
                    "Neuron doesn't have enough minted stake to submit proposal: {proposer_minted_stake_e8s}",
                ),
            ));
        }

        let min_dissolve_delay_seconds_to_vote = if action.manage_neuron().is_some() {
            0
        } else {
            self.neuron_minimum_dissolve_delay_to_vote_seconds()
        };

        // The proposer must be eligible to vote. This also ensures that the
        // neuron cannot be dissolved until the proposal has been adopted or
        // rejected.
        if proposer_dissolve_delay_seconds < min_dissolve_delay_seconds_to_vote {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                "Neuron's dissolve delay is too short.",
            ));
        }

        // Check that there are not too many proposals.
        if action.manage_neuron().is_some() {
            // Check that there are not too many open manage neuron
            // proposals already.
            if self
                .heap_data
                .proposals
                .values()
                .filter(|info| info.is_manage_neuron() && info.status() == ProposalStatus::Open)
                .count()
                >= MAX_NUMBER_OF_OPEN_MANAGE_NEURON_PROPOSALS
            {
                return Err(GovernanceError::new_with_message(
                    ErrorType::ResourceExhausted,
                    "Reached maximum number of 'manage neuron' proposals. \
                    Please try again later.",
                ));
            }
        } else {
            // What matters here is the number of proposals for which
            // ballots have not yet been cleared, because ballots take the
            // most amount of space. (In the case of proposals with a wasm
            // module in the payload, the payload also takes a lot of
            // space). Manage neuron proposals are not counted as they have
            // a smaller electoral roll and use their own limit.
            if self
                .heap_data
                .proposals
                .values()
                .filter(|info| !info.ballots.is_empty() && !info.is_manage_neuron())
                .count()
                >= MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS
                && !action.allowed_when_resources_are_low()
            {
                return Err(GovernanceError::new_with_message(
                    ErrorType::ResourceExhausted,
                    "Reached maximum number of proposals that have not yet \
                    been taken into account for voting rewards. \
                    Please try again later.",
                ));
            }
        }

        let (ballots, total_potential_voting_power, previous_ballots_timestamp_seconds) =
            self.compute_ballots_for_new_proposal(&action, proposer_id, now_seconds)?;

        if ballots.is_empty() {
            // Cannot make a proposal with no eligible voters.  This
            // is a precaution that shouldn't happen as we check that
            // the voter is allowed to vote.
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "No eligible voters.",
            ));
        }

        // In some cases we want to customize some aspects of the proposal
        let proposal = if let Some(manage_neuron) = action.manage_neuron() {
            // We want to customize the title for manage neuron proposals, to
            // specify the ID of the neuron being managed
            let managed_id = manage_neuron
                .get_neuron_id_or_subaccount()?
                .ok_or_else(|| {
                    GovernanceError::new_with_message(
                        ErrorType::NotFound,
                        "Proposal must include a neuron to manage.",
                    )
                })?;

            let managed_neuron_id = self
                .with_neuron_by_neuron_id_or_subaccount(&managed_id, |managed_neuron| {
                    managed_neuron.id()
                })?;

            let title = Some(format!(
                "Manage neuron proposal for neuron: {}",
                managed_neuron_id.id,
            ));

            Proposal {
                title,
                self_describing_action,
                ..proposal.clone()
            }
        } else {
            Proposal {
                self_describing_action,
                ..proposal.clone()
            }
        };

        // Wait-For-Quiet is not enabled for ManageNeuron
        let wait_for_quiet_enabled = action.manage_neuron().is_none();

        // Create a new proposal ID for this proposal.
        let proposal_num = self.next_proposal_id();
        let proposal_id = ProposalId { id: proposal_num };

        let wait_for_quiet_state = if wait_for_quiet_enabled {
            Some(WaitForQuietState {
                current_deadline_timestamp_seconds: now_seconds
                    .saturating_add(self.voting_period_seconds()(topic)),
            })
        } else {
            None
        };

        // Create the proposal.
        let proposal_data = ProposalData {
            id: Some(proposal_id),
            proposer: Some(*proposer_id),
            reject_cost_e8s,
            proposal: Some(proposal.clone()),
            proposal_timestamp_seconds: now_seconds,
            ballots,
            wait_for_quiet_state,
            total_potential_voting_power: Some(total_potential_voting_power),
            topic: Some(topic as i32),
            previous_ballots_timestamp_seconds,
            ..Default::default()
        };

        // Charge the proposal submission fee upfront.
        // This will protect from DOS in couple of ways:
        // - It prevents a neuron from having too many proposals outstanding.
        // - It reduces the voting power of the submitter so that for every proposal
        //   outstanding the submitter will have less voting power to get it approved.
        self.with_neuron_mut(proposer_id, |neuron| {
            neuron.neuron_fees_e8s += proposal_submission_fee;
        })
        .expect("Proposer not found.");

        // Finally, add this proposal as an open proposal.
        let voting_period_seconds = self.voting_period_seconds()(proposal_data.topic());
        self.closest_proposal_deadline_timestamp_seconds = std::cmp::min(
            proposal_data.proposal_timestamp_seconds + voting_period_seconds,
            self.closest_proposal_deadline_timestamp_seconds,
        );
        self.heap_data.proposals.insert(proposal_num, proposal_data);

        self.cast_vote_and_cascade_follow(proposal_id, *proposer_id, Vote::Yes, topic)
            .await;

        self.process_proposal(proposal_num);

        if let Err(err) = self.refresh_voting_power(proposer_id, caller) {
            // This is unreachable, but if it is reached, just log. Do not blow
            // up the whole operation, because this is just a secondary
            // suboperation, not the main thing.
            println!(
                "{}WARNING: Unable to refresh voting power as part of making a \
                 proposal (which involves direct voting). Err: {:?}",
                LOG_PREFIX, err,
            );
        }

        Ok(proposal_id)
    }

    /// Computes what ballots a new proposal should have, based on the action. Also returns
    /// Potential Voting Power and the timestamp of the previous ballots if a voting power spike was
    /// detected.
    #[allow(clippy::type_complexity)]
    fn compute_ballots_for_new_proposal(
        &self,
        action: &ValidProposalAction,
        proposer_id: &NeuronId,
        now_seconds: u64,
    ) -> Result<(HashMap<u64, Ballot>, u64, Option<u64>), GovernanceError> {
        if let Some(manage_neuron) = action.manage_neuron() {
            let managed_id = manage_neuron
                .get_neuron_id_or_subaccount()?
                .ok_or_else(|| {
                    GovernanceError::new_with_message(
                        ErrorType::NotFound,
                        "Proposal must include a neuron to manage.",
                    )
                })?;
            let ballots =
                self.compute_ballots_for_manage_neuron_proposal(&managed_id, proposer_id)?;
            // Voting power is weird in the case of ManageNeuron proposals. In that case, only
            // the followees of the targetted neuron can vote, and they all get 1 voting power,
            // regardless of refresh. Also, these proposals have no rewards. Therefore, in the
            // case of ManageNeuron, this returns ballots_len.
            let total_potential_voting_power = ballots.len() as u64;
            let previous_ballots_timestamp_seconds = None;
            Ok((
                ballots,
                total_potential_voting_power,
                previous_ballots_timestamp_seconds,
            ))
        } else {
            self.compute_ballots_for_standard_proposal(now_seconds)
        }
    }

    /// Computes ballots for a ManageNeuron proposal.
    /// Only the followees of the managed neuron can vote, and they all get 1 voting power.
    fn compute_ballots_for_manage_neuron_proposal(
        &self,
        managed_id: &NeuronIdOrSubaccount,
        proposer_id: &NeuronId,
    ) -> Result<HashMap<u64, Ballot>, GovernanceError> {
        let followees =
            self.with_neuron_by_neuron_id_or_subaccount(managed_id, |managed_neuron| {
                managed_neuron
                    .followees
                    .get(&(Topic::NeuronManagement as i32))
                    .cloned()
            })?;

        let followees = followees.ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Managed neuron does not specify any followees on the 'manage neuron' topic.",
            )
        })?;

        if !followees.followees.iter().any(|x| x.id == proposer_id.id) {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Proposer not among the followees of neuron.",
            ));
        }

        let ballots = followees
            .followees
            .iter()
            .map(|x| {
                (
                    x.id,
                    Ballot {
                        vote: Vote::Unspecified as i32,
                        voting_power: 1,
                    },
                )
            })
            .collect();
        Ok(ballots)
    }

    /// Computes what ballots a standard proposal should have. Also returns
    /// Potential Voting Power and the timestamp of the previous ballots if a voting power spike was
    /// detected.
    ///
    /// # Potential Voting Power vs. Deciding Voting Power
    ///
    /// If all neurons keep themselves refreshed, then deciding voting power = potential voting
    /// power. Whereas, if a neuron has not refreshed recently enough, the amount of voting power it
    /// can exercise is less than its potential.
    ///
    /// # Voting Power Spike
    ///
    /// A voting power spike is detected when the total potential voting power is more than 1.5
    /// times the minimum total potential voting power in the snapshots. If a voting power spike is
    /// detected, then the previous ballots are returned.
    #[allow(clippy::type_complexity)]
    fn compute_ballots_for_standard_proposal(
        &self,
        now_seconds: u64,
    ) -> Result<
        (
            HashMap<u64, Ballot>,
            u64,         /*potential_voting_power*/
            Option<u64>, /*previous_ballots_timestamp_seconds*/
        ),
        GovernanceError,
    > {
        let current_voting_power_snapshot = self
            .neuron_store
            .compute_voting_power_snapshot_for_standard_proposal(
                self.voting_power_economics(),
                now_seconds,
            )?;

        // Check if there is a voting power spike. If there is, then the return value here
        // will be `Some(...)`.
        let maybe_previous_ballots_if_voting_power_spike_detected = VOTING_POWER_SNAPSHOTS
            .with_borrow(|snapshots| {
                snapshots.previous_ballots_if_voting_power_spike_detected(
                    current_voting_power_snapshot.total_potential_voting_power(),
                    now_seconds,
                )
            });

        let (voting_power_snapshot, previous_ballots_timestamp_seconds) =
            match maybe_previous_ballots_if_voting_power_spike_detected {
                // This is the extraordinary case - we have a voting power spike, and we
                // need to use the previous snapshot.
                Some((previous_snapshot_timestamp, previous_snapshot)) => {
                    (previous_snapshot, Some(previous_snapshot_timestamp))
                }
                // This is the normal case - we have no voting power spike, so we use the
                // current snapshot.
                None => (current_voting_power_snapshot, None),
            };

        let (ballots, total_potential_voting_power) =
            voting_power_snapshot.create_ballots_and_total_potential_voting_power();
        Ok((
            ballots,
            total_potential_voting_power,
            previous_ballots_timestamp_seconds,
        ))
    }

    /// Calculate the reject_cost_e8s of a proposal. This value is set in `ProposalData` and
    /// is the amount reimbursed to the proposing neuron if the proposal passes.
    fn reject_cost_e8s(&self, proposal: &Proposal) -> Result<u64, GovernanceError> {
        let action = proposal.action.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Proposal lacks an action: {proposal:?}"),
            )
        })?;
        match *action {
            // We don't return proposal submission fee for ManageNeuron proposals.
            // if we did, there would be no cost to creating a bunch of ManageNeuron
            // proposals, because you could always vote to adopt them and get the
            // fee back. Therefore, we set this value to 0 and if the proposal
            // is adopted, 0 e8s is reimbursed to the proposing neuron.
            Action::ManageNeuron(_) => Ok(0),
            // For all other proposals, we return the proposal submission fee.
            _ => self.proposal_submission_fee(proposal),
        }
    }

    /// This value captures the amount of e8s decremented from the proposers
    /// stake. The amount returned to the proposer on proposal adoption can be
    /// found in `reject_cost_e8s`.
    fn proposal_submission_fee(&self, proposal: &Proposal) -> Result<u64, GovernanceError> {
        let action = proposal.action.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Proposal lacks an action: {proposal:?}"),
            )
        })?;
        match *action {
            Action::ManageNeuron(_) => Ok(self.economics().neuron_management_fee_per_proposal_e8s),
            _ => Ok(self.economics().reject_cost_e8s),
        }
    }

    /// Preconditions:
    /// 0. `register_vote.proposal` is a proposal ID of a proposal that still accepts votes.
    /// 1. `neuron_id` identifies an existing neuron that is eligible to vote on that proposal
    ///    (i.e., it has a corresponding ballot).
    /// 2. `caller` is authorized to vote on behalf of `neuron_id` (either due to being its
    ///    controller or a hotkey).
    /// 3. `register_vote.vote` must not be `Vote::Unspecified`.
    /// 4. The neuron has not already cast its vote.
    ///
    /// Practically, neurons that have already dissolved cannot vote, as long as the minimal
    /// possible dissolve delay is greated than the maximum possible voting period. Refer to:
    /// - `VotingPowerEconomics.NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS_BOUNDS`
    /// - `ProposalData.evaluate_wait_for_quiet`
    async fn register_vote(
        &mut self,
        neuron_id: &NeuronId,
        caller: &PrincipalId,
        register_vote: &manage_neuron::RegisterVote,
    ) -> Result<(), GovernanceError> {
        let now_seconds = self.env.now();
        let voting_period_seconds = self.voting_period_seconds();

        let is_neuron_authorized_to_vote =
            self.with_neuron(neuron_id, |neuron| neuron.is_authorized_to_vote(caller))?;
        // Check that the caller is authorized, i.e., either the
        // controller or a registered hot key.
        if !is_neuron_authorized_to_vote {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                "Caller is not authorized to vote for neuron.",
            ));
        }

        let manage_neuron::RegisterVote { proposal, vote } = register_vote;

        let proposal_id = proposal.as_ref().ok_or_else(||
            // Proposal not specified.
            GovernanceError::new_with_message(ErrorType::PreconditionFailed, "Vote must include a proposal id."))?;
        let proposal = self
            .heap_data
            .proposals
            .get_mut(&proposal_id.id)
            .ok_or_else(||
            // Proposal not found.
            GovernanceError::new_with_message(ErrorType::NotFound, "Can't find proposal."))?;
        let topic = proposal.topic();

        let vote = Vote::try_from(*vote).unwrap_or(Vote::Unspecified);
        if vote == Vote::Unspecified {
            // Invalid vote specified, i.e., not yes or no.
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Invalid vote specified.",
            ));
        }

        // Check if the proposal is still open for voting.
        let voting_period_seconds = voting_period_seconds(topic);
        let accepts_vote = proposal.accepts_vote(now_seconds, voting_period_seconds);
        if !accepts_vote {
            // Deadline has passed, so the proposal cannot be voted on
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Proposal deadline has passed.",
            ));
        }

        let neuron_ballot = proposal.ballots.get_mut(&neuron_id.id).ok_or_else(||
            // This neuron is not eligible to vote on this proposal.
            GovernanceError::new_with_message(ErrorType::NotAuthorized, "Neuron not authorized to vote on proposal."))?;
        if neuron_ballot.vote != (Vote::Unspecified as i32) {
            // Already voted.
            return Err(GovernanceError::new_with_message(
                ErrorType::NeuronAlreadyVoted,
                "Neuron already voted on proposal.",
            ));
        }

        self.cast_vote_and_cascade_follow(
            // Actually update the ballot, including following.
            *proposal_id,
            *neuron_id,
            vote,
            topic,
        )
        .await;

        self.process_proposal(proposal_id.id);

        if let Err(err) = self.refresh_voting_power(neuron_id, caller) {
            // This is unreachable, but if it is reached, just log. Do not blow
            // up the whole operation, because this is just a secondary
            // suboperation, not the main thing.
            println!(
                "{}WARNING: Unable to refresh voting power as part of \
                 voting directly. Err: {:?}",
                LOG_PREFIX, err,
            );
        }

        Ok(())
    }

    fn refresh_voting_power(
        &mut self,
        neuron_id: &NeuronId,
        caller: &PrincipalId,
    ) -> Result<(), GovernanceError> {
        let is_authorized =
            self.with_neuron(neuron_id, |neuron| neuron.is_authorized_to_vote(caller))?;
        if !is_authorized {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                format!(
                    "The caller ({}) is not authorized to refresh the voting power of neuron {}.",
                    caller, neuron_id.id,
                ),
            ));
        }

        let now_seconds = self.env.now();

        let result = self.with_neuron_mut(neuron_id, |neuron| {
            neuron.refresh_voting_power(now_seconds);
        });

        if let Err(err) = result {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!(
                    "Tried to refresh the voting power of neuron {}, \
                     but was unable to find it: {:?}",
                    neuron_id.id, err,
                ),
            ));
        }

        Ok(())
    }

    /// Add or remove followees for this neuron for a specified topic.
    ///
    /// If the list of followees is empty, remove the followees for
    /// this topic. If the list has at least one element, replace the
    /// current list of followees for the given topic with the
    /// provided list. Note that the list is replaced, not added to.
    fn follow(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        follow_request: &manage_neuron::Follow,
    ) -> Result<(), GovernanceError> {
        // Find the neuron to modify.
        let (is_neuron_controlled_by_caller, is_caller_authorized_to_vote) =
            self.with_neuron(id, |neuron| {
                (
                    neuron.is_controlled_by(caller),
                    neuron.is_authorized_to_vote(caller),
                )
            })?;

        // Only the controller, or a proposal (which passes the controller as the
        // caller), can change the followees for the ManageNeuron topic.
        if follow_request.topic() == Topic::NeuronManagement && !is_neuron_controlled_by_caller {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                "Caller is not authorized to manage following of neuron for the ManageNeuron topic.",
            ));
        } else {
            // Check that the caller is authorized, i.e., either the
            // controller or a registered hot key.
            if !is_caller_authorized_to_vote {
                return Err(GovernanceError::new_with_message(
                    ErrorType::NotAuthorized,
                    "Caller is not authorized to manage following of neuron.",
                ));
            }
        }

        // Check that the list of followees is not too
        // long. Allowing neurons to follow too many neurons
        // allows a memory exhaustion attack on the neurons
        // canister.
        if follow_request.followees.len() > MAX_FOLLOWEES_PER_TOPIC {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Too many followees.",
            ));
        }

        // Validate topic exists
        let topic = Topic::try_from(follow_request.topic).map_err(|_| {
            GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                format!("Not a known topic number. Follow:\n{follow_request:#?}"),
            )
        })?;

        let now_seconds = self.env.now();
        let new_neuron_followees = self.with_neuron(id, |neuron| {
            modify_followees(
                &self.neuron_store,
                neuron,
                &neuron.followees,
                topic as i32,
                Followees {
                    followees: follow_request.followees.clone(),
                },
            )
        })??;

        self.with_neuron_mut(id, |neuron| {
            neuron.followees = new_neuron_followees;

            // Changing followees may change the voting power, so refresh it.
            neuron.refresh_voting_power(now_seconds);
        })?;

        Ok(())
    }

    fn configure_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        c: &manage_neuron::Configure,
    ) -> Result<(), GovernanceError> {
        let now_seconds = self.env.now();

        let lock_command = NeuronInFlightCommand {
            timestamp: now_seconds,
            command: Some(InFlightCommand::Configure(c.clone())),
        };
        let _lock = self.lock_neuron_for_command(id.id, lock_command)?;

        self.with_neuron_mut(id, |neuron| neuron.configure(caller, now_seconds, c))??;

        Ok(())
    }

    pub fn prune_some_following(
        &mut self,
        begin: std::ops::Bound<NeuronId>,
        carry_on: impl FnMut() -> bool,
    ) -> std::ops::Bound<NeuronId> {
        // Hack: Here, we would prefer to use the voting_power_economics method
        // instead, but if we simply passed self.voting_power_economics() to
        // prune_some_following, we wouldn't be able to also pass &mut
        // self.neuron_store. Hence, we essentially inline the method here.
        let voting_power_economics = self
            .heap_data
            .economics
            .as_ref()
            .and_then(|economics| economics.voting_power_economics.as_ref())
            .unwrap_or_else(|| {
                println!(
                    "{}ERROR: VotingPowerEconomics not found while pruning_some_following. \
                     Falling back to default. (This is actually ok in tests.)",
                    LOG_PREFIX,
                );
                &VotingPowerEconomics::DEFAULT
            });

        prune_some_following(
            voting_power_economics,
            &mut self.neuron_store,
            begin,
            carry_on,
        )
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
        let subaccount = ledger::compute_neuron_staking_subaccount(controller, memo);
        match self.neuron_store.get_neuron_id_for_subaccount(subaccount) {
            Some(neuron_id) => {
                self.refresh_neuron(neuron_id, subaccount, claim_or_refresh)
                    .await
            }
            None => {
                self.claim_neuron(subaccount, controller, claim_or_refresh)
                    .await
            }
        }
    }

    /// Refreshes the neuron, getting both it's id and subaccount, if only one
    /// of them was provided as argument.
    async fn refresh_neuron_by_id_or_subaccount(
        &mut self,
        id: NeuronIdOrSubaccount,
        claim_or_refresh: &ClaimOrRefresh,
    ) -> Result<NeuronId, GovernanceError> {
        let (nid, subaccount) = match id {
            NeuronIdOrSubaccount::NeuronId(neuron_id) => {
                let neuron_subaccount =
                    self.with_neuron(&neuron_id, |neuron| neuron.subaccount())?;
                (neuron_id, neuron_subaccount)
            }
            NeuronIdOrSubaccount::Subaccount(subaccount_bytes) => {
                let subaccount = Self::bytes_to_subaccount(&subaccount_bytes)?;
                let neuron_id = self
                    .neuron_store
                    .get_neuron_id_for_subaccount(subaccount)
                    .ok_or_else(|| Self::no_neuron_for_subaccount_error(&subaccount.0))?;
                (neuron_id, subaccount)
            }
        };
        self.refresh_neuron(nid, subaccount, claim_or_refresh).await
    }

    /// Refreshes the stake of a given neuron by checking it's account.
    #[cfg_attr(feature = "tla", tla_update_method(REFRESH_NEURON_DESC.clone(), tla_snapshotter!()))]
    async fn refresh_neuron(
        &mut self,
        nid: NeuronId,
        subaccount: Subaccount,
        claim_or_refresh: &ClaimOrRefresh,
    ) -> Result<NeuronId, GovernanceError> {
        let account = neuron_subaccount(subaccount);
        // We need to lock the neuron to make sure it doesn't undergo
        // concurrent changes while we're checking the balance and
        // refreshing the stake.
        let now = self.env.now();
        let _neuron_lock = self.lock_neuron_for_command(
            nid.id,
            NeuronInFlightCommand {
                timestamp: now,
                command: Some(InFlightCommand::ClaimOrRefreshNeuron(
                    claim_or_refresh.clone(),
                )),
            },
        )?;

        // Get the balance of the neuron from the ledger canister.
        tla_log_locals! { neuron_id: nid.id };
        let balance = self.ledger.account_balance(account).await?;
        let min_stake = self.economics().neuron_minimum_stake_e8s;
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
        self.with_neuron_mut(&nid, |neuron| {
            match neuron.cached_neuron_stake_e8s.cmp(&balance.get_e8s()) {
                Ordering::Greater => {
                    println!(
                        "{}ERROR. Neuron cached stake was inconsistent.\
                     Neuron account: {} has less e8s: {} than the cached neuron stake: {}.\
                     Stake adjusted.",
                        LOG_PREFIX,
                        account,
                        balance.get_e8s(),
                        neuron.cached_neuron_stake_e8s
                    );
                    neuron.update_stake_adjust_age(balance.get_e8s(), now);
                }
                Ordering::Less => {
                    neuron.update_stake_adjust_age(balance.get_e8s(), now);
                }
                // If the stake is the same as the account balance,
                // just return the neuron id (this way this method
                // also serves the purpose of allowing to discover the
                // neuron id based on the memo and the controller).
                Ordering::Equal => (),
            };
        })?;

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
    /// - The new neuron won't take us above the `MAX_NUMBER_OF_NEURONS`.
    /// - The amount transferred was greater than or equal to
    ///   `self.economics.neuron_minimum_stake_e8s`.
    ///
    /// Note that we need to create the neuron before checking the balance
    /// so that we record the neuron and avoid a race where a user calls
    /// this method a second time before the first time responds. If we store
    /// the neuron and lock it before we make the call, we know that any
    /// concurrent call to mutate the same neuron will need to wait for this
    /// one to finish before proceeding.
    #[cfg_attr(feature = "tla", tla_update_method(CLAIM_NEURON_DESC.clone(), tla_snapshotter!()))]
    async fn claim_neuron(
        &mut self,
        subaccount: Subaccount,
        controller: PrincipalId,
        claim_or_refresh: &ClaimOrRefresh,
    ) -> Result<NeuronId, GovernanceError> {
        let neuron_limit_reservation = self.rate_limiter.try_reserve(
            self.env.now_system_time(),
            NEURON_RATE_LIMITER_KEY.to_string(),
            1,
        )?;

        let nid = self.neuron_store.new_neuron_id(&mut *self.randomness)?;
        let now = self.env.now();
        let neuron = NeuronBuilder::new(
            nid,
            subaccount,
            controller,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: INITIAL_NEURON_DISSOLVE_DELAY,
                aging_since_timestamp_seconds: now,
            },
            now,
        )
        .with_followees(self.heap_data.default_followees.clone())
        .with_kyc_verified(true)
        .build();

        // This also verifies that there are not too many neurons already.
        self.add_neuron(nid.id, neuron.clone())?;

        let _neuron_lock = self.lock_neuron_for_command(
            nid.id,
            NeuronInFlightCommand {
                timestamp: now,
                command: Some(InFlightCommand::ClaimOrRefreshNeuron(
                    claim_or_refresh.clone(),
                )),
            },
        )?;

        // Get the balance of the neuron's subaccount from ledger canister.
        let account = neuron_subaccount(subaccount);
        tla_log_locals! { account: tla::account_to_tla(account), neuron_id: nid.id };
        let balance = self.ledger.account_balance(account).await?;
        let min_stake = self.economics().neuron_minimum_stake_e8s;
        if balance.get_e8s() < min_stake {
            // To prevent this method from creating non-staked
            // neurons, we must also remove the neuron that was
            // previously created.
            self.remove_neuron(neuron)?;
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

        // Commit the reservation now that the neuron can no longer be deleted.
        if self
            .rate_limiter
            .commit(self.env.now_system_time(), neuron_limit_reservation)
            .is_err()
        {
            println!(
                "{LOG_PREFIX}Warning: Failed to commit rate limiter reservation. This may indicate a bug in the reservation system."
            );
        }

        let result = self.with_neuron_mut(&nid, |neuron| {
            // Adjust the stake.
            neuron.update_stake_adjust_age(balance.get_e8s(), now);
        });
        match result {
            Ok(_) => Ok(nid),
            Err(err) => {
                // This should not be possible, but let's be defensive and provide a
                // reasonable error message, but still panic so that the lock remains
                // acquired and we can investigate.
                panic!(
                    "When attempting to stake a neuron with ID {:?} and stake {:?},\
                    the neuron disappeared while the operation was in flight.\
                    Please try again: {:?}",
                    nid,
                    balance.get_e8s(),
                    err
                )
            }
        }
    }

    pub async fn manage_neuron(
        &mut self,
        caller: &PrincipalId,
        mgmt: &ManageNeuron,
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
        if !mgmt
            .command
            .as_ref()
            .map(|command| command.allowed_when_resources_are_low())
            .unwrap_or_default()
        {
            self.check_heap_can_grow()?;
        }
        // We run claim or refresh before we check whether a neuron exists because it
        // may not in the case of the neuron being claimed
        if let Some(Command::ClaimOrRefresh(claim_or_refresh)) = &mgmt.command {
            // Note that we return here, so none of the rest of this method is executed
            // in this case.
            return match &claim_or_refresh.by {
                Some(By::Memo(memo)) => {
                    let memo_and_controller = MemoAndController {
                        memo: *memo,
                        controller: None,
                    };
                    self.claim_or_refresh_neuron_by_memo_and_controller(
                        caller,
                        memo_and_controller,
                        claim_or_refresh,
                    )
                    .await
                    .map(ManageNeuronResponse::claim_or_refresh_neuron_response)
                }
                Some(By::MemoAndController(memo_and_controller)) => self
                    .claim_or_refresh_neuron_by_memo_and_controller(
                        caller,
                        memo_and_controller.clone(),
                        claim_or_refresh,
                    )
                    .await
                    .map(ManageNeuronResponse::claim_or_refresh_neuron_response),

                Some(By::NeuronIdOrSubaccount(_)) => {
                    let id = mgmt.get_neuron_id_or_subaccount()?.ok_or_else(|| {
                        GovernanceError::new_with_message(
                            ErrorType::NotFound,
                            "No neuron ID specified in the management request.",
                        )
                    })?;
                    self.refresh_neuron_by_id_or_subaccount(id, claim_or_refresh)
                        .await
                        .map(ManageNeuronResponse::claim_or_refresh_neuron_response)
                }
                None => Err(GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    "Need to provide a way by which to claim or refresh the neuron.",
                )),
            };
        }

        let id = self.neuron_id_from_manage_neuron(mgmt)?;

        match &mgmt.command {
            Some(Command::Configure(c)) => self
                .configure_neuron(&id, caller, c)
                .map(|_| ManageNeuronResponse::configure_response()),
            Some(Command::Disburse(d)) => self
                .disburse_neuron(&id, caller, d)
                .await
                .map(ManageNeuronResponse::disburse_response),
            Some(Command::Spawn(s)) => self
                .spawn_neuron(&id, caller, s)
                .map(ManageNeuronResponse::spawn_response),
            Some(Command::MergeMaturity(_)) => Self::merge_maturity_removed_error(),
            Some(Command::StakeMaturity(s)) => self
                .stake_maturity_of_neuron(&id, caller, s)
                .map(ManageNeuronResponse::stake_maturity_response),
            Some(Command::Split(s)) => self
                .split_neuron(&id, caller, s)
                .await
                .map(ManageNeuronResponse::split_response),
            Some(Command::DisburseToNeuron(d)) => self
                .disburse_to_neuron(&id, caller, d)
                .await
                .map(ManageNeuronResponse::disburse_to_neuron_response),
            Some(Command::Merge(s)) => self.merge_neurons(&id, caller, s).await,
            Some(Command::Follow(f)) => self
                .follow(&id, caller, f)
                .map(|_| ManageNeuronResponse::follow_response()),
            Some(Command::MakeProposal(p)) => {
                self.make_proposal(&id, caller, p).await.map(|proposal_id| {
                    ManageNeuronResponse::make_proposal_response(
                        proposal_id,
                        "The proposal has been created successfully.".to_string(),
                    )
                })
            }
            Some(Command::RegisterVote(v)) => self
                .register_vote(&id, caller, v)
                .await
                .map(|_| ManageNeuronResponse::register_vote_response()),
            Some(Command::ClaimOrRefresh(_)) => {
                panic!("This should have already returned")
            }
            Some(Command::RefreshVotingPower(_)) => self
                .refresh_voting_power(&id, caller)
                .map(ManageNeuronResponse::refresh_voting_power_response),
            Some(Command::DisburseMaturity(disburse_maturity)) => self
                .disburse_maturity(&id, caller, disburse_maturity)
                .map(ManageNeuronResponse::disburse_maturity_response),
            Some(Command::SetFollowing(set_following)) => self
                .set_following(&id, caller, set_following)
                .map(ManageNeuronResponse::set_following_response),
            None => panic!(),
        }
    }

    fn neuron_id_from_manage_neuron(
        &self,
        mgmt: &ManageNeuron,
    ) -> Result<NeuronId, GovernanceError> {
        let id = match mgmt.get_neuron_id_or_subaccount()? {
            Some(NeuronIdOrSubaccount::NeuronId(id)) => Ok(id),
            Some(NeuronIdOrSubaccount::Subaccount(sid)) => {
                let subaccount = Self::bytes_to_subaccount(&sid)?;
                match self.neuron_store.get_neuron_id_for_subaccount(subaccount) {
                    Some(neuron_id) => Ok(neuron_id),
                    None => Err(GovernanceError::new_with_message(
                        ErrorType::NotFound,
                        "No neuron ID specified in the management request.",
                    )),
                }
            }
            None => Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                "No neuron ID specified in the management request.",
            )),
        }?;

        Ok(id)
    }

    pub fn get_ledger(&self) -> Arc<dyn IcpLedger + Send + Sync> {
        self.ledger.clone()
    }

    /// Triggers a reward distribution event if enough time has passed since
    /// the last one. This is intended to be called by a cron
    /// process.
    pub async fn run_periodic_tasks(&mut self) {
        self.process_proposals();
        // Commit whatever changes were just made by process_proposals by making a canister call.
        let _unused_canister_status_response = self
            .env
            .call_canister_method(
                GOVERNANCE_CANISTER_ID,
                "get_build_metadata",
                Encode!().unwrap_or_default(),
            )
            .await;

        // First try to mint node provider rewards (once per month).
        if self.is_time_to_mint_monthly_node_provider_rewards() {
            match self.mint_monthly_node_provider_rewards().await {
                Ok(()) => (),
                Err(e) => println!(
                    "{}Error when minting monthly node provider rewards in run_periodic_tasks: {}",
                    LOG_PREFIX, e,
                ),
            }
            // Second try to compute cached metrics (once per day).
        } else if self.should_compute_cached_metrics() {
            match self.ledger.total_supply().await {
                Ok(supply) => {
                    if self.should_compute_cached_metrics() {
                        let now = self.env.now();
                        let metrics = self.compute_cached_metrics(now, supply);
                        self.heap_data.metrics = Some(metrics);
                    }
                }
                Err(e) => println!(
                    "{}Error when getting total ICP supply: {}",
                    LOG_PREFIX,
                    GovernanceError::from(e),
                ),
            }
        // Try to update maturity modulation (once per day).
        } else if self.should_update_maturity_modulation() {
            self.update_maturity_modulation().await;
        } else {
            // This is the lowest-priority async task. All other tasks should have their own
            // `else if`, like the ones above.
            let refresh_xdr_rate_result = self.maybe_refresh_xdr_rate().await;
            if let Err(err) = refresh_xdr_rate_result {
                println!(
                    "{}Error when refreshing XDR rate in run_periodic_tasks: {}",
                    LOG_PREFIX, err,
                );
            }
        }

        self.maybe_gc();
    }

    fn should_update_maturity_modulation(&self) -> bool {
        // Check if we're already updating the neuron maturity modulation.
        let now_seconds = self.env.now();
        let last_updated = self
            .heap_data
            .maturity_modulation_last_updated_at_timestamp_seconds;
        last_updated.is_none() || last_updated.unwrap() + ONE_DAY_SECONDS <= now_seconds
    }

    async fn update_maturity_modulation(&mut self) {
        if !self.should_update_maturity_modulation() {
            return;
        };

        let now_seconds = self.env.now();
        let maturity_modulation = match self.cmc.neuron_maturity_modulation().await {
            Ok(maturity_modulation) => maturity_modulation,
            Err(err) => {
                let silence_message =
                    err.contains("Canister rkp4c-7iaaa-aaaaa-aaaca-cai not found");
                if !silence_message {
                    println!(
                        "{}Couldn't update maturity modulation. Error: {}",
                        LOG_PREFIX, err
                    );
                }
                return;
            }
        };
        println!(
            "{}Updated daily maturity modulation rate to (in basis points): {}, at: {}. Last updated: {:?}",
            LOG_PREFIX,
            maturity_modulation,
            now_seconds,
            self.heap_data
                .maturity_modulation_last_updated_at_timestamp_seconds,
        );
        self.heap_data.cached_daily_maturity_modulation_basis_points = Some(maturity_modulation);
        self.heap_data
            .maturity_modulation_last_updated_at_timestamp_seconds = Some(now_seconds);
    }

    fn should_refresh_xdr_rate(&self) -> bool {
        let xdr_conversion_rate = &self.heap_data.xdr_conversion_rate;

        let now_seconds = self.env.now();

        let seconds_since_last_conversion_rate_refresh =
            now_seconds.saturating_sub(xdr_conversion_rate.timestamp_seconds);

        // Return `true` if more than 1 day has passed since the last `xdr_conversion_rate` was
        // updated. This assumes that `xdr_conversion_rate.timestamp_seconds` is rounded down to
        // the nearest day's beginning.
        seconds_since_last_conversion_rate_refresh > ONE_DAY_SECONDS
    }

    async fn maybe_refresh_xdr_rate(&mut self) -> Result<(), GovernanceError> {
        if !self.should_refresh_xdr_rate() {
            return Ok(());
        };

        // The average (last 30 days) conversion rate from 10,000ths of an XDR to 1 ICP
        let IcpXdrConversionRate {
            timestamp_seconds,
            xdr_permyriad_per_icp,
        } = self.get_average_icp_xdr_conversion_rate().await?.data;

        self.heap_data.xdr_conversion_rate = XdrConversionRate {
            timestamp_seconds,
            xdr_permyriad_per_icp,
        };

        Ok(())
    }

    pub fn maybe_run_validations(&mut self) {
        // Running validations might increase heap size. Do not run it when heap should not grow.
        if self.check_heap_can_grow().is_err() {
            return;
        }
        self.neuron_data_validator
            .maybe_validate(self.env.now(), &self.neuron_store);
    }

    /// Returns the 30-day average of the ICP/XDR conversion rate.
    ///
    /// Returns `None` if the data has not been fetched from the CMC canister yet.
    pub fn icp_xdr_rate(&self) -> Decimal {
        let xdr_permyriad_per_icp = self.heap_data.xdr_conversion_rate.xdr_permyriad_per_icp;
        let xdr_permyriad_per_icp = Decimal::from(xdr_permyriad_per_icp);
        xdr_permyriad_per_icp / dec!(10_000)
    }

    /// Unstakes the maturity of neurons that have dissolved.
    pub fn unstake_maturity_of_dissolved_neurons(&mut self) {
        // We assume that modifying a neuron can use <400 StableBTreeMap read operations and <400
        // write operations (100 recent ballots + 270 followees entries + others), and one read + one
        // write operation takes 400K instructions in total, unstaking 100 neurons should take less
        // than 16B instructions. Note that this is the worst case scenario, and the actual number
        // of instructions should be much less.
        const MAX_NEURONS_TO_UNSTAKE: usize = 100;
        let now_seconds = self.env.now();
        self.neuron_store
            .unstake_maturity_of_dissolved_neurons(now_seconds, MAX_NEURONS_TO_UNSTAKE);
    }

    fn can_spawn_neurons(&self) -> bool {
        let spawning = self.heap_data.spawning_neurons.unwrap_or(false);
        if spawning {
            return false;
        }

        let now_seconds = self.env.now();
        let neuron_count_ready_to_spawn = self
            .neuron_store
            .list_ready_to_spawn_neuron_ids(now_seconds)
            .len();

        neuron_count_ready_to_spawn > 0
    }

    /// Actually spawn neurons by minting their maturity, modulated by the maturity modulation rate of the day.
    /// There can only be one execution of this method running at a time to keep the reasoning about this simple.
    /// This means that programming in this method needs to be extra-defensive on the handling of results so that
    /// we're sure not to trap after we've acquired the global lock and made an async call, as otherwise the global
    /// lock will be permanently held and no spawning will occur until a upgrade to fix it is made.
    #[cfg_attr(feature = "tla", tla_update_method(SPAWN_NEURONS_DESC.clone(), tla_snapshotter!()))]
    pub async fn maybe_spawn_neurons(&mut self) {
        if !self.can_spawn_neurons() {
            return;
        }

        let now_seconds = self.env.now();
        let maturity_modulation = match self.heap_data.cached_daily_maturity_modulation_basis_points
        {
            None => return,
            Some(value) => value,
        };

        // Sanity check that the maturity modulation returned is within bounds.
        if !VALID_MATURITY_MODULATION_BASIS_POINTS_RANGE.contains(&maturity_modulation) {
            println!(
                "{}Maturity modulation (in basis points) out-of-bounds. Should be in range [-500, 500], actually is: {}",
                LOG_PREFIX, maturity_modulation
            );
            return;
        }

        // Acquire the global "spawning" lock.
        self.heap_data.spawning_neurons = Some(true);

        // Filter all the neurons that are currently in "spawning" state.
        // Do this here to avoid having to borrow *self while we perform changes below.
        // Spawning neurons must have maturity, and no neurons in stable storage should have maturity.
        let ready_to_spawn_ids = self
            .neuron_store
            .list_ready_to_spawn_neuron_ids(now_seconds);

        // We can't alias ready_to_spawn_ids in the loop below, but the TLA model needs access to it,
        // so we clone it here.
        #[cfg(feature = "tla")]
        let mut _tla_ready_to_spawn_ids: BTreeSet<u64> =
            ready_to_spawn_ids.iter().map(|nid| nid.id).collect();

        for neuron_id in ready_to_spawn_ids {
            // Actually mint the neuron's ICP.
            let in_flight_command = NeuronInFlightCommand {
                timestamp: now_seconds,
                command: Some(InFlightCommand::Spawn(neuron_id)),
            };

            // Add the neuron to the set of neurons undergoing ledger updates.
            match self.lock_neuron_for_command(neuron_id.id, in_flight_command.clone()) {
                Ok(mut lock) => {
                    // Since we're multiplying a potentially pretty big number by up to 10500, do
                    // the calculations as u128 before converting back.
                    let neuron = self
                        .with_neuron(&neuron_id, |neuron| neuron.clone())
                        .expect("Neuron should exist, just found in list");

                    let original_maturity = neuron.maturity_e8s_equivalent;
                    let subaccount = neuron.subaccount();

                    let neuron_stake: u64 = match apply_maturity_modulation(
                        original_maturity,
                        maturity_modulation,
                    ) {
                        Ok(neuron_stake) => neuron_stake,
                        Err(err) => {
                            // Do not retain the lock so that other Neuron operations can continue.
                            // This is safe as no changes to the neuron have been made to the neuron
                            // both internally to governance and externally in ledger.
                            println!(
                                "{}Could not apply modulation to {:?} for neuron {:?} due to {:?}, skipping",
                                LOG_PREFIX,
                                neuron.maturity_e8s_equivalent,
                                neuron.id(),
                                err
                            );
                            continue;
                        }
                    };

                    println!(
                        "{}Spawning neuron: {:?}. Performing ledger update.",
                        LOG_PREFIX, neuron
                    );

                    let (staked_neuron_clone, original_spawn_at_timestamp_seconds) = self
                        .with_neuron_mut(&neuron_id, |neuron| {
                            // Reset the neuron's maturity and set that it's spawning before we actually mint
                            // the stake. This is conservative to prevent a neuron having _both_ the stake and
                            // the maturity at any point in time.
                            let original_spawn_ts = neuron.spawn_at_timestamp_seconds;
                            neuron.maturity_e8s_equivalent = 0;
                            neuron.spawn_at_timestamp_seconds = None;
                            neuron.cached_neuron_stake_e8s = neuron_stake;

                            (neuron.clone(), original_spawn_ts)
                        })
                        .unwrap();

                    tla_log_locals! {
                        neuron_id: neuron_id.id,
                        ready_to_spawn_ids: _tla_ready_to_spawn_ids
                    };

                    // Do the transfer, this is a minting transfer, from the governance canister's
                    // (which is also the minting canister) main account into the neuron's
                    // subaccount.
                    match self
                        .ledger
                        .transfer_funds(
                            neuron_stake,
                            0, // Minting transfer don't pay a fee.
                            None,
                            neuron_subaccount(subaccount),
                            now_seconds,
                        )
                        .await
                    {
                        Ok(_) => {
                            println!(
                                "{}Spawned neuron: {:?}. Ledger update performed.",
                                LOG_PREFIX, staked_neuron_clone,
                            );
                        }
                        Err(error) => {
                            println!(
                                "{}Error spawning neuron: {:?}. Ledger update failed with err: {:?}. \
                                Reverting state, so another attempt can be made.",
                                LOG_PREFIX, neuron_id, error,
                            );
                            match self.with_neuron_mut(&neuron_id, |neuron| {
                                neuron.maturity_e8s_equivalent = original_maturity;
                                neuron.cached_neuron_stake_e8s = 0;
                                neuron.spawn_at_timestamp_seconds =
                                    original_spawn_at_timestamp_seconds;
                            }) {
                                Ok(_) => (),
                                Err(e) => {
                                    println!(
                                        "{} Error reverting state for neuron: {:?}. Retaining lock: {}",
                                        LOG_PREFIX, neuron_id, e
                                    );
                                    // Retain the neuron lock, the neuron won't be able to undergo stake changing
                                    // operations until this is fixed.
                                    // This is different from what we do in most places because we usually rely
                                    // on trapping to retain the lock, but we can't do that here since we're not
                                    // working on a single neuron.
                                    lock.retain();
                                }
                            };
                        }
                    };
                }
                Err(error) => {
                    // If the lock was already acquired, just continue.
                    println!(
                        "{}Tried to spawn neuron but was already locked: {:?}. Error: {:?}",
                        LOG_PREFIX, neuron_id, error,
                    );
                    continue;
                }
            }
            #[cfg(feature = "tla")]
            _tla_ready_to_spawn_ids.remove(&neuron_id.id);
        }

        // Release the global spawning lock
        self.heap_data.spawning_neurons = Some(false);
    }

    /// Calculates the voting rewards to distribute and returns the rewards event and the
    /// distribution per neuron. There are 3 cases for the return value:
    /// 1. `None`. This is the case when the it's not the time to distribute rewards yet, and it can
    ///    happen when the distribute_rewards is called several times at almost the same time.
    /// 2. Some((reward_event, None)). This is the case where there are no proposals to settle, and
    ///    the rewards will be rolled over.
    /// 3. Some((reward_event, Some(distribution))). This is the case where there are proposals to
    ///    settle, and the rewards will be distributed.
    fn calculate_voting_rewards(
        &self,
        supply: Tokens,
    ) -> Option<(RewardEvent, Option<RewardsDistribution>)> {
        let now = self.env.now();

        let latest_reward_event = self.latest_reward_event();

        // Which reward rounds (i.e. days) require rewards? (Usually, there is
        // just one of these, but we support rewarding many consecutive rounds.)
        let day_after_genesis =
            (now - self.heap_data.genesis_timestamp_seconds) / REWARD_DISTRIBUTION_PERIOD_SECONDS;
        let last_event_day_after_genesis = latest_reward_event.day_after_genesis;
        let days = last_event_day_after_genesis..day_after_genesis;
        let new_rounds_count = days.clone().count();

        if new_rounds_count == 0 {
            // This may happen, in case consider_distributing_rewards was called
            // several times at almost the same time. This is
            // harmless, just abandon.
            return None;
        }

        if new_rounds_count > 1 {
            println!(
                "{}More than one reward round (i.e. days) has passed since the last \
                 RewardEvent. This could mean that rewards are being rolled over, \
                 or earlier rounds were missed. It is now {} full days since \
                 IC genesis, and the last distribution nominally happened at {} \
                 full days since IC genesis.",
                LOG_PREFIX, day_after_genesis, last_event_day_after_genesis
            );
        }

        // Only used for metrics.
        let latest_day_fraction: f64 = days
            .clone()
            .last()
            .map(|day| {
                crate::reward::calculation::rewards_pool_to_distribute_in_supply_fraction_for_one_day(day)
            })
            .unwrap_or(0.0);
        let latest_round_available_e8s_equivalent_float =
            (supply.get_e8s() as f64) * latest_day_fraction;

        let fraction: f64 = days
            .map(crate::reward::calculation::rewards_pool_to_distribute_in_supply_fraction_for_one_day)
            .sum();

        let rolling_over_from_previous_reward_event_e8s_equivalent =
            latest_reward_event.e8s_equivalent_to_be_rolled_over();
        let total_available_e8s_equivalent_float = (supply.get_e8s() as f64) * fraction
            + rolling_over_from_previous_reward_event_e8s_equivalent as f64;
        let rounds_since_last_distribution = (new_rounds_count as u64)
            .saturating_add(latest_reward_event.rounds_since_last_distribution_to_be_rolled_over());

        let as_of_timestamp_seconds =
            self.most_recent_fully_elapsed_reward_round_end_timestamp_seconds();
        let considered_proposals: Vec<ProposalId> = self
            .ready_to_be_settled_proposal_ids(as_of_timestamp_seconds)
            .collect();
        println!(
            "{}distributing voting rewards for the following proposals: {}",
            LOG_PREFIX,
            considered_proposals
                .iter()
                .map(|id| format!("{}", id.id))
                .join(", "),
        );
        // The "actually_distributed_e8s_equivalent" recorded in the RewardEvent
        // protoshould match exactly the sum of the distributed integer e8
        // equivalents. This amount has to be computed bottom-up and is dependent
        // on the how many neurons voted, with what voting power and on the
        // reward weight of proposals being voted on.
        let mut actually_distributed_e8s_equivalent = 0_u64;

        // We filter out proposals with votes that still need to be propogated to the ballots.
        let considered_proposals: Vec<ProposalId> = considered_proposals
            .into_iter()
            .filter(
                |proposal_id| match self.heap_data.proposals.get(&proposal_id.id) {
                    None => {
                        println!(
                            "{}ERROR: Trying to give voting rewards for proposal {}, \
                             but it was not found.",
                            LOG_PREFIX, proposal_id.id,
                        );
                        false
                    }
                    Some(proposal_data) => !proposal_data.has_unprocessed_votes(),
                },
            )
            .collect();

        let (voters_to_used_voting_right, total_voting_rights) = sum_weighted_voting_power(
            considered_proposals
                .iter()
                .flat_map(|proposal_id| self.heap_data.proposals.get(&proposal_id.id)),
        );

        // Increment neuron maturities (and actually_distributed_e8s_equivalent).
        //
        // The point of this guard is to avoid divide by zero (or super tiny
        // positive number). Not sure if that is theoretically possible, but
        // even if it isn't, it might occur due to some bug.
        //
        // Theoretically, the smallest nonzero we can get is 0.01, because we
        // are just adding and multiplying, and everything is just integers,
        // except for proposal weights, which are currently (as of Mar, 2023)
        // 20x, 1x, and 0.01x.
        let reward_distribution = if total_voting_rights < 0.001 {
            println!(
                "{}WARNING: total_voting_rights == {}, even though considered_proposals \
                 is nonempty (see earlier log). Therefore, we skip incrementing maturity \
                 to avoid dividing by zero (or super small number).",
                LOG_PREFIX, total_voting_rights,
            );
            None
        } else {
            let mut reward_distribution = RewardsDistribution::new();
            for (neuron_id, used_voting_rights) in voters_to_used_voting_right {
                if self.neuron_store.contains(neuron_id) {
                    let reward = (used_voting_rights * total_available_e8s_equivalent_float
                        / total_voting_rights) as u64;

                    reward_distribution.add_reward(neuron_id, reward);

                    // NOTE: This is the only reason we are checking the existence of neurons
                    // at this stage. Otherwise, we could defer until we distribute them in the
                    // schedule task.
                    actually_distributed_e8s_equivalent += reward;
                } else {
                    println!(
                        "{}Cannot find neuron {}, despite having voted with power {} \
                            in the considered reward period. The reward that should have been \
                            distributed to this neuron is simply skipped, so the total amount \
                            of distributed reward for this period will be lower than the maximum \
                            allowed.",
                        LOG_PREFIX, neuron_id.id, used_voting_rights
                    );
                }
            }
            Some(reward_distribution)
        };

        let reward_event = RewardEvent {
            day_after_genesis,
            actual_timestamp_seconds: now,
            settled_proposals: considered_proposals,
            distributed_e8s_equivalent: actually_distributed_e8s_equivalent,
            total_available_e8s_equivalent: total_available_e8s_equivalent_float as u64,
            rounds_since_last_distribution: Some(rounds_since_last_distribution),
            latest_round_available_e8s_equivalent: Some(
                latest_round_available_e8s_equivalent_float as u64,
            ),
        };

        Some((reward_event, reward_distribution))
    }

    /// Distributes voting rewards to neurons.
    ///
    /// This method:
    /// * collects all proposals in state ReadyToSettle, that is, proposals that
    ///   can no longer accept votes for the purpose of rewards and that have
    ///   not yet been considered in a reward event.
    /// * calculates the voting rewards to distribute.
    /// * schedules the rewards distribution.
    /// * updates the reward event.
    /// * updates the proposals from ReadyToSettle to Settled.
    pub(crate) fn distribute_voting_rewards_to_neurons(&mut self, supply: Tokens) {
        println!(
            "{}distribute_voting_rewards_to_neurons. Supply: {:?}",
            LOG_PREFIX, supply
        );

        let voting_rewards_calculation_result = self.calculate_voting_rewards(supply);
        let Some((new_reward_event, reward_distribution)) = voting_rewards_calculation_result
        else {
            return;
        };

        // Now the mutations begin. Once any mutation has happened, we cannot exit early without the
        // rest. Otherwise we could end up in an inconsistent state and break some properties we
        // would like to hold.
        //
        // The properties we would like to hold are:
        // * The rewards for a given day is only distributed once. This is made sure by updating the
        //   reward event, in particular the `day_after_genesis` field every time
        //   `schedule_pending_rewards_distribution` is called. This is also the main reason that
        //   once mutations begin, we should not exit early before  `latest_reward_event` is
        //   updated.
        // * The proposals should only be settled once. This is made sure by updating the proposal
        //   status from `ReadyToSettle` to `Settled`.

        if let Some(reward_distribution) = reward_distribution {
            self.schedule_pending_rewards_distribution(
                new_reward_event.day_after_genesis,
                reward_distribution,
            );
        }

        let known_neuron_ids = self.neuron_store.list_known_neuron_ids();

        // Mark the proposals that we just considered as "rewarded". More
        // formally, causes their reward_status to be Settled; whereas, before,
        // they were in the ReadyToSettle state.
        for pid in new_reward_event.settled_proposals.iter() {
            // Before considering a proposal for reward, it must be fully processed --
            // because we're about to clear the ballots, so no further processing will be
            // possible.
            self.process_proposal(pid.id);

            match self.mut_proposal_data(*pid) {
                None => println!(
                    "{}Cannot find proposal {}, despite it being considered for rewards distribution.",
                    LOG_PREFIX, pid.id
                ),
                Some(p) => {
                    if p.status() == ProposalStatus::Open {
                        println!(
                            "{}Proposal {} was considered for reward distribution despite \
                          being open. This code line is expected not to be reachable. We need to \
                          clear the ballots here to avoid a risk of the memory getting too large. \
                          In doubt, reject the proposal",
                            LOG_PREFIX, pid.id
                        );
                        p.decided_timestamp_seconds = new_reward_event.actual_timestamp_seconds;
                        p.latest_tally = Some(Tally {
                            timestamp_seconds: new_reward_event.actual_timestamp_seconds,
                            yes: 0,
                            no: 0,
                            total: 0,
                        })
                    };
                    p.reward_event_round = new_reward_event.day_after_genesis;
                    let ballots = std::mem::take(&mut p.ballots);
                    record_known_neuron_abstentions(&known_neuron_ids, *pid, ballots);
                }
            };
        }

        if new_reward_event.settled_proposals.is_empty() {
            println!(
                "{}Voting rewards will roll over, because no there were proposals \
                 that needed rewards (i.e. have reward_status == ReadyToSettle)",
                LOG_PREFIX,
            );
        };

        self.heap_data.latest_reward_event = Some(new_reward_event);
    }

    /// Recompute cached metrics once per day
    pub fn should_compute_cached_metrics(&self) -> bool {
        if let Some(metrics) = self.heap_data.metrics.as_ref() {
            let metrics_age_s = self.env.now() - metrics.timestamp_seconds;
            metrics_age_s > ONE_DAY_SECONDS
        } else {
            true
        }
    }

    /// Return the effective _voting period_ of a given topic.
    ///
    /// This function is "curried" to alleviate lifetime issues on the
    /// `self` parameter.
    pub fn voting_period_seconds(&self) -> impl Fn(Topic) -> u64 + use<> {
        let short = self.heap_data.short_voting_period_seconds;
        let private = self.heap_data.neuron_management_voting_period_seconds;
        let normal = self.heap_data.wait_for_quiet_threshold_seconds;
        move |topic| match topic {
            Topic::NeuronManagement => private,
            Topic::ExchangeRate => short,
            _ => normal,
        }
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

    /// Update the metadata for the given Node Provider
    pub fn update_node_provider(
        &mut self,
        node_provider_id: &PrincipalId,
        update: UpdateNodeProvider,
    ) -> Result<(), GovernanceError> {
        let node_provider = self
            .heap_data
            .node_providers
            .iter_mut()
            .find(|np| np.id.as_ref() == Some(node_provider_id))
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!("Node Provider {node_provider_id} is not known by the NNS"),
                )
            })?;

        if let Some(new_reward_account) = update.reward_account {
            validate_account_identifier(&new_reward_account).map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!("Invalid reward_account for Node Provider {node_provider_id}: {e}"),
                )
            })?;
            node_provider.reward_account = Some(new_reward_account);
        } else {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "reward_account not specified",
            ));
        }

        Ok(())
    }

    fn get_proposal_data_or_err(
        &self,
        proposal_id: &ProposalId,
        context: &str,
    ) -> Result<&ProposalData, GovernanceError> {
        let Some(proposal_data) = self.get_proposal_data(*proposal_id) else {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!("Proposal {proposal_id:?} not found ({context})"),
            ));
        };
        Ok(proposal_data)
    }

    fn mut_proposal_data_or_err(
        &mut self,
        proposal_id: &ProposalId,
        context: &str,
    ) -> Result<&mut ProposalData, GovernanceError> {
        let Some(proposal_data) = self.mut_proposal_data(*proposal_id) else {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!("Proposal {proposal_id:?} not found ({context})"),
            ));
        };
        Ok(proposal_data)
    }

    fn mut_proposal_data_and_neuron_store_or_err(
        &mut self,
        proposal_id: &ProposalId,
        context: &str,
    ) -> Result<(&mut ProposalData, &mut NeuronStore), GovernanceError> {
        let (Some(proposal_data), neuron_store) =
            self.mut_proposal_data_and_neuron_store(proposal_id)
        else {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!("Proposal {proposal_id:?} not found ({context})"),
            ));
        };
        Ok((proposal_data, neuron_store))
    }

    /// If the request is `Committed`, mint ICP and deposit it in the SNS treasury as per the rules
    /// of Matched Funding, refunding the leftover maturity to the Neurons' Fund neurons.
    ///
    /// If the request is `Aborted`, refund all Neurons' Fund neurons with the maturity reserved for
    /// this SNS swap.
    ///
    /// Caller must be a SNS Swap Canister Id.
    ///
    /// Unless this function fails, it sets the `sns_token_swap_lifecycle` field of the NNS proposal
    /// that created this SNS instance to `Committed` or `Aborted`, as per the request.
    pub async fn settle_neurons_fund_participation(
        &mut self,
        caller: PrincipalId,
        request: SettleNeuronsFundParticipationRequest,
    ) -> Result<NeuronsFundSnapshot, GovernanceError> {
        let request = ValidatedSettleNeuronsFundParticipationRequest::try_from(request)?;
        let proposal_data = self.get_proposal_data_or_err(
            &request.nns_proposal_id,
            &format!("before awaiting SNS-W for {:?}", request.request_str),
        )?;

        // Check that the action associated with this proposal is indeed CreateServiceNervousSystem.
        if let Some(action) = proposal_data
            .proposal
            .as_ref()
            .and_then(|p| p.action.as_ref())
        {
            if let Action::CreateServiceNervousSystem(_) = action {
                // All good.
            } else {
                return Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!(
                        "Proposal {:?} is not of type CreateServiceNervousSystem.",
                        proposal_data.id,
                    ),
                ));
            }
        } else {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Proposal {:?} is missing its action and cannot authorize {} to \
                    settle Neurons' Fund participation.",
                    proposal_data.id, caller
                ),
            ));
        }
        // Check authorization. Note that a Swap could settle each other's participation.
        let target_canister_id: CanisterId = caller.try_into().map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                format!(
                    "Caller {caller} is not a valid CanisterId and is not authorized to \
                        settle Neuron's Fund participation in a decentralization swap. Err: {err:?}",
                ),
            )
        })?;
        if let Err(err_msg) =
            is_canister_id_valid_swap_canister_id(target_canister_id, &*self.env).await
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                format!(
                    "Caller {caller} is not authorized to settle Neurons' Fund \
                    participation in a decentralization swap. Err: {err_msg:?}",
                ),
            ));
        }
        // Re-acquire the proposal_data mutably after `SnsWasm.list_deployed_snses().await`.
        // Mutability will be needed later, when we aquire the lock (see
        // `proposal_data.set_swap_lifecycle_by_settle_neurons_fund_participation_request_type`).
        let proposal_data = self.mut_proposal_data_or_err(
            &request.nns_proposal_id,
            &format!("after awaiting SNS-W for {:?}", request.request_str),
        )?;

        // Record the proposal's current lifecycle. If an error occurs when settling
        // the Neurons' Fund the previous Lifecycle should be set to allow for retries.
        let original_sns_token_swap_lifecycle = proposal_data
            .sns_token_swap_lifecycle
            .and_then(|v| Lifecycle::try_from(v).ok())
            .unwrap_or(Lifecycle::Unspecified);

        let neurons_fund_data = proposal_data.get_neurons_fund_data_or_err()?;

        // This field is expected to be set if and only if this function has been called before.
        let initial_neurons_fund_participation = neurons_fund_data
            .initial_neurons_fund_participation
            .as_ref()
            .map(|initial_neurons_fund_participation| {
                initial_neurons_fund_participation.validate().map(Some)
            })
            .unwrap_or(Ok(None)) // No data means this function should not have been called
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!(
                    "Error while loading previously computed `initial_neurons_fund_participation` \
                    for proposal {:?}: {}",
                    request.nns_proposal_id,
                    err,
                ),
                )
            })?;
        // This field is expected to be set if this function has been called before (normal case)
        // or the Swap canister deployment has failed (in case there a bug).
        let previously_computed_neurons_fund_refunds = neurons_fund_data
            .neurons_fund_refunds
            .as_ref()
            .map(|neurons_fund_refunds| neurons_fund_refunds.validate().map(Some))
            .unwrap_or(Ok(None)) // No data means this is the first call of this function.
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!(
                        "Error while loading previously computed `neurons_fund_refunds` \
                        for proposal {:?}: {}",
                        request.nns_proposal_id, err,
                    ),
                )
            })?;
        // This field is expected to be set if and only if this function has been called before.
        let previously_computed_final_neurons_fund_participation = neurons_fund_data
            .final_neurons_fund_participation
            .as_ref()
            .map(|final_neurons_fund_participation| {
                final_neurons_fund_participation.validate().map(Some)
            })
            .unwrap_or(Ok(None)) // No data means this is the first call of this function.
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!(
                        "Error while loading previously computed `final_neurons_fund_participation` \
                        for proposal {:?}: {}",
                        request.nns_proposal_id,
                        err,
                    ),
                )
            })?;

        // Validate the state machine
        match (
            &initial_neurons_fund_participation,
            previously_computed_neurons_fund_refunds,
            previously_computed_final_neurons_fund_participation,
        ) {
            // The first two cases detect mismatch between `previously_computed_*`:
            // When this function is called, they must both be `Some`, or they must both be `None`.
            (_, None, Some(_)) => {
                return Err(GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!(
                        "Refunds must be set if there is final participation (ProposalId {:?}).",
                        request.nns_proposal_id,
                    ),
                ));
            }
            (_, Some(_), None) => {
                return Err(GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!(
                        "If the swap failed early, the refunds are set and there is no final \
                        participation. However, settle_neurons_fund_participation cannot be called \
                        in this state (ProposalId {:?}).",
                        request.nns_proposal_id,
                    ),
                ));
            }
            // In all remaining cases, `previously_computed_*` are either both `Some`, or both `None`.
            (Some(_), Some(_), Some(_)) if !original_sns_token_swap_lifecycle.is_terminal() => {
                // Err case 3. All data is present for this proposal, but the SNS lifecycle is not
                // terminal. This can only happen if there is a bug.
                return Err(GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!(
                        "All data is present for this proposal, but the SNS lifecycle is not \
                        terminal ({:?}). This likely indicates that there's a bug \
                        (ProposalId {:?}).",
                        original_sns_token_swap_lifecycle, request.nns_proposal_id,
                    ),
                ));
            }
            (Some(_), None, None) if original_sns_token_swap_lifecycle.is_terminal() => {
                // Err case 4. This function has been called before, but its ultimate results are
                // still being computed.
                return Err(GovernanceError::new_with_message(
                    ErrorType::Unavailable,
                    format!(
                        "Neurons' Fund settlement in progress. Try calling this function later \
                        (ProposalId {:?})",
                        request.nns_proposal_id,
                    ),
                ));
            }
            (Some(_), Some(_), Some(previously_computed_final_neurons_fund_participation)) => {
                // Ok case I: Return the priorly computed results (this is an idempotent function).
                println!(
                    "{}INFO: settle_neurons_fund_participation was called for a swap \
                        that has already been settled with ProposalId {:?}. Returning without \
                        doing additional work.",
                    LOG_PREFIX, proposal_data.id
                );
                return Ok(previously_computed_final_neurons_fund_participation.into_snapshot());
            }
            (None, _, _) => {
                // Ok case II: The Neurons' Fund does not participate in this swap.
                // Nothing to do.
            }
            (Some(_), None, None) => {
                // Ok case III: This function invocation should compute the Neurons' Fund
                // participation, mint ICP to SNS treasury, refund the leftovers, and return
                // the (newly computed) Neurons' Fund participants.
                // Nothing to do.
            }
        };

        let Some(initial_neurons_fund_participation) = initial_neurons_fund_participation else {
            println!(
                "{}INFO: The Neurons' Fund does not participate in the SNS created with \
                ProposalId {:?}. Setting lifecycle to {:?} and returning empty list of \
                Neurons' Fund participants.",
                LOG_PREFIX, request.nns_proposal_id, request.swap_result,
            );
            return Ok(NeuronsFundSnapshot::empty());
        };

        let direct_participation_icp_e8s = if let SwapResult::Committed {
            total_direct_participation_icp_e8s,
            ..
        } = request.swap_result
        {
            println!(
                "{}INFO: The Swap canister of the SNS created via proposal {:?} has requested \
                Neurons' Fund Matched Funding for {} ICP e8s of direct participation.",
                LOG_PREFIX, request.nns_proposal_id, total_direct_participation_icp_e8s
            );
            total_direct_participation_icp_e8s
        } else {
            println!(
                "{}INFO: The Swap canister of the SNS created via proposal {:?} has reported \
                that the swap had been aborted. There should not be Neurons' Fund participation.",
                LOG_PREFIX, request.nns_proposal_id
            );
            // Our intention is that the following implications hold:
            // Aborted swap ==> Zero direct participation ==> Zero Neurons' Fund participation.
            0
        };

        // This is the source of truth for the Neurons' Fund participation in the SNS swap.
        let final_neurons_fund_participation = initial_neurons_fund_participation
            .from_initial_participation(direct_participation_icp_e8s)
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!(
                        "Error while computing final NeuronsFundParticipation \
                        for proposal {:?}: {}",
                        request.nns_proposal_id, err,
                    ),
                )
            })?;

        // Set the lifecycle of the proposal to avoid interleaving callers.
        proposal_data.set_swap_lifecycle_by_settle_neurons_fund_participation_request_type(
            &request.swap_result,
        );

        let amount_icp_e8s = final_neurons_fund_participation.total_amount_icp_e8s();
        let settlement_result = if final_neurons_fund_participation.is_empty() {
            // TODO: Provide the reason why there is no Matched Funding in this case.
            println!(
                "{}INFO: The Neurons' Fund has decided against participating in the SNS \
                created via proposal {:?}.",
                LOG_PREFIX, request.nns_proposal_id,
            );

            Ok(NeuronsFundSnapshot::empty())
        } else if let SwapResult::Committed {
            sns_governance_canister_id,
            total_neurons_fund_participation_icp_e8s:
                swap_estimated_total_neurons_fund_participation_icp_e8s,
            ..
        } = request.swap_result
        {
            println!(
                "{}INFO: The Neurons' Fund has decided to provide Matched Funding to the \
                SNS created via proposal {:?}, in the amount of {} ICP e8s taken from {} \
                of its neurons. Congratulations!",
                LOG_PREFIX,
                request.nns_proposal_id,
                amount_icp_e8s,
                final_neurons_fund_participation.num_neurons(),
            );

            let mint_icp_result = self
                .mint_to_sns_governance(
                    &request.nns_proposal_id,
                    sns_governance_canister_id,
                    swap_estimated_total_neurons_fund_participation_icp_e8s,
                    amount_icp_e8s,
                )
                .await;

            // We need to clone the snapshot because `final_neurons_fund_participation` is recorded
            // in stable memory, while the snapshot is used to build up this function's response.
            mint_icp_result.map(|_| final_neurons_fund_participation.snapshot_cloned())
        } else {
            // This should never happen, as it would mean that the swap was aborted, but
            // the Neurons' Fund still decided to participate. This could indicate a bug
            // in `NeuronsFundParticipation::from_initial_participation`.
            Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!(
                    "Despite the fact that the SNS swap aborted, the Neurons' Fund estimated \
                    to provide Matched Funding to the SNS created via proposal {:?}, in the amount \
                    of {} ICP e8s taken from {} of its neurons. This is a bug.",
                    request.nns_proposal_id,
                    amount_icp_e8s,
                    final_neurons_fund_participation.num_neurons(),
                ),
            ))
        };

        // We need to re-acquire `proposal_data` mutably again due to the await above.
        let (proposal_data, neuron_store) = self.mut_proposal_data_and_neuron_store_or_err(
            &request.nns_proposal_id,
            &format!("after awaiting ICP Ledger for {:?}", request.request_str),
        )?;

        let Ok(ref participated_reserves) = settlement_result else {
            // Reset the Proposal's lifecycle and complete the request. Note that the field
            // `final_neurons_fund_participation` remains unset in this case.
            proposal_data.sns_token_swap_lifecycle = Some(original_sns_token_swap_lifecycle as i32);
            return settlement_result;
        };

        // We need to re-acquire `neurons_fund_data` as it is a sub-structure of the (re-acquired)
        // `proposal_data` structure.
        let neurons_fund_data = proposal_data.mut_neurons_fund_data_or_err()?;

        // At last, set this proposal's `final_neurons_fund_participation` field; we need
        // to re-acquire `neurons_fund_data` as it is a sub-structure of the (re-acquired)
        // `proposal_data` structure.
        neurons_fund_data.final_neurons_fund_participation = Some(
            NeuronsFundParticipationPb::from(final_neurons_fund_participation),
        );

        // We purposefully do not release the lock (`proposal_data.sns_token_swap_lifecycle`)
        // if the following two operations fail. This is because we want to have enough time for
        // a manual intervention (NNS hot fix) in case of a highly unexpected failure.
        let refund = initial_neurons_fund_participation
            .into_snapshot()
            .diff(participated_reserves)?;

        let total_refund_amount_icp_e8s = refund.total_amount_icp_e8s()?;
        if total_refund_amount_icp_e8s > 0 {
            println!(
                "{}INFO: About to refund {} Neurons' Fund neurons with a total of {} \
                ICP e8s (after settling the SNS swap created via proposal {:?}) ...",
                LOG_PREFIX,
                refund.num_neurons(),
                total_refund_amount_icp_e8s,
                request.nns_proposal_id,
            );
        } else {
            println!(
                "{}INFO: No refunds needed for {} Neurons' Fund neurons (after settling \
                the SNS swap created via proposal {:?}).",
                LOG_PREFIX,
                refund.num_neurons(),
                request.nns_proposal_id,
            );
            // Although there are effectively no refunds, we still save the refund snapshot
            // (via `refund_maturity_to_neurons_fund` below) for aiding potential future audits.
        }

        // If refunding failed for whatever reason, we opt for providing data to the SNS Swap
        // canister, as the ICP were successfully sent to the SNS Governance. Thus, we return
        // normally in this case, merely logging the error for human inspection.
        let _ = neuron_store
            .refund_maturity_to_neurons_fund(&refund)
            .map_err(|err| {
                println!(
                    "{}ERROR while trying to refund Neurons' Fund: {}. \
                    Total refund amount: {} ICP e8s.",
                    LOG_PREFIX, err, total_refund_amount_icp_e8s,
                );
            });

        neurons_fund_data.neurons_fund_refunds = Some(NeuronsFundSnapshotPb::from(refund));

        settlement_result
    }

    fn draw_maturity_from_neurons_fund(
        &mut self,
        proposal_id: &ProposalId,
        create_service_nervous_system: &CreateServiceNervousSystem,
    ) -> Result<(NeuronsFundSnapshot, NeuronsFundParticipationConstraints), GovernanceError> {
        let swap_participation_limits = create_service_nervous_system
            .swap_parameters
            .as_ref()
            .ok_or_else(|| {
                "CreateServiceNervousSystem.swap_parameters is not specified.".to_string()
            })?;
        let swap_participation_limits =
            SwapParticipationLimits::try_from_swap_parameters(swap_participation_limits)?;
        let neurons_fund_participation_limits =
            self.try_derive_neurons_fund_participation_limits()?;
        let neurons_fund = self.neuron_store.list_active_neurons_fund_neurons();
        let initial_neurons_fund_participation = PolynomialNeuronsFundParticipation::new(
            neurons_fund_participation_limits,
            swap_participation_limits,
            neurons_fund,
        )?;
        // Check that the maximum number of Neurons' Fund participants is not too high. Otherwise,
        // the SNS may be unable to distribute SNS tokens to all participants after the swap.
        {
            let maximum_neurons_fund_participants = initial_neurons_fund_participation
                .snapshot()
                .neurons()
                .len() as u64;
            if maximum_neurons_fund_participants > MAX_NEURONS_FUND_PARTICIPANTS {
                return Err(GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    format!(
                        "The maximum number of Neurons' Fund participants ({maximum_neurons_fund_participants}) must not exceed \
                        MAX_NEURONS_FUND_PARTICIPANTS ({MAX_NEURONS_FUND_PARTICIPANTS}).",
                    ),
                ));
            };
        }
        let constraints = initial_neurons_fund_participation.compute_constraints()?;
        let initial_neurons_fund_participation_snapshot =
            initial_neurons_fund_participation.snapshot_cloned();
        // First check if the ProposalData is available (and error out if not); then actually draw
        // the funds from the Neurons' Fund. This way, we do not need to issue refunds in case
        // of an error.
        if self.get_proposal_data(*proposal_id).is_none() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("ProposalData must be present for proposal {proposal_id:?}."),
            ));
        }
        self.neuron_store
            .draw_maturity_from_neurons_fund(&initial_neurons_fund_participation_snapshot)?;
        let initial_neurons_fund_participation = Some(initial_neurons_fund_participation.into());
        let neurons_fund_data = NeuronsFundData {
            initial_neurons_fund_participation,
            // These two fields will be known after `settle_neurons_fund_participation` is called.
            final_neurons_fund_participation: None,
            neurons_fund_refunds: None,
        };
        // Unwrapping is safe due to the `self.get_proposal_data().is_none()` check above.
        let proposal_data = self.mut_proposal_data(*proposal_id).unwrap();
        proposal_data.neurons_fund_data = Some(neurons_fund_data);
        Ok((initial_neurons_fund_participation_snapshot, constraints))
    }

    /// Records the empty participation into ProposalData for this `proposal_id`.
    fn record_neurons_fund_participation_not_requested(
        &mut self,
        proposal_id: &ProposalId,
    ) -> Result<(), GovernanceError> {
        let proposal_data = self.mut_proposal_data_or_err(
            proposal_id,
            "in record_neurons_fund_participation_not_requested",
        )?;
        let neurons_fund_data = NeuronsFundData {
            initial_neurons_fund_participation: None,
            final_neurons_fund_participation: None,
            neurons_fund_refunds: None,
        };
        proposal_data.neurons_fund_data = Some(neurons_fund_data);
        Ok(())
    }

    /// Refunds the maturity represented via `refund` and stores this information in ProposalData
    /// of this `proposal_id` (for auditability).
    fn refund_maturity_to_neurons_fund(
        &mut self,
        proposal_id: &ProposalId,
        refund: NeuronsFundSnapshot,
    ) -> Result<(), GovernanceError> {
        self.neuron_store.refund_maturity_to_neurons_fund(&refund)?;
        let proposal_data =
            self.mut_proposal_data_or_err(proposal_id, "in refund_maturity_to_neurons_fund")?;
        let neurons_fund_data = proposal_data.mut_neurons_fund_data_or_err()?;
        neurons_fund_data.neurons_fund_refunds = Some(NeuronsFundSnapshotPb::from(refund));
        Ok(())
    }

    /// Asks ICP Ledger to mint `amount_icp_e8s`.
    ///
    /// This function may be called only from `settle_neurons_fund_participation`.
    async fn mint_to_sns_governance(
        &self,
        proposal_id: &ProposalId,
        sns_governance_canister_id: PrincipalId,
        swap_estimated_total_neurons_fund_participation_icp_e8s: u64,
        amount_icp_e8s: u64,
    ) -> Result<(), GovernanceError> {
        // Sanity check if the NNS Governance and the Swap canister agree on how much ICP
        // the Neurons' Fund should participate with.
        //
        // Warning. This value should be used for validation only. NNS Governance should
        // re-compute the amount of Neurons' Fund participation itself. A significant
        // deviation between the self-computed amount and this value would indicates that
        // (1) there is an incompatibility between NNS Governance and Swap, due to a bug or
        // a problematic upgrade or (2) some Neurons' Fund neurons became inactive during
        // the swap.
        if amount_icp_e8s != swap_estimated_total_neurons_fund_participation_icp_e8s {
            println!(
                "{}WARNING: mismatch between amount_icp_e8s computed while settling Neurons' Fund \
                participation in SNS swap created via proposal {:?}. NNS Governance \
                calculation = {}, Swap estimate = {}",
                LOG_PREFIX,
                proposal_id,
                amount_icp_e8s,
                swap_estimated_total_neurons_fund_participation_icp_e8s,
            );
        }

        let destination =
            AccountIdentifier::new(sns_governance_canister_id, /* subaccount = */ None);

        let _ = self
            .ledger
            .transfer_funds(
                amount_icp_e8s,
                /* fee_e8s = */ 0, // Because there is no fee for minting.
                /* from_subaccount = */ None,
                destination,
                /* memo = */ 0,
            )
            .await
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Minting ICP from the Neuron's Fund failed with error: {err:#?}"),
                )
            })?;

        Ok(())
    }

    /// Return the given Node Provider, if it exists
    pub fn get_node_provider(
        &self,
        node_provider_id: &PrincipalId,
    ) -> Result<NodeProvider, GovernanceError> {
        // TODO(NNS1-1168): More efficient Node Provider lookup
        self.heap_data
            .node_providers
            .iter()
            .find(|np| np.id.as_ref() == Some(node_provider_id))
            .cloned()
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!("Node Provider {node_provider_id} is not known by the NNS"),
                )
            })
    }

    /// A helper for the Node Rewards Canister get_node_providers_rewards method
    async fn get_node_providers_xdr_permyriad_rewards(
        &self,
        start_date: DateUtc,
        end_date: DateUtc,
    ) -> Result<
        (
            BTreeMap<PrincipalId, u64>,
            RewardsCalculationAlgorithmVersion,
        ),
        GovernanceError,
    > {
        let response: Vec<u8> = self
            .env
            .call_canister_method(
                NODE_REWARDS_CANISTER_ID,
                "get_node_providers_rewards",
                Encode!(&GetNodeProvidersRewardsRequest {
                    from_day: start_date,
                    to_day: end_date,
                    algorithm_version: None
                })
                .unwrap(),
            )
            .await
            .map_err(|(code, msg)| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Error calling 'get_node_providers_rewards': code: {code:?}, message: {msg}"
                    ),
                )
            })?;

        let response = Decode!(&response, GetNodeProvidersRewardsResponse).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Cannot decode return type from get_node_providers_rewards \
                        as GetNodeProvidersRewardsResponse'. Error: {err}",
                ),
            )
        })?;

        if let Err(err_msg) = response {
            return Err(GovernanceError::new_with_message(
                ErrorType::External,
                format!("Error calling 'get_node_providers_rewards': {err_msg}"),
            ));
        }

        if let Ok(result) = response {
            let rewards = result
                .rewards_xdr_permyriad
                .into_iter()
                .map(|(principal, amount)| (PrincipalId::from(principal), amount))
                .collect();
            let algorithm_version = result.algorithm_version;
            return Ok((rewards, algorithm_version));
        }

        Err(GovernanceError::new_with_message(
            ErrorType::Unspecified,
            "get_node_providers_rewards returned empty response, \
                which should be impossible.",
        ))
    }

    pub async fn get_node_providers_rewards_cached(
        &self,
    ) -> Result<MonthlyNodeProviderRewards, GovernanceError> {
        thread_local! {
            static INFLIGHT: Cell<bool> = const { Cell::new(false) };
            static CACHE: RefCell<Option<(u64, MonthlyNodeProviderRewards)>> = const { RefCell::new(None) };
        }

        let now = self.env.now();
        const FIVE_MINUTES_IN_SECONDS: u64 = 5 * 60;

        if let Some((last_update_timestamp_seconds, rewards)) =
            CACHE.with(|cache| cache.borrow().clone())
        {
            let time_since_last_update_seconds = now.saturating_sub(last_update_timestamp_seconds);

            if time_since_last_update_seconds < FIVE_MINUTES_IN_SECONDS {
                return Ok(rewards);
            }
        }

        if INFLIGHT.get() {
            return Err(GovernanceError::new_with_message(
                ErrorType::External,
                "get_node_provider_rewards called while there is an inflight call to NRC.\
                Please try again in 10 seconds.",
            ));
        }

        INFLIGHT.set(true);
        let rewards = self.get_node_providers_rewards().await?;
        INFLIGHT.set(false);

        CACHE.set(Some((now, rewards.clone())));

        Ok(rewards)
    }

    /// Return the rewards that node providers should be awarded with.
    ///
    /// Fetches the map from node provider to XDR rewards valid between 'from' and 'to' boundaries from the
    /// Node Rewards Canister, then fetches the average XDR to ICP conversion rate for
    /// the last 30 days, then applies this conversion rate to convert each
    /// node provider's XDR rewards to ICP.
    pub async fn get_node_providers_rewards(
        &self,
    ) -> Result<MonthlyNodeProviderRewards, GovernanceError> {
        let mut rewards = vec![];

        let start_date = self.next_start_date_node_providers_rewards();
        let now = self.env.now();

        // Today we have collected up to and included node metrics of yesterday
        // in the node rewards canister.
        let end_date_timestamp_seconds = now.saturating_sub(ONE_DAY_SECONDS);
        let end_date = DateUtc::from_unix_timestamp_seconds(end_date_timestamp_seconds);

        // Maps node providers to their rewards in XDR
        let (rewards_per_node_provider, algorithm_version) = self
            .get_node_providers_xdr_permyriad_rewards(start_date, end_date)
            .await?;

        // The average (last 30 days) conversion rate from 10,000ths of an XDR to 1 ICP
        let icp_xdr_conversion_rate = self.get_average_icp_xdr_conversion_rate().await?.data;
        let avg_xdr_permyriad_per_icp = icp_xdr_conversion_rate.xdr_permyriad_per_icp;

        // Convert minimum_icp_xdr_rate to basis points for comparison with avg_xdr_permyriad_per_icp
        let minimum_xdr_permyriad_per_icp = self
            .economics()
            .minimum_icp_xdr_rate
            .saturating_mul(NetworkEconomics::ICP_XDR_RATE_TO_BASIS_POINT_MULTIPLIER);

        let maximum_node_provider_rewards_e8s = self.economics().maximum_node_provider_rewards_e8s;

        let xdr_permyriad_per_icp = max(avg_xdr_permyriad_per_icp, minimum_xdr_permyriad_per_icp);

        // Iterate over all node providers, calculate their rewards, and append them to
        // `rewards`
        for np in &self.heap_data.node_providers {
            if let Some(np_id) = &np.id {
                let xdr_permyriad_reward = *rewards_per_node_provider.get(np_id).unwrap_or(&0);

                if let Some(reward_node_provider) =
                    get_node_provider_reward(np, xdr_permyriad_reward, xdr_permyriad_per_icp)
                {
                    rewards.push(reward_node_provider);
                }
            }
        }

        let xdr_conversion_rate = XdrConversionRate {
            timestamp_seconds: icp_xdr_conversion_rate.timestamp_seconds,
            xdr_permyriad_per_icp: icp_xdr_conversion_rate.xdr_permyriad_per_icp,
        };

        Ok(MonthlyNodeProviderRewards {
            timestamp: now,
            start_date: Some(pb::v1::DateUtc::try_from(start_date).expect("from date exists")),
            end_date: Some(pb::v1::DateUtc::try_from(end_date).expect("to date exists")),
            rewards,
            xdr_conversion_rate: Some(xdr_conversion_rate.into()),
            minimum_xdr_permyriad_per_icp: Some(minimum_xdr_permyriad_per_icp),
            maximum_node_provider_rewards_e8s: Some(maximum_node_provider_rewards_e8s),
            node_providers: self.heap_data.node_providers.clone(),
            algorithm_version: Some(algorithm_version.version),
            registry_version: None,
        })
    }

    /// Return the monthly rewards that node providers should be awarded
    ///
    /// Fetches the map from node provider to monthly XDR rewards from the
    /// Registry, then fetches the average XDR to ICP conversion rate for
    /// the last 30 days, then applies this conversion rate to convert each
    /// node provider's XDR rewards to ICP.
    pub async fn get_monthly_node_provider_rewards(
        &self,
    ) -> Result<MonthlyNodeProviderRewards, GovernanceError> {
        let mut rewards = vec![];

        // Maps node providers to their rewards in XDR
        let (reg_rewards, maybe_version) = self.get_node_providers_monthly_xdr_rewards().await?;
        let registry_version = maybe_version.ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::External,
                "Registry version was not available in the response to \
                    get_node_providers_monthly_xdr_rewards, which indicates a problem."
                    .to_string(),
            )
        })?;

        // The average (last 30 days) conversion rate from 10,000ths of an XDR to 1 ICP
        let icp_xdr_conversion_rate = self.get_average_icp_xdr_conversion_rate().await?.data;
        let avg_xdr_permyriad_per_icp = icp_xdr_conversion_rate.xdr_permyriad_per_icp;

        // Convert minimum_icp_xdr_rate to basis points for comparison with avg_xdr_permyriad_per_icp
        let minimum_xdr_permyriad_per_icp = self
            .economics()
            .minimum_icp_xdr_rate
            .saturating_mul(NetworkEconomics::ICP_XDR_RATE_TO_BASIS_POINT_MULTIPLIER);

        let maximum_node_provider_rewards_e8s = self.economics().maximum_node_provider_rewards_e8s;

        let xdr_permyriad_per_icp = max(avg_xdr_permyriad_per_icp, minimum_xdr_permyriad_per_icp);

        // Iterate over all node providers, calculate their rewards, and append them to
        // `rewards`
        for np in &self.heap_data.node_providers {
            if let Some(np_id) = &np.id {
                let xdr_permyriad_reward = *reg_rewards.get(np_id).unwrap_or(&0);

                if let Some(reward_node_provider) =
                    get_node_provider_reward(np, xdr_permyriad_reward, xdr_permyriad_per_icp)
                {
                    rewards.push(reward_node_provider);
                }
            }
        }

        let xdr_conversion_rate = XdrConversionRate {
            timestamp_seconds: icp_xdr_conversion_rate.timestamp_seconds,
            xdr_permyriad_per_icp: icp_xdr_conversion_rate.xdr_permyriad_per_icp,
        };

        Ok(MonthlyNodeProviderRewards {
            timestamp: self.env.now(),
            rewards,
            xdr_conversion_rate: Some(xdr_conversion_rate.into()),
            minimum_xdr_permyriad_per_icp: Some(minimum_xdr_permyriad_per_icp),
            maximum_node_provider_rewards_e8s: Some(maximum_node_provider_rewards_e8s),
            registry_version: Some(registry_version),
            node_providers: self.heap_data.node_providers.clone(),
            ..Default::default()
        })
    }

    /// A helper for the Registry's get_node_providers_monthly_xdr_rewards method
    async fn get_node_providers_monthly_xdr_rewards(
        &self,
    ) -> Result<(BTreeMap<PrincipalId, u64>, Option<u64>), GovernanceError> {
        let response: Vec<u8> = self.env.call_canister_method(
            NODE_REWARDS_CANISTER_ID,
            "get_node_providers_monthly_xdr_rewards",
            Encode!(&GetNodeProvidersMonthlyXdrRewardsRequest {registry_version: None }).unwrap(),
        ).await
            .map_err(|(code, msg)| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Error calling 'get_node_providers_monthly_xdr_rewards': code: {code:?}, message: {msg}"
                    ),
                )
            })?;

        let response =
            Decode!(&response, GetNodeProvidersMonthlyXdrRewardsResponse).map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Cannot decode return type from get_node_providers_monthly_xdr_rewards \
                        as GetNodeProvidersMonthlyXdrRewardsResponse'. Error: {err}",
                    ),
                )
            })?;

        let GetNodeProvidersMonthlyXdrRewardsResponse { rewards, error } = response;

        if let Some(err_msg) = error {
            return Err(GovernanceError::new_with_message(
                ErrorType::External,
                format!("Error calling 'get_node_providers_monthly_xdr_rewards': {err_msg}"),
            ));
        }

        if let Some(rewards) = rewards {
            let ic_node_rewards_canister_api::monthly_rewards::NodeProvidersMonthlyXdrRewards {
                rewards,
                registry_version,
            } = rewards;
            let rewards = rewards
                .into_iter()
                .map(|(principal, amount)| (PrincipalId::from(principal), amount))
                .collect();
            return Ok((rewards, registry_version));
        }

        Err(GovernanceError::new_with_message(
            ErrorType::Unspecified,
            "get_node_providers_monthly_xdr_rewards returned empty response, \
                which should be impossible.",
        ))
    }

    /// A helper for the CMC's get_average_icp_xdr_conversion_rate method
    async fn get_average_icp_xdr_conversion_rate(
        &self,
    ) -> Result<IcpXdrConversionRateCertifiedResponse, GovernanceError> {
        let cmc_response:
            Vec<u8> = self
            .env
            .call_canister_method(
                CYCLES_MINTING_CANISTER_ID,
                "get_average_icp_xdr_conversion_rate",
                Encode!().unwrap(),
            )
            .await
            .map_err(|(code, msg)| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Error calling 'get_average_icp_xdr_conversion_rate': code: {code:?}, message: {msg}"
                    ),
                )
            })?;

        Decode!(&cmc_response, IcpXdrConversionRateCertifiedResponse)
            .map_err(|err| GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Cannot decode return type from get_average_icp_xdr_conversion_rate'. Error: {err}",
                ),
            ))
    }

    /// Return the cached governance metrics.
    /// Governance metrics are updated once a day.
    pub fn get_metrics(&self) -> Result<GovernanceCachedMetrics, GovernanceError> {
        let metrics = &self.heap_data.metrics;
        match metrics {
            None => Err(GovernanceError::new_with_message(
                ErrorType::Unavailable,
                "Metrics not available",
            )),
            Some(m) => Ok(m.clone()),
        }
    }

    /// Picks a value at random in [00:00, 23:45] that is a multiple of 15
    /// minutes past midnight.
    pub fn randomly_pick_swap_start(&mut self) -> GlobalTimeOfDay {
        // It's not critical that we have perfect randomness here, so we can default to a fixed value
        // for the edge case where the RNG is not initialized (which should never happen in practice).
        let time_of_day_seconds = self.randomness.random_u64().unwrap_or(10_000) % ONE_DAY_SECONDS;

        // Round down to nearest multiple of 15 min.
        let remainder_seconds = time_of_day_seconds % (15 * 60);
        let seconds_after_utc_midnight = Some(time_of_day_seconds - remainder_seconds);

        GlobalTimeOfDay {
            seconds_after_utc_midnight,
        }
    }

    /// Iterate over all neurons and compute `GovernanceCachedMetrics`
    pub fn compute_cached_metrics(&self, now: u64, icp_supply: Tokens) -> GovernanceCachedMetrics {
        let network_economics = self.economics();
        let neuron_minimum_stake_e8s = network_economics.neuron_minimum_stake_e8s;
        let voting_power_economics = network_economics
            .voting_power_economics
            .as_ref()
            .unwrap_or(&VotingPowerEconomics::DEFAULT);

        let NeuronMetrics {
            dissolving_neurons_count,
            dissolving_neurons_e8s_buckets,
            dissolving_neurons_count_buckets,
            not_dissolving_neurons_count,
            not_dissolving_neurons_e8s_buckets,
            not_dissolving_neurons_count_buckets,
            dissolved_neurons_count,
            dissolved_neurons_e8s,
            garbage_collectable_neurons_count,
            neurons_with_invalid_stake_count,
            total_staked_e8s,
            neurons_with_less_than_6_months_dissolve_delay_count,
            neurons_with_less_than_6_months_dissolve_delay_e8s,
            community_fund_total_staked_e8s,
            community_fund_total_maturity_e8s_equivalent,
            neurons_fund_total_active_neurons,
            total_locked_e8s,
            total_maturity_e8s_equivalent,
            total_staked_maturity_e8s_equivalent,
            dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
            dissolving_neurons_staked_maturity_e8s_equivalent_sum,
            not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
            not_dissolving_neurons_staked_maturity_e8s_equivalent_sum,
            seed_neuron_count,
            ect_neuron_count,
            total_staked_e8s_seed,
            total_staked_e8s_ect,
            total_staked_maturity_e8s_equivalent_seed,
            total_staked_maturity_e8s_equivalent_ect,
            dissolving_neurons_e8s_buckets_seed,
            dissolving_neurons_e8s_buckets_ect,
            not_dissolving_neurons_e8s_buckets_seed,
            not_dissolving_neurons_e8s_buckets_ect,
            spawning_neurons_count,
            non_self_authenticating_controller_neuron_subset_metrics,
            public_neuron_subset_metrics,
            declining_voting_power_neuron_subset_metrics,
            fully_lost_voting_power_neuron_subset_metrics,
        } = self.neuron_store.compute_neuron_metrics(
            neuron_minimum_stake_e8s,
            voting_power_economics,
            now,
        );

        let total_staked_e8s_non_self_authenticating_controller =
            Some(non_self_authenticating_controller_neuron_subset_metrics.total_staked_e8s);
        let total_voting_power_non_self_authenticating_controller =
            Some(non_self_authenticating_controller_neuron_subset_metrics.total_voting_power);

        let non_self_authenticating_controller_neuron_subset_metrics = Some(
            NeuronSubsetMetricsPb::from(non_self_authenticating_controller_neuron_subset_metrics),
        );
        let public_neuron_subset_metrics =
            Some(NeuronSubsetMetricsPb::from(public_neuron_subset_metrics));
        let declining_voting_power_neuron_subset_metrics = Some(NeuronSubsetMetricsPb::from(
            declining_voting_power_neuron_subset_metrics,
        ));
        let fully_lost_voting_power_neuron_subset_metrics = Some(NeuronSubsetMetricsPb::from(
            fully_lost_voting_power_neuron_subset_metrics,
        ));

        GovernanceCachedMetrics {
            timestamp_seconds: now,
            total_supply_icp: icp_supply.get_tokens(),
            dissolving_neurons_count,
            dissolving_neurons_e8s_buckets,
            dissolving_neurons_count_buckets,
            not_dissolving_neurons_count,
            not_dissolving_neurons_e8s_buckets,
            not_dissolving_neurons_count_buckets,
            dissolved_neurons_count,
            dissolved_neurons_e8s,
            garbage_collectable_neurons_count,
            neurons_with_invalid_stake_count,
            total_staked_e8s,
            neurons_with_less_than_6_months_dissolve_delay_count,
            neurons_with_less_than_6_months_dissolve_delay_e8s,
            community_fund_total_staked_e8s,
            community_fund_total_maturity_e8s_equivalent,
            neurons_fund_total_active_neurons,
            total_locked_e8s,
            total_maturity_e8s_equivalent,
            total_staked_maturity_e8s_equivalent,
            dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
            dissolving_neurons_staked_maturity_e8s_equivalent_sum,
            not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
            not_dissolving_neurons_staked_maturity_e8s_equivalent_sum,
            seed_neuron_count,
            ect_neuron_count,
            total_staked_e8s_seed,
            total_staked_e8s_ect,
            total_staked_maturity_e8s_equivalent_seed,
            total_staked_maturity_e8s_equivalent_ect,
            dissolving_neurons_e8s_buckets_seed,
            dissolving_neurons_e8s_buckets_ect,
            not_dissolving_neurons_e8s_buckets_seed,
            not_dissolving_neurons_e8s_buckets_ect,
            spawning_neurons_count,
            total_staked_e8s_non_self_authenticating_controller,
            total_voting_power_non_self_authenticating_controller,

            non_self_authenticating_controller_neuron_subset_metrics,
            public_neuron_subset_metrics,
            declining_voting_power_neuron_subset_metrics,
            fully_lost_voting_power_neuron_subset_metrics,
        }
    }

    pub fn neuron_data_validation_summary(&self) -> NeuronDataValidationSummary {
        self.neuron_data_validator.summary()
    }

    pub fn get_restore_aging_summary(&self) -> Option<RestoreAgingSummary> {
        self.heap_data.restore_aging_summary.clone()
    }
}

impl From<NeuronSubsetMetrics> for NeuronSubsetMetricsPb {
    fn from(src: NeuronSubsetMetrics) -> NeuronSubsetMetricsPb {
        let NeuronSubsetMetrics {
            count,
            total_staked_e8s,
            total_staked_maturity_e8s_equivalent,
            total_maturity_e8s_equivalent,
            total_voting_power,
            total_deciding_voting_power,
            total_potential_voting_power,

            count_buckets,
            staked_e8s_buckets,
            staked_maturity_e8s_equivalent_buckets,
            maturity_e8s_equivalent_buckets,
            voting_power_buckets,
            deciding_voting_power_buckets,
            potential_voting_power_buckets,
        } = src;

        let count = Some(count);
        let total_staked_e8s = Some(total_staked_e8s);
        let total_staked_maturity_e8s_equivalent = Some(total_staked_maturity_e8s_equivalent);
        let total_maturity_e8s_equivalent = Some(total_maturity_e8s_equivalent);
        let total_voting_power = Some(total_voting_power);
        let total_deciding_voting_power = Some(total_deciding_voting_power);
        let total_potential_voting_power = Some(total_potential_voting_power);

        NeuronSubsetMetricsPb {
            count,
            total_staked_e8s,
            total_staked_maturity_e8s_equivalent,
            total_maturity_e8s_equivalent,
            total_voting_power,
            total_deciding_voting_power,
            total_potential_voting_power,

            count_buckets,
            staked_e8s_buckets,
            staked_maturity_e8s_equivalent_buckets,
            maturity_e8s_equivalent_buckets,
            voting_power_buckets,
            deciding_voting_power_buckets,
            potential_voting_power_buckets,
        }
    }
}

/// Does what the name says: calls the deploy_new_sns method on the sns-wasm canister.
///
/// Currently, Err is returned in the following cases:
///
///   * Fail to encode request. Not sure how this can happen. I guess if the input is too big, and
///     we run out of memory? If that's right, this won't happen if the input is not excessively
///     large.
///
///   * Fail to make call. This could be the result of sns-wasm being stopped, deleted, or something
///     like that. Currently, there is no intention to ever do those things (except during an
///     upgrade).
///
///   * Fail to decode reply. This would most likely result from sns-wasm sending a response that
///     lacks a required field (presumably, the result of a non-backwards compatible interface
///     change). It might be possible to avoid this case by upgrading governance. Ideally, upgrading
///     governance would have been done before sns-wasm was upgraded (that is, upgrading the client
///     before the server), but late is better than never.
///
///   * DeployNewSnsResponse.error is populated. See documentation for the deploy_new_sns Candid
///     method supplied by sns-wasm.
///
/// All of these are of type External.
///
/// If Ok is returned, it can be assumed that the error field is not populated.
async fn call_deploy_new_sns(
    env: &Arc<dyn Environment>,
    sns_init_payload: SnsInitPayload,
) -> Result<DeployNewSnsResponse, GovernanceError> {
    // Step 2.1: Construct request
    let request = DeployNewSnsRequest {
        sns_init_payload: Some(sns_init_payload),
    };
    let request = Encode!(&request).map_err(|err| {
        GovernanceError::new_with_message(
            ErrorType::External,
            format!(
                "Failed to encode request for deploy_new_sns Candid \
                     method call: {err}\nrequest: {request:#?}",
            ),
        )
    })?;

    // Step 2.2: Send the request and wait for reply..
    let deploy_new_sns_response = env
        .call_canister_method(SNS_WASM_CANISTER_ID, "deploy_new_sns", request)
        .await
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!("Failed to send deploy_new_sns request to SNS_WASM canister: {err:?}",),
            )
        })?;

    // Step 2.3; Decode the response.
    let deploy_new_sns_response =
        Decode!(&deploy_new_sns_response, DeployNewSnsResponse).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!("Failed to decode deploy_new_sns response: {err}"),
            )
        })?;

    // Step 2.4: Convert to Result (from DeployNewSnsResponse).
    match deploy_new_sns_response.error {
        Some(err) => Err(GovernanceError::new_with_message(
            ErrorType::External,
            format!("Error in deploy_new_sns response: {err:?}"),
        )),
        None => Ok(deploy_new_sns_response),
    }
}

fn validate_motion(motion: &Motion) -> Result<(), GovernanceError> {
    if motion.motion_text.len() > PROPOSAL_MOTION_TEXT_BYTES_MAX {
        return Err(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            format!(
                "The maximum motion text size in a proposal action is {} bytes, this motion text is: {} bytes",
                PROPOSAL_MOTION_TEXT_BYTES_MAX,
                motion.motion_text.len()
            ),
        ));
    }

    Ok(())
}

fn validate_account_identifier(
    account_identifier: &icp_ledger::protobuf::AccountIdentifier,
) -> Result<(), String> {
    if account_identifier.hash.len() != 32 {
        return Err(format!(
            "The account identifier must be 32 bytes long (so that it includes the checksum) but, this account identifier is: {} bytes",
            account_identifier.hash.len()
        ));
    }

    AccountIdentifier::try_from(account_identifier)
        .map_err(|e| format!("The account identifier is not valid: {e}"))?;

    Ok(())
}

/// Given a target_canister_id, is it a CanisterId of a deployed SNS recorded by
/// the SNS-W canister.
async fn is_canister_id_valid_swap_canister_id(
    target_canister_id: CanisterId,
    env: &dyn Environment,
) -> Result<(), String> {
    let list_deployed_snses_response = env
        .call_canister_method(
            SNS_WASM_CANISTER_ID,
            "list_deployed_snses",
            Encode!(&ListDeployedSnsesRequest {}).expect(""),
        )
        .await
        .map_err(|err| {
            format!(
                "Failed to call the list_deployed_snses method on sns_wasm ({SNS_WASM_CANISTER_ID}): {err:?}",
            )
        })?;

    let list_deployed_snses_response =
        Decode!(&list_deployed_snses_response, ListDeployedSnsesResponse).map_err(|err| {
            format!(
                "Unable to decode response as ListDeployedSnsesResponse: {err}. reply_bytes = {list_deployed_snses_response:#?}",
            )
        })?;

    let is_swap = list_deployed_snses_response
        .instances
        .iter()
        .any(|sns| sns.swap_canister_id == Some(target_canister_id.into()));
    if !is_swap {
        return Err(format!(
            "target_swap_canister_id is not the ID of any swap canister known to sns_wasm: {target_canister_id}"
        ));
    }

    Ok(())
}

/// Given the XDR amount that the given node provider should be rewarded, and a
/// conversion rate from XDR to ICP, returns the ICP amount and wallet address
/// that should be awarded on behalf of the given node provider.
///
/// The simple way to calculate this might be:
/// xdr_permyriad_reward / xdr_permyriad_per_icp
/// or more explicitly:
/// $reward_amount XDR / ( $rate XDR / 1 ICP)
/// ==
/// $reward_amount XDR * (1 ICP / $rate XDR)
/// ==
/// ($reward_amount / $rate) ICP
///
/// However this discards e8s. In order to account for e8s, we convert ICP to
/// e8s using `TOKEN_SUBDIVIDABLE_BY`:
/// $reward_amount XDR * (TOKEN_SUBDIVIDABLE_BY e8s / 1 ICP) * (1 ICP / $rate
/// XDR) ==
/// $reward_amount XDR * (TOKEN_SUBDIVIDABLE_BY e8s / $rate XDR)
/// ==
/// (($reward_amount * TOKEN_SUBDIVIDABLE_BY) / $rate) e8s
pub fn get_node_provider_reward(
    np: &NodeProvider,
    xdr_permyriad_reward: u64,
    xdr_permyriad_per_icp: u64,
) -> Option<RewardNodeProvider> {
    if let Some(np_id) = np.id.as_ref() {
        let amount_e8s = ((xdr_permyriad_reward as u128 * TOKEN_SUBDIVIDABLE_BY as u128)
            / xdr_permyriad_per_icp as u128) as u64;

        let to_account = Some(if let Some(account) = &np.reward_account {
            account.clone()
        } else {
            AccountIdentifier::from(*np_id).into()
        });

        Some(RewardNodeProvider {
            node_provider: Some(np.clone()),
            amount_e8s,
            reward_mode: Some(RewardMode::RewardToAccount(RewardToAccount { to_account })),
        })
    } else {
        None
    }
}

impl From<&ic_nervous_system_clients::canister_status::CanisterStatusResultV2>
    for swap_background_information::CanisterStatusResultV2
{
    fn from(src: &ic_nervous_system_clients::canister_status::CanisterStatusResultV2) -> Self {
        // Extract from src.
        let status = src.status();
        let module_hash = src.module_hash();
        let controllers = src.controllers();
        let memory_size = src.memory_size();
        let cycles = src.cycles();
        let freezing_threshold = src.freezing_threshold();
        let idle_cycles_burned_per_day = src.idle_cycles_burned_per_day();

        // Convert data extracted from src.
        let status = swap_background_information::CanisterStatusType::from(status);
        let module_hash = module_hash.unwrap_or_default();
        let cycles = u64::try_from(cycles).unwrap_or_else(|err| {
            println!(
                "{}WARNING: Unable to convert cycles to u64: {:?}",
                LOG_PREFIX, err,
            );
            u64::MAX
        });
        let idle_cycles_burned_per_day =
            u64::try_from(idle_cycles_burned_per_day).unwrap_or_else(|err| {
                println!(
                    "{}WARNING: Unable to convert idle_cycles_burned_per_day to u64: {:?}",
                    LOG_PREFIX, err,
                );
                u64::MAX
            });

        // Repackage into PB type.
        Self {
            status: Some(status as i32),
            module_hash,
            controllers,
            memory_size: Some(memory_size.get()),
            cycles: Some(cycles),
            freezing_threshold: Some(freezing_threshold),
            idle_cycles_burned_per_day: Some(idle_cycles_burned_per_day),
        }
    }
}

impl From<ic_nervous_system_clients::canister_status::CanisterStatusType>
    for swap_background_information::CanisterStatusType
{
    fn from(src: ic_nervous_system_clients::canister_status::CanisterStatusType) -> Self {
        use ic_nervous_system_clients::canister_status::CanisterStatusType as Src;

        match src {
            Src::Running => Self::Running,
            Src::Stopping => Self::Stopping,
            Src::Stopped => Self::Stopped,
        }
    }
}

fn record_known_neuron_abstentions(
    known_neuron_ids: &[NeuronId],
    proposal_id: ProposalId,
    ballots: HashMap<u64, Ballot>,
) {
    for known_neuron_id in known_neuron_ids {
        if let Some(ballot) = ballots.get(&known_neuron_id.id)
            && ballot.vote() == Vote::Unspecified
        {
            with_voting_history_store_mut(|voting_history_store| {
                voting_history_store.record_vote(*known_neuron_id, proposal_id, Vote::Unspecified);
            });
        }
    }
}
/// Affects the perception of time by users of CanisterEnv (i.e. Governance).
///
/// Specifically, the time that Governance sees is the real time + delta.
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug, candid::CandidType, serde::Deserialize)]
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

fn modify_followees(
    neuron_store: &NeuronStore,
    neuron: &Neuron,
    topic_to_followees: &HashMap<i32, Followees>,
    topic: i32,
    new_followees: Followees,
) -> Result<HashMap<i32, Followees>, GovernanceError> {
    let controller = neuron.controller();
    let mut updated_followees = topic_to_followees.clone();
    if new_followees.followees.is_empty() {
        // If the new followees list is empty, remove the entry for the topic.
        updated_followees.remove(&topic);
        return Ok(updated_followees);
    }

    if !is_neuron_follow_restrictions_enabled() {
        // If the neuron follow restrictions are not enabled, we can directly update the entry.
        updated_followees.insert(topic, new_followees);
        return Ok(updated_followees);
    }

    if topic == Topic::NeuronManagement as i32 {
        // Neuron management followees are not subject to the follow restrictions.
        // This exception doesn't expose any security issue, as it doesn't reveal
        // any ballots regardging non-neuron-management proposals of the followees.
        updated_followees.insert(topic, new_followees);
        return Ok(updated_followees);
    }

    // Otherwise, update the entry with the new followees list.
    // A new can follow another neuron if:
    // 1. the followee neuron is a public neuron
    // 2. or if the followee neuron is a private neuron, either
    //      * they share a controller or
    //      * the controller of the follower neuron is in the hot keys of the followee neuron.
    // If in the list of followees, there are any follow relationships
    // that don't adhere to the aforementioned rules, return a GovernanceError
    // including all the invalid followees.
    let mut invalid_followees = 0_u32;
    let mut error_message = String::new();

    // To avoid looking up the already existing followees of the neuron
    // (which are not changing) we only validate the new followees.
    let old_followees = topic_to_followees
        .get(&topic)
        .map(|f| f.followees.iter().collect::<HashSet<&NeuronId>>())
        .unwrap_or_default();

    for followee in &new_followees.followees {
        if old_followees.contains(followee) {
            // An already existing follow relationship is either
            // grandfathered in, or it was already validated when it was created.
            // Hence, we don't need to validate it again.
            continue;
        }

        if let Ok((followee_visibility, followee_controller, followee_hot_keys)) = neuron_store
            .with_neuron(followee, |neuron| {
                (
                    neuron.visibility(),
                    neuron.controller(),
                    neuron.hot_keys.clone(),
                )
            })
        {
            let allowed_to_follow = followee_visibility == Visibility::Public
                || followee_controller == controller
                || followee_hot_keys.contains(&controller);

            if !allowed_to_follow {
                invalid_followees = invalid_followees.saturating_add(1);
                error_message.push_str(&format!(
                                "{}: Neuron {} is a private neuron.\n\
                                If you control neuron {}, you can follow it after adding your principal {} to its list of hotkeys or setting the neuron to public.",
                                invalid_followees,
                                followee.id,
                                followee.id,
                                controller
                            ));
            }
        } else {
            invalid_followees = invalid_followees.saturating_add(1);
            error_message.push_str(&format!(
                            "{}: The neuron with ID {} does not exist. Make sure that you copied the neuron ID correctly.\n",
                            invalid_followees,
                            followee.id
                        ));
        }
    }

    if invalid_followees > 0 {
        // Note: These error messages are matched in the nns-dapp. In case of changes, please sync with the nns dev team.
        error_message = format!(
            "The {} followee(s) listed below is(are) invalid:\n{}",
            invalid_followees, error_message
        );

        return Err(GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            error_message,
        ));
    }

    updated_followees.insert(topic, new_followees);

    Ok(updated_followees)
}
