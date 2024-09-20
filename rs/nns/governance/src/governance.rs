use crate::{
    are_set_visibility_proposals_enabled, decoder_config,
    governance::{
        merge_neurons::{
            build_merge_neurons_response, calculate_merge_neurons_effect,
            validate_merge_neurons_before_commit,
        },
        split_neuron::{calculate_split_neuron_effect, SplitNeuronEffect},
    },
    heap_governance_data::{
        reassemble_governance_proto, split_governance_proto, HeapGovernanceData, XdrConversionRate,
    },
    migrations::maybe_run_migrations,
    neuron::{DissolveStateAndAge, Neuron, NeuronBuilder},
    neuron_data_validation::{NeuronDataValidationSummary, NeuronDataValidator},
    neuron_store::{metrics::NeuronSubsetMetrics, NeuronMetrics, NeuronStore},
    neurons_fund::{
        NeuronsFund, NeuronsFundNeuronPortion, NeuronsFundSnapshot,
        PolynomialNeuronsFundParticipation, SwapParticipationLimits,
    },
    node_provider_rewards::{
        latest_node_provider_rewards, list_node_provider_rewards, record_node_provider_rewards,
        DateRangeFilter,
    },
    pb::v1::{
        add_or_remove_node_provider::Change,
        archived_monthly_node_provider_rewards,
        create_service_nervous_system::LedgerParameters,
        get_neurons_fund_audit_info_response,
        governance::{
            governance_cached_metrics::NeuronSubsetMetrics as NeuronSubsetMetricsPb,
            neuron_in_flight_command::{Command as InFlightCommand, SyncCommand},
            GovernanceCachedMetrics, NeuronInFlightCommand,
        },
        governance_error::ErrorType,
        manage_neuron,
        manage_neuron::{
            claim_or_refresh::{By, MemoAndController},
            ClaimOrRefresh, Command, NeuronIdOrSubaccount,
        },
        manage_neuron_response,
        manage_neuron_response::{MergeMaturityResponse, StakeMaturityResponse},
        neuron::Followees,
        neurons_fund_snapshot::NeuronsFundNeuronPortion as NeuronsFundNeuronPortionPb,
        proposal,
        proposal::Action,
        reward_node_provider::{RewardMode, RewardToAccount},
        settle_neurons_fund_participation_request, settle_neurons_fund_participation_response,
        settle_neurons_fund_participation_response::NeuronsFundNeuron as NeuronsFundNeuronPb,
        swap_background_information, ArchivedMonthlyNodeProviderRewards, Ballot,
        CreateServiceNervousSystem, ExecuteNnsFunction, GetNeuronsFundAuditInfoRequest,
        GetNeuronsFundAuditInfoResponse, Governance as GovernanceProto, GovernanceError,
        InstallCode, KnownNeuron, ListKnownNeuronsResponse, ListNeurons, ListNeuronsResponse,
        ListProposalInfo, ListProposalInfoResponse, ManageNeuron, ManageNeuronResponse,
        MonthlyNodeProviderRewards, Motion, NetworkEconomics, Neuron as NeuronProto, NeuronInfo,
        NeuronState, NeuronsFundAuditInfo, NeuronsFundData,
        NeuronsFundEconomics as NeuronsFundNetworkEconomicsPb,
        NeuronsFundParticipation as NeuronsFundParticipationPb,
        NeuronsFundSnapshot as NeuronsFundSnapshotPb, NnsFunction, NodeProvider, Proposal,
        ProposalData, ProposalInfo, ProposalRewardStatus, ProposalStatus, RestoreAgingSummary,
        RewardEvent, RewardNodeProvider, RewardNodeProviders,
        SettleNeuronsFundParticipationRequest, SettleNeuronsFundParticipationResponse,
        StopOrStartCanister, Tally, Topic, UpdateCanisterSettings, UpdateNodeProvider, Visibility,
        Vote, WaitForQuietState, XdrConversionRate as XdrConversionRatePb,
    },
    proposals::call_canister::CallCanister,
};
use async_trait::async_trait;
use candid::{Decode, Encode};
use cycles_minting_canister::{IcpXdrConversionRate, IcpXdrConversionRateCertifiedResponse};
use dfn_core::api::spawn;
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use dfn_protobuf::ToProto;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::{
    cmc::CMC, ledger, ledger::IcpLedger, NervousSystemError, ONE_DAY_SECONDS, ONE_MONTH_SECONDS,
    ONE_YEAR_SECONDS,
};
use ic_nervous_system_governance::maturity_modulation::apply_maturity_modulation;
use ic_nervous_system_proto::pb::v1::{GlobalTimeOfDay, Principals};
use ic_nns_common::{
    pb::v1::{NeuronId, ProposalId},
    types::UpdateIcpXdrConversionRatePayload,
};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID,
    LIFELINE_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
    SUBNET_RENTAL_CANISTER_ID,
};
use ic_nns_governance_api::{
    pb::v1::CreateServiceNervousSystem as ApiCreateServiceNervousSystem, proposal_validation,
    subnet_rental::SubnetRentalRequest,
};
use ic_protobuf::registry::dc::v1::AddOrRemoveDataCentersProposalPayload;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_swap::pb::v1::{self as sns_swap_pb, Lifecycle, NeuronsFundParticipationConstraints};
use ic_sns_wasm::pb::v1::{
    DeployNewSnsRequest, DeployNewSnsResponse, ListDeployedSnsesRequest, ListDeployedSnsesResponse,
};
use ic_stable_structures::{storable::Bound, Storable};
use icp_ledger::{
    AccountIdentifier, Subaccount, Tokens, DEFAULT_TRANSFER_FEE, TOKEN_SUBDIVIDABLE_BY,
};
use itertools::Itertools;
use maplit::hashmap;
use mockall::automock;
use registry_canister::{
    mutations::do_add_node_operator::AddNodeOperatorPayload, pb::v1::NodeProvidersMonthlyXdrRewards,
};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::{
    borrow::Cow,
    cmp::{max, Ordering},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    convert::{TryFrom, TryInto},
    fmt,
    ops::RangeInclusive,
    string::ToString,
};

mod ledger_helper;
mod merge_neurons;
mod split_neuron;
pub mod test_data;
#[cfg(test)]
mod tests;

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

// The maximum dissolve delay allowed for a neuron.
pub const MAX_DISSOLVE_DELAY_SECONDS: u64 = 8 * ONE_YEAR_SECONDS;

// The age of a neuron that saturates the age bonus for the voting power
// computation.
pub const MAX_NEURON_AGE_FOR_AGE_BONUS: u64 = 4 * ONE_YEAR_SECONDS;

/// The minimum dissolve delay so that a neuron may vote.
pub const MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS: u64 = 6 * ONE_MONTH_SECONDS;

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
pub const MAX_NUMBER_OF_NEURONS: usize = 350_000;

/// The maximum number results returned by the method `list_proposals`.
pub const MAX_LIST_PROPOSAL_RESULTS: u32 = 100;

const MAX_LIST_NODE_PROVIDER_REWARDS_RESULTS: usize = 24;

/// The number of e8s per ICP;
const E8S_PER_ICP: u64 = TOKEN_SUBDIVIDABLE_BY;

/// The max number of unsettled proposals -- that is proposals for which ballots
/// are still stored.
pub const MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS: usize = 200;

/// The max number of open manage neuron proposals.
pub const MAX_NUMBER_OF_OPEN_MANAGE_NEURON_PROPOSALS: usize = 100000;

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

/// Max character length for a neuron's name, in KnownNeuronData.
pub const KNOWN_NEURON_NAME_MAX_LEN: usize = 200;

/// Max character length for the field "description" in KnownNeuronData.
pub const KNOWN_NEURON_DESCRIPTION_MAX_LEN: usize = 3000;

/// The number of seconds between automated Node Provider reward events
/// Currently 1/12 of a year: 2629800 = 86400 * 365.25 / 12
const NODE_PROVIDER_REWARD_PERIOD_SECONDS: u64 = 2629800;

const VALID_MATURITY_MODULATION_BASIS_POINTS_RANGE: RangeInclusive<i32> = -500..=500;

/// Maximum allowed number of Neurons' Fund participants that may participate in an SNS swap.
/// Given the maximum number of SNS neurons per swap participant (a.k.a. neuron basket count),
/// this constant can be used to obtain an upper bound for the number of SNS neurons created
/// for the Neurons' Fund participants. See also `MAX_SNS_NEURONS_PER_BASKET`.
pub const MAX_NEURONS_FUND_PARTICIPANTS: u64 = 5_000;

impl NetworkEconomics {
    /// The multiplier applied to minimum_icp_xdr_rate to convert the XDR unit to basis_points
    pub const ICP_XDR_RATE_TO_BASIS_POINT_MULTIPLIER: u64 = 100;

    // The default values for network economics (until we initialize it).
    // Can't implement Default since it conflicts with Prost's.
    pub fn with_default_values() -> Self {
        Self {
            reject_cost_e8s: E8S_PER_ICP,                               // 1 ICP
            neuron_management_fee_per_proposal_e8s: 1_000_000,          // 0.01 ICP
            neuron_minimum_stake_e8s: E8S_PER_ICP,                      // 1 ICP
            neuron_spawn_dissolve_delay_seconds: ONE_DAY_SECONDS * 7,   // 7 days
            maximum_node_provider_rewards_e8s: 1_000_000 * 100_000_000, // 1M ICP
            minimum_icp_xdr_rate: 100,                                  // 1 XDR
            transaction_fee_e8s: DEFAULT_TRANSFER_FEE.get_e8s(),
            max_proposals_to_keep_per_topic: 100,
            neurons_fund_economics: Some(NeuronsFundNetworkEconomicsPb::with_default_values()),
        }
    }
}

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
    fn eligible_for_rewards(&self) -> bool {
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

    // TODO(NNS1-3228): Delete this.
    fn is_set_visibility(&self) -> bool {
        let Some(Command::Configure(ref configure)) = self.command else {
            return false;
        };

        matches!(
            configure.operation,
            Some(manage_neuron::configure::Operation::SetVisibility(_)),
        )
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

impl NnsFunction {
    /// Returns whether proposals where the action is such an NnsFunction should
    /// be allowed to be submitted when the heap growth potential is low.
    fn allowed_when_resources_are_low(&self) -> bool {
        matches!(
            self,
            NnsFunction::NnsRootUpgrade
                | NnsFunction::NnsCanisterUpgrade
                | NnsFunction::HardResetNnsRootToVersion
                | NnsFunction::ReviseElectedGuestosVersions
                | NnsFunction::DeployGuestosToAllSubnetNodes
        )
    }

    fn can_have_large_payload(&self) -> bool {
        matches!(
            self,
            NnsFunction::NnsCanisterUpgrade
                | NnsFunction::NnsCanisterInstall
                | NnsFunction::NnsRootUpgrade
                | NnsFunction::HardResetNnsRootToVersion
                | NnsFunction::AddSnsWasm
        )
    }

    fn is_obsolete(&self) -> bool {
        matches!(
            self,
            NnsFunction::UpdateAllowedPrincipals
                | NnsFunction::UpdateApiBoundaryNodesVersion
                | NnsFunction::UpdateUnassignedNodesConfig
                | NnsFunction::UpdateElectedHostosVersions
                | NnsFunction::UpdateNodesHostosVersion
                | NnsFunction::BlessReplicaVersion
                | NnsFunction::RetireReplicaVersion
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

    pub fn panic_if_error(self, msg: &str) -> Self {
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

    pub fn spawn_response(created_neuron_id: NeuronId) -> Self {
        let created_neuron_id = Some(created_neuron_id);
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Spawn(
                manage_neuron_response::SpawnResponse { created_neuron_id },
            )),
        }
    }

    pub fn merge_maturity_response(response: MergeMaturityResponse) -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::MergeMaturity(response)),
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

    pub fn make_proposal_response(proposal_id: ProposalId, message: String) -> Self {
        let proposal_id = Some(proposal_id);
        let message = Some(message);
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::MakeProposal(
                manage_neuron_response::MakeProposalResponse {
                    proposal_id,
                    message,
                },
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

    pub fn merge_response(merge_response: manage_neuron_response::MergeResponse) -> Self {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Merge(merge_response)),
        }
    }

    pub fn disburse_to_neuron_response(created_neuron_id: NeuronId) -> Self {
        let created_neuron_id = Some(created_neuron_id);
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::DisburseToNeuron(
                manage_neuron_response::DisburseToNeuronResponse { created_neuron_id },
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

impl NnsFunction {
    pub fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        let (canister_id, method) = match self {
            NnsFunction::Unspecified => {
                return Err(GovernanceError::new(ErrorType::PreconditionFailed));
            }
            NnsFunction::AssignNoid => (REGISTRY_CANISTER_ID, "add_node_operator"),

            NnsFunction::CreateSubnet => (REGISTRY_CANISTER_ID, "create_subnet"),
            NnsFunction::AddNodeToSubnet => (REGISTRY_CANISTER_ID, "add_nodes_to_subnet"),
            NnsFunction::RemoveNodesFromSubnet => {
                (REGISTRY_CANISTER_ID, "remove_nodes_from_subnet")
            }
            NnsFunction::ChangeSubnetMembership => {
                (REGISTRY_CANISTER_ID, "change_subnet_membership")
            }
            NnsFunction::NnsCanisterInstall => (ROOT_CANISTER_ID, "add_nns_canister"),
            NnsFunction::NnsCanisterUpgrade => (ROOT_CANISTER_ID, "change_nns_canister"),
            NnsFunction::NnsRootUpgrade => (LIFELINE_CANISTER_ID, "upgrade_root"),
            NnsFunction::HardResetNnsRootToVersion => {
                (LIFELINE_CANISTER_ID, "hard_reset_root_to_version")
            }
            NnsFunction::RecoverSubnet => (REGISTRY_CANISTER_ID, "recover_subnet"),
            NnsFunction::ReviseElectedGuestosVersions => {
                (REGISTRY_CANISTER_ID, "revise_elected_guestos_versions")
            }
            NnsFunction::UpdateNodeOperatorConfig => {
                (REGISTRY_CANISTER_ID, "update_node_operator_config")
            }
            NnsFunction::DeployGuestosToAllSubnetNodes => {
                (REGISTRY_CANISTER_ID, "deploy_guestos_to_all_subnet_nodes")
            }
            NnsFunction::UpdateElectedHostosVersions => {
                return Err(GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    format!(
                        "{:?} is an obsolete NnsFunction. Use ReviseElectedHostosVersions instead",
                        self
                    ),
                ));
            }
            NnsFunction::UpdateNodesHostosVersion => {
                return Err(GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    format!(
                        "{:?} is an obsolete NnsFunction. Use DeployHostosToSomeNodes instead",
                        self
                    ),
                ));
            }
            NnsFunction::ReviseElectedHostosVersions => {
                (REGISTRY_CANISTER_ID, "revise_elected_hostos_versions")
            }
            NnsFunction::DeployHostosToSomeNodes => {
                (REGISTRY_CANISTER_ID, "deploy_hostos_to_some_nodes")
            }
            NnsFunction::UpdateConfigOfSubnet => (REGISTRY_CANISTER_ID, "update_subnet"),
            NnsFunction::IcpXdrConversionRate => {
                (CYCLES_MINTING_CANISTER_ID, "set_icp_xdr_conversion_rate")
            }
            NnsFunction::ClearProvisionalWhitelist => {
                (REGISTRY_CANISTER_ID, "clear_provisional_whitelist")
            }
            NnsFunction::SetAuthorizedSubnetworks => {
                (CYCLES_MINTING_CANISTER_ID, "set_authorized_subnetwork_list")
            }
            NnsFunction::SetFirewallConfig => (REGISTRY_CANISTER_ID, "set_firewall_config"),
            NnsFunction::AddFirewallRules => (REGISTRY_CANISTER_ID, "add_firewall_rules"),
            NnsFunction::RemoveFirewallRules => (REGISTRY_CANISTER_ID, "remove_firewall_rules"),
            NnsFunction::UpdateFirewallRules => (REGISTRY_CANISTER_ID, "update_firewall_rules"),
            NnsFunction::StopOrStartNnsCanister => (ROOT_CANISTER_ID, "stop_or_start_nns_canister"),
            NnsFunction::RemoveNodes => (REGISTRY_CANISTER_ID, "remove_nodes"),
            NnsFunction::UninstallCode => (CanisterId::ic_00(), "uninstall_code"),
            NnsFunction::UpdateNodeRewardsTable => {
                (REGISTRY_CANISTER_ID, "update_node_rewards_table")
            }
            NnsFunction::AddOrRemoveDataCenters => {
                (REGISTRY_CANISTER_ID, "add_or_remove_data_centers")
            }
            NnsFunction::UpdateUnassignedNodesConfig => {
                (REGISTRY_CANISTER_ID, "update_unassigned_nodes_config")
            }
            NnsFunction::RemoveNodeOperators => (REGISTRY_CANISTER_ID, "remove_node_operators"),
            NnsFunction::RerouteCanisterRanges => (REGISTRY_CANISTER_ID, "reroute_canister_ranges"),
            NnsFunction::PrepareCanisterMigration => {
                (REGISTRY_CANISTER_ID, "prepare_canister_migration")
            }
            NnsFunction::CompleteCanisterMigration => {
                (REGISTRY_CANISTER_ID, "complete_canister_migration")
            }
            NnsFunction::AddSnsWasm => (SNS_WASM_CANISTER_ID, "add_wasm"),
            NnsFunction::UpdateSubnetType => (CYCLES_MINTING_CANISTER_ID, "update_subnet_type"),
            NnsFunction::ChangeSubnetTypeAssignment => {
                (CYCLES_MINTING_CANISTER_ID, "change_subnet_type_assignment")
            }
            NnsFunction::UpdateSnsWasmSnsSubnetIds => {
                (SNS_WASM_CANISTER_ID, "update_sns_subnet_list")
            }
            NnsFunction::InsertSnsWasmUpgradePathEntries => {
                (SNS_WASM_CANISTER_ID, "insert_upgrade_path_entries")
            }
            NnsFunction::BitcoinSetConfig => (ROOT_CANISTER_ID, "call_canister"),
            NnsFunction::BlessReplicaVersion
            | NnsFunction::RetireReplicaVersion
            | NnsFunction::UpdateAllowedPrincipals => {
                return Err(GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    format!(
                        "{:?} is an obsolete NnsFunction. Use ReviseElectedGuestosVersions instead",
                        self
                    ),
                ));
            }
            NnsFunction::AddApiBoundaryNodes => (REGISTRY_CANISTER_ID, "add_api_boundary_nodes"),
            NnsFunction::RemoveApiBoundaryNodes => {
                (REGISTRY_CANISTER_ID, "remove_api_boundary_nodes")
            }
            NnsFunction::UpdateApiBoundaryNodesVersion => {
                return Err(GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    format!(
                        "{:?} is an obsolete NnsFunction. Use DeployGuestosToSomeApiBoundaryNodes \
                        instead",
                        self
                    ),
                ));
            }
            NnsFunction::DeployGuestosToSomeApiBoundaryNodes => (
                REGISTRY_CANISTER_ID,
                "deploy_guestos_to_some_api_boundary_nodes",
            ),
            NnsFunction::DeployGuestosToAllUnassignedNodes => (
                REGISTRY_CANISTER_ID,
                "deploy_guestos_to_all_unassigned_nodes",
            ),
            NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => (
                REGISTRY_CANISTER_ID,
                "update_ssh_readonly_access_for_all_unassigned_nodes",
            ),
            NnsFunction::SubnetRentalRequest => {
                (SUBNET_RENTAL_CANISTER_ID, "execute_rental_request_proposal")
            }
        };
        Ok((canister_id, method))
    }
}

impl Proposal {
    /// Whether this proposal is restricted, that is, whether neuron voting
    /// eligibility depends on the content of this proposal.
    pub fn is_manage_neuron(&self) -> bool {
        self.topic() == Topic::NeuronManagement
    }

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

    /// Compute the topic that a given proposal belongs to. The topic
    /// of a proposal governs what followers that are taken into
    /// account when the proposal is voted on.
    pub(crate) fn topic(&self) -> Topic {
        if let Some(action) = &self.action {
            match action {
                Action::ManageNeuron(_) => Topic::NeuronManagement,
                Action::ManageNetworkEconomics(_) => Topic::NetworkEconomics,
                Action::Motion(_) => Topic::Governance,
                Action::ApproveGenesisKyc(_) => Topic::Kyc,
                Action::ExecuteNnsFunction(m) => {
                    if let Ok(mt) = NnsFunction::try_from(m.nns_function) {
                        match mt {
                            NnsFunction::Unspecified => {
                                println!("{}ERROR: NnsFunction::Unspecified", LOG_PREFIX);
                                Topic::Unspecified
                            }

                            NnsFunction::AssignNoid
                            | NnsFunction::UpdateNodeOperatorConfig
                            | NnsFunction::RemoveNodeOperators
                            | NnsFunction::RemoveNodes
                            | NnsFunction::UpdateUnassignedNodesConfig
                            | NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => {
                                Topic::NodeAdmin
                            }
                            NnsFunction::CreateSubnet
                            | NnsFunction::AddNodeToSubnet
                            | NnsFunction::RecoverSubnet
                            | NnsFunction::RemoveNodesFromSubnet
                            | NnsFunction::ChangeSubnetMembership
                            | NnsFunction::UpdateConfigOfSubnet => Topic::SubnetManagement,
                            NnsFunction::ReviseElectedGuestosVersions
                            | NnsFunction::ReviseElectedHostosVersions => {
                                Topic::IcOsVersionElection
                            }
                            NnsFunction::DeployHostosToSomeNodes
                            | NnsFunction::DeployGuestosToAllSubnetNodes
                            | NnsFunction::DeployGuestosToSomeApiBoundaryNodes
                            | NnsFunction::DeployGuestosToAllUnassignedNodes => {
                                Topic::IcOsVersionDeployment
                            }
                            NnsFunction::NnsCanisterUpgrade
                            | NnsFunction::NnsRootUpgrade
                            | NnsFunction::StopOrStartNnsCanister => {
                                Topic::NetworkCanisterManagement
                            }
                            NnsFunction::IcpXdrConversionRate => Topic::ExchangeRate,
                            NnsFunction::ClearProvisionalWhitelist => Topic::NetworkEconomics,
                            NnsFunction::SetAuthorizedSubnetworks => Topic::SubnetManagement,
                            NnsFunction::SetFirewallConfig => Topic::SubnetManagement,
                            NnsFunction::AddFirewallRules => Topic::SubnetManagement,
                            NnsFunction::RemoveFirewallRules => Topic::SubnetManagement,
                            NnsFunction::UpdateFirewallRules => Topic::SubnetManagement,
                            NnsFunction::UninstallCode => Topic::Governance,
                            NnsFunction::UpdateNodeRewardsTable => Topic::NetworkEconomics,
                            NnsFunction::AddOrRemoveDataCenters => Topic::ParticipantManagement,
                            NnsFunction::RerouteCanisterRanges => Topic::SubnetManagement,
                            NnsFunction::PrepareCanisterMigration => Topic::SubnetManagement,
                            NnsFunction::CompleteCanisterMigration => Topic::SubnetManagement,
                            NnsFunction::UpdateSubnetType => Topic::SubnetManagement,
                            NnsFunction::ChangeSubnetTypeAssignment => Topic::SubnetManagement,
                            NnsFunction::UpdateSnsWasmSnsSubnetIds => Topic::SubnetManagement,
                            // Retired NnsFunctions
                            NnsFunction::UpdateAllowedPrincipals => Topic::SnsAndCommunityFund,
                            NnsFunction::UpdateNodesHostosVersion
                            | NnsFunction::UpdateElectedHostosVersions => Topic::NodeAdmin,
                            NnsFunction::BlessReplicaVersion
                            | NnsFunction::RetireReplicaVersion => Topic::IcOsVersionElection,
                            NnsFunction::AddApiBoundaryNodes
                            | NnsFunction::RemoveApiBoundaryNodes
                            | NnsFunction::UpdateApiBoundaryNodesVersion => {
                                Topic::ApiBoundaryNodeManagement
                            }
                            NnsFunction::SubnetRentalRequest => Topic::SubnetRental,
                            NnsFunction::NnsCanisterInstall
                            | NnsFunction::HardResetNnsRootToVersion
                            | NnsFunction::BitcoinSetConfig => Topic::ProtocolCanisterManagement,
                            NnsFunction::AddSnsWasm
                            | NnsFunction::InsertSnsWasmUpgradePathEntries => {
                                Topic::ServiceNervousSystemManagement
                            }
                        }
                    } else {
                        println!(
                            "{}ERROR: Unknown NnsFunction: {}",
                            LOG_PREFIX, m.nns_function
                        );
                        Topic::Unspecified
                    }
                }
                Action::AddOrRemoveNodeProvider(_) => Topic::ParticipantManagement,
                Action::RewardNodeProvider(_) | Action::RewardNodeProviders(_) => {
                    Topic::NodeProviderRewards
                }
                Action::SetDefaultFollowees(_) | Action::RegisterKnownNeuron(_) => {
                    Topic::Governance
                }
                Action::SetSnsTokenSwapOpenTimeWindow(_)
                | Action::OpenSnsTokenSwap(_)
                | Action::CreateServiceNervousSystem(_) => Topic::SnsAndCommunityFund,
                Action::InstallCode(install_code) => {
                    // There should be a valid topic since the validation should be done when the
                    // proposal is created. We avoid panicking here since `topic()` is called in a
                    // lot of places.
                    install_code.valid_topic().unwrap_or(Topic::Unspecified)
                }
                Action::StopOrStartCanister(stop_or_start) => {
                    // There should be a valid topic since the validation should be done when the
                    // proposal is created. We avoid panicking here since `topic()` is called in a
                    // lot of places.
                    stop_or_start.valid_topic().unwrap_or(Topic::Unspecified)
                }
                Action::UpdateCanisterSettings(update_canister_settings) => {
                    // There should be a valid topic since the validation should be done when the
                    // proposal is created. We avoid panicking here since `topic()` is called in a
                    // lot of places.
                    update_canister_settings
                        .valid_topic()
                        .unwrap_or(Topic::Unspecified)
                }
            }
        } else {
            println!("{}ERROR: No action -> no topic.", LOG_PREFIX);
            Topic::Unspecified
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
                return format!("{}-{}", action_name, nns_function_name);
            }
            action_name.to_string()
        } else {
            println!("{}ERROR: No action -> no action type.", LOG_PREFIX);
            "NO_ACTION".to_string()
        }
    }

    /// Returns whether such a proposal should be allowed to
    /// be submitted when the heap growth potential is low.
    fn allowed_when_resources_are_low(&self) -> bool {
        self.action
            .as_ref()
            .map_or(false, |a| a.allowed_when_resources_are_low())
    }

    fn omit_large_fields(self) -> Self {
        Proposal {
            action: self.action.map(|action| action.omit_large_fields()),
            ..self
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
            Action::SetSnsTokenSwapOpenTimeWindow(_) => {
                "ACTION_SET_SNS_TOKEN_SWAP_OPEN_TIME_WINDOW"
            }
            Action::OpenSnsTokenSwap(_) => "ACTION_OPEN_SNS_TOKEN_SWAP",
            Action::CreateServiceNervousSystem(_) => "ACTION_CREATE_SERVICE_NERVOUS_SYSTEM",
            Action::ExecuteNnsFunction(_) => "ACTION_EXECUTE_NNS_FUNCTION",
            Action::InstallCode(_) => "ACTION_CHANGE_CANISTER",
            Action::StopOrStartCanister(_) => "ACTION_STOP_OR_START_CANISTER",
            Action::UpdateCanisterSettings(_) => "ACTION_UPDATE_CANISTER_SETTINGS",
        }
    }

    /// Returns whether proposals with such an action should be allowed to
    /// be submitted when the heap growth potential is low.
    fn allowed_when_resources_are_low(&self) -> bool {
        match &self {
            Action::ExecuteNnsFunction(update) => {
                match NnsFunction::try_from(update.nns_function).ok() {
                    Some(f) => f.allowed_when_resources_are_low(),
                    None => false,
                }
            }
            Action::InstallCode(install_code) => install_code.allowed_when_resources_are_low(),
            Action::UpdateCanisterSettings(update_canister_settings) => {
                update_canister_settings.allowed_when_resources_are_low()
            }
            _ => false,
        }
    }

    fn omit_large_fields(self) -> Self {
        match self {
            Action::CreateServiceNervousSystem(create_service_nervous_system) => {
                Action::CreateServiceNervousSystem(CreateServiceNervousSystem {
                    ledger_parameters: create_service_nervous_system.ledger_parameters.map(
                        |ledger_parameters| LedgerParameters {
                            token_logo: None,
                            ..ledger_parameters
                        },
                    ),
                    logo: None,
                    ..create_service_nervous_system
                })
            }
            Action::ExecuteNnsFunction(mut execute_nns_function) => {
                if execute_nns_function.payload.len()
                    > EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX
                {
                    execute_nns_function.payload.clear();
                }
                Action::ExecuteNnsFunction(execute_nns_function)
            }
            action => action,
        }
    }
}

impl ProposalData {
    pub fn topic(&self) -> Topic {
        if let Some(proposal) = &self.proposal {
            proposal.topic()
        } else {
            println!(
                "{}ERROR: ProposalData has no proposal! {:#?}",
                LOG_PREFIX, self
            );
            Topic::Unspecified
        }
    }

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
        self.proposal
            .as_ref()
            .map_or(false, Proposal::is_manage_neuron)
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
        let deciding_amount_no = (new_tally.total + 1) / 2;
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
        if let Some(old_tally) = self.latest_tally.clone() {
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
            let expired = !self.accepts_vote(now_seconds, voting_period_seconds);
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

impl ProposalInfo {
    fn omit_large_fields(self) -> Self {
        ProposalInfo {
            proposal: self.proposal.map(|proposal| proposal.omit_large_fields()),
            ..self
        }
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
    fn reward_weight(&self) -> f64 {
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
    fn to_bytes(&self) -> Cow<[u8]> {
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

/// A general trait for the environment in which governance is running.
#[automock]
#[async_trait]
pub trait Environment: Send + Sync {
    /// Returns the current time, in seconds since the epoch.
    fn now(&self) -> u64;

    fn set_time_warp(&mut self, _new_time_warp: TimeWarp) {
        panic!("Not implemented.");
    }

    /// Returns a random number.
    ///
    /// This number is the same in all replicas.
    fn random_u64(&mut self) -> u64;

    /// Returns a random byte array with 32 bytes.
    ///
    /// This number is the same in all replicas.
    fn random_byte_array(&mut self) -> [u8; 32];

    /// Executes a `ExecuteNnsFunction`. The standard implementation is
    /// expected to call out to another canister and eventually report the
    /// result back
    ///
    /// See also call_candid_method.
    fn execute_nns_function(
        &self,
        proposal_id: u64,
        update: &ExecuteNnsFunction,
    ) -> Result<(), GovernanceError>;

    /// Returns rough information as to how much the heap can grow.
    ///
    /// The intended use case is for the governance canister to avoid
    /// non-essential memory-consuming operations when the potential for heap
    /// growth becomes limited.
    fn heap_growth_potential(&self) -> HeapGrowthPotential;

    /// Basically, the same as dfn_core::api::call.
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

/// A single ongoing update for a single neuron.
/// Releases the lock when destroyed.
struct LedgerUpdateLock {
    nid: u64,
    gov: *mut Governance,
    // Retain this lock even on drop.
    retain: bool,
}

impl Drop for LedgerUpdateLock {
    fn drop(&mut self) {
        if self.retain {
            return;
        }
        // It's always ok to dereference the governance when a LedgerUpdateLock
        // goes out of scope. Indeed, in the scope of any Governance method,
        // &self always remains alive. The 'mut' is not an issue, because
        // 'unlock_neuron' will verify that the lock exists.
        //
        // See "Recommendations for Using `unsafe` in the Governance canister" in canister.rs
        let gov: &mut Governance = unsafe { &mut *self.gov };
        gov.unlock_neuron(self.nid);
    }
}

impl LedgerUpdateLock {
    fn retain(&mut self) {
        self.retain = true;
    }
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
    pub env: Box<dyn Environment>,

    /// Implementation of the interface with the Ledger canister.
    ledger: Box<dyn IcpLedger>,

    /// Implementation of the interface with the CMC canister.
    cmc: Box<dyn CMC>,

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

    /// Scope guard for minting node provider rewards.
    minting_node_provider_rewards: bool,
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

impl XdrConversionRatePb {
    /// This constructor should be used only at canister creation, and not, e.g., after upgrades.
    /// The reason this function exists is because `Default::default` is already defined by prost.
    /// However, the Governance canister relies on the fields of this structure being `Some`.
    pub fn with_default_values() -> Self {
        Self {
            timestamp_seconds: Some(0),
            xdr_permyriad_per_icp: Some(10_000),
        }
    }
}

impl Governance {
    /// Initializes Governance for the first time from init payload. When restoring after an upgrade
    /// with its persisted state, `Governance::new_restored` should be called instead.
    pub fn new(
        mut governance_proto: GovernanceProto,
        env: Box<dyn Environment>,
        ledger: Box<dyn IcpLedger>,
        cmc: Box<dyn CMC>,
    ) -> Self {
        // Step 1: Populate some fields governance_proto if they are blank.

        // Step 1.1: genesis_timestamp_seconds. 0 indicates it hasn't been set already.
        if governance_proto.genesis_timestamp_seconds == 0 {
            governance_proto.genesis_timestamp_seconds = env.now();
        }

        // Step 1.2: latest_reward_event.
        if governance_proto.latest_reward_event.is_none() {
            // Introduce a dummy reward event to mark the origin of the IC era.
            // This is required to be able to compute accurately the rewards for the
            // very first reward distribution.
            governance_proto.latest_reward_event = Some(RewardEvent {
                actual_timestamp_seconds: env.now(),
                day_after_genesis: 0,
                settled_proposals: vec![],
                distributed_e8s_equivalent: 0,
                total_available_e8s_equivalent: 0,
                rounds_since_last_distribution: Some(0),
                latest_round_available_e8s_equivalent: Some(0),
            })
        }

        // Step 1.3: xdr_conversion_rate.
        if governance_proto.xdr_conversion_rate.is_none() {
            governance_proto.xdr_conversion_rate = Some(XdrConversionRatePb::with_default_values());
        }

        // Step 2: Break out Neurons from governance_proto. Neurons are managed separately by
        // NeuronStore. NeuronStore is in charge of Neurons, because some are stored in stable
        // memory, while others are stored in heap. "inactive" Neurons live in stable memory, while
        // the rest live in heap.

        let (neurons, topic_followee_index, heap_governance_proto) =
            split_governance_proto(governance_proto);

        assert!(
            topic_followee_index.is_empty(),
            "Topic followee index should be empty when initializing for the first time"
        );

        // Step 3: Final assembly.
        Self {
            heap_data: heap_governance_proto,
            neuron_store: NeuronStore::new(
                // Neurons are converted from API type to internal type.
                neurons
                    .into_iter()
                    .map(|(id, proto)| (id, Neuron::try_from(proto).expect("Invalid neuron")))
                    .collect(),
            ),
            env,
            ledger,
            cmc,
            closest_proposal_deadline_timestamp_seconds: 0,
            latest_gc_timestamp_seconds: 0,
            latest_gc_num_proposals: 0,
            neuron_data_validator: NeuronDataValidator::new(),
            minting_node_provider_rewards: false,
        }
    }

    /// Restores Governance after an upgrade from its persisted state.
    pub fn new_restored(
        governance_proto: GovernanceProto,
        env: Box<dyn Environment>,
        ledger: Box<dyn IcpLedger>,
        cmc: Box<dyn CMC>,
    ) -> Self {
        let (heap_neurons, topic_followee_map, heap_governance_proto) =
            split_governance_proto(governance_proto);

        Self {
            heap_data: heap_governance_proto,
            neuron_store: NeuronStore::new_restored((heap_neurons, topic_followee_map)),
            env,
            ledger,
            cmc,
            closest_proposal_deadline_timestamp_seconds: 0,
            latest_gc_timestamp_seconds: 0,
            latest_gc_num_proposals: 0,
            neuron_data_validator: NeuronDataValidator::new(),
            minting_node_provider_rewards: false,
        }
    }

    /// After calling this method, the proto and neuron_store (the heap neurons at least)
    /// becomes unusable, so it should only be called in pre_upgrade once.
    pub fn take_heap_proto(&mut self) -> GovernanceProto {
        let neuron_store = std::mem::take(&mut self.neuron_store);
        let (neurons, heap_topic_followee_index) = neuron_store.take();
        let heap_governance_proto = std::mem::take(&mut self.heap_data);
        reassemble_governance_proto(neurons, heap_topic_followee_index, heap_governance_proto)
    }

    pub fn clone_proto(&self) -> GovernanceProto {
        let neurons = self.neuron_store.clone_neurons();
        let heap_topic_followee_index = self.neuron_store.clone_topic_followee_index();
        let heap_governance_proto = self.heap_data.clone();
        reassemble_governance_proto(neurons, heap_topic_followee_index, heap_governance_proto)
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
        GovernanceError::new_with_message(
            ErrorType::NotFound,
            format!("Neuron not found: {:?}", nid),
        )
    }

    fn no_neuron_for_subaccount_error(subaccount: &[u8]) -> GovernanceError {
        GovernanceError::new_with_message(
            ErrorType::NotFound,
            format!("No neuron found for subaccount {:?}", subaccount),
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

    /// Locks a given neuron for a specific, signaling there is an ongoing
    /// ledger update.
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
    /// > the value to the variable, whereas _ doesn’t bind at all.
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
        id: u64,
        command: NeuronInFlightCommand,
    ) -> Result<LedgerUpdateLock, GovernanceError> {
        if self.heap_data.in_flight_commands.contains_key(&id) {
            return Err(GovernanceError::new_with_message(
                ErrorType::LedgerUpdateOngoing,
                "Neuron has an ongoing ledger update.",
            ));
        }

        self.heap_data.in_flight_commands.insert(id, command);

        Ok(LedgerUpdateLock {
            nid: id,
            gov: self,
            retain: false,
        })
    }

    /// Unlocks a given neuron.
    fn unlock_neuron(&mut self, id: u64) {
        match self.heap_data.in_flight_commands.remove(&id) {
            None => {
                println!(
                    "Unexpected condition when unlocking neuron {}: the neuron was not registered as 'in flight'",
                    id
                );
            }
            // This is the expected case.
            Some(_) => (),
        }
    }

    /// Updates a neuron in the list of neurons.
    ///
    /// Preconditions:
    /// - the given `neuron` already exists in `self.neuron_store.neurons`
    #[cfg(feature = "test")]
    pub fn update_neuron(&mut self, neuron: NeuronProto) -> Result<(), GovernanceError> {
        // Converting from API type to internal type.
        let new_neuron = Neuron::try_from(neuron).expect("Neuron must be valid");

        self.with_neuron_mut(&new_neuron.id(), |old_neuron| {
            let subaccount = old_neuron.subaccount();
            if new_neuron.subaccount() != subaccount {
                return Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!("Cannot change the subaccount {} of a neuron.", subaccount),
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
    fn add_neuron(&mut self, neuron_id: u64, neuron: Neuron) -> Result<(), GovernanceError> {
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
                        "The neuron's ID {} does not match the provided ID {}",
                        neuron_real_id, neuron_id
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
                format!(
                    "Cannot add neuron. There is already a neuron with id: {:?}",
                    neuron_id
                ),
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
                format!(
                    "Cannot remove neuron. Can't find a neuron with id: {:?}",
                    neuron_id
                ),
            ));
        }
        self.neuron_store.remove_neuron(&neuron_id);

        Ok(())
    }

    /// TODO(NNS1-2499): inline this.
    /// Return the Neuron IDs of all Neurons that have `principal` as their
    /// controller or as one of their hot keys.
    pub fn get_neuron_ids_by_principal(&self, principal_id: &PrincipalId) -> Vec<NeuronId> {
        self.neuron_store
            .get_neuron_ids_readable_by_caller(*principal_id)
            .into_iter()
            .collect()
    }

    /// Return the union of `followees` with the set of Neuron IDs of all
    /// Neurons that directly follow the `followees` w.r.t. the
    /// topic `NeuronManagement`.
    pub fn get_managed_neuron_ids_for(&self, followees: Vec<NeuronId>) -> Vec<NeuronId> {
        // Tap into the `topic_followee_index` for followers of level zero neurons.
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
        } = list_neurons;

        let include_empty_neurons_readable_by_caller = include_empty_neurons_readable_by_caller
            // This default is to maintain the previous behavior. (Unlike
            // protobuf, we do not have a convention that says "the default
            // value is falsy".)
            .unwrap_or(true);
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
            } else {
                self.neuron_store
                    .get_non_empty_neuron_ids_readable_by_caller(caller)
            }
        } else {
            Vec::new()
        };

        // Concatenate (explicit and implicit)-ly included neurons.
        let mut requested_neuron_ids: Vec<NeuronId> =
            neuron_ids.iter().map(|id| NeuronId { id: *id }).collect();
        requested_neuron_ids.append(&mut implicitly_requested_neuron_ids);

        // These will be assembled into the final result.
        let mut neuron_infos = hashmap![];
        let mut full_neurons = vec![];

        // Populate the above two neuron collections.
        for neuron_id in requested_neuron_ids {
            // Ignore when a neuron is not found. It is not guaranteed that a
            // neuron will be found, because some of the elements in
            // requested_neuron_ids are supplied by the caller.
            let _ignore_when_neuron_not_found = self.with_neuron(&neuron_id, |neuron| {
                // Populate neuron_infos.
                neuron_infos.insert(neuron_id.id, neuron.get_neuron_info(now, caller));

                // Populate full_neurons.
                let let_caller_read_full_neuron =
                    // (Caller can vote with neuron if it is the controller or a hotkey of the neuron.)
                    neuron.is_authorized_to_vote(&caller)
                        || self.neuron_store.can_principal_vote_on_proposals_that_target_neuron(caller, neuron)
                        // neuron is public, and the caller requested that
                        // public neurons be included (in full_neurons).
                        || (include_public_neurons_in_full_neurons
                            && neuron.visibility() == Some(Visibility::Public)
                        );
                if let_caller_read_full_neuron {
                    full_neurons.push(NeuronProto::from(neuron.clone()));
                }
            });
        }

        // Assemble final result.
        ListNeuronsResponse {
            neuron_infos,
            full_neurons,
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
                        known_neuron_data: n.known_neuron_data.clone(),
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
                    format!("The recipient's subaccount is invalid due to: {}", e),
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
    pub async fn split_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        split: &manage_neuron::Split,
    ) -> Result<NeuronId, GovernanceError> {
        // New neurons are not allowed when the heap is too large.
        self.check_heap_can_grow()?;

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

        if minted_stake_e8s < min_stake + split.amount_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!(
                    "Trying to split {} e8s out of neuron {}. \
                     This is not allowed, because the parent has stake {} e8s. \
                     If the requested amount was subtracted from it, there would be less than \
                     the minimum allowed stake, which is {} e8s. ",
                    split.amount_e8s, id.id, minted_stake_e8s, min_stake
                ),
            ));
        }

        let created_timestamp_seconds = self.env.now();
        let child_nid = self.neuron_store.new_neuron_id(&mut *self.env);

        let from_subaccount = parent_neuron.subaccount();

        let to_subaccount = Subaccount(self.env.random_byte_array());

        // Make sure there isn't already a neuron with the same sub-account.
        if self.neuron_store.has_neuron_with_subaccount(to_subaccount) {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "There is already a neuron with the same subaccount.",
            ));
        }

        let in_flight_command = NeuronInFlightCommand {
            timestamp: created_timestamp_seconds,
            command: Some(InFlightCommand::Split(split.clone())),
        };

        let staked_amount = split.amount_e8s - transaction_fee_e8s;

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
                .checked_sub(split.amount_e8s)
                .expect("Subtracting neuron stake underflows");
        })?;

        let now = self.env.now();
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
                        .checked_add(split.amount_e8s)
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
            split.amount_e8s,
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
    pub async fn merge_neurons(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        merge: &manage_neuron::Merge,
    ) -> Result<ManageNeuronResponse, GovernanceError> {
        let now = self.env.now();
        let in_flight_command = NeuronInFlightCommand {
            timestamp: now,
            command: Some(InFlightCommand::Merge(merge.clone())),
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
            source_burn_fees
                .burn_neuron_fees_with_ledger(&*self.ledger, &mut self.neuron_store, now)
                .await?;
        }

        // Step 5: transfer the stake if needed.
        if let Some(stake_transfer) = effect.stake_transfer() {
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
            build_merge_neurons_response(&source_neuron, &target_neuron, now, *caller),
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
            build_merge_neurons_response(&source_neuron, &target_neuron, now, *caller),
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
                "The percentage of maturity to spawn must be a value between 1 and 100 (inclusive)."));
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

        let child_nid = self.neuron_store.new_neuron_id(&mut *self.env);

        // use provided sub-account if any, otherwise generate a random one.
        let to_subaccount = match spawn.nonce {
            None => Subaccount(self.env.random_byte_array()),
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
    ) -> Result<(StakeMaturityResponse, MergeMaturityResponse), GovernanceError> {
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
                "The percentage of maturity to stake must be a value between 0 (exclusive) and 100 (inclusive)."));
        }

        let mut maturity_to_stake =
            (neuron_maturity_e8s_equivalent.saturating_mul(percentage_to_stake as u64)) / 100;

        if maturity_to_stake > neuron_maturity_e8s_equivalent {
            // In case we have some bug, clamp maturity_to_stake by available maturity.
            maturity_to_stake = neuron_maturity_e8s_equivalent;
            println!(
                "{}WARNING: a portion of maturity ({}% * {} = {}) should not be larger than its entirety {}",
                LOG_PREFIX, percentage_to_stake, neuron_maturity_e8s_equivalent, maturity_to_stake, neuron_maturity_e8s_equivalent
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
        let responses = self
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
                let new_stake_e8s = neuron.cached_neuron_stake_e8s + staked_maturity_e8s;

                (
                    StakeMaturityResponse {
                        maturity_e8s: neuron.maturity_e8s_equivalent,
                        staked_maturity_e8s,
                    },
                    MergeMaturityResponse {
                        merged_maturity_e8s: maturity_to_stake,
                        new_stake_e8s,
                    },
                )
            })
            .expect("Expected the neuron to exist");

        Ok(responses)
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
    pub async fn disburse_to_neuron(
        &mut self,
        id: &NeuronId,
        caller: &PrincipalId,
        disburse_to_neuron: &manage_neuron::DisburseToNeuron,
    ) -> Result<NeuronId, GovernanceError> {
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

        let child_nid = self.neuron_store.new_neuron_id(&mut *self.env);
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
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: created_timestamp_seconds,
            },
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

    /// Set the status of a proposal that is 'being executed' to
    /// 'executed' or 'failed' depending on the value of 'success'.
    ///
    /// The proposal ID 'pid' is taken as a raw integer to avoid
    /// lifetime issues.
    pub fn set_proposal_execution_status(&mut self, pid: u64, result: Result<(), GovernanceError>) {
        match self.heap_data.proposals.get_mut(&pid) {
            Some(proposal_data) => {
                // The proposal has to be adopted before it is executed.
                assert!(proposal_data.status() == ProposalStatus::Adopted);
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
                            proposal_data.proposal.as_ref().and_then(|proposal| proposal.title.clone())
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
        self.with_neuron(id, |neuron| neuron.get_neuron_info(now, requester))
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
            neuron.get_neuron_info(self.env.now(), requester)
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
    ) -> Result<NeuronProto, GovernanceError> {
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
    ) -> Result<NeuronProto, GovernanceError> {
        self.neuron_store
            .get_full_neuron(*id, *caller)
            .map(NeuronProto::from)
            .map_err(GovernanceError::from)
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
        let proposal_data = self.heap_data.proposals.get(&pid.into().id);
        match proposal_data {
            None => None,
            Some(pd) => {
                let caller_neurons: HashSet<NeuronId> =
                    self.neuron_store.get_neuron_ids_readable_by_caller(*caller);
                let now = self.env.now();
                Some(self.proposal_data_to_info(pd, &caller_neurons, now, false))
            }
        }
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
                    format!(
                        "Proposal data for {:?} is missing the `proposal` field.",
                        proposal_id
                    ),
                )
            })?
            .action
            .as_ref()
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!(
                        "Proposal data for {:?} is missing `proposal.action`.",
                        proposal_id,
                    ),
                )
            })?;
        if !matches!(action, Action::CreateServiceNervousSystem(_)) {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Proposal {:?} is not of type CreateServiceNervousSystem.",
                    proposal_id,
                ),
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
    pub fn get_pending_proposals(&self, caller: &PrincipalId) -> Vec<ProposalInfo> {
        let caller_neurons: HashSet<NeuronId> =
            self.neuron_store.get_neuron_ids_readable_by_caller(*caller);
        let now = self.env.now();
        self.get_pending_proposals_data()
            .map(|data| self.proposal_data_to_info(data, &caller_neurons, now, true))
            .collect()
    }

    /// Iterator over proposals info of pending proposals.
    pub fn get_pending_proposals_data(&self) -> impl Iterator<Item = &ProposalData> {
        self.heap_data
            .proposals
            .values()
            .filter(|data| data.status() == ProposalStatus::Open)
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

    fn proposal_data_to_info(
        &self,
        data: &ProposalData,
        caller_neurons: &HashSet<NeuronId>,
        now_seconds: u64,
        multi_query: bool,
    ) -> ProposalInfo {
        // Calculate derived fields
        let topic = data.topic();
        let status = data.status();
        let voting_period_seconds = self.voting_period_seconds()(topic);
        let reward_status = data.reward_status(now_seconds, voting_period_seconds);

        // For multi-queries, large fields such as WASM blobs need to be omitted. Otherwise the
        // message limit will be exceeded.
        let proposal = if multi_query {
            if let Some(
                proposal @ Proposal {
                    action: Some(proposal::Action::ExecuteNnsFunction(_)),
                    ..
                },
            ) = data.proposal.clone()
            {
                Some(proposal.omit_large_fields())
            } else {
                data.proposal.clone()
            }
        } else {
            data.proposal.clone()
        };

        /// Remove all ballots except the ballots belonging to a neuron present
        /// in `except_from`.
        fn remove_ballots_not_cast_by(
            all_ballots: &HashMap<u64, Ballot>,
            except_from: &HashSet<NeuronId>,
        ) -> HashMap<u64, Ballot> {
            let mut ballots = HashMap::new();
            for neuron_id in except_from.iter() {
                if let Some(v) = all_ballots.get(&neuron_id.id) {
                    ballots.insert(neuron_id.id, v.clone());
                }
            }
            ballots
        }

        ProposalInfo {
            id: data.id,
            proposer: data.proposer,
            reject_cost_e8s: data.reject_cost_e8s,
            proposal,
            proposal_timestamp_seconds: data.proposal_timestamp_seconds,
            ballots: remove_ballots_not_cast_by(&data.ballots, caller_neurons),
            latest_tally: data.latest_tally.clone(),
            decided_timestamp_seconds: data.decided_timestamp_seconds,
            executed_timestamp_seconds: data.executed_timestamp_seconds,
            failed_timestamp_seconds: data.failed_timestamp_seconds,
            failure_reason: data.failure_reason.clone(),
            reward_event_round: data.reward_event_round,
            topic: topic as i32,
            status: status as i32,
            reward_status: reward_status as i32,
            deadline_timestamp_seconds: Some(
                data.get_deadline_timestamp_seconds(voting_period_seconds),
            ),
            derived_proposal_information: data.derived_proposal_information.clone(),
        }
    }

    /// Return true if the 'info' proposal is visible to some of the neurons in
    /// 'caller_neurons'.
    fn proposal_is_visible_to_neurons(
        &self,
        info: &ProposalData,
        caller_neurons: &HashSet<NeuronId>,
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
    /// let mut lst = gov.list_proposals(ListProposalInfo {});
    /// while !lst.empty() {
    ///   /* do stuff with lst */
    ///   lst = gov.list_proposals(ListProposalInfo {
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
        req: &ListProposalInfo,
    ) -> ListProposalInfoResponse {
        let caller_neurons: HashSet<NeuronId> =
            self.neuron_store.get_neuron_ids_readable_by_caller(*caller);
        let exclude_topic: HashSet<i32> = req.exclude_topic.iter().cloned().collect();
        let include_reward_status: HashSet<i32> =
            req.include_reward_status.iter().cloned().collect();
        let include_status: HashSet<i32> = req.include_status.iter().cloned().collect();
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
            .take(limit);

        let proposal_info = proposals
            .map(|(_, y)| y)
            .map(|pd| self.proposal_data_to_info(pd, &caller_neurons, now, true))
            .collect::<Vec<_>>();

        let proposal_info = if req.omit_large_fields() {
            proposal_info
                .into_iter()
                .map(|data| data.omit_large_fields())
                .collect()
        } else {
            proposal_info
        };

        ListProposalInfoResponse { proposal_info }
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

        // Recompute the tally here. It should correctly reflect all votes,
        // even the ones after the proposal has been decided. It's possible
        // to have Open status while it does not accept votes anymore, since
        // the status change happens below this point.
        if proposal.status() == ProposalStatus::Open
            || proposal.accepts_vote(now_seconds, voting_period_seconds)
        {
            proposal.recompute_tally(now_seconds, voting_period_seconds);
        }

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
        let is_manage_neuron = proposal
            .proposal
            .as_ref()
            .map(|x| x.is_manage_neuron())
            .unwrap_or(false);

        // The proposal was adopted, return the rejection fee for non-ManageNeuron
        // proposals.
        if !is_manage_neuron {
            if let Some(nid) = proposal.proposer {
                let rejection_cost = proposal.reject_cost_e8s;
                self.with_neuron_mut(&nid, |neuron| {
                    if neuron.neuron_fees_e8s >= rejection_cost {
                        neuron.neuron_fees_e8s -= rejection_cost;
                    }
                })
                .ok();
            }
        }

        if let Some(action) = action {
            // A yes decision as been made, execute the proposal!
            self.start_proposal_execution(proposal_id, &action);
        } else {
            self.set_proposal_execution_status(
                proposal_id,
                Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    "Proposal is missing.",
                )),
            );
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
    fn start_proposal_execution(&mut self, pid: u64, action: &Action) {
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
        spawn(governance.perform_action(pid, action.clone()));
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
                let to_subaccount = Subaccount(self.env.random_byte_array());
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
                let nid = self.neuron_store.new_neuron_id(&mut *self.env);
                let dissolve_delay_seconds = std::cmp::min(
                    reward_to_neuron.dissolve_delay_seconds,
                    MAX_DISSOLVE_DELAY_SECONDS,
                );
                // Transfer successful.
                let neuron = NeuronBuilder::new(
                    nid,
                    to_subaccount,
                    *np_principal,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds,
                        aging_since_timestamp_seconds: now,
                    },
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
                            format!("The recipient's subaccount is invalid due to: {}", e),
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
                        format!("Node provider with id {} not found.", np_principal),
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

    /// Mint and transfer monthly node provider rewards
    async fn mint_monthly_node_provider_rewards(&mut self) -> Result<(), GovernanceError> {
        if self.minting_node_provider_rewards {
            // There is an ongoing attempt to mint node provider rewards. Do nothing.
            return Ok(());
        }

        // Acquire the lock before doing anything meaningful.
        self.minting_node_provider_rewards = true;

        let monthly_node_provider_rewards = self.get_monthly_node_provider_rewards().await?;
        let _ = self
            .reward_node_providers(&monthly_node_provider_rewards.rewards)
            .await;
        self.update_most_recent_monthly_node_provider_rewards(monthly_node_provider_rewards);

        // Release the lock before committing the result.
        self.minting_node_provider_rewards = false;

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

    async fn perform_action(&mut self, pid: u64, action: Action) {
        match action {
            Action::ManageNeuron(mgmt) => {
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
            Action::ManageNetworkEconomics(ne) => {
                if let Some(economics) = &mut self.heap_data.economics {
                    // The semantics of the proposal is to modify all values specified with a
                    // non-default value in the proposed new `NetworkEconomics`.
                    if ne.reject_cost_e8s != 0 {
                        economics.reject_cost_e8s = ne.reject_cost_e8s
                    }
                    if ne.neuron_minimum_stake_e8s != 0 {
                        economics.neuron_minimum_stake_e8s = ne.neuron_minimum_stake_e8s
                    }
                    if ne.neuron_management_fee_per_proposal_e8s != 0 {
                        economics.neuron_management_fee_per_proposal_e8s =
                            ne.neuron_management_fee_per_proposal_e8s
                    }
                    if ne.minimum_icp_xdr_rate != 0 {
                        economics.minimum_icp_xdr_rate = ne.minimum_icp_xdr_rate
                    }
                    if ne.neuron_spawn_dissolve_delay_seconds != 0 {
                        economics.neuron_spawn_dissolve_delay_seconds =
                            ne.neuron_spawn_dissolve_delay_seconds
                    }
                    if ne.maximum_node_provider_rewards_e8s != 0 {
                        economics.maximum_node_provider_rewards_e8s =
                            ne.maximum_node_provider_rewards_e8s
                    }
                    if ne.transaction_fee_e8s != 0 {
                        economics.transaction_fee_e8s = ne.transaction_fee_e8s
                    }
                    if ne.max_proposals_to_keep_per_topic != 0 {
                        economics.max_proposals_to_keep_per_topic =
                            ne.max_proposals_to_keep_per_topic
                    }
                    if ne.neurons_fund_economics.is_some() {
                        economics.neurons_fund_economics = ne.neurons_fund_economics
                    }
                } else {
                    // If for some reason, we don't have an
                    // 'economics' proto, use the proposed one.
                    self.heap_data.economics = Some(ne)
                }
                self.set_proposal_execution_status(pid, Ok(()));
            }
            // A motion is not executed, just recorded for posterity.
            Action::Motion(_) => {
                self.set_proposal_execution_status(pid, Ok(()));
            }
            Action::ExecuteNnsFunction(m) => {
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
            Action::ApproveGenesisKyc(proposal) => {
                self.approve_genesis_kyc(&proposal.principals);
                self.set_proposal_execution_status(pid, Ok(()));
            }
            Action::AddOrRemoveNodeProvider(ref proposal) => {
                if let Some(change) = &proposal.change {
                    match change {
                        Change::ToAdd(node_provider) => {
                            if node_provider.id.is_none() {
                                self.set_proposal_execution_status(
                                    pid,
                                    Err(GovernanceError::new_with_message(
                                        ErrorType::PreconditionFailed,
                                        "Node providers must have a principal id.",
                                    )),
                                );
                                return;
                            }

                            // Check if the node provider already exists
                            if self
                                .heap_data
                                .node_providers
                                .iter()
                                .any(|np| np.id == node_provider.id)
                            {
                                self.set_proposal_execution_status(
                                    pid,
                                    Err(GovernanceError::new_with_message(
                                        ErrorType::PreconditionFailed,
                                        "A node provider with the same principal already exists.",
                                    )),
                                );
                                return;
                            }
                            self.heap_data.node_providers.push(node_provider.clone());
                            self.set_proposal_execution_status(pid, Ok(()));
                        }
                        Change::ToRemove(node_provider) => {
                            if node_provider.id.is_none() {
                                self.set_proposal_execution_status(
                                    pid,
                                    Err(GovernanceError::new_with_message(
                                        ErrorType::PreconditionFailed,
                                        "Node providers must have a principal id.",
                                    )),
                                );
                                return;
                            }

                            if let Some(pos) = self
                                .heap_data
                                .node_providers
                                .iter()
                                .position(|np| np.id == node_provider.id)
                            {
                                self.heap_data.node_providers.remove(pos);
                                self.set_proposal_execution_status(pid, Ok(()));
                            } else {
                                self.set_proposal_execution_status(
                                    pid,
                                    Err(GovernanceError::new_with_message(
                                        ErrorType::NotFound,
                                        "Can't find a NodeProvider with the same principal id.",
                                    )),
                                );
                            }
                        }
                    }
                } else {
                    self.set_proposal_execution_status(
                        pid,
                        Err(GovernanceError::new_with_message(
                            ErrorType::PreconditionFailed,
                            "The proposal didn't contain a change.",
                        )),
                    );
                }
            }
            Action::RewardNodeProvider(ref reward) => {
                self.reward_node_provider(pid, reward).await;
            }
            Action::SetDefaultFollowees(ref proposal) => {
                let validate_result = self.validate_default_followees(&proposal.default_followees);
                if validate_result.is_err() {
                    self.set_proposal_execution_status(pid, validate_result);
                    return;
                }
                self.heap_data
                    .default_followees
                    .clone_from(&proposal.default_followees);
                self.set_proposal_execution_status(pid, Ok(()));
            }
            Action::RewardNodeProviders(proposal) => {
                self.reward_node_providers_from_proposal(pid, proposal)
                    .await;
            }
            Action::RegisterKnownNeuron(known_neuron) => {
                let result = self.register_known_neuron(known_neuron);
                self.set_proposal_execution_status(pid, result);
            }
            Action::CreateServiceNervousSystem(ref create_service_nervous_system) => {
                self.create_service_nervous_system(pid, create_service_nervous_system)
                    .await;
            }

            Action::SetSnsTokenSwapOpenTimeWindow(obsolete_action) => {
                self.perform_obsolete_action(pid, obsolete_action);
            }
            Action::OpenSnsTokenSwap(obsolete_action) => {
                self.perform_obsolete_action(pid, obsolete_action);
            }
            Action::InstallCode(install_code) => {
                self.perform_install_code(pid, install_code).await;
            }
            Action::StopOrStartCanister(stop_or_start) => {
                self.perform_stop_or_start_canister(pid, stop_or_start)
                    .await;
            }
            Action::UpdateCanisterSettings(update_settings) => {
                self.perform_update_canister_settings(pid, update_settings)
                    .await;
            }
        }
    }

    /// Fails immediately, because this type of proposal is obsolete.
    fn perform_obsolete_action<T>(&mut self, proposal_id: u64, obsolete_action: T)
    where
        T: std::fmt::Debug,
    {
        self.set_proposal_execution_status(
            proposal_id,
            Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Proposal action {:?} is obsolete.", obsolete_action),
            )),
        );
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
                    "Error calling external canister for proposal {}. Rejection code: {:?} message: {}",
                    proposal_id, code, message
                ),
            )),
        }
    }

    /// Always fails, because this type of proposal is obsolete.
    fn validate_obsolete_proposal_action<T>(obsolete_action: T) -> Result<(), GovernanceError>
    where
        T: std::fmt::Debug,
    {
        Err(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            format!("Proposal action {:?} is obsolete.", obsolete_action),
        ))
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
                    "Failed to convert CreateServiceNervousSystem proposal to SnsInitPayload: {}",
                    err,
                ),
            )
        })?;

        // Step 1.2: Validate the SnsInitPayload.
        sns_init_payload.validate_post_execution().map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Failed to validate SnsInitPayload: {}", err),
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
            call_deploy_new_sns(&mut self.env, sns_init_payload).await;

        // Step 3: React to response from deploy_new_sns (Ok or Err).

        // Step 3.1: If the call was not successful, issue refunds (and then, return).
        if let Err(ref mut err) = &mut deploy_new_sns_response {
            let refund_result = self.refund_maturity_to_neurons_fund(
                &proposal_id,
                initial_neurons_fund_participation_snapshot,
            );
            err.error_message += &format!(" refund result: {:#?}", refund_result);
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
    pub fn approve_genesis_kyc(&mut self, principals: &[PrincipalId]) {
        let principal_set: HashSet<&PrincipalId> = principals.iter().collect();

        for principal in principal_set {
            for neuron_id in self.get_neuron_ids_by_principal(principal) {
                self.with_neuron_mut(&neuron_id, |neuron| {
                    if neuron.controller() == *principal {
                        neuron.kyc_verified = true;
                    }
                })
                .ok();
            }
        }
    }

    fn validate_manage_neuron_proposal(
        &self,
        manage_neuron: &ManageNeuron,
    ) -> Result<(), GovernanceError> {
        // TODO(NNS1-3228): Delete this.
        if manage_neuron.is_set_visibility() &&
            // But SetVisibility proposals are disabled
            !are_set_visibility_proposals_enabled()
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::Unavailable,
                "Setting neuron visibility via proposal is not allowed yet, \
                 but it will be in the not too distant future. If you need \
                 this sooner, please, start a new thread at forum.dfinity.org \
                 and describe your use case."
                    .to_string(),
            ));
        }

        let manage_neuron = ManageNeuron::from_proto(manage_neuron.clone()).map_err(|e| {
            GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                format!("Failed to validate ManageNeuron {}", e),
            )
        })?;

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

        // Early exit for deprecated commands.
        if let Command::MergeMaturity(_) = manage_neuron.command.as_ref().unwrap() {
            return Self::merge_maturity_removed_error();
        }

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

    pub(crate) fn economics(&self) -> &NetworkEconomics {
        self.heap_data
            .economics
            .as_ref()
            .expect("NetworkEconomics not present")
    }

    /// Inserts a proposals that has already been validated in the state.
    ///
    /// This is a low-level function that makes no verification whatsoever.
    fn insert_proposal(&mut self, pid: u64, data: ProposalData) {
        let voting_period_seconds = self.voting_period_seconds()(data.topic());
        self.closest_proposal_deadline_timestamp_seconds = std::cmp::min(
            data.proposal_timestamp_seconds + voting_period_seconds,
            self.closest_proposal_deadline_timestamp_seconds,
        );
        self.heap_data.proposals.insert(pid, data);
        self.process_proposal(pid);
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

    fn validate_proposal(&self, proposal: &Proposal) -> Result<Action, GovernanceError> {
        impl From<String> for GovernanceError {
            fn from(message: String) -> Self {
                Self::new_with_message(ErrorType::InvalidProposal, message)
            }
        }

        if proposal.topic() == Topic::Unspecified {
            Err(format!("Topic not specified. proposal: {:#?}", proposal))?;
        }

        proposal_validation::validate_user_submitted_proposal_fields(
            &ic_nns_governance_api::pb::v1::Proposal::from(proposal.clone()),
        )?;

        if !proposal.allowed_when_resources_are_low() {
            self.check_heap_can_grow()?;
        }

        // Require that oneof action is populated.
        let action = proposal
            .action
            .as_ref()
            .ok_or(format!("Proposal lacks an action: {:?}", proposal))?;

        // Finally, perform Action-specific validation.
        match action {
            Action::ExecuteNnsFunction(execute_nns_function) => {
                self.validate_execute_nns_function(execute_nns_function)
            }
            Action::Motion(motion) => validate_motion(motion),
            Action::CreateServiceNervousSystem(create_service_nervous_system) => {
                self.validate_create_service_nervous_system(create_service_nervous_system)
            }
            Action::ManageNeuron(manage_neuron) => {
                self.validate_manage_neuron_proposal(manage_neuron)
            }
            Action::ManageNetworkEconomics(_)
            | Action::ApproveGenesisKyc(_)
            | Action::AddOrRemoveNodeProvider(_)
            | Action::RewardNodeProvider(_)
            | Action::RewardNodeProviders(_)
            | Action::RegisterKnownNeuron(_) => Ok(()),

            Action::SetDefaultFollowees(obsolete_action) => {
                Self::validate_obsolete_proposal_action(obsolete_action)
            }
            Action::SetSnsTokenSwapOpenTimeWindow(obsolete_action) => {
                Self::validate_obsolete_proposal_action(obsolete_action)
            }
            Action::OpenSnsTokenSwap(obsolete_action) => {
                Self::validate_obsolete_proposal_action(obsolete_action)
            }
            Action::InstallCode(install_code) => install_code.validate(),
            Action::StopOrStartCanister(stop_or_start) => stop_or_start.validate(),
            Action::UpdateCanisterSettings(update_settings) => update_settings.validate(),
        }?;

        Ok(action.clone())
    }

    fn validate_execute_nns_function(
        &self,
        update: &ExecuteNnsFunction,
    ) -> Result<(), GovernanceError> {
        let nns_function = NnsFunction::try_from(update.nns_function).map_err(|_| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Invalid NnsFunction id: {}", update.nns_function),
            )
        })?;

        let invalid_proposal_error = |error_message: String| -> GovernanceError {
            GovernanceError::new_with_message(ErrorType::InvalidProposal, error_message)
        };

        if !nns_function.can_have_large_payload()
            && update.payload.len() > PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX
        {
            return Err(invalid_proposal_error(format!(
                "The maximum NNS function payload size in a proposal action is {} bytes, this payload is: {} bytes",
                PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX,
                update.payload.len(),
            )));
        }

        if nns_function.is_obsolete() {
            return Err(invalid_proposal_error(format!(
                "{} proposal is obsolete",
                nns_function.as_str_name()
            )));
        }

        match nns_function {
            NnsFunction::SubnetRentalRequest => {
                self.validate_subnet_rental_proposal(&update.payload)
                    .map_err(invalid_proposal_error)?;
            }
            NnsFunction::IcpXdrConversionRate => {
                Self::validate_icp_xdr_conversion_rate_payload(
                    &update.payload,
                    self.heap_data
                        .economics
                        .as_ref()
                        .ok_or_else(|| GovernanceError::new(ErrorType::Unavailable))?
                        .minimum_icp_xdr_rate,
                )
                .map_err(invalid_proposal_error)?;
            }
            NnsFunction::AssignNoid => {
                Self::validate_assign_noid_payload(&update.payload, &self.heap_data.node_providers)
                    .map_err(invalid_proposal_error)?;
            }
            NnsFunction::AddOrRemoveDataCenters => {
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
            return Err(format!("Invalid SubnetRentalRequest: {}", e));
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
                "There is another open SubnetRentalRequest proposal: {:?}",
                other_proposal_ids,
            ));
        }

        Ok(())
    }

    fn validate_icp_xdr_conversion_rate_payload(
        payload: &[u8],
        minimum_icp_xdr_rate: u64,
    ) -> Result<(), String> {
        let decoded_payload = match Decode!([decoder_config()]; payload, UpdateIcpXdrConversionRatePayload)
        {
            Ok(payload) => payload,
            Err(e) => {
                return Err(format!(
                    "The payload could not be decoded into a UpdateIcpXdrConversionRatePayload: {}",
                    e
                ));
            }
        };

        if decoded_payload.xdr_permyriad_per_icp < minimum_icp_xdr_rate {
            return Err(format!(
                "The proposed rate {} is below the minimum allowable rate",
                decoded_payload.xdr_permyriad_per_icp
            ))?;
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
                    "The payload could not be decoded into a AddNodeOperatorPayload: {}",
                    e
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
                return Err(format!("The payload could not be decoded into a AddOrRemoveDataCentersProposalPayload: {}", e));
            }
        };

        decoded_payload.validate().map_err(|e| {
            format!(
                "The given AddOrRemoveDataCentersProposalPayload is invalid: {}",
                e
            )
        })
    }

    fn validate_create_service_nervous_system(
        &self,
        create_service_nervous_system: &CreateServiceNervousSystem,
    ) -> Result<(), GovernanceError> {
        // Must be able to convert to a valid SnsInitPayload.
        let conversion_result = SnsInitPayload::try_from(ApiCreateServiceNervousSystem::from(
            create_service_nervous_system.clone(),
        ));
        if let Err(err) = conversion_result {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Invalid CreateServiceNervousSystem: {}", err),
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

    pub fn make_proposal(
        &mut self,
        proposer_id: &NeuronId,
        caller: &PrincipalId,
        proposal: &Proposal,
    ) -> Result<ProposalId, GovernanceError> {
        let topic = proposal.topic();
        let now_seconds = self.env.now();

        // Validate proposal
        let action = self.validate_proposal(proposal)?;

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
                    "Neuron doesn't have enough minted stake to submit proposal: {}",
                    proposer_minted_stake_e8s,
                ),
            ));
        }

        let min_dissolve_delay_seconds_to_vote = if let Action::ManageNeuron(_) = action {
            0
        } else {
            MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS
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
        if let Action::ManageNeuron(_) = action {
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
                && !proposal.allowed_when_resources_are_low()
            {
                return Err(GovernanceError::new_with_message(
                    ErrorType::ResourceExhausted,
                    "Reached maximum number of proposals that have not yet \
                    been taken into account for voting rewards. \
                    Please try again later.",
                ));
            }
        }

        let ballots = self.compute_ballots_for_new_proposal(&action, proposer_id, now_seconds)?;

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
        let proposal = if let Action::ManageNeuron(ref manage_neuron) = action {
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
                ..proposal.clone()
            }
        } else {
            proposal.clone()
        };

        // Wait-For-Quiet is not enabled for ManageNeuron
        let wait_for_quiet_enabled = !matches!(action, Action::ManageNeuron(_));

        // Create a new proposal ID for this proposal.
        let proposal_num = self.next_proposal_id();
        let proposal_id = ProposalId { id: proposal_num };

        // Create the proposal.
        let wait_for_quiet_state = if wait_for_quiet_enabled {
            Some(WaitForQuietState {
                current_deadline_timestamp_seconds: now_seconds
                    .saturating_add(self.voting_period_seconds()(topic)),
            })
        } else {
            None
        };
        let mut proposal_data = ProposalData {
            id: Some(proposal_id),
            proposer: Some(*proposer_id),
            reject_cost_e8s,
            proposal: Some(proposal.clone()),
            proposal_timestamp_seconds: now_seconds,
            ballots,
            wait_for_quiet_state,
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

        // Cast self-vote, including following.
        Governance::cast_vote_and_cascade_follow(
            &proposal_id,
            &mut proposal_data.ballots,
            proposer_id,
            Vote::Yes,
            topic,
            &mut self.neuron_store,
        );
        // Finally, add this proposal as an open proposal.
        self.insert_proposal(proposal_num, proposal_data);

        Ok(proposal_id)
    }

    /// Computes what ballots a new proposal should have, based on the action.
    fn compute_ballots_for_new_proposal(
        &mut self,
        action: &Action,
        proposer_id: &NeuronId,
        now_seconds: u64,
    ) -> Result<HashMap<u64, Ballot>, GovernanceError> {
        Ok(match *action {
            // A neuron can be managed only by its followees on the
            // 'manage neuron' topic.
            Action::ManageNeuron(ref manage_neuron) => {
                let managed_id = manage_neuron
                    .get_neuron_id_or_subaccount()?
                    .ok_or_else(|| {
                        GovernanceError::new_with_message(
                            ErrorType::NotFound,
                            "Proposal must include a neuron to manage.",
                        )
                    })?;

                let followees =
                    self.with_neuron_by_neuron_id_or_subaccount(&managed_id, |managed_neuron| {
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
                let ballots: HashMap<u64, Ballot> = followees
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
                ballots
            }
            // For normal proposals, every neuron with a
            // dissolve delay over six months is allowed to
            // vote, with a voting power determined at the
            // time of the proposal (i.e., now).
            _ => {
                let mut ballots = HashMap::<u64, Ballot>::new();
                let mut total_power: u128 = 0;
                // No neuron in the stable storage should have maturity.

                for neuron in self.neuron_store.voting_eligible_neurons(now_seconds) {
                    let voting_power = neuron.voting_power(now_seconds);

                    total_power += voting_power as u128;

                    ballots.insert(
                        neuron.id().id,
                        Ballot {
                            vote: Vote::Unspecified as i32,
                            voting_power,
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
                ballots
            }
        })
    }

    /// Calculate the reject_cost_e8s of a proposal. This value is set in `ProposalData` and
    /// is the amount reimbursed to the proposing neuron if the proposal passes.
    fn reject_cost_e8s(&self, proposal: &Proposal) -> Result<u64, GovernanceError> {
        let action = proposal.action.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Proposal lacks an action: {:?}", proposal),
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
                format!("Proposal lacks an action: {:?}", proposal),
            )
        })?;
        match *action {
            Action::ManageNeuron(_) => Ok(self.economics().neuron_management_fee_per_proposal_e8s),
            _ => Ok(self.economics().reject_cost_e8s),
        }
    }

    /// Register `voting_neuron_id` voting according to
    /// `vote_of_neuron` (which must be `yes` or `no`) in 'ballots' and
    /// cascade voting according to the following relationships
    /// specified in 'followee_index' (mapping followees to followers for
    /// the topic) and 'neurons' (which contains a mapping of followers
    /// to followees).
    /// Cascading only occurs for proposal topics that support following (i.e.,
    /// all topics except Topic::NeuronManagement).
    fn cast_vote_and_cascade_follow(
        proposal_id: &ProposalId,
        ballots: &mut HashMap<u64, Ballot>,
        voting_neuron_id: &NeuronId,
        vote_of_neuron: Vote,
        topic: Topic,
        neuron_store: &mut NeuronStore,
    ) {
        assert!(topic != Topic::Unspecified);

        // This is the induction variable of the loop: a map from
        // neuron ID to the neuron's vote - 'yes' or 'no' (other
        // values not allowed).
        let mut induction_votes = BTreeMap::new();
        induction_votes.insert(*voting_neuron_id, vote_of_neuron);

        // Retain only neurons that have a ballot that can still be cast.  This excludes
        // neurons with no ballots or ballots that have already been cast.
        fn retain_neurons_with_castable_ballots(
            followers: &mut BTreeSet<NeuronId>,
            ballots: &HashMap<u64, Ballot>,
        ) {
            followers.retain(|f| {
                ballots
                    .get(&f.id)
                    // Only retain neurons with unspecified ballots
                    .map(|b| b.vote == Vote::Unspecified as i32)
                    // Neurons without ballots are also dropped
                    .unwrap_or_default()
            });
        }

        loop {
            // First, we cast the specified votes (in the first round,
            // this will be a single vote) and collect all neurons
            // that follow some of the neurons that are voting.
            let mut all_followers = BTreeSet::new();
            for (k, v) in induction_votes.iter() {
                // The new/induction votes cannot be unspecified.
                assert!(*v != Vote::Unspecified);
                if let Some(k_ballot) = ballots.get_mut(&k.id) {
                    // Neuron with ID k is eligible to vote.
                    if k_ballot.vote == (Vote::Unspecified as i32) {
                        let register_ballot_result =
                            neuron_store.with_neuron_mut(&NeuronId { id: k.id }, |k_neuron| {
                                // Register the neuron's ballot in the
                                // neuron itself.
                                k_neuron.register_recent_ballot(topic, proposal_id, *v);
                            });
                        match register_ballot_result {
                            Ok(_) => {
                                // Only update a vote if it was previously unspecified. Following
                                // can trigger votes for neurons that have already voted (manually)
                                // and we don't change these votes.
                                k_ballot.vote = *v as i32;
                                // Here k is the followee, i.e., the neuron that has just cast a
                                // vote that may be followed by other neurons.
                                //
                                // Insert followers from 'topic'
                                all_followers.extend(
                                    neuron_store.get_followers_by_followee_and_topic(*k, topic),
                                );
                                // Default following doesn't apply to governance or SNS
                                // decentralization sale proposals.
                                if ![Topic::Governance, Topic::SnsAndCommunityFund].contains(&topic)
                                {
                                    // Insert followers from 'Unspecified' (default followers)
                                    all_followers.extend(
                                        neuron_store.get_followers_by_followee_and_topic(
                                            *k,
                                            Topic::Unspecified,
                                        ),
                                    );
                                }
                            }
                            Err(e) => {
                                // The voting neuron not found in the neurons table. This is a bad
                                // inconsistency, but there is nothing that can be done about it at
                                // this place.
                                eprintln!("error in cast_vote_and_cascade_follow when attempting to cast ballot: {:?}", e);
                            }
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

            // Following is not enabled for neuron management proposals
            if topic == Topic::NeuronManagement {
                return;
            }

            // Calling "would_follow_ballots" for neurons that cannot vote is wasteful.
            retain_neurons_with_castable_ballots(&mut all_followers, ballots);

            for f in all_followers.iter() {
                let f_vote = match neuron_store.with_neuron(&NeuronId { id: f.id }, |n| {
                    n.would_follow_ballots(topic, ballots)
                }) {
                    Ok(vote) => vote,
                    Err(e) => {
                        // This is a bad inconsistency, but there is
                        // nothing that can be done about it at this
                        // place.  We somehow have followers recorded that don't exist.
                        eprintln!("error in cast_vote_and_cascade_follow when gathering induction votes: {:?}", e);
                        Vote::Unspecified
                    }
                };
                if f_vote != Vote::Unspecified {
                    // f_vote is yes or no, i.e., f_neuron's
                    // followee relations indicates that it should
                    // vote now.
                    induction_votes.insert(*f, f_vote);
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
            //
            // The above argument also shows how the algorithm deals
            // with cycles in the following graph: votes are
            // propagated through the graph in a manner similar to the
            // breadth-first search (BFS) algorithm. A node is
            // explored when it has voted yes or no.
        }
    }

    fn register_vote(
        &mut self,
        neuron_id: &NeuronId,
        caller: &PrincipalId,
        pb: &manage_neuron::RegisterVote,
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
        let proposal_id = pb.proposal.as_ref().ok_or_else(||
            // Proposal not specified.
            GovernanceError::new_with_message(ErrorType::PreconditionFailed, "Vote must include a proposal id."))?;
        let proposal = self
            .heap_data
            .proposals
            .get_mut(&proposal_id.id)
            .ok_or_else(||
            // Proposal not found.
            GovernanceError::new_with_message(ErrorType::NotFound, "Can't find proposal."))?;
        let topic = proposal
            .proposal
            .as_ref()
            .map(|p| p.topic())
            .unwrap_or(Topic::Unspecified);

        let vote = Vote::try_from(pb.vote).unwrap_or(Vote::Unspecified);
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

        Governance::cast_vote_and_cascade_follow(
            // Actually update the ballot, including following.
            proposal_id,
            &mut proposal.ballots,
            neuron_id,
            vote,
            topic,
            &mut self.neuron_store,
        );

        self.process_proposal(proposal_id.id);

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
        // The implementation of this method is complicated by the
        // fact that we have to maintain a reverse index of all follow
        // relationships, i.e., the `topic_followee_index`.

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
                format!("Not a known topic number. Follow:\n{:#?}", follow_request),
            )
        })?;

        self.with_neuron_mut(id, |neuron| {
            if follow_request.followees.is_empty() {
                neuron.followees.remove(&(topic as i32))
            } else {
                neuron.followees.insert(
                    topic as i32,
                    Followees {
                        followees: follow_request.followees.clone(),
                    },
                )
            }
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
    async fn claim_neuron(
        &mut self,
        subaccount: Subaccount,
        controller: PrincipalId,
        claim_or_refresh: &ClaimOrRefresh,
    ) -> Result<NeuronId, GovernanceError> {
        let nid = self.neuron_store.new_neuron_id(&mut *self.env);
        let now = self.env.now();
        let neuron = NeuronBuilder::new(
            nid,
            subaccount,
            controller,
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: now,
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

    /// Add some identifying metadata to a neuron. This metadata is represented
    /// in KnownNeuronData and includes:
    ///  - Name: the name given to the neuron.
    ///  - Description: optional field to add a short description of the neuron,
    ///    or organization behind it.
    ///
    /// Preconditions:
    ///  - A Neuron ID is given in the request and this ID identifies an existing neuron.
    ///  - Known Neuron Data is specified in the request.
    ///  - Name is at most of length KNOWN_NEURON_NAME_MAX_LEN.
    ///  - Description, if present, is at most of length KNOWN_NEURON_DESCRIPTION_MAX_LEN.
    ///  - Name is not already used in another known neuron.
    fn register_known_neuron(&mut self, known_neuron: KnownNeuron) -> Result<(), GovernanceError> {
        let neuron_id = known_neuron.id.ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::NotFound,
                "No neuron ID specified in the request to register a known neuron.",
            )
        })?;
        let known_neuron_data = known_neuron.known_neuron_data.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::NotFound,
                "No known neuron data specified in the register neuron request.",
            )
        })?;
        if known_neuron_data.name.len() > KNOWN_NEURON_NAME_MAX_LEN {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                format!(
                    "The maximum length for a neuron's name, which is {}, has been exceeded",
                    KNOWN_NEURON_NAME_MAX_LEN
                ),
            ));
        }
        if known_neuron_data.description.is_some()
            && known_neuron_data.description.as_ref().unwrap().len()
                > KNOWN_NEURON_DESCRIPTION_MAX_LEN
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                format!(
                    "The maximum length for a neuron's description, which is {}, has been exceeded",
                    KNOWN_NEURON_DESCRIPTION_MAX_LEN
                ),
            ));
        }
        if self
            .neuron_store
            .contains_known_neuron_name(&known_neuron_data.name)
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "The name {} already belongs to a Neuron",
                    known_neuron_data.name
                ),
            ));
        }

        self.with_neuron_mut(&neuron_id, |neuron| {
            neuron
                .known_neuron_data
                .replace(known_neuron_data.clone())
                .map(|old_known_neuron_data| old_known_neuron_data.name)
        })?;

        Ok(())
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
                .map(|(response, _)| ManageNeuronResponse::stake_maturity_response(response)),
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
                self.make_proposal(&id, caller, p).map(|proposal_id| {
                    ManageNeuronResponse::make_proposal_response(
                        proposal_id,
                        "The proposal has been created successfully.".to_string(),
                    )
                })
            }
            Some(Command::RegisterVote(v)) => self
                .register_vote(&id, caller, v)
                .map(|_| ManageNeuronResponse::register_vote_response()),
            Some(Command::ClaimOrRefresh(_)) => {
                panic!("This should have already returned")
            }
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

    fn maybe_run_migrations(&mut self) {
        self.heap_data.migrations = Some(maybe_run_migrations(
            self.heap_data.migrations.clone().unwrap_or_default(),
            &mut self.neuron_store,
        ));
    }

    fn maybe_run_validations(&mut self) {
        // Running validations might increase heap size. Do not run it when heap should not grow.
        if self.check_heap_can_grow().is_err() {
            return;
        }
        self.neuron_data_validator
            .maybe_validate(self.env.now(), &self.neuron_store);
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
        // Second try to distribute voting rewards (once per day).
        } else if self.should_distribute_rewards() {
            // Getting the total ICP supply from the ledger is expensive enough that we
            // don't want to do it on every call to `run_periodic_tasks`. So we only
            // fetch it when it's needed.
            match self.ledger.total_supply().await {
                Ok(supply) => {
                    if self.should_distribute_rewards() {
                        self.distribute_rewards(supply);
                    }
                }
                Err(e) => println!(
                    "{}Error when getting total ICP supply: {}",
                    LOG_PREFIX,
                    GovernanceError::from(e),
                ),
            }
        // Third try to compute cached metrics (once per day).
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
        // Try to spawn neurons (potentially multiple times per day).
        } else if self.can_spawn_neurons() {
            self.spawn_neurons().await;
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

        self.unstake_maturity_of_dissolved_neurons();
        self.maybe_gc();
        self.maybe_run_migrations();
        self.maybe_run_validations();
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
        let maturity_modulation = self.cmc.neuron_maturity_modulation().await;
        if maturity_modulation.is_err() {
            println!(
                "{}Couldn't update maturity modulation. Error: {}",
                LOG_PREFIX,
                maturity_modulation.err().unwrap()
            );
            return;
        }
        let maturity_modulation = maturity_modulation.unwrap();
        println!(
            "{}Updated daily maturity modulation rate to (in basis points): {}, at: {}. Last updated: {:?}",
            LOG_PREFIX, maturity_modulation, now_seconds, self.heap_data.maturity_modulation_last_updated_at_timestamp_seconds,
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

    /// Returns the 30-day average of the ICP/XDR conversion rate.
    ///
    /// Returns `None` if the data has not been fetched from the CMC canister yet.
    pub fn icp_xdr_rate(&self) -> Decimal {
        let xdr_permyriad_per_icp = self.heap_data.xdr_conversion_rate.xdr_permyriad_per_icp;
        let xdr_permyriad_per_icp = Decimal::from(xdr_permyriad_per_icp);
        xdr_permyriad_per_icp / dec!(10_000)
    }

    /// When a neuron is finally dissolved, if there is any staked maturity it is moved to regular maturity
    /// which can be spawned (and is modulated).
    fn unstake_maturity_of_dissolved_neurons(&mut self) {
        let now_seconds = self.env.now();
        // Filter all the neurons that are currently in "dissolved" state and have some staked maturity.
        // No neuron in stable storage should have staked maturity.
        for neuron_id in self
            .neuron_store
            .list_neurons_ready_to_unstake_maturity(now_seconds)
        {
            let unstake_result = self
                .neuron_store
                .with_neuron_mut(&neuron_id, |neuron| neuron.unstake_maturity(now_seconds));

            match unstake_result {
                Ok(_) => {}
                Err(e) => {
                    println!(
                        "{}Error in heartbeat when moving staked maturity for neuron {:?}: {:?}",
                        LOG_PREFIX, neuron_id, e
                    );
                }
            };
        }
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
    async fn spawn_neurons(&mut self) {
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

                    let maturity = neuron.maturity_e8s_equivalent;
                    let subaccount = neuron.subaccount();

                    let neuron_stake: u64 = match apply_maturity_modulation(
                        maturity,
                        maturity_modulation,
                    ) {
                        Ok(neuron_stake) => neuron_stake,
                        Err(err) => {
                            // Do not retain the lock so that other Neuron operations can continue.
                            // This is safe as no changes to the neuron have been made to the neuron
                            // both internally to governance and externally in ledger.
                            println!(
                                "{}Could not apply modulation to {:?} for neuron {:?} due to {:?}, skipping",
                                LOG_PREFIX, neuron.maturity_e8s_equivalent, neuron.id(), err
                            );
                            continue;
                        }
                    };

                    println!(
                        "{}Spawning neuron: {:?}. Performing ledger update.",
                        LOG_PREFIX, neuron
                    );

                    let staked_neuron_clone = self
                        .with_neuron_mut(&neuron_id, |neuron| {
                            // Reset the neuron's maturity and set that it's spawning before we actually mint
                            // the stake. This is conservative to prevent a neuron having _both_ the stake and
                            // the maturity at any point in time.
                            neuron.maturity_e8s_equivalent = 0;
                            neuron.spawn_at_timestamp_seconds = None;
                            neuron.cached_neuron_stake_e8s = neuron_stake;

                            neuron.clone()
                        })
                        .unwrap();

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
                            // Retain the neuron lock, the neuron won't be able to undergo stake changing
                            // operations until this is fixed.
                            // This is different from what we do in most places because we usually rely
                            // on trapping to retain the lock, but we can't do that here since we're not
                            // working on a single neuron.
                            lock.retain();
                            println!(
                                "{}Error spawning neuron: {:?}. Ledger update failed with err: {:?}.",
                                LOG_PREFIX,
                                neuron_id,
                                error,
                                );
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
        }

        // Release the global spawning lock
        self.heap_data.spawning_neurons = Some(false);
    }

    /// Return `true` if rewards should be distributed, `false` otherwise
    fn should_distribute_rewards(&self) -> bool {
        let latest_distribution_nominal_end_timestamp_seconds =
            self.latest_reward_event().day_after_genesis * REWARD_DISTRIBUTION_PERIOD_SECONDS
                + self.heap_data.genesis_timestamp_seconds;

        self.most_recent_fully_elapsed_reward_round_end_timestamp_seconds()
            > latest_distribution_nominal_end_timestamp_seconds
    }

    /// Create a reward event.
    ///
    /// This method:
    /// * collects all proposals in state ReadyToSettle, that is, proposals that
    ///   can no longer accept votes for the purpose of rewards and that have
    ///   not yet been considered in a reward event.
    /// * Associate those proposals to the new reward event
    fn distribute_rewards(&mut self, supply: Tokens) {
        println!("{}distribute_rewards. Supply: {:?}", LOG_PREFIX, supply);
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
            return;
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
                crate::reward::rewards_pool_to_distribute_in_supply_fraction_for_one_day(day)
            })
            .unwrap_or(0.0);
        let latest_round_available_e8s_equivalent_float =
            (supply.get_e8s() as f64) * latest_day_fraction;

        let fraction: f64 = days
            .map(crate::reward::rewards_pool_to_distribute_in_supply_fraction_for_one_day)
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

        // Sum up "voting rights", which determine the share of the pot earned
        // by a neuron.
        //
        // Construct map voters -> total _used_ voting rights for
        // considered proposals as well as the overall total voting
        // power on considered proposals, whether or not this voting
        // power was used to vote (yes or no).
        let (voters_to_used_voting_right, total_voting_rights) = {
            let mut voters_to_used_voting_right: HashMap<NeuronId, f64> = HashMap::new();
            let mut total_voting_rights = 0f64;

            for pid in considered_proposals.iter() {
                if let Some(proposal) = self.get_proposal_data(*pid) {
                    let reward_weight = proposal.topic().reward_weight();
                    for (voter, ballot) in proposal.ballots.iter() {
                        let voting_rights = (ballot.voting_power as f64) * reward_weight;
                        total_voting_rights += voting_rights;
                        #[allow(clippy::blocks_in_conditions)]
                        if Vote::try_from(ballot.vote)
                            .unwrap_or_else(|_| {
                                println!(
                                    "{}Vote::from invoked with unexpected value {}.",
                                    LOG_PREFIX, ballot.vote
                                );
                                Vote::Unspecified
                            })
                            .eligible_for_rewards()
                        {
                            *voters_to_used_voting_right
                                .entry(NeuronId { id: *voter })
                                .or_insert(0f64) += voting_rights;
                        }
                    }
                }
            }
            (voters_to_used_voting_right, total_voting_rights)
        };

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
        if total_voting_rights < 0.001 {
            println!(
                "{}WARNING: total_voting_rights == {}, even though considered_proposals \
                 is nonempty (see earlier log). Therefore, we skip incrementing maturity \
                 to avoid dividing by zero (or super small number).",
                LOG_PREFIX, total_voting_rights,
            );
        } else {
            for (neuron_id, used_voting_rights) in voters_to_used_voting_right {
                let maybe_reward = self.with_neuron_mut(&neuron_id, |neuron| {
                    // Note that " as u64" rounds toward zero; this is the desired
                    // behavior here. Also note that `total_voting_rights` has
                    // to be positive because (1) voters_to_used_voting_right
                    // is non-empty (otherwise we wouldn't be here in the
                    // first place) and (2) the voting power of all ballots is
                    // positive (non-zero).
                    let reward = (used_voting_rights * total_available_e8s_equivalent_float
                        / total_voting_rights) as u64;
                    // If the neuron has auto-stake-maturity on, add the new maturity to the
                    // staked maturity, otherwise add it to the un-staked maturity.
                    if neuron.auto_stake_maturity.unwrap_or(false) {
                        neuron.staked_maturity_e8s_equivalent =
                            Some(neuron.staked_maturity_e8s_equivalent.unwrap_or(0) + reward);
                    } else {
                        neuron.maturity_e8s_equivalent += reward;
                    }
                    reward
                });
                match maybe_reward {
                    Ok(reward) => {
                        actually_distributed_e8s_equivalent += reward;
                    }
                    Err(e) => println!(
                        "{}Cannot find neuron {}, despite having voted with power {} \
                            in the considered reward period. The reward that should have been \
                            distributed to this neuron is simply skipped, so the total amount \
                            of distributed reward for this period will be lower than the maximum \
                            allowed. Underlying error: {:?}.",
                        LOG_PREFIX, neuron_id.id, used_voting_rights, e
                    ),
                }
            }
        }

        // Mark the proposals that we just considered as "rewarded". More
        // formally, causes their reward_status to be Settled; whereas, before,
        // they were in the ReadyToSettle state.
        for pid in considered_proposals.iter() {
            // Before considering a proposal for reward, it must be fully processed --
            // because we're about to clear the ballots, so no further processing will be
            // possible.
            self.process_proposal(pid.id);

            match self.mut_proposal_data(*pid) {
                None =>  println!(
                    "{}Cannot find proposal {}, despite it being considered for rewards distribution.",
                    LOG_PREFIX, pid.id
                ),
                Some(p) => {
                    if p.status() == ProposalStatus::Open {
                        println!("{}Proposal {} was considered for reward distribution despite \
                          being open. This code line is expected not to be reachable. We need to \
                          clear the ballots here to avoid a risk of the memory getting too large. \
                          In doubt, reject the proposal", LOG_PREFIX, pid.id);
                        p.decided_timestamp_seconds = now;
                        p.latest_tally = Some(Tally {
                            timestamp_seconds: now,
                            yes:0,
                            no:0,
                            total:0,
                       })
                    };
                    p.reward_event_round = day_after_genesis;
                    p.ballots.clear();
                }
            };
        }

        if considered_proposals.is_empty() {
            println!(
                "{}Voting rewards will roll over, because no there were proposals \
                 that needed rewards (i.e. have reward_status == ReadyToSettle)",
                LOG_PREFIX,
            );
        };

        self.heap_data.latest_reward_event = Some(RewardEvent {
            day_after_genesis,
            actual_timestamp_seconds: now,
            settled_proposals: considered_proposals,
            distributed_e8s_equivalent: actually_distributed_e8s_equivalent,
            total_available_e8s_equivalent: total_available_e8s_equivalent_float as u64,
            rounds_since_last_distribution: Some(rounds_since_last_distribution),
            latest_round_available_e8s_equivalent: Some(
                latest_round_available_e8s_equivalent_float as u64,
            ),
        })
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
    pub fn voting_period_seconds(&self) -> impl Fn(Topic) -> u64 {
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
                    format!("Node Provider {} is not known by the NNS", node_provider_id),
                )
            })?;

        if let Some(new_reward_account) = update.reward_account {
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
                format!("Proposal {:?} not found ({})", proposal_id, context),
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
                format!("Proposal {:?} not found ({})", proposal_id, context),
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
                format!("Proposal {:?} not found ({})", proposal_id, context),
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
                    "Caller {} is not a valid CanisterId and is not authorized to \
                        settle Neuron's Fund participation in a decentralization swap. Err: {:?}",
                    caller, err,
                ),
            )
        })?;
        if let Err(err_msg) =
            is_canister_id_valid_swap_canister_id(target_canister_id, &mut *self.env).await
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                format!(
                    "Caller {} is not authorized to settle Neurons' Fund \
                    participation in a decentralization swap. Err: {:?}",
                    caller, err_msg,
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
                        "The maximum number of Neurons' Fund participants ({}) must not exceed \
                        MAX_NEURONS_FUND_PARTICIPANTS ({}).",
                        maximum_neurons_fund_participants, MAX_NEURONS_FUND_PARTICIPANTS,
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
                format!(
                    "ProposalData must be present for proposal {:?}.",
                    proposal_id
                ),
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
                    format!(
                        "Minting ICP from the Neuron's Fund failed with error: {:#?}",
                        err
                    ),
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
                    format!("Node Provider {} is not known by the NNS", node_provider_id),
                )
            })
    }

    /// Return the monthly rewards that node providers should be awarded
    ///
    /// Fetches the map from node provider to monthly XDR rewards from the
    /// Registry, then fetches the average XDR to ICP conversion rate for
    /// the last 30 days, then applies this conversion rate to convert each
    /// node provider's XDR rewards to ICP.
    pub async fn get_monthly_node_provider_rewards(
        &mut self,
    ) -> Result<MonthlyNodeProviderRewards, GovernanceError> {
        let mut rewards = vec![];

        // Maps node providers to their rewards in XDR
        let xdr_permyriad_rewards: NodeProvidersMonthlyXdrRewards =
            self.get_node_providers_monthly_xdr_rewards().await?;

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
                let np_id_str = np_id.to_string();
                let xdr_permyriad_reward =
                    *xdr_permyriad_rewards.rewards.get(&np_id_str).unwrap_or(&0);

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

        let registry_version = xdr_permyriad_rewards.registry_version.unwrap();

        Ok(MonthlyNodeProviderRewards {
            timestamp: self.env.now(),
            rewards,
            xdr_conversion_rate: Some(xdr_conversion_rate.into()),
            minimum_xdr_permyriad_per_icp: Some(minimum_xdr_permyriad_per_icp),
            maximum_node_provider_rewards_e8s: Some(maximum_node_provider_rewards_e8s),
            registry_version: Some(registry_version),
            node_providers: self.heap_data.node_providers.clone(),
        })
    }

    /// A helper for the Registry's get_node_providers_monthly_xdr_rewards method
    async fn get_node_providers_monthly_xdr_rewards(
        &mut self,
    ) -> Result<NodeProvidersMonthlyXdrRewards, GovernanceError> {
        let registry_response:
            Vec<u8> = self
            .env
            .call_canister_method(
                REGISTRY_CANISTER_ID,
                "get_node_providers_monthly_xdr_rewards",
                Encode!().unwrap(),
            )
            .await
            .map_err(|(code, msg)| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Error calling 'get_node_providers_monthly_xdr_rewards': code: {:?}, message: {}",
                        code, msg
                    ),
                )
            })?;

        Decode!(&registry_response, Result<NodeProvidersMonthlyXdrRewards, String>)
            .map_err(|err| GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Cannot decode return type from get_node_providers_monthly_xdr_rewards'. Error: {}",
                    err,
                ),
            ))?
            .map_err(|msg| GovernanceError::new_with_message(ErrorType::External, msg))
    }

    /// A helper for the CMC's get_average_icp_xdr_conversion_rate method
    async fn get_average_icp_xdr_conversion_rate(
        &mut self,
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
                        "Error calling 'get_average_icp_xdr_conversion_rate': code: {:?}, message: {}",
                        code, msg
                    ),
                )
            })?;

        Decode!(&cmc_response, IcpXdrConversionRateCertifiedResponse)
            .map_err(|err| GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Cannot decode return type from get_average_icp_xdr_conversion_rate'. Error: {}",
                    err,
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
        let time_of_day_seconds = self.env.random_u64() % ONE_DAY_SECONDS;

        // Round down to nearest multiple of 15 min.
        let remainder_seconds = time_of_day_seconds % (15 * 60);
        let seconds_after_utc_midnight = Some(time_of_day_seconds - remainder_seconds);

        GlobalTimeOfDay {
            seconds_after_utc_midnight,
        }
    }

    /// Iterate over all neurons and compute `GovernanceCachedMetrics`
    pub fn compute_cached_metrics(&self, now: u64, icp_supply: Tokens) -> GovernanceCachedMetrics {
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
            non_self_authenticating_controller_neuron_subset_metrics,
            public_neuron_subset_metrics,
        } = self
            .neuron_store
            .compute_neuron_metrics(now, self.economics().neuron_minimum_stake_e8s);

        let total_staked_e8s_non_self_authenticating_controller =
            Some(non_self_authenticating_controller_neuron_subset_metrics.total_staked_e8s);
        let total_voting_power_non_self_authenticating_controller =
            Some(non_self_authenticating_controller_neuron_subset_metrics.total_voting_power);

        let non_self_authenticating_controller_neuron_subset_metrics = Some(
            NeuronSubsetMetricsPb::from(non_self_authenticating_controller_neuron_subset_metrics),
        );
        let public_neuron_subset_metrics =
            Some(NeuronSubsetMetricsPb::from(public_neuron_subset_metrics));

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
            total_staked_e8s_non_self_authenticating_controller,
            total_voting_power_non_self_authenticating_controller,

            non_self_authenticating_controller_neuron_subset_metrics,
            public_neuron_subset_metrics,
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

            count_buckets,
            staked_e8s_buckets,
            staked_maturity_e8s_equivalent_buckets,
            maturity_e8s_equivalent_buckets,
            voting_power_buckets,
        } = src;

        let count = Some(count);
        let total_staked_e8s = Some(total_staked_e8s);
        let total_staked_maturity_e8s_equivalent = Some(total_staked_maturity_e8s_equivalent);
        let total_maturity_e8s_equivalent = Some(total_maturity_e8s_equivalent);
        let total_voting_power = Some(total_voting_power);

        NeuronSubsetMetricsPb {
            count,
            total_staked_e8s,
            total_staked_maturity_e8s_equivalent,
            total_maturity_e8s_equivalent,
            total_voting_power,

            count_buckets,
            staked_e8s_buckets,
            staked_maturity_e8s_equivalent_buckets,
            maturity_e8s_equivalent_buckets,
            voting_power_buckets,
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
    env: &mut Box<dyn Environment>,
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
                     method call: {}\nrequest: {:#?}",
                err, request,
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
                format!(
                    "Failed to send deploy_new_sns request to SNS_WASM canister: {:?}",
                    err,
                ),
            )
        })?;

    // Step 2.3; Decode the response.
    let deploy_new_sns_response =
        Decode!(&deploy_new_sns_response, DeployNewSnsResponse).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!("Failed to decode deploy_new_sns response: {}", err),
            )
        })?;

    // Step 2.4: Convert to Result (from DeployNewSnsResponse).
    match deploy_new_sns_response.error {
        Some(err) => Err(GovernanceError::new_with_message(
            ErrorType::External,
            format!("Error in deploy_new_sns response: {:?}", err),
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

/// Given a target_canister_id, is it a CanisterId of a deployed SNS recorded by
/// the SNS-W canister.
async fn is_canister_id_valid_swap_canister_id(
    target_canister_id: CanisterId,
    env: &mut dyn Environment,
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
                "Failed to call the list_deployed_snses method on sns_wasm ({}): {:?}",
                SNS_WASM_CANISTER_ID, err,
            )
        })?;

    let list_deployed_snses_response =
        Decode!(&list_deployed_snses_response, ListDeployedSnsesResponse).map_err(|err| {
            format!(
                "Unable to decode response as ListDeployedSnsesResponse: {}. reply_bytes = {:#?}",
                err, list_deployed_snses_response,
            )
        })?;

    let is_swap = list_deployed_snses_response
        .instances
        .iter()
        .any(|sns| sns.swap_canister_id == Some(target_canister_id.into()));
    if !is_swap {
        return Err(format!(
            "target_swap_canister_id is not the ID of any swap canister known to sns_wasm: {}",
            target_canister_id
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
