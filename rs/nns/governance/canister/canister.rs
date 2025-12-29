use ic_base_types::PrincipalId;
use ic_cdk::{heartbeat, init, post_upgrade, pre_upgrade, println, query, update};
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_nervous_system_canisters::cmc::CMCCanister;
use ic_nervous_system_common::{
    memory_manager_upgrade_storage::{load_protobuf, store_protobuf},
    serve_metrics,
};
use ic_nervous_system_runtime::CdkRuntime;
use ic_nns_common::{
    access_control::{check_caller_is_gtc, check_caller_is_ledger},
    pb::v1::{NeuronId as NeuronIdProto, ProposalId as ProposalIdProto},
    types::{NeuronId, ProposalId},
};
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_nns_governance::{
    canister_state::{CanisterEnv, governance, governance_mut, set_governance},
    encode_metrics,
    governance::Governance,
    neuron_data_validation::NeuronDataValidationSummary,
    pb::v1::{self as gov_pb, Governance as InternalGovernanceProto},
    storage::{grow_upgrades_memory_to, validate_stable_storage, with_upgrades_memory},
    timer_tasks::schedule_tasks,
};
#[cfg(feature = "test")]
use ic_nns_governance_api::test_api::TimeWarp;
use ic_nns_governance_api::{
    ClaimOrRefreshNeuronFromAccount, ClaimOrRefreshNeuronFromAccountResponse,
    GetNeuronIndexRequest, GetNeuronsFundAuditInfoRequest, GetNeuronsFundAuditInfoResponse,
    GetPendingProposalsRequest, Governance as ApiGovernanceProto, GovernanceError,
    ListKnownNeuronsResponse, ListNeuronVotesRequest, ListNeuronVotesResponse, ListNeurons,
    ListNeuronsResponse, ListNodeProviderRewardsRequest, ListNodeProviderRewardsResponse,
    ListNodeProvidersResponse, ListProposalInfoRequest, ListProposalInfoResponse,
    ManageNeuronCommandRequest, ManageNeuronRequest, ManageNeuronResponse,
    MonthlyNodeProviderRewards, NetworkEconomics, Neuron, NeuronIndexData, NeuronInfo,
    NodeProvider, Proposal, ProposalInfo, RestoreAgingSummary, RewardEvent,
    SettleCommunityFundParticipation, SettleNeuronsFundParticipationRequest,
    SettleNeuronsFundParticipationResponse, UpdateNodeProvider, Vote,
    claim_or_refresh_neuron_from_account_response::Result as ClaimOrRefreshNeuronFromAccountResponseResult,
    governance::GovernanceCachedMetrics,
    governance_error::ErrorType,
    manage_neuron::{
        ClaimOrRefresh, NeuronIdOrSubaccount, RegisterVote,
        claim_or_refresh::{By, MemoAndController},
    },
    manage_neuron_response,
};
use std::sync::Arc;
use std::{boxed::Box, time::Duration};

#[cfg(feature = "test")]
use ic_nns_governance::governance::TimeWarp as GovTimeWarp;

use ic_nns_governance::canister_state::{CanisterRandomnessGenerator, with_governance};

#[cfg(feature = "tla")]
mod tla_ledger;

#[cfg(not(feature = "tla"))]
use ic_nervous_system_canisters::ledger::IcpLedgerCanister;
#[cfg(feature = "tla")]
use tla_ledger::LoggingIcpLedgerCanister as IcpLedgerCanister;

/// WASM memory equivalent to 4GiB, which we want to reserve for upgrades memory. The heap memory
/// limit is 4GiB but its serialized form with prost should be smaller, so we reserve for 4GiB. This
/// is to make sure that even if we have a bug causing stable memory getting full, we do not trap in
/// pre_upgrade by trying to grow UPGRADES_MEMORY.
const WASM_PAGES_RESERVED_FOR_UPGRADES_MEMORY: u64 = 65_536;

pub(crate) const LOG_PREFIX: &str = "[Governance] ";

fn schedule_timers() {
    schedule_spawn_neurons();
    schedule_vote_processing();
    schedule_tasks();
}

const SPAWN_NEURONS_INTERVAL: Duration = Duration::from_secs(60);
fn schedule_spawn_neurons() {
    ic_cdk_timers::set_timer_interval(SPAWN_NEURONS_INTERVAL, async || {
        governance_mut().maybe_spawn_neurons().await;
    });
}

/// The interval at which the voting state machines are processed.
const VOTE_PROCESSING_INTERVAL: Duration = Duration::from_secs(3);

fn schedule_vote_processing() {
    ic_cdk_timers::set_timer_interval(VOTE_PROCESSING_INTERVAL, async || {
        governance_mut().process_voting_state_machines().await;
    });
}

// We expect PrincipalId for all methods, but ic_cdk returns candid::Principal, so we need to
// convert it.
fn caller() -> PrincipalId {
    PrincipalId::from(ic_cdk::api::msg_caller())
}

fn debug_log(s: &str) {
    if cfg!(feature = "test") {
        println!("{}{}", LOG_PREFIX, s);
    }
}

#[init]
fn canister_init(governance: ApiGovernanceProto) {
    canister_init_(governance);
}

fn canister_init_(init_payload: ApiGovernanceProto) {
    println!(
        "{}canister_init: Initializing with: economics: \
          {:?}, genesis_timestamp_seconds: {}, neuron count: {}",
        LOG_PREFIX,
        init_payload.economics,
        init_payload.genesis_timestamp_seconds,
        init_payload.neurons.len()
    );

    set_governance(Governance::new(
        init_payload,
        Arc::new(CanisterEnv::new()),
        Arc::new(IcpLedgerCanister::<CdkRuntime>::new(LEDGER_CANISTER_ID)),
        Arc::new(CMCCanister::<CdkRuntime>::new()),
        Box::new(CanisterRandomnessGenerator::new()),
    ));

    // Timers etc should not be scheduled until after Governance has been initialized, since
    // some of them may rely on Governance state to determine when they should run.
    schedule_timers();
}

#[pre_upgrade]
fn canister_pre_upgrade() {
    println!("{}Executing pre upgrade", LOG_PREFIX);

    with_upgrades_memory(|memory| {
        let governance_proto = governance_mut().take_heap_proto();
        store_protobuf(memory, &governance_proto).expect("Failed to encode protobuf pre_upgrade");
    });
}

#[post_upgrade]
fn canister_post_upgrade() {
    println!("{}Executing post upgrade", LOG_PREFIX);

    let restored_state = with_upgrades_memory(|memory| {
        let result: Result<InternalGovernanceProto, _> = load_protobuf(memory);
        result
    })
    .expect(
        "Error deserializing canister state post-upgrade with MemoryManager memory segment. \
             CANISTER MIGHT HAVE BROKEN STATE!!!!.",
    );

    grow_upgrades_memory_to(WASM_PAGES_RESERVED_FOR_UPGRADES_MEMORY);

    println!(
        "{}canister_post_upgrade: Initializing with: economics: \
          {:?}, genesis_timestamp_seconds: {}, xdr_conversion_rate: {:?}",
        LOG_PREFIX,
        restored_state.economics,
        restored_state.genesis_timestamp_seconds,
        restored_state.xdr_conversion_rate,
    );

    set_governance(Governance::new_restored(
        restored_state,
        Arc::new(CanisterEnv::new()),
        Arc::new(IcpLedgerCanister::<CdkRuntime>::new(LEDGER_CANISTER_ID)),
        Arc::new(CMCCanister::<CdkRuntime>::new()),
        Box::new(CanisterRandomnessGenerator::new()),
    ));

    validate_stable_storage();

    // Timers etc should not be scheduled until after Governance has been initialized, since
    // some of them may rely on Governance state to determine when they should run.
    schedule_timers();
}

#[cfg(feature = "test")]
#[update(hidden = true)]
fn set_time_warp(new_time_warp: TimeWarp) {
    governance_mut().set_time_warp(GovTimeWarp::from(new_time_warp));
}

/// DEPRECATED: Use manage_neuron directly instead.
#[update(hidden = true)]
async fn forward_vote(
    neuron_id: NeuronId,
    proposal_id: ProposalId,
    vote: Vote,
) -> ManageNeuronResponse {
    debug_log("forward_vote");
    manage_neuron(ManageNeuronRequest {
        id: Some(NeuronIdProto::from(neuron_id)),
        command: Some(ManageNeuronCommandRequest::RegisterVote(RegisterVote {
            proposal: Some(ProposalIdProto::from(proposal_id)),
            vote: vote as i32,
        })),
        neuron_id_or_subaccount: None,
    })
    .await
}

#[update(hidden = true)]
fn transfer_notification() {
    debug_log("neuron_stake_transfer_notification");
    check_caller_is_ledger();
    panic!("Method removed. Please use ManageNeuron::ClaimOrRefresh.",)
}

// DEPRECATED: Please use ManageNeuron::ClaimOrRefresh.
//
// Just redirects to ManageNeuron.
#[update]
async fn claim_or_refresh_neuron_from_account(
    claim_or_refresh: ClaimOrRefreshNeuronFromAccount,
) -> ClaimOrRefreshNeuronFromAccountResponse {
    debug_log("claim_or_refresh_neuron_from_account");
    let manage_neuron_response = manage_neuron(ManageNeuronRequest {
        id: None,
        command: Some(ManageNeuronCommandRequest::ClaimOrRefresh(ClaimOrRefresh {
            by: Some(By::MemoAndController(MemoAndController {
                memo: claim_or_refresh.memo,
                controller: claim_or_refresh.controller,
            })),
        })),
        neuron_id_or_subaccount: None,
    })
    .await;

    match manage_neuron_response.command.unwrap() {
        manage_neuron_response::Command::Error(error) => ClaimOrRefreshNeuronFromAccountResponse {
            result: Some(ClaimOrRefreshNeuronFromAccountResponseResult::Error(error)),
        },
        manage_neuron_response::Command::ClaimOrRefresh(response) => {
            ClaimOrRefreshNeuronFromAccountResponse {
                result: Some(ClaimOrRefreshNeuronFromAccountResponseResult::NeuronId(
                    response.refreshed_neuron_id.unwrap(),
                )),
            }
        }
        _ => panic!("Invalid command response"),
    }
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method_cdk! {}

#[update]
fn claim_gtc_neurons(
    new_controller: PrincipalId,
    neuron_ids: Vec<NeuronIdProto>,
) -> Result<(), GovernanceError> {
    debug_log("claim_gtc_neurons");
    check_caller_is_gtc();
    Ok(governance_mut().claim_gtc_neurons(&caller(), new_controller, neuron_ids)?)
}

#[update]
async fn transfer_gtc_neuron(
    donor_neuron_id: NeuronIdProto,
    recipient_neuron_id: NeuronIdProto,
) -> Result<(), GovernanceError> {
    debug_log("transfer_gtc_neuron");
    check_caller_is_gtc();
    Ok(governance_mut()
        .transfer_gtc_neuron(&caller(), &donor_neuron_id, &recipient_neuron_id)
        .await?)
}

#[update]
async fn manage_neuron(_manage_neuron: ManageNeuronRequest) -> ManageNeuronResponse {
    debug_log("manage_neuron");
    governance_mut()
        .manage_neuron(&caller(), &(gov_pb::ManageNeuron::from(_manage_neuron)))
        .await
}

#[cfg(feature = "test")]
#[update]
/// Internal method for calling update_neuron.
///
/// *_voting_power fields are ignored, because the value in those fields is derived.
fn update_neuron(neuron: Neuron) -> Option<GovernanceError> {
    debug_log("update_neuron");
    governance_mut()
        .update_neuron(neuron)
        .err()
        .map(GovernanceError::from)
}

#[update]
fn simulate_manage_neuron(manage_neuron: ManageNeuronRequest) -> ManageNeuronResponse {
    debug_log("simulate_manage_neuron");
    governance().simulate_manage_neuron(&caller(), gov_pb::ManageNeuron::from(manage_neuron))
}

#[query]
fn get_full_neuron_by_id_or_subaccount(
    by: NeuronIdOrSubaccount,
) -> Result<Neuron, GovernanceError> {
    debug_log("get_full_neuron_by_id_or_subaccount");
    governance()
        .get_full_neuron_by_id_or_subaccount(
            &(gov_pb::manage_neuron::NeuronIdOrSubaccount::from(by)),
            &caller(),
        )
        .map_err(GovernanceError::from)
}

#[query]
fn get_full_neuron(neuron_id: NeuronId) -> Result<Neuron, GovernanceError> {
    debug_log("get_full_neuron");
    governance()
        .get_full_neuron(&NeuronIdProto::from(neuron_id), &caller())
        .map_err(GovernanceError::from)
}

#[query]
fn get_neuron_info(neuron_id: NeuronId) -> Result<NeuronInfo, GovernanceError> {
    debug_log("get_neuron_info");
    governance()
        .get_neuron_info(&NeuronIdProto::from(neuron_id), caller())
        .map_err(GovernanceError::from)
}

#[query]
fn get_neuron_info_by_id_or_subaccount(
    by: NeuronIdOrSubaccount,
) -> Result<NeuronInfo, GovernanceError> {
    debug_log("get_neuron_info_by_subaccount");
    governance()
        .get_neuron_info_by_id_or_subaccount(
            &(gov_pb::manage_neuron::NeuronIdOrSubaccount::from(by)),
            caller(),
        )
        .map_err(GovernanceError::from)
}

#[query]
fn get_proposal_info(id: ProposalId) -> Option<ProposalInfo> {
    debug_log("get_proposal_info");
    with_governance(|governance| governance.get_proposal_info(&caller(), id))
}

#[query]
fn get_neurons_fund_audit_info(
    request: GetNeuronsFundAuditInfoRequest,
) -> GetNeuronsFundAuditInfoResponse {
    debug_log("get_neurons_fund_audit_info");
    let response = governance().get_neurons_fund_audit_info(request.into());
    let intermediate = gov_pb::GetNeuronsFundAuditInfoResponse::from(response);
    GetNeuronsFundAuditInfoResponse::from(intermediate)
}

#[query]
fn get_pending_proposals(req: Option<GetPendingProposalsRequest>) -> Vec<ProposalInfo> {
    debug_log("get_pending_proposals");
    with_governance(|governance| governance.get_pending_proposals(&caller(), req))
}

#[query]
fn list_proposals(req: ListProposalInfoRequest) -> ListProposalInfoResponse {
    debug_log("list_proposals");
    with_governance(|governance| governance.list_proposals(&caller(), req))
}

#[query]
fn list_neurons(req: ListNeurons) -> ListNeuronsResponse {
    debug_log("list_neurons");
    governance().list_neurons(&req, caller())
}

#[query]
fn get_neuron_index(req: GetNeuronIndexRequest) -> Result<NeuronIndexData, GovernanceError> {
    debug_log("get_neuron_index");
    governance()
        .get_neuron_index(req, caller())
        .map_err(GovernanceError::from)
}

#[query]
fn get_metrics() -> Result<GovernanceCachedMetrics, GovernanceError> {
    debug_log("get_metrics");
    governance()
        .get_metrics()
        .map(GovernanceCachedMetrics::from)
        .map_err(GovernanceError::from)
}

#[update]
async fn get_monthly_node_provider_rewards() -> Result<MonthlyNodeProviderRewards, GovernanceError>
{
    debug_log("get_monthly_node_provider_rewards");
    let rewards = governance_mut().get_monthly_node_provider_rewards().await?;
    Ok(MonthlyNodeProviderRewards::from(rewards))
}

#[update(hidden = true)]
async fn get_node_provider_rewards() -> Result<MonthlyNodeProviderRewards, GovernanceError> {
    debug_log("get_node_provider_rewards");
    let rewards = governance().get_node_providers_rewards_cached().await?;
    Ok(MonthlyNodeProviderRewards::from(rewards))
}

#[query]
fn list_node_provider_rewards(
    req: ListNodeProviderRewardsRequest,
) -> ListNodeProviderRewardsResponse {
    debug_log("list_node_provider_rewards");
    let rewards = governance()
        .list_node_provider_rewards(req.date_filter.map(|d| d.into()))
        .into_iter()
        .map(MonthlyNodeProviderRewards::from)
        .collect();

    ListNodeProviderRewardsResponse { rewards }
}

#[query]
fn list_known_neurons() -> ListKnownNeuronsResponse {
    debug_log("list_known_neurons");
    let response = governance().list_known_neurons();
    ListKnownNeuronsResponse::from(response)
}

/// DEPRECATED: Always panics. Use manage_neuron instead.
/// TODO(NNS1-413): Remove this once we are sure that there are no callers.
#[update(hidden = true)]
fn submit_proposal(_proposer: NeuronId, _proposal: Proposal, _caller: PrincipalId) -> ProposalId {
    panic!(
        "{LOG_PREFIX}submit_proposal is deprecated, and now always panics. \
               Use `manage_neuron` instead to submit a proposal."
    );
}

/// DEPRECATED: Proposals are now executed on every vote.
#[update(hidden = true)]
fn execute_eligible_proposals() {
    println!(
        "{}execute_eligible_proposals -- This method does nothing!",
        LOG_PREFIX
    )
}

#[query]
fn get_latest_reward_event() -> RewardEvent {
    debug_log("get_latest_reward_event");
    let response = governance().latest_reward_event().clone();
    RewardEvent::from(response)
}

/// Return the Neuron IDs of all Neurons that have `caller()` as their
/// controller or as one of their hot keys. Furthermore the Neuron IDs of all
/// Neurons that directly follow the former in the topic `NeuronManagement`
/// are included. Summarily, the Neuron IDs in the set returned can be queried
/// by `get_full_neuron` without getting an authorization error.
#[query]
fn get_neuron_ids() -> Vec<NeuronId> {
    debug_log("get_neuron_ids");
    let votable = governance()
        .get_neuron_ids_by_principal(&caller())
        .into_iter()
        .collect();

    governance()
        .get_managed_neuron_ids_for(votable)
        .into_iter()
        .map(NeuronId::from)
        .collect()
}

#[query]
fn get_network_economics_parameters() -> NetworkEconomics {
    debug_log("get_network_economics_parameters");
    let response = governance()
        .heap_data
        .economics
        .as_ref()
        .expect("Governance must have network economics.")
        .clone();
    NetworkEconomics::from(response)
}

#[heartbeat]
async fn heartbeat() {
    governance_mut().run_periodic_tasks().await
}

// Protobuf interface.
#[update]
fn update_node_provider(req: UpdateNodeProvider) -> Result<(), GovernanceError> {
    debug_log("update_node_provider");
    Ok(governance_mut().update_node_provider(&caller(), gov_pb::UpdateNodeProvider::from(req))?)
}

/// Obsolete, so always returns an error. Please use `settle_neurons_fund_participation`
/// instead.
#[update]
async fn settle_community_fund_participation(
    _request: SettleCommunityFundParticipation,
) -> Result<(), GovernanceError> {
    debug_log("settle_community_fund_participation");
    Err(GovernanceError::new_with_message(
        ErrorType::Unavailable,
        "settle_community_fund_participation is obsolete; please \
        use settle_neurons_fund_participation instead."
            .to_string(),
    ))
}

#[update]
async fn settle_neurons_fund_participation(
    request: SettleNeuronsFundParticipationRequest,
) -> SettleNeuronsFundParticipationResponse {
    debug_log("settle_neurons_fund_participation");
    let response = governance_mut()
        .settle_neurons_fund_participation(caller(), request.into())
        .await;
    let intermediate = gov_pb::SettleNeuronsFundParticipationResponse::from(response);
    SettleNeuronsFundParticipationResponse::from(intermediate)
}

/// Return the NodeProvider record where NodeProvider.id == caller(), if such a
/// NodeProvider record exists.
#[query]
fn get_node_provider_by_caller(_: ()) -> Result<NodeProvider, GovernanceError> {
    debug_log("get_node_provider_by_caller");
    governance()
        .get_node_provider(&caller())
        .map(NodeProvider::from)
        .map_err(GovernanceError::from)
}

#[query]
fn list_node_providers() -> ListNodeProvidersResponse {
    debug_log("list_node_providers");
    let node_providers = governance()
        .get_node_providers()
        .iter()
        .map(|np| NodeProvider::from(np.clone()))
        .collect::<Vec<_>>();
    ListNodeProvidersResponse { node_providers }
}

#[query]
fn get_most_recent_monthly_node_provider_rewards() -> Option<MonthlyNodeProviderRewards> {
    governance()
        .get_most_recent_monthly_node_provider_rewards()
        .map(MonthlyNodeProviderRewards::from)
}

#[query(hidden = true)]
fn get_neuron_data_validation_summary() -> NeuronDataValidationSummary {
    governance().neuron_data_validation_summary()
}

#[query]
fn get_restore_aging_summary() -> RestoreAgingSummary {
    let response = governance().get_restore_aging_summary().unwrap_or_default();
    RestoreAgingSummary::from(response)
}

#[query]
fn list_neuron_votes(request: ListNeuronVotesRequest) -> ListNeuronVotesResponse {
    with_governance(|governance| {
        governance
            .list_neuron_votes(request)
            .map_err(GovernanceError::from)
    })
}

#[query(
    hidden = true,
    decode_with = "candid::decode_one_with_decoding_quota::<100000,_>"
)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => serve_metrics(|encoder| encode_metrics(governance(), encoder)),
        _ => HttpResponseBuilder::not_found().build(),
    }
}

fn main() {
    // This block is intentionally left blank.
}

// A query method to get the TLA traces collected in a test run.
#[cfg(all(feature = "tla", feature = "test"))]
#[query(hidden = true)]
fn get_tla_traces() -> Vec<tla_instrumentation::UpdateTrace> {
    use ic_nns_governance::governance::tla::TLA_TRACES_MUTEX;
    let mut traces = TLA_TRACES_MUTEX
        .as_ref()
        .expect("TLA_TRACES_MUTEX is None in get_tla_traces")
        .write()
        .expect("Couldn't acquire TLA_TRACES_MUTEX write lock in get_tla_traces");
    let mut result = Vec::new();
    std::mem::swap(&mut result, &mut *traces);
    result
}

// In order for some of the test(s) within this mod to work,
// this MUST occur at the end.
#[cfg(test)]
mod tests;
