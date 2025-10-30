// TODO: Jira ticket NNS1-3556
#![allow(deprecated)]
#![allow(static_mut_refs)]
use async_trait::async_trait;
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_log::log;
use ic_canister_profiler::{measure_span, measure_span_async};
use ic_cdk::{caller as cdk_caller, init, post_upgrade, pre_upgrade, println, query, update};
use ic_cdk_timers::TimerId;
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_nervous_system_canisters::{cmc::CMCCanister, ledger::IcpLedgerCanister};
use ic_nervous_system_clients::{
    canister_status::CanisterStatusResultV2, ledger_client::LedgerCanister,
};
use ic_nervous_system_common::{
    memory_manager_upgrade_storage::{load_protobuf, store_protobuf},
    serve_logs, serve_logs_v2, serve_metrics,
};
use ic_nervous_system_proto::pb::v1::{
    GetTimersRequest, GetTimersResponse, ResetTimersRequest, ResetTimersResponse, Timers,
};
use ic_nervous_system_runtime::CdkRuntime;
use ic_nns_constants::LEDGER_CANISTER_ID as NNS_LEDGER_CANISTER_ID;
#[cfg(feature = "test")]
use ic_sns_governance::extensions::add_allowed_extension_spec;
#[cfg(feature = "test")]
use ic_sns_governance::pb::v1::AddAllowedExtensionRequest;
use ic_sns_governance::{
    governance::{Governance, TimeWarp, ValidGovernanceProto, log_prefix},
    logs::{ERROR, INFO},
    pb::v1::{self as sns_gov_pb},
    storage::with_upgrades_memory,
    types::{Environment, HeapGrowthPotential},
    upgrade_journal::serve_journal,
};
#[cfg(feature = "test")]
use ic_sns_governance_api::pb::v1::{
    AddMaturityRequest, AddMaturityResponse, AdvanceTargetVersionRequest,
    AdvanceTargetVersionResponse, MintTokensRequest, MintTokensResponse,
    RefreshCachedUpgradeStepsRequest, RefreshCachedUpgradeStepsResponse,
};
use ic_sns_governance_api::pb::v1::{
    ClaimSwapNeuronsRequest, ClaimSwapNeuronsResponse, FailStuckUpgradeInProgressRequest,
    FailStuckUpgradeInProgressResponse, GetMaturityModulationRequest,
    GetMaturityModulationResponse, GetMetadataRequest, GetMetadataResponse, GetMetricsRequest,
    GetMode, GetModeResponse, GetNeuron, GetNeuronResponse, GetProposal, GetProposalResponse,
    GetRunningSnsVersionRequest, GetRunningSnsVersionResponse,
    GetSnsInitializationParametersRequest, GetSnsInitializationParametersResponse,
    GetUpgradeJournalRequest, GetUpgradeJournalResponse, Governance as GovernanceApi,
    GovernanceError, ListNervousSystemFunctionsResponse, ListNeurons, ListNeuronsResponse,
    ListProposals, ListProposalsResponse, ManageNeuron, ManageNeuronResponse,
    NervousSystemParameters, RewardEvent, SetMode, SetModeResponse, get_metrics_response,
    get_running_sns_version_response::UpgradeInProgress,
    governance::Version,
    governance_error::ErrorType,
    topics::{ListTopicsRequest, ListTopicsResponse},
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{
    boxed::Box,
    cell::RefCell,
    convert::TryFrom,
    time::{Duration, SystemTime},
};

static mut GOVERNANCE: Option<Governance> = None;

thread_local! {
    static TIMER_ID: RefCell<Option<TimerId>> = RefCell::new(Default::default());
}

/// This guarantees that timers cannot be restarted more often than once every 60 intervals.
const RESET_TIMERS_COOL_DOWN_INTERVAL: Duration = Duration::from_secs(600);

const RUN_PERIODIC_TASKS_INTERVAL: Duration = Duration::from_secs(10);

/// Returns an immutable reference to the governance's global state.
///
/// This should only be called once the global state has been initialized, which
/// happens in `canister_init` or `canister_post_upgrade`.
fn governance() -> &'static Governance {
    unsafe { GOVERNANCE.as_ref().expect("Canister not initialized!") }
}

/// Returns a mutable reference to the governance's global state.
///
/// This should only be called once the global state has been initialized, which
/// happens in `canister_init` or `canister_post_upgrade`.
fn governance_mut() -> &'static mut Governance {
    unsafe { GOVERNANCE.as_mut().expect("Canister not initialized!") }
}

struct CanisterEnv {
    rng: ChaCha20Rng,
    time_warp: TimeWarp,
}

impl CanisterEnv {
    fn new() -> Self {
        CanisterEnv {
            // Seed the pseudo-random number generator (PRNG) with the current time.
            //
            // All replicas are guaranteed to see the same result of now() and the resulting
            // number isn't easily predictable from the outside.
            //
            // Why we don't use raw_rand from the ic00 api instead: this is an asynchronous
            // call so can't really be used to generate random numbers for most cases.
            // It could be used to seed the PRNG, but that wouldn't add any security regarding
            // unpredictability since the pseudo-random numbers could still be predicted after
            // inception.
            rng: {
                let now_nanos = now_nanoseconds() as u128;
                let mut seed = [0u8; 32];
                seed[..16].copy_from_slice(&now_nanos.to_be_bytes());
                seed[16..32].copy_from_slice(&now_nanos.to_be_bytes());
                ChaCha20Rng::from_seed(seed)
            },
            time_warp: TimeWarp { delta_s: 0 },
        }
    }
}

#[async_trait]
impl Environment for CanisterEnv {
    fn now(&self) -> u64 {
        self.time_warp.apply(now_seconds())
    }

    fn set_time_warp(&mut self, new_time_warp: TimeWarp) {
        self.time_warp = new_time_warp;
    }

    // Returns a random u64.
    fn insecure_random_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    // Calls an external method (i.e., on a canister outside the nervous system) to execute a
    // proposal as a result of the proposal being adopted.
    //
    // The method returns either a success or error.
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
    > {
        // Due to object safety constraints in Rust, call_canister sends and returns bytes, so we are using
        // call_raw here instead of call, which requires known candid types.
        ic_cdk::api::call::call_raw(canister_id.get().0, method_name, &arg, 0)
            .await
            .map_err(|(rejection_code, message)| (Some(rejection_code as i32), message))
    }

    #[cfg(target_arch = "wasm32")]
    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        if core::arch::wasm32::memory_size(0)
            < ic_sns_governance::governance::HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES
        {
            HeapGrowthPotential::NoIssue
        } else {
            HeapGrowthPotential::LimitedAvailability
        }
    }

    /// Returns how much the heap can still grow.
    #[cfg(not(target_arch = "wasm32"))]
    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        unimplemented!("CanisterEnv can only be used with wasm32 environment.");
    }

    /// Return the canister's ID.
    fn canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(PrincipalId::from(ic_cdk::id()))
    }

    /// Return the canister version.
    fn canister_version(&self) -> Option<u64> {
        Some(ic_cdk::api::canister_version())
    }
}

fn now_nanoseconds() -> u64 {
    if cfg!(target_arch = "wasm32") {
        ic_cdk::api::time()
    } else {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get time since epoch")
            .as_nanos()
            .try_into()
            .expect("Failed to convert time to u64")
    }
}

fn now_seconds() -> u64 {
    Duration::from_nanos(now_nanoseconds()).as_secs()
}

fn caller() -> PrincipalId {
    PrincipalId::from(cdk_caller())
}

#[init]
fn canister_init(init_payload: GovernanceApi) {
    let init_payload = sns_gov_pb::Governance::from(init_payload);
    canister_init_(init_payload);
}

fn canister_init_(init_payload: sns_gov_pb::Governance) {
    let init_payload = ValidGovernanceProto::try_from(init_payload).expect(
        "Cannot start canister, because the deserialized \
         GovernanceProto is invalid in some way",
    );

    log!(
        INFO,
        "canister_init_: Initializing with: {}",
        init_payload.summary(),
    );

    let ledger_canister_id = init_payload.ledger_canister_id();

    unsafe {
        assert!(
            GOVERNANCE.is_none(),
            "{}Trying to initialize an already-initialized governance canister!",
            log_prefix()
        );
        let governance = Governance::new(
            init_payload,
            Box::new(CanisterEnv::new()),
            Box::new(LedgerCanister::new(ledger_canister_id)),
            Box::new(IcpLedgerCanister::<CdkRuntime>::new(NNS_LEDGER_CANISTER_ID)),
            Box::new(CMCCanister::<CdkRuntime>::new()),
        );
        let governance = if cfg!(feature = "test") {
            governance.enable_test_features()
        } else {
            governance
        };
        GOVERNANCE = Some(governance);
    }

    init_timers();
}

/// Executes some logic before executing an upgrade, including serializing and writing the
/// governance's state to stable memory so that it is preserved during the upgrade and can
/// be deserialized again in canister_post_upgrade. That is, the stable memory allows
/// saving the state and restoring it after the upgrade.
#[pre_upgrade]
fn canister_pre_upgrade() {
    log!(INFO, "Executing pre upgrade");

    with_upgrades_memory(|memory| {
        store_protobuf(memory, &governance().proto).expect("Failed to encode protobuf pre_upgrade")
    });

    log!(INFO, "Completed pre upgrade");
}

/// Executes some logic after executing an upgrade, including deserializing what has been written
/// to stable memory in canister_pre_upgrade and initializing the governance's state with it.
#[post_upgrade]
fn canister_post_upgrade() {
    log!(INFO, "Executing post upgrade");

    let governance_proto = with_upgrades_memory(|memory| {
        let result: Result<sns_gov_pb::Governance, _> = load_protobuf(memory);
        result
    })
    .expect(
        "Error deserializing canister state post-upgrade with MemoryManager memory segment. \
             CANISTER MIGHT HAVE BROKEN STATE!!!!.",
    );

    canister_init_(governance_proto);

    init_timers();

    log!(INFO, "Completed post upgrade");
}

/// Test only feature. Internal method for calling set_time_warp.
#[cfg(feature = "test")]
#[update(hidden = true)]
fn set_time_warp(new_time_warp: TimeWarp) {
    governance_mut().env.set_time_warp(new_time_warp);
}

/// Returns the governance's NervousSystemParameters
#[query]
fn get_nervous_system_parameters(_: ()) -> NervousSystemParameters {
    log!(INFO, "get_nervous_system_parameters");
    NervousSystemParameters::from(
        governance()
            .proto
            .parameters
            .clone()
            .expect("NervousSystemParameters are not set"),
    )
}

/// Returns metadata describing the SNS.
#[query]
fn get_metadata(request: GetMetadataRequest) -> GetMetadataResponse {
    log!(INFO, "get_metadata");
    GetMetadataResponse::from(
        governance().get_metadata(&sns_gov_pb::GetMetadataRequest::from(request)),
    )
}

async fn get_metrics_common(
    request: GetMetricsRequest,
) -> get_metrics_response::GetMetricsResponse {
    use get_metrics_response::*;

    let request = sns_gov_pb::GetMetricsRequest::try_from(request);

    let time_window_seconds = match request {
        Ok(request) => request.time_window_seconds,
        Err(error_message) => {
            return GetMetricsResponse {
                get_metrics_result: Some(GetMetricsResult::Err(GovernanceError {
                    error_type: i32::from(ErrorType::InvalidCommand),
                    error_message,
                })),
            };
        }
    };

    let result = governance().get_metrics(time_window_seconds).await;

    let get_metrics_result = match result {
        Ok(metrics) => {
            let metrics = Metrics::from(metrics);
            Some(GetMetricsResult::Ok(metrics))
        }
        Err(err) => {
            let err = GovernanceError::from(err);
            Some(GetMetricsResult::Err(err))
        }
    };
    GetMetricsResponse { get_metrics_result }
}

/// Returns statistics of the SNS
///
/// Cannot be called by other canisters. See also: [`get_metrics_replicated`].
#[query(composite = true)]
async fn get_metrics(request: GetMetricsRequest) -> get_metrics_response::GetMetricsResponse {
    log!(INFO, "get_metrics");
    get_metrics_common(request).await
}

/// Returns statistics of the SNS
///
/// Can be called by other canisters. See also: [`get_metrics`].
#[update]
async fn get_metrics_replicated(
    request: GetMetricsRequest,
) -> get_metrics_response::GetMetricsResponse {
    log!(INFO, "get_metrics_replicated");
    get_metrics_common(request).await
}

/// Returns the initialization parameters used to spawn an SNS
#[query]
fn get_sns_initialization_parameters(
    request: GetSnsInitializationParametersRequest,
) -> GetSnsInitializationParametersResponse {
    log!(INFO, "get_sns_initialization_parameters");
    GetSnsInitializationParametersResponse::from(governance().get_sns_initialization_parameters(
        &sns_gov_pb::GetSnsInitializationParametersRequest::from(request),
    ))
}

/// Performs a command on a neuron if the caller is authorized to do so.
/// The possible neuron commands are (for details, see the SNS's governance.proto):
/// - configuring the neuron (increasing or setting its dissolve delay or changing the
///   dissolve state),
/// - disbursing the neuron's stake to a ledger account
/// - following a set of neurons for proposals of a certain action
/// - make a proposal in the name of the neuron
/// - register a vote for the neuron
/// - split the neuron
/// - claim or refresh the neuron
/// - merge the neuron's maturity into the neuron's stake
#[update]
async fn manage_neuron(request: ManageNeuron) -> ManageNeuronResponse {
    log!(INFO, "manage_neuron");
    let governance = governance_mut();
    let result = measure_span_async(
        governance.profiling_information,
        "manage_neuron",
        governance.manage_neuron(&sns_gov_pb::ManageNeuron::from(request), &caller()),
    )
    .await;
    ManageNeuronResponse::from(result)
}

#[cfg(feature = "test")]
#[update]
/// Test only feature. Update neuron parameters.
fn update_neuron(neuron: ic_sns_governance_api::pb::v1::Neuron) -> Option<GovernanceError> {
    log!(INFO, "update_neuron");
    let governance = governance_mut();
    measure_span(governance.profiling_information, "update_neuron", || {
        governance
            .update_neuron(sns_gov_pb::Neuron::from(neuron))
            .map_err(GovernanceError::from)
            .err()
    })
}

/// Returns the full neuron corresponding to the neuron with ID `neuron_id`.
#[query]
fn get_neuron(request: GetNeuron) -> GetNeuronResponse {
    log!(INFO, "get_neuron");
    GetNeuronResponse::from(governance().get_neuron(sns_gov_pb::GetNeuron::from(request)))
}

/// Returns a list of neurons of size `limit` using `start_page_at` to
/// indicate the start of the list. Specifying `of_principal` will return
/// Neurons of which the given PrincipalId has permissions.
///
/// To paginate through the all neurons, `start_page_at` should be set to
/// the last neuron of the previously returned page and will not be included
/// in the next page. If not set, i.e. in the first call to list_neurons,
/// list_neurons will return a page of size `limit` starting at the neuron
/// with the smallest ID. Neurons are not kept in any specific order, but their
/// ordering is deterministic, so this can be used to return all the neurons one
/// page at a time.
///
/// If this method is called as a query call, the returned list is not certified.
#[query]
fn list_neurons(request: ListNeurons) -> ListNeuronsResponse {
    log!(INFO, "list_neurons");
    ListNeuronsResponse::from(governance().list_neurons(&sns_gov_pb::ListNeurons::from(request)))
}

/// Returns the full proposal corresponding to the `proposal_id`.
#[query]
fn get_proposal(request: GetProposal) -> GetProposalResponse {
    GetProposalResponse::from(governance().get_proposal(&sns_gov_pb::GetProposal::from(request)))
}

/// Returns a list of proposals of size `limit` using `before_proposal` to
/// indicate the start of the list. Additional filter parameters can be set on the
/// request.
///
/// Proposals are stored in increasing order of ids, where the most recent proposals
/// have the highest ids. ListProposals paginates in reverse, where the first proposals
/// returned are the most recent. To paginate through the all proposals, `before_proposal`
/// should be set to the last proposal of the previously returned page and will not be
/// included in the next page. If not set i.e. in the first call to list_proposals,
/// list_proposals will return a page of size `limit` starting at the most recent proposal.
///
/// If this method is called as a query call, the returned list is not certified.
#[query]
fn list_proposals(request: ListProposals) -> ListProposalsResponse {
    log!(INFO, "list_proposals");
    ListProposalsResponse::from(
        governance().list_proposals(&sns_gov_pb::ListProposals::from(request), &caller()),
    )
}

/// Returns the current list of available NervousSystemFunctions.
#[query]
fn list_nervous_system_functions() -> ListNervousSystemFunctionsResponse {
    log!(INFO, "list_nervous_system_functions");
    ListNervousSystemFunctionsResponse::from(governance().list_nervous_system_functions())
}

/// Returns the latest reward event.
#[query]
fn get_latest_reward_event() -> RewardEvent {
    log!(INFO, "get_latest_reward_event");
    RewardEvent::from(governance().latest_reward_event())
}

/// Deprecated method. Previously returned the root canister's status.
/// No longer necessary now that canisters can get their own status.
#[update]
#[allow(clippy::let_unit_value)] // clippy false positive
async fn get_root_canister_status(_: ()) -> CanisterStatusResultV2 {
    panic!(
        "This method is deprecated and should not be used. Please use the root canister's `get_sns_canisters_summary` method."
    )
}

/// Gets the current SNS version, as understood by Governance.  This is useful
/// for diagnosing upgrade problems, such as if multiple ledger archives are not
/// running the same version.
#[query]
fn get_running_sns_version(_: GetRunningSnsVersionRequest) -> GetRunningSnsVersionResponse {
    log!(INFO, "get_running_sns_version");
    let pending_version = governance().proto.pending_version.clone();
    let upgrade_in_progress = pending_version.map(|upgrade_in_progress| UpgradeInProgress {
        target_version: upgrade_in_progress
            .target_version
            .clone()
            .map(Version::from),
        mark_failed_at_seconds: upgrade_in_progress.mark_failed_at_seconds,
        checking_upgrade_lock: upgrade_in_progress.checking_upgrade_lock,
        proposal_id: upgrade_in_progress.proposal_id.unwrap_or(0),
    });
    GetRunningSnsVersionResponse {
        deployed_version: governance()
            .proto
            .deployed_version
            .clone()
            .map(Version::from),
        pending_version: upgrade_in_progress,
    }
}

/// Marks an in progress upgrade that has passed its deadline as failed.
#[update]
fn fail_stuck_upgrade_in_progress(
    request: FailStuckUpgradeInProgressRequest,
) -> FailStuckUpgradeInProgressResponse {
    log!(INFO, "fail_stuck_upgrade_in_progress");
    FailStuckUpgradeInProgressResponse::from(governance_mut().fail_stuck_upgrade_in_progress(
        sns_gov_pb::FailStuckUpgradeInProgressRequest::from(request),
    ))
}

/// Sets the mode. Only the swap canister is allowed to call this.
///
/// In practice, the only mode that the swap canister would ever choose is
/// Normal. Also, in practice, the current value of mode should be
/// PreInitializationSwap.  whenever the swap canister calls this.
#[update]
fn set_mode(request: SetMode) -> SetModeResponse {
    log!(INFO, "set_mode");
    governance_mut().set_mode(request.mode, caller());
    SetModeResponse {}
}

#[query]
fn get_mode(request: GetMode) -> GetModeResponse {
    log!(INFO, "get_mode");
    GetModeResponse::from(governance().get_mode(sns_gov_pb::GetMode::from(request)))
}

/// Claims a batch of neurons requested by the SNS Swap canister. This method is
/// only callable by the Swap canister that was deployed along with this
/// SNS Governance canister.
///
/// This API takes a request of multiple `NeuronRecipes` that provide
/// the configurable parameters of the to-be-created neurons. Since these neurons
/// are responsible for the decentralization of an SNS during the Swap, there are
/// a few differences in neuron creation that occur in comparison to the normal
/// `ManageNeuron::ClaimOrRefresh` API. See `Governance::claim_swap_neurons` for
/// more details.
///
/// This method is idempotent. If called with a `NeuronRecipes` of an already
/// created Neuron, the `ClaimSwapNeuronsResponse.skipped_claims` field will be
/// incremented and execution will continue.
#[update]
fn claim_swap_neurons(
    claim_swap_neurons_request: ClaimSwapNeuronsRequest,
) -> ClaimSwapNeuronsResponse {
    log!(INFO, "claim_swap_neurons");
    let governance = governance_mut();
    measure_span(
        governance.profiling_information,
        "claim_swap_neurons",
        || {
            ClaimSwapNeuronsResponse::from(governance.claim_swap_neurons(
                sns_gov_pb::ClaimSwapNeuronsRequest::from(claim_swap_neurons_request),
                caller(),
            ))
        },
    )
}

/// This is not really useful to the public. It is, however, useful to integration tests.
#[update]
fn get_maturity_modulation(request: GetMaturityModulationRequest) -> GetMaturityModulationResponse {
    log!(INFO, "get_maturity_modulation");
    let governance = governance_mut();
    measure_span(
        governance.profiling_information,
        "get_maturity_modulation",
        || {
            GetMaturityModulationResponse::from(
                governance.get_maturity_modulation(sns_gov_pb::GetMaturityModulationRequest::from(
                    request,
                )),
            )
        },
    )
}

async fn run_periodic_tasks() {
    if let Some(ref mut timers) = governance_mut().proto.timers {
        timers.last_spawned_timestamp_seconds.replace(now_seconds());
    };

    governance_mut().run_periodic_tasks().await;
}

/// Test only feature. Internal method for calling run_periodic_tasks.
#[cfg(feature = "test")]
#[update(hidden = true)]
async fn run_periodic_tasks_now(_request: ()) {
    governance_mut().run_periodic_tasks().await;
}

#[query]
fn get_timers(_arg: GetTimersRequest) -> GetTimersResponse {
    let timers = governance().proto.timers;
    GetTimersResponse { timers }
}

fn init_timers() {
    governance_mut().proto.timers.replace(Timers {
        last_reset_timestamp_seconds: Some(now_seconds()),
        ..Default::default()
    });

    let new_timer_id = ic_cdk_timers::set_timer_interval(RUN_PERIODIC_TASKS_INTERVAL, || {
        ic_cdk::spawn(run_periodic_tasks())
    });
    TIMER_ID.with(|saved_timer_id| {
        let mut saved_timer_id = saved_timer_id.borrow_mut();
        if let Some(saved_timer_id) = *saved_timer_id {
            ic_cdk_timers::clear_timer(saved_timer_id);
        }
        saved_timer_id.replace(new_timer_id);
    });
}

#[update]
fn reset_timers(_request: ResetTimersRequest) -> ResetTimersResponse {
    let reset_timers_cool_down_interval_seconds = RESET_TIMERS_COOL_DOWN_INTERVAL.as_secs();

    if let Some(timers) = governance_mut().proto.timers
        && let Some(last_reset_timestamp_seconds) = timers.last_reset_timestamp_seconds
    {
        assert!(
            now_seconds().saturating_sub(last_reset_timestamp_seconds)
                >= reset_timers_cool_down_interval_seconds,
            "Reset has already been called within the past {reset_timers_cool_down_interval_seconds:?} seconds"
        );
    }

    init_timers();

    ResetTimersResponse {}
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method_cdk! {}

/// Serve an HttpRequest made to this canister
#[query(
    hidden = true,
    decode_with = "candid::decode_one_with_decoding_quota::<100000,_>"
)]
pub fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/journal/json" => {
            let journal = governance()
                .proto
                .upgrade_journal
                .clone()
                .expect("The upgrade journal is not initialized for this SNS.");

            serve_journal(journal)
        }
        "/metrics" => serve_metrics(encode_metrics),
        "/logs" => serve_logs_v2(request, &INFO, &ERROR),

        // These are obsolete.
        "/log/info" => serve_logs(&INFO),
        "/log/error" => serve_logs(&ERROR),

        _ => HttpResponseBuilder::not_found().build(),
    }
}

/// Encode the metrics in a format that can be understood by Prometheus.
fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    let governance = governance();

    w.encode_gauge(
        "sns_governance_neurons_total",
        governance.proto.neurons.len() as f64,
        "Total number of neurons.",
    )?;

    match w.histogram_vec(
        "sns_governance_performance_metrics",
        "Performance data of the SNS governance canister.",
    ) {
        Ok(instrumentation_builder) => {
            let recording_result = governance
                .profiling_information
                .with(|r| r.borrow().record_metrics(instrumentation_builder));
            match recording_result {
                Ok(_) => {}
                Err(e) => {
                    log!(ERROR, "Unable to record instrumentation metrics: {}", e);
                }
            }
        }
        Err(e) => {
            log!(
                ERROR,
                "Unable to create instrumentation histogram builder: {}",
                e
            );
        }
    }

    Ok(())
}

/// Returns a list of topics
#[query]
async fn list_topics(request: ListTopicsRequest) -> ListTopicsResponse {
    let ListTopicsRequest {} = request;
    ListTopicsResponse::from(governance().list_topics())
}

/// Adds maturity to a neuron for testing
#[cfg(feature = "test")]
#[update]
fn add_maturity(request: AddMaturityRequest) -> AddMaturityResponse {
    AddMaturityResponse::from(
        governance_mut().add_maturity(sns_gov_pb::AddMaturityRequest::from(request)),
    )
}

#[query]
fn get_upgrade_journal(arg: GetUpgradeJournalRequest) -> GetUpgradeJournalResponse {
    GetUpgradeJournalResponse::from(
        governance().get_upgrade_journal(sns_gov_pb::GetUpgradeJournalRequest::from(arg)),
    )
}

/// Mints tokens for testing
#[cfg(feature = "test")]
#[update]
async fn mint_tokens(request: MintTokensRequest) -> MintTokensResponse {
    MintTokensResponse::from(
        governance_mut()
            .mint_tokens(sns_gov_pb::MintTokensRequest::from(request))
            .await,
    )
}

// Test-only API that advances the target version of the SNS.
#[cfg(feature = "test")]
#[update]
fn advance_target_version(request: AdvanceTargetVersionRequest) -> AdvanceTargetVersionResponse {
    AdvanceTargetVersionResponse::from(
        governance_mut()
            .advance_target_version(sns_gov_pb::AdvanceTargetVersionRequest::from(request)),
    )
}

/// Test only feature. Immediately refreshes the cached upgrade steps.
#[cfg(feature = "test")]
#[update]
async fn refresh_cached_upgrade_steps(
    _: RefreshCachedUpgradeStepsRequest,
) -> RefreshCachedUpgradeStepsResponse {
    let goverance = governance_mut();
    let deployed_version = goverance
        .try_temporarily_lock_refresh_cached_upgrade_steps()
        .unwrap();
    goverance
        .refresh_cached_upgrade_steps(deployed_version)
        .await;
    RefreshCachedUpgradeStepsResponse {}
}

#[cfg(feature = "test")]
#[update(hidden = true)]
async fn add_allowed_extension(request: AddAllowedExtensionRequest) {
    log!(INFO, "Adding an allowed extension!");
    let hash = <[u8; 32]>::try_from(request.wasm_hash).expect("Hash must be valid 32-bytes");
    let extension = request
        .spec
        .expect("ExtensionSpec is required")
        .try_into()
        .unwrap();
    add_allowed_extension_spec(hash, extension);
}

fn main() {
    // This block is intentionally left blank.
}

// In order for some of the test(s) within this mod to work,
// this MUST occur at the end.
#[cfg(test)]
mod tests;
