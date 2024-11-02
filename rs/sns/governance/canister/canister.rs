// Note on `candid_method`: each canister method should have a function
// annotated with `#[candid_method]` that has the arguments and return type
// expected by the canister method, to be able to generate `governance.did`
// automatically.
//
// This often means we need a function with `#[export_name = "canister_query
// my_method"]` that doesn't take arguments and doesn't return anything (per IC
// spec), then another function with the actual method arguments and return
// type, annotated with `#[candid_method(query/update)]` to be able to generate
// the did definition of the method.

use async_trait::async_trait;
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_log::log;
use ic_canister_profiler::{measure_span, measure_span_async};
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::{caller as cdk_caller, init, post_upgrade, pre_upgrade, query, update};
use ic_cdk_timers::TimerId;
use ic_nervous_system_canisters::{cmc::CMCCanister, ledger::IcpLedgerCanister};
use ic_nervous_system_clients::{
    canister_status::CanisterStatusResultV2, ledger_client::LedgerCanister,
};
use ic_nervous_system_common::{
    dfn_core_stable_mem_utils::{BufferedStableMemReader, BufferedStableMemWriter},
    serve_journal, serve_logs, serve_logs_v2, serve_metrics,
};
use ic_nervous_system_proto::pb::v1::{
    GetTimersRequest, GetTimersResponse, ResetTimersRequest, ResetTimersResponse, Timers,
};
use ic_nervous_system_runtime::CdkRuntime;
use ic_nns_constants::LEDGER_CANISTER_ID as NNS_LEDGER_CANISTER_ID;
#[cfg(feature = "test")]
use ic_sns_governance::pb::v1::{
    AddMaturityRequest, AddMaturityResponse, AdvanceTargetVersionRequest,
    AdvanceTargetVersionResponse, GovernanceError, MintTokensRequest, MintTokensResponse, Neuron,
};
use ic_sns_governance::{
    governance::{
        log_prefix, Governance, TimeWarp, ValidGovernanceProto, MATURITY_DISBURSEMENT_DELAY_SECONDS,
    },
    logs::{ERROR, INFO},
    pb::v1::{
        get_running_sns_version_response::UpgradeInProgress, ClaimSwapNeuronsRequest,
        ClaimSwapNeuronsResponse, FailStuckUpgradeInProgressRequest,
        FailStuckUpgradeInProgressResponse, GetMaturityModulationRequest,
        GetMaturityModulationResponse, GetMetadataRequest, GetMetadataResponse, GetMode,
        GetModeResponse, GetNeuron, GetNeuronResponse, GetProposal, GetProposalResponse,
        GetRunningSnsVersionRequest, GetRunningSnsVersionResponse,
        GetSnsInitializationParametersRequest, GetSnsInitializationParametersResponse,
        GetUpgradeJournalRequest, GetUpgradeJournalResponse, Governance as GovernanceProto,
        ListNervousSystemFunctionsResponse, ListNeurons, ListNeuronsResponse, ListProposals,
        ListProposalsResponse, ManageNeuron, ManageNeuronResponse, NervousSystemParameters,
        RewardEvent, SetMode, SetModeResponse,
    },
    types::{Environment, HeapGrowthPotential},
};
use prost::Message;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{
    boxed::Box,
    cell::RefCell,
    convert::TryFrom,
    time::{Duration, SystemTime},
};

/// Size of the buffer for stable memory reads and writes.
///
/// Smaller buffer size means more stable_write and stable_read calls. With
/// 100MiB buffer size, when the heap is near full, we need ~40 system calls.
/// Larger buffer size means we may not be able to serialize the heap fully in
/// some cases.
const STABLE_MEM_BUFFER_SIZE: u32 = 100 * 1024 * 1024; // 100MiB

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

/// In contrast to canister_init(), this method does not do deserialization.
/// In addition to canister_init, this method is called by canister_post_upgrade.
#[init]
fn canister_init_(init_payload: GovernanceProto) {
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

    let mut writer = BufferedStableMemWriter::new(STABLE_MEM_BUFFER_SIZE);

    governance()
        .proto
        .encode(&mut writer)
        .expect("Error. Couldn't serialize canister pre-upgrade.");

    writer.flush(); // or `drop(writer)`
    log!(INFO, "Completed pre upgrade");
}

/// Executes some logic after executing an upgrade, including deserializing what has been written
/// to stable memory in canister_pre_upgrade and initializing the governance's state with it.
#[post_upgrade]
fn canister_post_upgrade() {
    log!(INFO, "Executing post upgrade");

    let reader = BufferedStableMemReader::new(STABLE_MEM_BUFFER_SIZE);

    match GovernanceProto::decode(reader) {
        Err(err) => {
            log!(
                ERROR,
                "Error deserializing canister state post-upgrade. \
                 CANISTER MIGHT HAVE BROKEN STATE!!!!. Error: {:?}",
                err
            );
            Err(err)
        }
        Ok(mut governance_proto) => {
            // Post-process GovernanceProto

            // TODO: Delete this once it's been released.
            populate_finalize_disbursement_timestamp_seconds(&mut governance_proto);

            canister_init_(governance_proto);
            Ok(())
        }
    }
    .expect("Couldn't upgrade canister.");

    init_timers();

    log!(INFO, "Completed post upgrade");
}

fn populate_finalize_disbursement_timestamp_seconds(governance_proto: &mut GovernanceProto) {
    for neuron in governance_proto.neurons.values_mut() {
        for disbursement in neuron.disburse_maturity_in_progress.iter_mut() {
            disbursement.finalize_disbursement_timestamp_seconds = Some(
                disbursement.timestamp_of_disbursement_seconds
                    + MATURITY_DISBURSEMENT_DELAY_SECONDS,
            );
        }
    }
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
    governance()
        .proto
        .parameters
        .clone()
        .expect("NervousSystemParameters are not set")
}

/// Returns metadata describing the SNS.
#[query]
fn get_metadata(request: GetMetadataRequest) -> GetMetadataResponse {
    log!(INFO, "get_metadata");
    governance().get_metadata(&request)
}

/// Returns the initialization parameters used to spawn an SNS
#[query]
fn get_sns_initialization_parameters(
    request: GetSnsInitializationParametersRequest,
) -> GetSnsInitializationParametersResponse {
    log!(INFO, "get_sns_initialization_parameters");
    governance().get_sns_initialization_parameters(&request)
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
    measure_span_async(
        governance.profiling_information,
        "manage_neuron",
        governance.manage_neuron(&request, &caller()),
    )
    .await
}

#[cfg(feature = "test")]
#[update]
/// Test only feature. Update neuron parameters.
fn update_neuron(neuron: Neuron) -> Option<GovernanceError> {
    log!(INFO, "update_neuron");
    let governance = governance_mut();
    measure_span(governance.profiling_information, "update_neuron", || {
        governance.update_neuron(neuron).err()
    })
}

/// Returns the full neuron corresponding to the neuron with ID `neuron_id`.
#[query]
fn get_neuron(request: GetNeuron) -> GetNeuronResponse {
    log!(INFO, "get_neuron");
    governance().get_neuron(request)
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
    governance().list_neurons(&request)
}

/// Returns the full proposal corresponding to the `proposal_id`.
#[query]
fn get_proposal(request: GetProposal) -> GetProposalResponse {
    governance().get_proposal(&request)
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
    governance().list_proposals(&request, &caller())
}

/// Returns the current list of available NervousSystemFunctions.
#[query]
fn list_nervous_system_functions() -> ListNervousSystemFunctionsResponse {
    log!(INFO, "list_nervous_system_functions");
    governance().list_nervous_system_functions()
}

/// Returns the latest reward event.
#[query]
fn get_latest_reward_event() -> RewardEvent {
    log!(INFO, "get_latest_reward_event");
    governance().latest_reward_event()
}

/// Deprecated method. Previously returned the root canister's status.
/// No longer necessary now that canisters can get their own status.
#[update]
#[allow(clippy::let_unit_value)] // clippy false positive
async fn get_root_canister_status(_: ()) -> CanisterStatusResultV2 {
    panic!("This method is deprecated and should not be used. Please use the root canister's `get_sns_canisters_summary` method.")
}

/// Gets the current SNS version, as understood by Governance.  This is useful
/// for diagnosing upgrade problems, such as if multiple ledger archives are not
/// running the same version.
#[query]
fn get_running_sns_version(_: GetRunningSnsVersionRequest) -> GetRunningSnsVersionResponse {
    log!(INFO, "get_running_sns_version");
    let pending_version = governance().proto.pending_version.clone();
    let upgrade_in_progress = pending_version.map(|upgrade_in_progress| UpgradeInProgress {
        target_version: upgrade_in_progress.target_version.clone(),
        mark_failed_at_seconds: upgrade_in_progress.mark_failed_at_seconds,
        checking_upgrade_lock: upgrade_in_progress.checking_upgrade_lock,
        proposal_id: upgrade_in_progress.proposal_id.unwrap_or(0),
    });
    GetRunningSnsVersionResponse {
        deployed_version: governance().proto.deployed_version.clone(),
        pending_version: upgrade_in_progress,
    }
}

/// Marks an in progress upgrade that has passed its deadline as failed.
#[update]
fn fail_stuck_upgrade_in_progress(
    request: FailStuckUpgradeInProgressRequest,
) -> FailStuckUpgradeInProgressResponse {
    log!(INFO, "fail_stuck_upgrade_in_progress");
    governance_mut().fail_stuck_upgrade_in_progress(request)
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
    governance().get_mode(request)
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
        || governance.claim_swap_neurons(claim_swap_neurons_request, caller()),
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
        || governance.get_maturity_modulation(request),
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
fn get_timers(arg: GetTimersRequest) -> GetTimersResponse {
    let GetTimersRequest {} = arg;
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

    if let Some(timers) = governance_mut().proto.timers {
        if let Some(last_reset_timestamp_seconds) = timers.last_reset_timestamp_seconds {
            assert!(
                now_seconds().saturating_sub(last_reset_timestamp_seconds)
                    >= reset_timers_cool_down_interval_seconds,
                "Reset has already been called within the past {:?} seconds",
                reset_timers_cool_down_interval_seconds
            );
        }
    }

    init_timers();

    ResetTimersResponse {}
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method_cdk! {}

/// Serve an HttpRequest made to this canister
#[query(hidden = true, decoding_quota = 10000)]
pub fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/journal/json" => {
            let journal_entries = &governance()
                .proto
                .upgrade_journal
                .as_ref()
                .expect("The upgrade journal is not initialized for this SNS.")
                .entries;
            serve_journal(journal_entries)
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

/// Adds maturity to a neuron for testing
#[cfg(feature = "test")]
#[update]
fn add_maturity(request: AddMaturityRequest) -> AddMaturityResponse {
    governance_mut().add_maturity(request)
}

#[query]
fn get_upgrade_journal(arg: GetUpgradeJournalRequest) -> GetUpgradeJournalResponse {
    let GetUpgradeJournalRequest {} = arg;
    governance().get_upgrade_journal()
}

/// Mints tokens for testing
#[cfg(feature = "test")]
#[update]
async fn mint_tokens(request: MintTokensRequest) -> MintTokensResponse {
    governance_mut().mint_tokens(request).await
}

// Test-only API that advances the target version of the SNS.
#[cfg(feature = "test")]
#[update]
fn advance_target_version(request: AdvanceTargetVersionRequest) -> AdvanceTargetVersionResponse {
    governance_mut().advance_target_version(request)
}

// When run on native this prints the candid service definition of this
// canister, from the methods annotated with `candid_method` above.
//
// Note that `cargo test` calls `main`, and `export_service` (which defines
// `__export_service` in the current scope) needs to be called exactly once. So
// in addition to `not(target_arch = "wasm32")` we have a `not(test)` guard here
// to avoid calling `export_service`, which we need to call in the test below.
use std::fmt::Write;
use syn::{Fields, GenericArgument, Ident, Item, ItemEnum, ItemStruct, Type, Variant};

fn is_scalar(ty: &Type) -> bool {
    matches!(
        ty,
        Type::Path(type_path) if type_path.path.segments.len() == 1 &&
        matches!(
            type_path.path.segments.first().unwrap().ident.to_string().as_str(),
            "i8" | "i16" | "i32" | "i64" | "i128" |
            "u8" | "u16" | "u32" | "u64" | "u128" |
            "f32" | "f64" | "bool" | "char" | "String"
        )
    )
}

fn get_field_conversion_code(ty: &Type) -> String {
    let ty = ty.clone();
    match ty {
        Type::Path(type_path) => {
            // std::println!("Path");
            let segment = type_path.path.segments.first().unwrap();
            let ident = &segment.ident;
            // std::println!("{}", ident);

            for segment in &type_path.path.segments {
                let ident = &segment.ident;
                if ident == "Option" || ident == "Vec" {
                    let inner_type = if let syn::PathArguments::AngleBracketed(angle_bracketed) =
                        &segment.arguments
                    {
                        angle_bracketed
                            .args
                            .first()
                            .map(|angle| {
                                if let GenericArgument::Type(ty) = angle {
                                    Some(ty)
                                } else {
                                    None
                                }
                            })
                            .unwrap()
                    } else {
                        None
                    };

                    if inner_type.is_none() {
                        return "".to_string();
                    }
                    let inner_type = inner_type.unwrap();

                    if is_scalar(inner_type) {
                        return "".to_string();
                    }

                    let inner_type = if let Type::Path(foo) = inner_type {
                        let type_string = foo
                            .path
                            .segments
                            .clone()
                            .into_iter()
                            .map(|segment| segment.ident.to_string())
                            .collect::<Vec<String>>()
                            .join("::");
                        type_string
                    } else {
                        panic!("What else is there?");
                    };

                    if inner_type.starts_with("icp_ledger")
                        || inner_type.starts_with("ic_base_types")
                        || inner_type.starts_with("icp_ledger")
                        || inner_type.starts_with("ic_nns_common")
                        || inner_type.starts_with("ic_sns_swap")
                        || inner_type.starts_with("ic_nervous_system_proto")
                    {
                        return "".to_string();
                    }

                    if ident == "Option" {
                        return ".map(|x| x.into())".to_string();
                    }
                    return ".into_iter().map(|x| x.into()).collect()".to_string();
                }
                if ident == "HashMap" || ident == "BTreeMap" {
                    return ".into_iter().map(|(k, v)| (k.into(), v.into())).collect()".to_string();
                }
            }
        }

        Type::Array(_) => {
            std::println!("Array");
        }
        Type::BareFn(_) => {
            std::println!("BareFn");
        }
        Type::Group(_) => {
            std::println!("Group");
        }
        Type::ImplTrait(_) => {
            std::println!("ImplTrait");
        }
        Type::Infer(_) => {
            std::println!("Infer");
        }
        Type::Macro(_) => {
            std::println!("Macro");
        }
        Type::Never(_) => {
            std::println!("Never");
        }
        Type::Paren(_) => {
            std::println!("Paren");
        }
        Type::Ptr(_) => {
            std::println!("Ptr");
        }
        Type::Reference(_) => {
            std::println!("Reference");
        }
        Type::Slice(_) => {
            std::println!("Slice");
        }
        Type::TraitObject(_) => {
            std::println!("TraitObject");
        }
        Type::Tuple(_) => {
            std::println!("Tuple");
        }
        Type::Verbatim(_) => {
            std::println!("Verbatim");
        }

        _ => {
            std::println!("Other");
        }
    }

    "".to_string()
}

fn add_from_impls_for_struct(result: &mut String, item: &ItemStruct, prefix: &str) {
    let ty = format!("{}{}", prefix, item.ident);

    let (field_defs, has_fields) = match &item.fields {
        syn::Fields::Named(named) => {
            let fields = named
                .named
                .iter()
                .map(|field| {
                    let ident = field.ident.as_ref().unwrap();
                    // std::println!("{}", ident);
                    let conversion_code = get_field_conversion_code(&field.ty);
                    format!("{}: item.{}{}", ident, ident, conversion_code)
                })
                .collect::<Vec<String>>();
            let has_fields = !fields.is_empty();
            let fields_strings = fields.join(",\n            ");
            let fields_defs = format!(
                "Self {{
            {}
    }}",
                fields_strings
            );
            (fields_defs, has_fields)
        }
        syn::Fields::Unnamed(unnamed) => todo!(),
        syn::Fields::Unit => ("Self".to_string(), false),
    };

    let item_or_underscore = if has_fields { "item" } else { "_" };

    let _ = writeln!(
        result,
        "impl From<pb::{}> for pb_api::{} {{
    fn from({}: pb::{}) -> Self {{
        {}
    }}
}}
impl From<pb_api::{}> for pb::{} {{
    fn from({}: pb_api::{}) -> Self {{
        {}
    }}
}}
",
        ty, ty, item_or_underscore, ty, field_defs, ty, ty, item_or_underscore, ty, field_defs
    );
}

fn extract_variant_details(variant: &Variant) -> (String, Option<String>, bool) {
    let variant_name = variant.ident.to_string();

    let field_type = match &variant.fields {
        Fields::Unnamed(fields_unnamed) => {
            if let Some(field) = fields_unnamed.unnamed.first() {
                Some(field.ty.clone())
            } else {
                None
            }
        }
        _ => None,
    };

    let is_scalar = field_type.as_ref().map_or(false, |ty| is_scalar(ty));

    let variant_type = if let Some(Type::Path(type_path)) = field_type {
        let path = &type_path.path;
        let segments: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        Some(segments.join("::"))
    } else {
        None
    };

    (variant_name, variant_type, is_scalar)
}

fn add_from_impls_for_enum(result: &mut String, item: &ItemEnum, prefix: &str) {
    let ty = format!("{}{}", prefix, item.ident);

    let item = item.clone();

    let field_defs_pb_to_api = item
        .variants
        .iter()
        .map(|variant| {
            let (variant_name, variant_type, scalar) = extract_variant_details(variant);
            if let Some(variant_type) = variant_type {
                // std::println!("variant type, {}", variant_type);

                let field_code = if variant_type.contains("Box") {
                    "Box::new((*v).into())"
                } else if scalar {
                    "v"
                } else {
                    "v.into()"
                };
                format!(
                    "pb::{}::{}(v) => pb_api::{}::{}({})",
                    ty, variant_name, ty, variant_name, field_code
                )
            } else {
                format!(
                    "pb::{}::{} => pb_api::{}::{}",
                    ty, variant_name, ty, variant_name
                )
            }
        })
        .collect::<Vec<String>>()
        .join(",\n            ");

    let field_defs_api_to_pb = item
        .variants
        .iter()
        .map(|variant| {
            let (variant_name, variant_type, scalar) = extract_variant_details(variant);
            if let Some(variant_type) = variant_type {
                let field_code = if variant_type.contains("Box") {
                    "Box::new((*v).into())"
                } else if scalar {
                    "v"
                } else {
                    "v.into()"
                };
                format!(
                    "pb_api::{}::{}(v) => pb::{}::{}({})",
                    ty, variant_name, ty, variant_name, field_code
                )
            } else {
                format!(
                    "pb_api::{}::{} => pb::{}::{}",
                    ty, variant_name, ty, variant_name
                )
            }
        })
        .collect::<Vec<String>>()
        .join(",\n            ");
    let _ = writeln!(
        result,
        "impl From<pb::{}> for pb_api::{} {{
    fn from(item: pb::{}) -> Self {{
        match item {{
            {}
        }}
    }}
}}
impl From<pb_api::{}> for pb::{} {{
    fn from(item: pb_api::{}) -> Self {{
        match item {{
            {}
        }}
    }}
}}
",
        ty, ty, ty, field_defs_pb_to_api, ty, ty, ty, field_defs_api_to_pb
    );
}

fn process_items(items: &[Item], result: &mut String, prefix: &str) {
    for item in items {
        match item {
            Item::Mod(mod_item) => {
                let mod_item = mod_item.clone();
                let sub_items = mod_item.content.unwrap().1;
                process_items(
                    &sub_items,
                    result,
                    &format!("{}{}::", prefix, mod_item.ident),
                );
                // for the_item in mod_item.
            }
            Item::Struct(struct_item) => {
                add_from_impls_for_struct(result, struct_item, prefix);
            }
            Item::Enum(enum_item) => {
                add_from_impls_for_enum(result, enum_item, prefix);
            }
            Item::Const(_)
            | Item::ExternCrate(_)
            | Item::Fn(_)
            | Item::ForeignMod(_)
            | Item::Impl(_)
            | Item::Macro(_)
            | Item::Macro2(_)
            | Item::Static(_)
            | Item::Trait(_)
            | Item::TraitAlias(_)
            | Item::Type(_)
            | Item::Union(_)
            | Item::Use(_)
            | Item::Verbatim(_) => {}
            _ => {}
            &_ => {}
        }
    }
}

fn generate_from_impls() -> String {
    let mut result = String::new();
    // Parse the file at src/gen
    // std::println!("{}", std::env::var("CARGO_MANIFEST_DIR").expect("fuck"));
    let syntax_tree =
        syn::parse_file(include_str!("../src/gen/ic_sns_governance.pb.v1.rs",)).unwrap();

    process_items(&syntax_tree.items, &mut result, "");

    result
}

#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    let impls = generate_from_impls();

    std::println!("{}", impls);
}

// In order for some of the test(s) within this mod to work,
// this MUST occur at the end.
#[cfg(test)]
mod tests;
