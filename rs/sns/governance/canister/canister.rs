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
use candid::candid_method;
use dfn_candid::{candid, candid_one, candid_one_with_config, CandidOne};
use dfn_core::{
    api::{call_bytes_with_cleanup, caller, id, now, Funds},
    over, over_async, over_init,
};
use ic_base_types::CanisterId;
use ic_canister_log::log;
use ic_canister_profiler::{measure_span, measure_span_async};
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_nervous_system_clients::canister_status::CanisterStatusResultV2;
use ic_nervous_system_clients::ledger_client::LedgerCanister;
use ic_nervous_system_common::{
    cmc::CMCCanister,
    dfn_core_stable_mem_utils::{BufferedStableMemReader, BufferedStableMemWriter},
    ledger::IcpLedgerCanister,
    serve_logs, serve_logs_v2, serve_metrics,
};
use ic_nervous_system_runtime::DfnRuntime;
use ic_nns_constants::LEDGER_CANISTER_ID as NNS_LEDGER_CANISTER_ID;
#[cfg(feature = "test")]
use ic_sns_governance::pb::v1::{
    AddMaturityRequest, AddMaturityResponse, GovernanceError, MintTokensRequest,
    MintTokensResponse, Neuron,
};
use ic_sns_governance::{
    governance::{
        log_prefix, Governance, TimeWarp, ValidGovernanceProto, MATURITY_DISBURSEMENT_DELAY_SECONDS,
    },
    logs::{ERROR, INFO},
    pb::v1::{
        ClaimSwapNeuronsRequest, ClaimSwapNeuronsResponse, FailStuckUpgradeInProgressRequest,
        FailStuckUpgradeInProgressResponse, GetMaturityModulationRequest,
        GetMaturityModulationResponse, GetMetadataRequest, GetMetadataResponse, GetMode,
        GetModeResponse, GetNeuron, GetNeuronResponse, GetProposal, GetProposalResponse,
        GetRunningSnsVersionRequest, GetRunningSnsVersionResponse,
        GetSnsInitializationParametersRequest, GetSnsInitializationParametersResponse,
        Governance as GovernanceProto, ListNervousSystemFunctionsResponse, ListNeurons,
        ListNeuronsResponse, ListProposals, ListProposalsResponse, ManageNeuron,
        ManageNeuronResponse, NervousSystemParameters, RewardEvent, SetMode, SetModeResponse,
    },
    types::{Environment, HeapGrowthPotential},
};
use prost::Message;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{boxed::Box, convert::TryFrom, time::SystemTime};

/// Size of the buffer for stable memory reads and writes.
///
/// Smaller buffer size means more stable_write and stable_read calls. With
/// 100MiB buffer size, when the heap is near full, we need ~40 system calls.
/// Larger buffer size means we may not be able to serialize the heap fully in
/// some cases.
const STABLE_MEM_BUFFER_SIZE: u32 = 100 * 1024 * 1024; // 100MiB

static mut GOVERNANCE: Option<Governance> = None;

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
                let now_nanos = now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
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
        self.time_warp.apply(
            now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Could not get the duration.")
                .as_secs(),
        )
    }

    fn set_time_warp(&mut self, new_time_warp: TimeWarp) {
        self.time_warp = new_time_warp;
    }

    // Returns a random u64.
    fn random_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    // Returns a random byte array.
    fn random_byte_array(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.rng.fill_bytes(&mut bytes);
        bytes
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
        call_bytes_with_cleanup(canister_id, method_name, &arg, Funds::zero()).await
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
        id()
    }

    /// Return the canister version.
    fn canister_version(&self) -> Option<u64> {
        Some(dfn_core::api::canister_version())
    }
}

#[export_name = "canister_init"]
fn canister_init() {
    over_init(|CandidOne(arg)| canister_init_(arg))
}

/// In contrast to canister_init(), this method does not do deserialization.
/// In addition to canister_init, this method is called by canister_post_upgrade.
#[candid_method(init)]
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
        GOVERNANCE = Some(Governance::new(
            init_payload,
            Box::new(CanisterEnv::new()),
            Box::new(LedgerCanister::new(ledger_canister_id)),
            Box::new(IcpLedgerCanister::new(NNS_LEDGER_CANISTER_ID)),
            Box::new(CMCCanister::<DfnRuntime>::new()),
        ));
    }
}

/// Executes some logic before executing an upgrade, including serializing and writing the
/// governance's state to stable memory so that it is preserved during the upgrade and can
/// be deserialized again in canister_post_upgrade. That is, the stable memory allows
/// saving the state and restoring it after the upgrade.
#[export_name = "canister_pre_upgrade"]
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
#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
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

#[cfg(feature = "test")]
#[export_name = "canister_update set_time_warp"]
/// Test only feature. When used, a delta is applied to the canister's system timestamp.
fn set_time_warp() {
    over(candid_one, set_time_warp_);
}

/// Test only feature. Internal method for calling set_time_warp.
#[cfg(feature = "test")]
fn set_time_warp_(new_time_warp: TimeWarp) {
    governance_mut().env.set_time_warp(new_time_warp);
}

/// Returns the governance's NervousSystemParameters
#[export_name = "canister_query get_nervous_system_parameters"]
fn get_nervous_system_parameters() {
    log!(INFO, "get_nervous_system_parameters");
    over(candid_one, get_nervous_system_parameters_)
}

/// Internal method for calling get_nervous_system_parameters.
#[candid_method(query, rename = "get_nervous_system_parameters")]
fn get_nervous_system_parameters_(_: ()) -> NervousSystemParameters {
    governance()
        .proto
        .parameters
        .clone()
        .expect("NervousSystemParameters are not set")
}

/// Returns metadata describing the SNS.
#[export_name = "canister_query get_metadata"]
fn get_metadata() {
    log!(INFO, "get_metadata");
    over(candid_one, get_metadata_)
}

/// Internal method for calling get_metadata.
#[candid_method(query, rename = "get_metadata")]
fn get_metadata_(request: GetMetadataRequest) -> GetMetadataResponse {
    governance().get_metadata(&request)
}

/// Returns the initialization parameters used to spawn an SNS
#[export_name = "canister_query get_sns_initialization_parameters"]
fn get_sns_initialization_parameters() {
    log!(INFO, "get_sns_initialization_parameters");
    over(candid_one, get_sns_initialization_parameters_)
}

/// Internal method for calling get_sns_initialization_parameters.
#[candid_method(query, rename = "get_sns_initialization_parameters")]
fn get_sns_initialization_parameters_(
    request: GetSnsInitializationParametersRequest,
) -> GetSnsInitializationParametersResponse {
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
#[export_name = "canister_update manage_neuron"]
fn manage_neuron() {
    log!(INFO, "manage_neuron");
    over_async(candid_one, manage_neuron_)
}

/// Internal method for calling manage_neuron.
#[candid_method(update, rename = "manage_neuron")]
async fn manage_neuron_(manage_neuron: ManageNeuron) -> ManageNeuronResponse {
    let governance = governance_mut();
    measure_span_async(
        governance.profiling_information,
        "manage_neuron",
        governance.manage_neuron(&manage_neuron, &caller()),
    )
    .await
}

#[cfg(feature = "test")]
#[export_name = "canister_update update_neuron"]
/// Test only feature. Update neuron parameters.
fn update_neuron() {
    log!(INFO, "update_neuron");
    over(candid_one, update_neuron_)
}

#[cfg(feature = "test")]
#[candid_method(update, rename = "update_neuron")]
/// Internal method for calling update_neuron.
fn update_neuron_(neuron: Neuron) -> Option<GovernanceError> {
    let governance = governance_mut();
    measure_span(governance.profiling_information, "update_neuron", || {
        governance.update_neuron(neuron).err()
    })
}

/// Returns the full neuron corresponding to the neuron with ID `neuron_id`.
#[export_name = "canister_query get_neuron"]
fn get_neuron() {
    log!(INFO, "get_neuron");
    over(candid_one, get_neuron_)
}

/// Internal method for calling get_neuron.
#[candid_method(query, rename = "get_neuron")]
fn get_neuron_(get_neuron: GetNeuron) -> GetNeuronResponse {
    governance().get_neuron(get_neuron)
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
#[export_name = "canister_query list_neurons"]
fn list_neurons() {
    log!(INFO, "list_neurons");
    over(candid_one, list_neurons_)
}

/// Internal method for calling list_neurons.
#[candid_method(query, rename = "list_neurons")]
fn list_neurons_(list_neurons: ListNeurons) -> ListNeuronsResponse {
    governance().list_neurons(&list_neurons)
}

/// Returns the full proposal corresponding to the `proposal_id`.
#[export_name = "canister_query get_proposal"]
fn get_proposal() {
    over(candid_one, get_proposal_)
}

/// Internal method for calling get_proposal.
#[candid_method(query, rename = "get_proposal")]
fn get_proposal_(get_proposal: GetProposal) -> GetProposalResponse {
    governance().get_proposal(&get_proposal)
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
#[export_name = "canister_query list_proposals"]
fn list_proposals() {
    log!(INFO, "list_proposals");
    over(candid_one, list_proposals_)
}

/// Internal method for calling list_proposals.
#[candid_method(query, rename = "list_proposals")]
fn list_proposals_(list_proposals: ListProposals) -> ListProposalsResponse {
    governance().list_proposals(&list_proposals, &caller())
}

/// Returns the current list of available NervousSystemFunctions.
#[export_name = "canister_query list_nervous_system_functions"]
fn list_nervous_system_functions() {
    log!(INFO, "list_nervous_system_functions");
    over(candid, |()| list_nervous_system_functions_())
}

/// Internal method for calling list_nervous_system_functions.
#[candid_method(query, rename = "list_nervous_system_functions")]
fn list_nervous_system_functions_() -> ListNervousSystemFunctionsResponse {
    governance().list_nervous_system_functions()
}

/// Returns the latest reward event.
#[export_name = "canister_query get_latest_reward_event"]
fn get_latest_reward_event() {
    log!(INFO, "get_latest_reward_event");
    over(candid, |()| get_latest_reward_event_());
}

#[candid_method(query, rename = "get_latest_reward_event")]
fn get_latest_reward_event_() -> RewardEvent {
    governance().latest_reward_event()
}

/// Deprecated method. Previously returned the root canister's status.
/// No longer necessary now that canisters can get their own status.
#[export_name = "canister_update get_root_canister_status"]
fn get_root_canister_status() {
    over_async(candid_one, get_root_canister_status_)
}

/// Internal method for calling get_root_canister_status.
#[candid_method(update, rename = "get_root_canister_status")]
#[allow(clippy::let_unit_value)] // clippy false positive
async fn get_root_canister_status_(_: ()) -> CanisterStatusResultV2 {
    panic!("This method is deprecated and should not be used. Please use the root canister's `get_sns_canisters_summary` method.")
}

/// Gets the current SNS version, as understood by Governance.  This is useful
/// for diagnosing upgrade problems, such as if multiple ledger archives are not
/// running the same version.
#[export_name = "canister_query get_running_sns_version"]
fn get_running_sns_version() {
    log!(INFO, "get_running_sns_version");
    over(candid_one, get_running_sns_version_)
}

/// Internal method for calling get_sns_version.
#[candid_method(query, rename = "get_running_sns_version")]
fn get_running_sns_version_(_: GetRunningSnsVersionRequest) -> GetRunningSnsVersionResponse {
    GetRunningSnsVersionResponse {
        deployed_version: governance().proto.deployed_version.clone(),
        pending_version: governance().proto.pending_version.clone(),
    }
}

/// Marks an in progress upgrade that has passed its deadline as failed.
#[export_name = "canister_update fail_stuck_upgrade_in_progress"]
fn fail_stuck_upgrade_in_progress() {
    log!(INFO, "fail_stuck_upgrade_in_progress");
    over(candid_one, fail_stuck_upgrade_in_progress_)
}

/// Internal method for calling fail_stuck_upgrade_in_progress.
#[candid_method(update, rename = "fail_stuck_upgrade_in_progress")]
fn fail_stuck_upgrade_in_progress_(
    request: FailStuckUpgradeInProgressRequest,
) -> FailStuckUpgradeInProgressResponse {
    governance_mut().fail_stuck_upgrade_in_progress(request)
}

/// Sets the mode. Only the swap canister is allowed to call this.
///
/// In practice, the only mode that the swap canister would ever choose is
/// Normal. Also, in practice, the current value of mode should be
/// PreInitializationSwap.  whenever the swap canister calls this.
#[export_name = "canister_update set_mode"]
fn set_mode() {
    log!(INFO, "set_mode");
    over(candid_one, set_mode_);
}

/// Internal method for calling set_mode.
#[candid_method(update, rename = "set_mode")]
fn set_mode_(request: SetMode) -> SetModeResponse {
    governance_mut().set_mode(request.mode, caller());
    SetModeResponse {}
}

#[export_name = "canister_query get_mode"]
fn get_mode() {
    log!(INFO, "get_mode");
    over(candid_one, get_mode_);
}

#[candid_method(query, rename = "get_mode")]
fn get_mode_(request: GetMode) -> GetModeResponse {
    governance().get_mode(request)
}

/// Claims a batch of neurons requested by the SNS Swap canister. This method is
/// only callable by the Swap canister that was deployed along with this
/// SNS Governance canister.
///
/// This API takes a request of multiple `NeuronParameters` that provide
/// the configurable parameters of the to-be-created neurons. Since these neurons
/// are responsible for the decentralization of an SNS during the Swap, there are
/// a few differences in neuron creation that occur in comparison to the normal
/// `ManageNeuron::ClaimOrRefresh` API. See `Governance::claim_swap_neurons` for
/// more details.
///
/// This method is idempotent. If called with a `NeuronParameters` of an already
/// created Neuron, the `ClaimSwapNeuronsResponse.skipped_claims` field will be
/// incremented and execution will continue.
#[export_name = "canister_update claim_swap_neurons"]
fn claim_swap_neurons() {
    log!(INFO, "claim_swap_neurons");
    over(candid_one, claim_swap_neurons_)
}

/// Internal method for calling claim_swap_neurons.
#[candid_method(update, rename = "claim_swap_neurons")]
fn claim_swap_neurons_(
    claim_swap_neurons_request: ClaimSwapNeuronsRequest,
) -> ClaimSwapNeuronsResponse {
    let governance = governance_mut();
    measure_span(
        governance.profiling_information,
        "claim_swap_neurons",
        || governance.claim_swap_neurons(claim_swap_neurons_request, caller()),
    )
}

/// This is not really useful to the public. It is, however, useful to integration tests.
#[export_name = "canister_query get_maturity_modulation"]
fn get_maturity_modulation() {
    log!(INFO, "get_maturity_modulation");
    over(candid_one, get_maturity_modulation_)
}

/// Internal method for calling get_maturity_modulation.
#[candid_method(update, rename = "get_maturity_modulation")]
fn get_maturity_modulation_(
    request: GetMaturityModulationRequest,
) -> GetMaturityModulationResponse {
    let governance = governance_mut();
    measure_span(
        governance.profiling_information,
        "get_maturity_modulation",
        || governance.get_maturity_modulation(request),
    )
}

/// The canister's heartbeat.
#[export_name = "canister_heartbeat"]
fn canister_heartbeat() {
    let future = governance_mut().heartbeat();

    // The canister_heartbeat must be synchronous, so we cannot .await the future.
    dfn_core::api::futures::spawn(future);
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method! {}

/// Resources to serve for a given http_request
#[export_name = "canister_query http_request"]
fn http_request() {
    over(candid_one_with_config, serve_http)
}

/// Serve an HttpRequest made to this canister
pub fn serve_http(request: HttpRequest) -> HttpResponse {
    match request.path() {
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

/// This makes this Candid service self-describing, so that for example Candid
/// UI, but also other tools, can seamlessly integrate with it.
/// The concrete interface (__get_candid_interface_tmp_hack) is provisional, but
/// works.
///
/// We include the .did file as committed, which means it is included verbatim in
/// the .wasm; using `candid::export_service` here would involve unnecessary
/// runtime computation.
#[cfg(not(feature = "test"))]
#[export_name = "canister_query __get_candid_interface_tmp_hack"]
fn expose_candid() {
    over(candid, |_: ()| include_str!("governance.did").to_string())
}
#[cfg(feature = "test")]
#[export_name = "canister_query __get_candid_interface_tmp_hack"]
fn expose_candid() {
    over(candid, |_: ()| {
        include_str!("governance_test.did").to_string()
    })
}

/// Adds maturity to a neuron for testing
#[cfg(feature = "test")]
#[export_name = "canister_update add_maturity"]
fn add_maturity() {
    over(candid_one, add_maturity_)
}

#[cfg(feature = "test")]
#[candid_method(update, rename = "add_maturity")]
fn add_maturity_(request: AddMaturityRequest) -> AddMaturityResponse {
    governance_mut().add_maturity(request)
}

/// Mints tokens for testing
#[cfg(feature = "test")]
#[export_name = "canister_update mint_tokens"]
fn mint_tokens() {
    over_async(candid_one, mint_tokens_)
}

#[cfg(feature = "test")]
#[candid_method(update, rename = "mint_tokens")]
async fn mint_tokens_(request: MintTokensRequest) -> MintTokensResponse {
    governance_mut().mint_tokens(request).await
}

fn main() {
    // This block is intentionally left blank.
}

// In order for some of the test(s) within this mod to work,
// this MUST occur at the end.
#[cfg(test)]
mod tests;
