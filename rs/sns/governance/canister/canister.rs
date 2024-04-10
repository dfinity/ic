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
use dfn_candid::{candid, candid_one, CandidOne};
use dfn_core::{
    api::{call_bytes_with_cleanup, caller, id, now, Funds},
    over, over_async, over_init,
};
use ic_base_types::CanisterId;
use ic_canister_log::log;
use ic_canister_profiler::{measure_span, measure_span_async};
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_nervous_system_clients::canister_status::CanisterStatusResultV2;
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
    ledger::LedgerCanister,
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
        ManageNeuronResponse, NervousSystemParameters, ProposalData, ProposalRewardStatus,
        RewardEvent, SetMode, SetModeResponse,
    },
    types::{Environment, HeapGrowthPotential},
};
use maplit::btreemap;
use prost::Message;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{boxed::Box, collections::BTreeMap, convert::TryFrom, time::SystemTime};

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

    let now = now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Cannot tell what time it is.")
        .as_secs();

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

            // TODO(NNS1-2994): Delete this once it's been released.
            settle_proposals_stuck_in_ready_to_settle(now, id(), &mut governance_proto.proposals);

            // TODO: Delete this once it's been released.
            populate_finalize_disbursement_timestamp_seconds(&mut governance_proto);

            canister_init_(governance_proto);
            Ok(())
        }
    }
    .expect("Couldn't upgrade canister.");
    log!(INFO, "Completed post upgrade");
}

/// A recent survey found that these are the proposals that are stuck in ReadyToSettle:
///
///   1. Dragginz proposal 36
///   2. ICX proposal 41
///
/// Modifications on affect proposal(s):
///
///   1. Set is_eligible_to_rewards to false.
fn settle_proposals_stuck_in_ready_to_settle(
    now: u64,
    our_canister_id: CanisterId,
    proposals: &mut BTreeMap<u64, ProposalData>,
) {
    let governance_canister_id_to_proposal_id = btreemap! {
        "rceqh-cqaaa-aaaaq-aabqa-cai".to_string() => 41,  // ICX
        "zqfso-syaaa-aaaaq-aaafq-cai".to_string() => 36,  // Dragginz
    };

    let proposal_id = governance_canister_id_to_proposal_id.get(&our_canister_id.to_string());
    let proposal_id = match proposal_id {
        Some(ok) => ok,
        None => return,
    };

    let proposal = proposals.get_mut(proposal_id);
    let proposal = match proposal {
        Some(ok) => ok,
        None => return,
    };

    log!(
        INFO,
        "Proposal {} is stuck in ReadyToSettle. Forcing it to be Settled \
         (by setting is_eligible_for_rewards to false).",
        proposal_id,
    );

    proposal.is_eligible_for_rewards = false;
    assert_eq!(proposal.reward_status(now), ProposalRewardStatus::Settled);
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
/// dissolve state),
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
    over(candid_one, serve_http)
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

/// When run on native, this prints the candid service definition of this
/// canister, from the methods annotated with `candid_method` above.
///
/// Note that `cargo test` calls `main`, and `export_service` (which defines
/// `__export_service` in the current scope) needs to be called exactly once. So
/// in addition to `not(target_arch = "wasm32")` we have a `not(test)` guard here
/// to avoid calling `export_service`, which we need to call in the test below.
#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    // The line below generates did types and service definition from the
    // methods annotated with `candid_method` above. The definition is then
    // obtained with `__export_service()`.
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}

/// A test that fails if the API was updated but the candid definition was not.
#[cfg(not(feature = "test"))]
#[test]
fn check_governance_candid_file() {
    let did_path = format!(
        "{}/canister/governance.did",
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set")
    );
    let did_contents = String::from_utf8(std::fs::read(did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if did_contents != expected {
        panic!(
            "Generated candid definition does not match canister/governance.did. \
            Run `bazel run :generate_did > canister/governance.did` (no nix and/or direnv) or \
            `cargo run --bin sns-governance-canister > canister/governance.did` in \
            rs/sns/governance to update canister/governance.did."
        )
    }
}

#[cfg(feature = "test")]
#[test]
fn check_governance_candid_file() {
    let did_path = format!(
        "{}/canister/governance_test.did",
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set")
    );
    let did_contents = String::from_utf8(std::fs::read(did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if did_contents != expected {
        panic!(
            "Generated candid definition does not match canister/governance_test.did. \
            Run `bazel run :generate_test_did > canister/governance_test.did` (no nix and/or direnv) in \
            rs/sns/governance to update canister/governance_test.did."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Decode;
    use hex::FromHex;
    use ic_sns_governance::pb::v1::{DisburseMaturityInProgress, Neuron, ProposalId};
    use maplit::btreemap;
    use std::str::FromStr;

    /// A test that checks that set_time_warp advances time correctly.
    #[test]
    fn test_set_time_warp() {
        let mut environment = CanisterEnv::new();

        let start = environment.now();
        environment.set_time_warp(TimeWarp { delta_s: 1_000 });
        let delta_s = environment.now() - start;

        assert!(delta_s >= 1000, "delta_s = {}", delta_s);
        assert!(delta_s < 1005, "delta_s = {}", delta_s);
    }

    #[test]
    fn test_settle_proposals_stuck_in_ready_to_settle() {
        fn decode_proposal(hex_encoded: &str) -> ProposalData {
            let mut response = Decode!(
                &Vec::<u8>::from_hex(hex_encoded).unwrap(),
                ListProposalsResponse
            )
            .unwrap();

            response.proposals.pop().unwrap()
        }

        let dragginz_governance_canister_id =
            CanisterId::from_str("zqfso-syaaa-aaaaq-aaafq-cai").unwrap();
        let icx_governance_canister_id =
            CanisterId::from_str("rceqh-cqaaa-aaaaq-aabqa-cai").unwrap();

        let dragginz_proposal_36 = decode_proposal(
            "4449444c496e7e6c01dbb701786e016e716c0290c6c1960571d19bc28f0e756e046e756e686d7b6c01ad86ca8305086e096c02b3b0dac30307ad86ca83050a6e0b6c0182c0a0fa02036e0d6e786c01e0a9b3020f6e106c03e2fba7e1030eb5faeba7040edaae9c8f09116e126c04f985aea10106adf9e78a0a0c86cef6930a13d6d5dac60f0f6e146c01c18fb88806156b029eb481da0b16d0abb0820e166e176c03ea99cff204759694a08a0578ad9e83b60e786c02007101196d1a6c01c4d9d3ea0f0f6e1c6c04c1c00178a7d2f00278c4a7c9a10178d6d5dac60f786e1e6c01dbb701086d206c01c2cee0d80c216c02007801226d236c01c2cee0d80c246e256d756c0184f9d176276e286e796c04dc87d3aa030f8e8ab6f3080fefca8bdf0d0fa5a389b40f0f6e2b6c1484aead3326f0cefc350fe9f1b4470fd2bbc8ef020fe28b959c03299eb493cf030fd8aa8f8f050f9ebddfd6050f81a6cee6050fce89be97060fc7dae0cc062afeeaf491090f93dfe6aa090f86f998bc090fc182ad960a0ff5cedb9b0b0faf899aba0d29fde7b1fd0d2cb19bf7e60e00c2b0c4aa0f0f6c006c0486fef0ea0a0785f2acb20b07fcc8d7e40e03fbbc93ac0f036b02c2a2dd88072e829aa4b40e2f6e306c04dbb70178cbe4fdc70471fc91f4f8050381d9b08e0a316d686c06c0cff2710fe095a6a4033380ad988a040fedd9c8c90706deebb5a90e0fa882acc60f0f6c01e095a6a403336c05f8aff58a0175aaeff3c60107b1edd681040aba89e5c2040fb9ef938008786e086c049db0f1b80208e3a683c30406b3c4b1f204079bc9bf920e376c02e095a6a40333b8fdadb80c336c04aaeff3c60107b1edd681040aba89e5c2040fb9ef9380080f6c04efd6e40203ebbedebd0403cbe4fdc70403fc91f4f805036c02e28bbf14788effd6e90e086c01f2c794ae030f6c0196bdb4e904716b0fc6c0d5102d838db44932acf4a87a34e6d6e4ab0678aedd92a2072eecca918a0a359eb481da0b36d1a8b0ae0c38cbc0c7b80d39d0abb0820e3a97f7e1c30e2e82a1cfcd0e3b97899f8d0f3cd8cccec40f3dd6f4c7ff0f3e6e3f6c04efd6e4027198abec810171b6f798b201c000a696a48708716ec1006e206c01b5c7dbca06786ec4006c16dbb70102cbad973203b6f798b20178d9dcf28e0205fd83a1b202188f8ecfd6021b98d8b2cc031d9996f39e04789491a1b50578fdfde2c7050fa39f83cb05789ebddfd60578ce89be970678f494ede1071ffeeaf4910978d3a4a3a20a78b2b8d4960bc200b4bfd4960bc30086f5b2e00bc500e0d691b80c1dfbb5e3cf0c7ee687feb20f786dc6006c02acc3b8df060081a08ebd0cc70001c80001010101240000000000000001a809232050726f706f73616c20746f207570677261646520534e5320746f206e6578742076657273696f6e3a0a0a232320534e532043757272656e742056657273696f6e3a0a56657273696f6e207b0a20202020726f6f743a20666531393637313436383431613234376232663739336165363165356566336336623435656366626531363265636161386166323436626635653037333333662c0a20202020676f7665726e616e63653a20383962316339363534306639383066663730636234623063613361306465353866366331383632663937636130633430376631353566383232386630653035352c0a202020206c65646765723a20386662623231323030323830643634313333326461633436646233323363656165313938633963613665646563393531326334393865656665386330333838362c0a20202020737761703a20396431326537323238316130343836373432633662306664633438343962336637396632306236346331643363343537666536393836633136333939353036632c0a20202020617263686976653a20376361383063623266656532626165386536363330366231643766653433316530613335643166373663333834626532663434633263636133336337326130332c0a20202020696e6465783a20373236316162633536616237386438336335333961623133636366616263666439323337336530366634373365336138313439316232306265303135303534342c0a7d0a0a232320534e53204e65772056657273696f6e3a0a56657273696f6e207b0a20202020726f6f743a20666531393637313436383431613234376232663739336165363165356566336336623435656366626531363265636161386166323436626635653037333333662c0a20202020676f7665726e616e63653a20663664343964383362636331393464366236363335643032363239353663333838663637326538316561666230313163643065343534313561373135663137312c0a202020206c65646765723a20386662623231323030323830643634313333326461633436646233323363656165313938633963613665646563393531326334393865656665386330333838362c0a20202020737761703a20396431326537323238316130343836373432633662306664633438343962336637396632306236346331643363343537666536393836633136333939353036632c0a20202020617263686976653a20376361383063623266656532626165386536363330366231643766653433316530613335643166373663333834626532663434633263636133336337326130332c0a20202020696e6465783a20373236316162633536616237386438336335333961623133636366616263666439323337336530366634373365336138313439316232306265303135303534342c0a7d0a0a23232043616e69737465727320746f2062652075706772616465643a207a7166736f2d73796161612d61616161712d61616166712d6361690a232320557067726164652056657273696f6e3a20663664343964383362636331393464366236363335643032363239353663333838663637326538316561666230313163643065343534313561373135663137310a070000000000000000000140343239303063396466383437393839373231353063633732393035373463663764326161363939316332613031346534623533383464393133393039666165320100000097a6e16300000000ad21990c00000000000000000000000000000000000000000000bf38e163000000000046050000000000809698000000000001bc95882f000000003d5acc351a000000e2bc83b437000000aa7be663000000008051010000000000bf7ee66300000000013668747470733a2f2f64617368626f6172642e696e7465726e6574636f6d70757465722e6f72672f70726f706f73616c2f3130343938312f50726f706f73616c20746f20757067726164652074686520534e5320746f20746865206e6578742076657273696f6e0104d1090a23232050726f706f73616c20746f20757067726164652074686520534e5320746f20746865206e6578742076657273696f6e0a0a2d2d2d0a48656c6c6f20534e532d3120636f6d6d756e6974792120546869732070726f706f73616c2069732066726f6d2061204446494e49545920534e5320456e67696e6565722e205765207375676765737420746865207365636f6e642070726f706f73616c206f662074797065202a2a55706772616465536e73546f4e65787456657273696f6e2a2a2e20496620746869732070726f706f73616c2069732061646f70746564206279207468652044414f2c2074686520534e532d3120676f7665726e616e63652063616e69737465722077696c6c206175746f6e6f6d6f75736c79207570677261646520697473656c6620746f20746865205741534d204861736820663664343964383362636331393464366236363335643032363239353663333838663637326538316561666230313163643065343534313561373135663137312e2054686973205741534d2076657273696f6e206f662074686520676f7665726e616e63652063616e6973746572207761732070726576696f75736c792076657474656420627920746865204e4e5320636f6d6d756e69747920696e2070726f706f73616c20313034393831202868747470733a2f2f64617368626f6172642e696e7465726e6574636f6d70757465722e6f72672f70726f706f73616c2f313034393831292e0a0a23232046656174757265730a2d20416c6c6f7720677a6970706564207761736d206d6f64756c657320666f722075706772616465730a2d20566172696f757320736d616c6c206275672066697865730a2d20476f7665726e616e63652063616e697374657220636865636b732075706772616465207461726765742063616e6973746572732076657273696f6e206f6e6c790a0a0a232320486f7720534e5320557067726164657320576f726b0a0a416e20534e53206973206d616465207570206f6620362063616e6973746572732077686f7365205741534d73206172652073746f72656420696e20616e204e4e532063616e69737465722063616c6c65642074686520534e53207761736d206d6f64756c65732063616e69737465722c20534e532d5720666f722073686f72742e205768656e20757064617465732061726520616464656420746f20616e79206f6e65206f662074686573652063616e69737465727320736f7572636520636f64652c20746865204e4e532044414f206d75737420696e737065637420746865206368616e676520616e6420617070726f766520616e204e4e532070726f706f73616c20746f207075626c69736820746865206e65772076657273696f6e20746f20534e532d572e205468656e2c206561636820696e646976696475616c20534e532044414f206d75737420646563696465207768656e20616e642069662069742077696c6c207570677261646520746f2074686174206e65772076657273696f6e2076696120616e20534e532070726f706f73616c2e20496620617070726f7665642c2074686520534e5320676f7665726e616e63652073797374656d2077696c6c206175746f6e6f6d6f75736c79207570677261646520746f20746865206e6578742076657273696f6e20617661696c61626c6520696e20534e532d572e01201b066e6798fb7fdfbe2cf894756ffd3c76752d0e4f6e543087b6fa640c595fb201bf7ee663000000000001167fe66300000000"
        );
        let icx_proposal_41 = decode_proposal(
            "4449444c3c6c01dbb701786e006e716c0290c6c1960571d19bc28f0e756e036c03ea99cff204759694a08a0578ad9e83b60e786c02007101056d066e786c01c4d9d3ea0f086e096c04c1c00178a7d2f00278c4a7c9a10178d6d5dac60f786e0b6d7b6c01dbb7010d6d0e6c01c2cee0d80c0f6c02007801106d116c01c2cee0d80c126e136d756c0184f9d176156e166e796c04dc87d3aa03088e8ab6f30808efca8bdf0d08a5a389b40f086e196e7e6c1484aead3314f0cefc3508e9f1b44708d2bbc8ef0208e28b959c03179eb493cf0308d8aa8f8f05089ebddfd6050881a6cee60508ce89be970608c7dae0cc0618feeaf491090893dfe6aa090886f998bc0908c182ad960a08f5cedb9b0b08af899aba0d17fde7b1fd0d1ab19bf7e60e1bc2b0c4aa0f086c006e686c0486fef0ea0a1e85f2acb20b1efcc8d7e40e02fbbc93ac0f026b02c2a2dd88071d829aa4b40e1f6e206c04dbb70178cbe4fdc70471fc91f4f8050281d9b08e0a216d686e756c06c0cff27108e095a6a4032380ad988a0408edd9c8c90724deebb5a90e08a882acc60f086c01e095a6a403236c01ad86ca83050d6e276c05f8aff58a0175aaeff3c6011eb1edd6810428ba89e5c20408b9ef938008786e0d6c049db0f1b8020de3a683c30424b3c4b1f2041e9bc9bf920e2a6c02e095a6a40323b8fdadb80c236c04aaeff3c6011eb1edd6810428ba89e5c20408b9ef938008086c04efd6e40202ebbedebd0402cbe4fdc70402fc91f4f805026c02e28bbf14788effd6e90e0d6c01f2c794ae03086c0196bdb4e904716b0fc6c0d5101c838db44922acf4a87a25e6d6e4ab0678aedd92a2071decca918a0a269eb481da0b29d1a8b0ae0c2bcbc0c7b80d2cd0abb0820e2d97f7e1c30e1d82a1cfcd0e2e97899f8d0f2fd8cccec40f30d6f4c7ff0f316e326c04efd6e4027198abec810171b6f798b20133a696a48708716e346e0e6c01b5c7dbca06786e376c15dbb70101cbad973202b6f798b20178d9dcf28e02048f8ecfd6020798d8b2cc030a9996f39e04789491a1b50578fdfde2c70508a39f83cb05789ebddfd60578ce89be970678f494ede1070cfeeaf4910978d3a4a3a20a78b2b8d4960b35b4bfd4960b3686f5b2e00b38e0d691b80c0afbb5e3cf0c7ee687feb20f786d396c0181a08ebd0c3a013b0101290000000000000001d11d232050726f706f73616c20746f206368616e6765206e6572766f75732073797374656d20706172616d65746572733a0a23232043757272656e74206e6572766f75732073797374656d20706172616d65746572733a0a0a4e6572766f757353797374656d506172616d6574657273207b0a2020202072656a6563745f636f73745f6538733a20536f6d65280a20202020202020203130303030303030303030302c0a20202020292c0a202020206e6575726f6e5f6d696e696d756d5f7374616b655f6538733a20536f6d65280a20202020202020203430303030303030302c0a20202020292c0a202020207472616e73616374696f6e5f6665655f6538733a20536f6d65280a20202020202020203130303030302c0a20202020292c0a202020206d61785f70726f706f73616c735f746f5f6b6565705f7065725f616374696f6e3a20536f6d65280a20202020202020203130302c0a20202020292c0a20202020696e697469616c5f766f74696e675f706572696f645f7365636f6e64733a20536f6d65280a20202020202020203334353630302c0a20202020292c0a20202020776169745f666f725f71756965745f646561646c696e655f696e6372656173655f7365636f6e64733a20536f6d65280a202020202020202038363430302c0a20202020292c0a2020202064656661756c745f666f6c6c6f776565733a20536f6d65280a202020202020202044656661756c74466f6c6c6f77656573207b0a202020202020202020202020666f6c6c6f776565733a207b7d2c0a20202020202020207d2c0a20202020292c0a202020206d61785f6e756d6265725f6f665f6e6575726f6e733a20536f6d65280a20202020202020203230303030302c0a20202020292c0a202020206e6575726f6e5f6d696e696d756d5f646973736f6c76655f64656c61795f746f5f766f74655f7365636f6e64733a20536f6d65280a2020202020202020323633303031362c0a20202020292c0a202020206d61785f666f6c6c6f776565735f7065725f66756e6374696f6e3a20536f6d65280a202020202020202031352c0a20202020292c0a202020206d61785f646973736f6c76655f64656c61795f7365636f6e64733a20536f6d65280a202020202020202036333131353230302c0a20202020292c0a202020206d61785f6e6575726f6e5f6167655f666f725f6167655f626f6e75733a20536f6d65280a2020202020202020373839303034382c0a20202020292c0a202020206d61785f6e756d6265725f6f665f70726f706f73616c735f776974685f62616c6c6f74733a20536f6d65280a20202020202020203730302c0a20202020292c0a202020206e6575726f6e5f636c61696d65725f7065726d697373696f6e733a20536f6d65280a20202020202020204e6575726f6e5065726d697373696f6e4c697374207b0a2020202020202020202020207065726d697373696f6e733a205b0a20202020202020202020202020202020556e7370656369666965642c0a20202020202020202020202020202020436f6e666967757265446973736f6c766553746174652c0a202020202020202020202020202020204d616e6167655072696e636970616c732c0a202020202020202020202020202020205375626d697450726f706f73616c2c0a20202020202020202020202020202020566f74652c0a2020202020202020202020202020202044697362757273652c0a2020202020202020202020202020202053706c69742c0a202020202020202020202020202020204d657267654d617475726974792c0a2020202020202020202020202020202044697362757273654d617475726974792c0a202020202020202020202020202020205374616b654d617475726974792c0a202020202020202020202020202020204d616e616765566f74696e675065726d697373696f6e2c0a2020202020202020202020205d2c0a20202020202020207d2c0a20202020292c0a202020206e6575726f6e5f6772616e7461626c655f7065726d697373696f6e733a20536f6d65280a20202020202020204e6575726f6e5065726d697373696f6e4c697374207b0a2020202020202020202020207065726d697373696f6e733a205b0a20202020202020202020202020202020556e7370656369666965642c0a20202020202020202020202020202020436f6e666967757265446973736f6c766553746174652c0a202020202020202020202020202020204d616e6167655072696e636970616c732c0a202020202020202020202020202020205375626d697450726f706f73616c2c0a20202020202020202020202020202020566f74652c0a2020202020202020202020202020202044697362757273652c0a2020202020202020202020202020202053706c69742c0a202020202020202020202020202020204d657267654d617475726974792c0a2020202020202020202020202020202044697362757273654d617475726974792c0a202020202020202020202020202020205374616b654d617475726974792c0a202020202020202020202020202020204d616e616765566f74696e675065726d697373696f6e2c0a2020202020202020202020205d2c0a20202020202020207d2c0a20202020292c0a202020206d61785f6e756d6265725f6f665f7072696e636970616c735f7065725f6e6575726f6e3a20536f6d65280a2020202020202020352c0a20202020292c0a20202020766f74696e675f726577617264735f706172616d65746572733a20536f6d65280a2020202020202020566f74696e6752657761726473506172616d6574657273207b0a202020202020202020202020726f756e645f6475726174696f6e5f7365636f6e64733a20536f6d65280a2020202020202020202020202020202038363430302c0a202020202020202020202020292c0a2020202020202020202020207265776172645f726174655f7472616e736974696f6e5f6475726174696f6e5f7365636f6e64733a20536f6d65280a20202020202020202020202020202020302c0a202020202020202020202020292c0a202020202020202020202020696e697469616c5f7265776172645f726174655f62617369735f706f696e74733a20536f6d65280a202020202020202020202020202020203235302c0a202020202020202020202020292c0a20202020202020202020202066696e616c5f7265776172645f726174655f62617369735f706f696e74733a20536f6d65280a202020202020202020202020202020203235302c0a202020202020202020202020292c0a20202020202020207d2c0a20202020292c0a202020206d61785f646973736f6c76655f64656c61795f626f6e75735f70657263656e746167653a20536f6d65280a20202020202020203130302c0a20202020292c0a202020206d61785f6167655f626f6e75735f70657263656e746167653a20536f6d65280a202020202020202032352c0a20202020292c0a202020206d617475726974795f6d6f64756c6174696f6e5f64697361626c65643a20536f6d65280a202020202020202066616c73652c0a20202020292c0a7d0a0a2323204e6577206e6572766f75732073797374656d20706172616d65746572733a0a0a4e6572766f757353797374656d506172616d6574657273207b0a2020202072656a6563745f636f73745f6538733a204e6f6e652c0a202020206e6575726f6e5f6d696e696d756d5f7374616b655f6538733a204e6f6e652c0a202020207472616e73616374696f6e5f6665655f6538733a204e6f6e652c0a202020206d61785f70726f706f73616c735f746f5f6b6565705f7065725f616374696f6e3a204e6f6e652c0a20202020696e697469616c5f766f74696e675f706572696f645f7365636f6e64733a204e6f6e652c0a20202020776169745f666f725f71756965745f646561646c696e655f696e6372656173655f7365636f6e64733a204e6f6e652c0a2020202064656661756c745f666f6c6c6f776565733a204e6f6e652c0a202020206d61785f6e756d6265725f6f665f6e6575726f6e733a204e6f6e652c0a202020206e6575726f6e5f6d696e696d756d5f646973736f6c76655f64656c61795f746f5f766f74655f7365636f6e64733a204e6f6e652c0a202020206d61785f666f6c6c6f776565735f7065725f66756e6374696f6e3a204e6f6e652c0a202020206d61785f646973736f6c76655f64656c61795f7365636f6e64733a204e6f6e652c0a202020206d61785f6e6575726f6e5f6167655f666f725f6167655f626f6e75733a204e6f6e652c0a202020206d61785f6e756d6265725f6f665f70726f706f73616c735f776974685f62616c6c6f74733a204e6f6e652c0a202020206e6575726f6e5f636c61696d65725f7065726d697373696f6e733a204e6f6e652c0a202020206e6575726f6e5f6772616e7461626c655f7065726d697373696f6e733a204e6f6e652c0a202020206d61785f6e756d6265725f6f665f7072696e636970616c735f7065725f6e6575726f6e3a204e6f6e652c0a20202020766f74696e675f726577617264735f706172616d65746572733a20536f6d65280a2020202020202020566f74696e6752657761726473506172616d6574657273207b0a202020202020202020202020726f756e645f6475726174696f6e5f7365636f6e64733a204e6f6e652c0a2020202020202020202020207265776172645f726174655f7472616e736974696f6e5f6475726174696f6e5f7365636f6e64733a204e6f6e652c0a202020202020202020202020696e697469616c5f7265776172645f726174655f62617369735f706f696e74733a20536f6d65280a20202020202020202020202020202020302c0a202020202020202020202020292c0a20202020202020202020202066696e616c5f7265776172645f726174655f62617369735f706f696e74733a20536f6d65280a20202020202020202020202020202020302c0a202020202020202020202020292c0a20202020202020207d2c0a20202020292c0a202020206d61785f646973736f6c76655f64656c61795f626f6e75735f70657263656e746167653a204e6f6e652c0a202020206d61785f6167655f626f6e75735f70657263656e746167653a204e6f6e652c0a202020206d617475726974795f6d6f64756c6174696f6e5f64697361626c65643a204e6f6e652c0a7d0200000000000000000001012c0100000000000000000000000000000000000000000000005f09e66500000000004605000000000000e87648170000000181dd76c1b7050000b269780f15020d0036ecda91ab8710008920eb650000000080510100000000002542e76500000000010f68747470733a2f2f6963782e6f6e651644697361626c6520766f74696e67207265776172647301000000000000000000000000000000000000010100000000000000000100000000000000000000000077546869732070726f706f73616c20696e74656e647320746f20646973636f6e74696e756520766f74696e67207265776172647320696e20616c69676e6d656e742077697468207468652070726576696f75736c792061646f70746564204d6f74696f6e2050726f706f73616c204e756d6265722033392e0120eda6976220ea999ed4d5df28b217e4d452786b6c9dc8f3d892256eaca00017ce015f4feb650000000001018813000000000000012542e76500000000"
        );

        let now = 1712674575;

        let proposal = ProposalData {
            id: Some(ProposalId { id: 99 }),
            ..Default::default()
        };

        fn vec_to_map(proposals: Vec<ProposalData>) -> BTreeMap<u64, ProposalData> {
            proposals
                .into_iter()
                .map(|proposal| {
                    let proposal_id = proposal.id.as_ref().unwrap().id;
                    (proposal_id, proposal)
                })
                .collect()
        }

        let original_proposals = vec_to_map(vec![
            dragginz_proposal_36.clone(),
            icx_proposal_41.clone(),
            proposal.clone(),
        ]);

        let mut observed_proposals = original_proposals.clone();
        settle_proposals_stuck_in_ready_to_settle(
            now,
            dragginz_governance_canister_id,
            &mut observed_proposals,
        );

        let modified_dragginz_proposal_36 = ProposalData {
            is_eligible_for_rewards: false,
            ..dragginz_proposal_36.clone()
        };
        assert_eq!(
            modified_dragginz_proposal_36.reward_status(now),
            ProposalRewardStatus::Settled,
        );

        assert_eq!(
            observed_proposals,
            vec_to_map(vec![
                modified_dragginz_proposal_36,
                icx_proposal_41.clone(),
                proposal.clone(),
            ]),
        );

        let mut observed_proposals = original_proposals.clone();
        settle_proposals_stuck_in_ready_to_settle(
            now,
            icx_governance_canister_id,
            &mut observed_proposals,
        );

        let modified_icx_proposal_41 = ProposalData {
            is_eligible_for_rewards: false,
            ..icx_proposal_41.clone()
        };
        assert_eq!(
            modified_icx_proposal_41.reward_status(now),
            ProposalRewardStatus::Settled,
        );

        assert_eq!(
            observed_proposals,
            vec_to_map(vec![
                dragginz_proposal_36,
                modified_icx_proposal_41,
                proposal,
            ]),
        );
    }

    #[test]
    fn test_populate_finalize_disbursement_timestamp_seconds() {
        // Step 1: prepare a neuron with 2 in progress disbursement, one with
        // finalize_disbursement_timestamp_seconds as None, and the other has incorrect timestamp.
        let mut governance_proto = GovernanceProto {
            neurons: btreemap! {
                "1".to_string() => Neuron {
                    disburse_maturity_in_progress: vec![
                        DisburseMaturityInProgress {
                            timestamp_of_disbursement_seconds: 1,
                            finalize_disbursement_timestamp_seconds: None,
                            ..Default::default()
                        },
                        DisburseMaturityInProgress {
                            timestamp_of_disbursement_seconds: 2,
                            finalize_disbursement_timestamp_seconds: Some(3),
                            ..Default::default()
                        }
                    ],
                    ..Default::default()
                },
            },
            ..Default::default()
        };

        // Step 2: populates the timestamps.
        populate_finalize_disbursement_timestamp_seconds(&mut governance_proto);

        // Step 3: verifies that both disbursements have the correct finalization timestamps.
        let expected_governance_proto = GovernanceProto {
            neurons: btreemap! {
                "1".to_string() => Neuron {
                    disburse_maturity_in_progress: vec![
                        DisburseMaturityInProgress {
                            timestamp_of_disbursement_seconds: 1,
                            finalize_disbursement_timestamp_seconds: Some(1 + MATURITY_DISBURSEMENT_DELAY_SECONDS),
                            ..Default::default()
                        },
                        DisburseMaturityInProgress {
                            timestamp_of_disbursement_seconds: 2,
                            finalize_disbursement_timestamp_seconds: Some(2 + MATURITY_DISBURSEMENT_DELAY_SECONDS),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
            },
            ..Default::default()
        };
        assert_eq!(governance_proto, expected_governance_proto);
    }
}
