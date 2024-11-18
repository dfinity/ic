use async_trait::async_trait;
use candid::{candid_method, Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::{
    api::call::arg_data_raw, caller as ic_cdk_caller, heartbeat, post_upgrade, pre_upgrade,
    println, query, spawn, update,
};
use ic_management_canister_types::IC_00;
use ic_nervous_system_canisters::cmc::CMCCanister;
use ic_nervous_system_common::{
    memory_manager_upgrade_storage::{load_protobuf, store_protobuf},
    serve_metrics,
};
use ic_nervous_system_runtime::{CdkRuntime, Runtime};
use ic_nns_common::{
    access_control::{check_caller_is_gtc, check_caller_is_ledger},
    pb::v1::{NeuronId as NeuronIdProto, ProposalId as ProposalIdProto},
    types::{CallCanisterProposal, NeuronId, ProposalId},
};
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_nns_governance::{
    decoder_config, encode_metrics,
    governance::{Environment, Governance, HeapGrowthPotential, RngError, TimeWarp as GovTimeWarp},
    neuron_data_validation::NeuronDataValidationSummary,
    pb::v1::{self as gov_pb, Governance as InternalGovernanceProto},
    storage::{grow_upgrades_memory_to, validate_stable_storage, with_upgrades_memory},
};
#[cfg(feature = "test")]
use ic_nns_governance_api::test_api::TimeWarp;
use ic_nns_governance_api::{
    bitcoin::{BitcoinNetwork, BitcoinSetConfigProposal},
    pb::v1::{
        claim_or_refresh_neuron_from_account_response::Result as ClaimOrRefreshNeuronFromAccountResponseResult,
        governance::{GovernanceCachedMetrics, Migrations},
        governance_error::ErrorType,
        manage_neuron::{
            claim_or_refresh::{By, MemoAndController},
            ClaimOrRefresh, NeuronIdOrSubaccount, RegisterVote,
        },
        manage_neuron_response, ClaimOrRefreshNeuronFromAccount,
        ClaimOrRefreshNeuronFromAccountResponse, GetNeuronsFundAuditInfoRequest,
        GetNeuronsFundAuditInfoResponse, Governance as ApiGovernanceProto, GovernanceError,
        ListKnownNeuronsResponse, ListNeurons, ListNeuronsResponse, ListNodeProviderRewardsRequest,
        ListNodeProviderRewardsResponse, ListNodeProvidersResponse, ListProposalInfo,
        ListProposalInfoResponse, ManageNeuronCommandRequest, ManageNeuronRequest,
        ManageNeuronResponse, MonthlyNodeProviderRewards, NetworkEconomics, Neuron, NeuronInfo,
        NodeProvider, Proposal, ProposalInfo, RestoreAgingSummary, RewardEvent,
        SettleCommunityFundParticipation, SettleNeuronsFundParticipationRequest,
        SettleNeuronsFundParticipationResponse, UpdateNodeProvider, Vote,
    },
    subnet_rental::{SubnetRentalProposalPayload, SubnetRentalRequest},
};
use ic_sns_wasm::pb::v1::{AddWasmRequest, SnsWasm};
use prost::Message;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{
    boxed::Box,
    str::FromStr,
    time::{Duration, SystemTime},
};

#[cfg(not(feature = "tla"))]
use ic_nervous_system_canisters::ledger::IcpLedgerCanister;

#[cfg(feature = "tla")]
mod tla_ledger;
#[cfg(feature = "tla")]
use tla_ledger::LoggingIcpLedgerCanister as IcpLedgerCanister;

/// WASM memory equivalent to 4GiB, which we want to reserve for upgrades memory. The heap memory
/// limit is 4GiB but its serialized form with prost should be smaller, so we reserve for 4GiB. This
/// is to make sure that even if we have a bug causing stable memory getting full, we do not trap in
/// pre_upgrade by trying to grow UPGRADES_MEMORY.
const WASM_PAGES_RESERVED_FOR_UPGRADES_MEMORY: u64 = 65_536;

pub(crate) const LOG_PREFIX: &str = "[Governance] ";

// https://dfinity.atlassian.net/browse/NNS1-1050: We are not following
// standard/best practices for canister globals here.
//
// Do not access these global variables directly. Instead, use accessor
// functions, which are defined immediately after.
static mut GOVERNANCE: Option<Governance> = None;

/*
Recommendations for Using `unsafe` in the Governance canister:

The state of governance is captured in a mutable static global variable to allow for
concurrent mutable access and modification of state in the NNS Governance canister. Due
to safety checks in Rust, accessing the static variable must be done in an unsafe block.
While this is generally an unsafe practice in normal Rust code, due to the message model of
the Internet Computer, only one instance of the state is ever accessed at once. The following
are best practices for making use of the unsafe block:

1. Initialization First:
    - Always ensure the global state (e.g., `GOVERNANCE`) has been initialized before access.
      Typically, this initialization occurs in `canister_init` or `canister_post_upgrade`.

2. Understanding
    - Lifetimes in Runtime Context: When working with asynchronous functions that use mutable
      references to Governance pay close attention to the different runtimes the code may run in:
        - In unit tests, all futures are immediately ready. Mutating a `'static` ref is still
          valid since futures resolve instantly, but is an abuse of the rules in Rust.
        - In mainnet, "self" refers to the `GOVERNANCE` static variable, which is initialized
          once in functions like `canister_init` or `canister_post_upgrade`.

3. Lifetime Assurances:
    - In a `Drop` implementation that takes mutable references of `self`, the scope of any
      `Governance` method ensures `&self` remains alive since Governance is always
      initialized immediately after an upgrade in the post upgrade hook. Additionally,
      since upgrades cannot happen during an asynchronous call (the upgrade waits for
      all open-call-contexts to be closed), Governance will never be un-initialized
      when an async method returns. De-referencing is acceptable in this context. For
      instance, it's always safe when a `LedgerUpdateLock` goes out of scope,
      but requires an `unsafe` block.

4. Safety Checks Inside Unsafe:
    - Although a block is marked `unsafe`, internal verifications are still essential. For
      instance, `unlock_neuron` within the `Drop` implementation of `LedgerUpdateLock`
      confirms the lock's existence despite being inside an unsafe context.

5. Modifying references across and await:
    - Since the CDK will put local variables on the stack, accessing a reference across an
      await is not advised. It is best practice to reacquire a reference to the state after
      an async call.
*/
/// Returns an immutable reference to the global state.
///
/// This should only be called once the global state has been initialized, which
/// happens in `canister_init` or `canister_post_upgrade`.
fn governance() -> &'static Governance {
    unsafe { GOVERNANCE.as_ref().expect("Canister not initialized!") }
}

/// Returns a mutable reference to the global state.
///
/// This should only be called once the global state has been initialized, which
/// happens in `canister_init` or `canister_post_upgrade`.
fn governance_mut() -> &'static mut Governance {
    unsafe { GOVERNANCE.as_mut().expect("Canister not initialized!") }
}

// Sets governance global state to the given object.
fn set_governance(gov: Governance) {
    unsafe {
        assert!(
            GOVERNANCE.is_none(),
            "{}Trying to initialize an already-initialized governance canister!",
            LOG_PREFIX
        );
        GOVERNANCE = Some(gov);
    }

    governance()
        .validate()
        .expect("Error initializing the governance canister.");
}

fn schedule_timers() {
    schedule_seeding(Duration::from_nanos(0));
    schedule_adjust_neurons_storage(Duration::from_nanos(0), NeuronIdProto { id: 0 });
    schedule_vote_processing();
}

// Seeding interval seeks to find a balance between the need for rng secrecy, and
// avoiding the overhead of frequent reseeding.
const SEEDING_INTERVAL: Duration = Duration::from_secs(3600);
const RETRY_SEEDING_INTERVAL: Duration = Duration::from_secs(30);

fn schedule_seeding(duration: Duration) {
    ic_cdk_timers::set_timer(duration, || {
        spawn(async {
            let result: Result<([u8; 32],), (i32, String)> =
                CdkRuntime::call_with_cleanup(IC_00, "raw_rand", ()).await;

            let seed = match result {
                Ok((seed,)) => seed,
                Err((code, msg)) => {
                    println!(
                        "{}Error seeding RNG. Error Code: {}. Error Message: {}",
                        LOG_PREFIX, code, msg
                    );
                    schedule_seeding(RETRY_SEEDING_INTERVAL);
                    return;
                }
            };

            () = governance_mut().env.seed_rng(seed);
            // Schedule reseeding on a timer with duration SEEDING_INTERVAL
            schedule_seeding(SEEDING_INTERVAL);
        })
    });
}

// The interval before adjusting neuron storage for the next batch of neurons starting from last
// neuron id scanned in the last batch.
const ADJUST_NEURON_STORAGE_BATCH_INTERVAL: Duration = Duration::from_secs(5);
// The interval before adjusting neuron storage for the next round starting from the smallest neuron
// id.
const ADJUST_NEURON_STORAGE_ROUND_INTERVAL: Duration = Duration::from_secs(3600);

fn schedule_adjust_neurons_storage(delay: Duration, start_neuron_id: NeuronIdProto) {
    ic_cdk_timers::set_timer(delay, move || {
        let next_neuron_id = governance_mut().batch_adjust_neurons_storage(start_neuron_id);
        match next_neuron_id {
            Some(next_neuron_id) => schedule_adjust_neurons_storage(
                ADJUST_NEURON_STORAGE_BATCH_INTERVAL,
                next_neuron_id,
            ),
            None => schedule_adjust_neurons_storage(
                ADJUST_NEURON_STORAGE_ROUND_INTERVAL,
                NeuronIdProto { id: 0 },
            ),
        };
    });
}

/// The interval at which the voting state machines are processed.
const VOTE_PROCESSING_INTERVAL: Duration = Duration::from_secs(3);

fn schedule_vote_processing() {
    ic_cdk_timers::set_timer_interval(VOTE_PROCESSING_INTERVAL, || {
        governance_mut().process_voting_state_machines();
    });
}

struct CanisterEnv {
    rng: Option<ChaCha20Rng>,
    time_warp: GovTimeWarp,
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

impl CanisterEnv {
    fn new() -> Self {
        CanisterEnv {
            rng: None,
            time_warp: GovTimeWarp { delta_s: 0 },
        }
    }
}

#[async_trait]
impl Environment for CanisterEnv {
    fn now(&self) -> u64 {
        self.time_warp.apply(now_seconds())
    }

    fn set_time_warp(&mut self, new_time_warp: GovTimeWarp) {
        self.time_warp = new_time_warp;
    }

    fn random_u64(&mut self) -> Result<u64, RngError> {
        match self.rng.as_mut() {
            Some(rand) => Ok(rand.next_u64()),
            None => Err(RngError::RngNotInitialized),
        }
    }

    fn random_byte_array(&mut self) -> Result<[u8; 32], RngError> {
        match self.rng.as_mut() {
            Some(rand) => {
                let mut bytes = [0u8; 32];
                rand.fill_bytes(&mut bytes);
                Ok(bytes)
            }
            None => Err(RngError::RngNotInitialized),
        }
    }

    fn seed_rng(&mut self, seed: [u8; 32]) {
        self.rng.replace(ChaCha20Rng::from_seed(seed));
    }

    fn get_rng_seed(&self) -> Option<[u8; 32]> {
        self.rng.as_ref().map(|rng| rng.get_seed())
    }

    fn execute_nns_function(
        &self,
        proposal_id: u64,
        update: &gov_pb::ExecuteNnsFunction,
    ) -> Result<(), gov_pb::GovernanceError> {
        // use internal types, as this API is used in core
        use gov_pb::{governance_error::ErrorType, GovernanceError, NnsFunction};

        let mt = NnsFunction::try_from(update.nns_function).map_err(|_|
            // No update type specified.
            GovernanceError::new(ErrorType::PreconditionFailed))?;

        let reply = move || {
            governance_mut().set_proposal_execution_status(proposal_id, Ok(()));
        };
        let reject = move |(code, msg): (i32, String)| {
            let mut msg = msg;
            // There's no guarantee that the reject response is a string of character, and
            // it can also be potential large. Propagating error information
            // here is on a best-effort basis.
            const MAX_REJECT_MSG_SIZE: usize = 10000;
            if msg.len() > MAX_REJECT_MSG_SIZE {
                msg = "(truncated error message) "
                    .to_string()
                    .chars()
                    .chain(
                        msg.char_indices()
                            .take_while(|(pos, _)| *pos < MAX_REJECT_MSG_SIZE)
                            .map(|(_, char)| char),
                    )
                    .collect();
            }

            governance_mut().set_proposal_execution_status(
                proposal_id,
                Err(GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Error executing ExecuteNnsFunction proposal. Error Code: {}. Rejection message: {}",
                        code,
                        msg
                    ),
                )),
            );
        };
        let (canister_id, method) = mt.canister_and_function()?;
        let method = method.to_owned();
        let proposal_timestamp_seconds = governance()
            .get_proposal_data(ProposalId(proposal_id))
            .map(|data| data.proposal_timestamp_seconds)
            .ok_or(GovernanceError::new(ErrorType::PreconditionFailed))?;
        let effective_payload = get_effective_payload(
            mt,
            update.payload.clone(),
            proposal_id,
            proposal_timestamp_seconds,
        )?;

        spawn(async move {
            match CdkRuntime::call_bytes_with_cleanup(canister_id, &method, &effective_payload)
                .await
            {
                Ok(_) => reply(),
                Err(e) => reject(e),
            }
        });

        Ok(())
    }

    async fn call_canister_method(
        &self,
        target: CanisterId,
        method_name: &str,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        CdkRuntime::call_bytes_with_cleanup(target, method_name, &request)
            .await
            .map_err(|(code, msg)| (Some(code), msg))
    }

    #[cfg(target_arch = "wasm32")]
    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        if core::arch::wasm32::memory_size(0)
            < ic_nns_governance::governance::HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES
        {
            HeapGrowthPotential::NoIssue
        } else {
            HeapGrowthPotential::LimitedAvailability
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        unimplemented!("CanisterEnv can only be used with wasm32 environment.");
    }
}

// We expect PrincipalId for all methods, but ic_cdk returns candid::Principal, so we need to
// convert it.
fn caller() -> PrincipalId {
    PrincipalId::from(ic_cdk_caller())
}

fn debug_log(s: &str) {
    if cfg!(feature = "test") {
        println!("{}{}", LOG_PREFIX, s);
    }
}

fn panic_with_probability(probability: f64, message: &str) {
    // We cannot use the `CanisterEnv::random_u64` method here, since panicking rolls back the
    // state, which makes sure that the next time still panics, unless some other operation modifies
    // the `rng` successfully, such as spawning a neuron.
    let random = ChaCha20Rng::seed_from_u64(now_seconds()).next_u64();
    let should_panic = (random as f64) / (u64::MAX as f64) < probability;
    if should_panic {
        panic!("{}", message);
    }
}

// TODO - can we migrate the canister_init to use candid later?
#[export_name = "canister_init"]
fn canister_init() {
    ic_cdk::setup();

    match ApiGovernanceProto::decode(&arg_data_raw()[..]) {
        Err(err) => {
            println!(
                "Error deserializing canister state in initialization: {}.",
                err
            );
            Err(err)
        }
        Ok(proto) => {
            canister_init_(proto);
            Ok(())
        }
    }
    .expect("Couldn't initialize canister.");
}

#[candid_method(init)]
fn canister_init_(init_payload: ApiGovernanceProto) {
    println!(
        "{}canister_init: Initializing with: economics: \
          {:?}, genesis_timestamp_seconds: {}, neuron count: {}",
        LOG_PREFIX,
        init_payload.economics,
        init_payload.genesis_timestamp_seconds,
        init_payload.neurons.len()
    );

    schedule_timers();
    set_governance(Governance::new(
        InternalGovernanceProto::from(init_payload),
        Box::new(CanisterEnv::new()),
        Box::new(IcpLedgerCanister::<CdkRuntime>::new(LEDGER_CANISTER_ID)),
        Box::new(CMCCanister::<CdkRuntime>::new()),
    ));
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
          {:?}, genesis_timestamp_seconds: {}, neuron count: {}, xdr_conversion_rate: {:?}",
        LOG_PREFIX,
        restored_state.economics,
        restored_state.genesis_timestamp_seconds,
        restored_state.neurons.len(),
        restored_state.xdr_conversion_rate,
    );

    schedule_timers();
    set_governance(Governance::new_restored(
        restored_state,
        Box::new(CanisterEnv::new()),
        Box::new(IcpLedgerCanister::<CdkRuntime>::new(LEDGER_CANISTER_ID)),
        Box::new(CMCCanister::<CdkRuntime>::new()),
    ));

    validate_stable_storage();
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

#[update(hidden = true)]
fn transfer_notification_pb() {
    debug_log("neuron_stake_transfer_notification_pb");
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
    ManageNeuronResponse::from(
        governance_mut()
            .manage_neuron(&caller(), &(gov_pb::ManageNeuron::from(_manage_neuron)))
            .await,
    )
}

#[cfg(feature = "test")]
#[update]
/// Internal method for calling update_neuron.
fn update_neuron(neuron: Neuron) -> Option<GovernanceError> {
    debug_log("update_neuron");
    governance_mut()
        .update_neuron(gov_pb::Neuron::from(neuron))
        .err()
        .map(GovernanceError::from)
}

#[update]
fn simulate_manage_neuron(manage_neuron: ManageNeuronRequest) -> ManageNeuronResponse {
    debug_log("simulate_manage_neuron");
    let response =
        governance().simulate_manage_neuron(&caller(), gov_pb::ManageNeuron::from(manage_neuron));
    ManageNeuronResponse::from(response)
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
        .map(Neuron::from)
        .map_err(GovernanceError::from)
}

#[query]
fn get_full_neuron(neuron_id: NeuronId) -> Result<Neuron, GovernanceError> {
    debug_log("get_full_neuron");
    governance()
        .get_full_neuron(&NeuronIdProto::from(neuron_id), &caller())
        .map(Neuron::from)
        .map_err(GovernanceError::from)
}

#[query]
fn get_neuron_info(neuron_id: NeuronId) -> Result<NeuronInfo, GovernanceError> {
    debug_log("get_neuron_info");
    governance()
        .get_neuron_info(&NeuronIdProto::from(neuron_id), caller())
        .map(NeuronInfo::from)
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
        .map(NeuronInfo::from)
        .map_err(GovernanceError::from)
}

#[query]
fn get_proposal_info(id: ProposalId) -> Option<ProposalInfo> {
    debug_log("get_proposal_info");
    governance()
        .get_proposal_info(&caller(), id)
        .map(ProposalInfo::from)
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
fn get_pending_proposals() -> Vec<ProposalInfo> {
    debug_log("get_pending_proposals");
    governance()
        .get_pending_proposals(&caller())
        .into_iter()
        .map(ProposalInfo::from)
        .collect()
}

#[query]
fn list_proposals(req: ListProposalInfo) -> ListProposalInfoResponse {
    debug_log("list_proposals");
    governance().list_proposals(&caller(), &(req.into())).into()
}

#[query]
fn list_neurons(req: ListNeurons) -> ListNeuronsResponse {
    debug_log("list_neurons");
    governance().list_neurons(&(req.into()), caller()).into()
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
        "{}submit_proposal is deprecated, and now always panics. \
               Use `manage_neuron` instead to submit a proposal.",
        LOG_PREFIX
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
    let votable = governance().get_neuron_ids_by_principal(&caller());

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

#[export_name = "canister_update manage_neuron_pb"]
fn manage_neuron_pb() {
    debug_log("manage_neuron_pb");
    panic_with_probability(
        0.1,
        "manage_neuron_pb is deprecated. Please use manage_neuron instead.",
    );

    let input = arg_data_raw();

    ic_cdk::spawn(async move {
        ic_cdk::setup();
        let request =
            ManageNeuronRequest::decode(&input[..]).expect("Could not decode ManageNeuronRequest");
        let res: ManageNeuronResponse = manage_neuron(request).await;
        let mut buf = Vec::with_capacity(res.encoded_len());
        res.encode(&mut buf)
            .map_err(|e| e.to_string())
            .expect("Could not encode response");
        ic_cdk::api::call::reply_raw(&buf)
    })
}

#[export_name = "canister_update claim_or_refresh_neuron_from_account_pb"]
fn claim_or_refresh_neuron_from_account_pb() {
    debug_log("claim_or_refresh_neuron_from_account_pb");
    panic!("Method removed. Please use ManageNeuron::ClaimOrRefresh.",)
}

#[export_name = "canister_query list_proposals_pb"]
fn list_proposals_pb() {
    debug_log("list_proposals_pb");
    panic!("Method removed.  Please use list_proposals instead.")
}

#[export_name = "canister_query list_neurons_pb"]
fn list_neurons_pb() {
    debug_log("list_neurons_pb");
    panic_with_probability(
        0.1,
        "list_neurons_pb is deprecated. Please use list_neurons instead.",
    );

    ic_cdk::setup();
    let request = ListNeurons::decode(&arg_data_raw()[..]).expect("Could not decode ListNeurons");
    let res: ListNeuronsResponse = list_neurons(request);
    let mut buf = Vec::with_capacity(res.encoded_len());
    res.encode(&mut buf)
        .map_err(|e| e.to_string())
        .expect("Could not encode response");
    ic_cdk::api::call::reply_raw(&buf);
}

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

#[query(hidden = true)]
fn get_migrations() -> Migrations {
    let response = governance()
        .heap_data
        .migrations
        .clone()
        .unwrap_or_default();
    Migrations::from(response)
}

#[query]
fn get_restore_aging_summary() -> RestoreAgingSummary {
    let response = governance().get_restore_aging_summary().unwrap_or_default();
    RestoreAgingSummary::from(response)
}

#[query(hidden = true, decoding_quota = 10000)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => serve_metrics(|encoder| encode_metrics(governance(), encoder)),
        _ => HttpResponseBuilder::not_found().build(),
    }
}

// Processes the payload received and transforms it into a form the intended canister expects.
// The arguments `proposal_id` is used by AddSnsWasm proposals.
// `_proposal_timestamp_seconds` will be used in the future by subnet rental NNS proposals.
fn get_effective_payload(
    mt: gov_pb::NnsFunction,
    payload: Vec<u8>,
    proposal_id: u64,
    proposal_timestamp_seconds: u64,
) -> Result<Vec<u8>, gov_pb::GovernanceError> {
    use gov_pb::{governance_error::ErrorType, GovernanceError, NnsFunction};

    const BITCOIN_SET_CONFIG_METHOD_NAME: &str = "set_config";
    const BITCOIN_MAINNET_CANISTER_ID: &str = "ghsi2-tqaaa-aaaan-aaaca-cai";
    const BITCOIN_TESTNET_CANISTER_ID: &str = "g4xu7-jiaaa-aaaan-aaaaq-cai";

    match mt {
        NnsFunction::BitcoinSetConfig => {
            // Decode the payload to get the network.
            let payload = match Decode!([decoder_config()]; &payload, BitcoinSetConfigProposal) {
              Ok(payload) => payload,
              Err(_) => {
                return Err(GovernanceError::new_with_message(ErrorType::InvalidProposal, "Payload must be a valid BitcoinSetConfigProposal."));
              }
            };

            // Convert it to a call canister payload.
            let canister_id = CanisterId::from_str(match payload.network {
                BitcoinNetwork::Mainnet => BITCOIN_MAINNET_CANISTER_ID,
                BitcoinNetwork::Testnet => BITCOIN_TESTNET_CANISTER_ID,
            }).expect("bitcoin canister id must be valid.");

            let encoded_payload = Encode!(&CallCanisterProposal {
                canister_id,
                method_name: BITCOIN_SET_CONFIG_METHOD_NAME.to_string(),
                payload: payload.payload
            })
            .unwrap();

            Ok(encoded_payload)
        }
        NnsFunction::SubnetRentalRequest => {
            // Decode the payload to `SubnetRentalRequest`.
            let payload = match Decode!([decoder_config()]; &payload, SubnetRentalRequest) {
              Ok(payload) => payload,
              Err(_) => {
                return Err(GovernanceError::new_with_message(ErrorType::InvalidProposal, "Payload must be a valid SubnetRentalRequest."));
              }
            };

            // Convert the payload to `SubnetRentalProposalPayload`.
            let SubnetRentalRequest {
                user,
                rental_condition_id,
            } = payload;
            let proposal_creation_time_seconds = proposal_timestamp_seconds;
            let encoded_payload = Encode!(&SubnetRentalProposalPayload {
                user,
                rental_condition_id,
                proposal_id,
                proposal_creation_time_seconds,
            }).unwrap();

            Ok(encoded_payload)
        }

        | NnsFunction::AddSnsWasm => {
            let payload = add_proposal_id_to_add_wasm_request(&payload, proposal_id)?;

            Ok(payload)
        }

        // NOTE: Methods are listed explicitly as opposed to using the `_` wildcard so
        // that adding a new function causes a compile error here, ensuring that the developer
        // makes an explicit decision on how the payload is handled.
        NnsFunction::Unspecified
        | NnsFunction::UpdateElectedHostosVersions
        | NnsFunction::UpdateNodesHostosVersion
        | NnsFunction::ReviseElectedHostosVersions
        | NnsFunction::DeployHostosToSomeNodes
        | NnsFunction::AssignNoid
        | NnsFunction::CreateSubnet
        | NnsFunction::AddNodeToSubnet
        | NnsFunction::RemoveNodesFromSubnet
        | NnsFunction::ChangeSubnetMembership
        | NnsFunction::NnsCanisterInstall
        | NnsFunction::NnsCanisterUpgrade
        | NnsFunction::NnsRootUpgrade
        | NnsFunction::HardResetNnsRootToVersion
        | NnsFunction::RecoverSubnet
        | NnsFunction::BlessReplicaVersion
        | NnsFunction::RetireReplicaVersion
        | NnsFunction::ReviseElectedGuestosVersions
        | NnsFunction::UpdateNodeOperatorConfig
        | NnsFunction::DeployGuestosToAllSubnetNodes
        | NnsFunction::UpdateConfigOfSubnet
        | NnsFunction::IcpXdrConversionRate
        | NnsFunction::ClearProvisionalWhitelist
        | NnsFunction::SetAuthorizedSubnetworks
        | NnsFunction::SetFirewallConfig
        | NnsFunction::AddFirewallRules
        | NnsFunction::RemoveFirewallRules
        | NnsFunction::UpdateFirewallRules
        | NnsFunction::StopOrStartNnsCanister
        | NnsFunction::RemoveNodes
        | NnsFunction::UninstallCode
        | NnsFunction::UpdateNodeRewardsTable
        | NnsFunction::AddOrRemoveDataCenters
        | NnsFunction::UpdateUnassignedNodesConfig // obsolete
        | NnsFunction::RemoveNodeOperators
        | NnsFunction::RerouteCanisterRanges
        | NnsFunction::PrepareCanisterMigration
        | NnsFunction::CompleteCanisterMigration
        | NnsFunction::UpdateSubnetType
        | NnsFunction::ChangeSubnetTypeAssignment
        | NnsFunction::UpdateAllowedPrincipals
        | NnsFunction::UpdateSnsWasmSnsSubnetIds
        | NnsFunction::InsertSnsWasmUpgradePathEntries
        | NnsFunction::AddApiBoundaryNodes
        | NnsFunction::RemoveApiBoundaryNodes
        | NnsFunction::UpdateApiBoundaryNodesVersion // obsolete
        | NnsFunction::DeployGuestosToAllUnassignedNodes
        | NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes
        | NnsFunction::DeployGuestosToSomeApiBoundaryNodes => Ok(payload),
    }
}

fn add_proposal_id_to_add_wasm_request(
    payload: &[u8],
    proposal_id: u64,
) -> Result<Vec<u8>, GovernanceError> {
    let add_wasm_request = match Decode!([decoder_config()]; payload, AddWasmRequest) {
        Ok(add_wasm_request) => add_wasm_request,
        Err(e) => {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Payload must be a valid AddWasmRequest. Error: {e}"),
            ));
        }
    };

    let wasm = add_wasm_request
        .wasm
        .ok_or(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            "Payload must contain a wasm.",
        ))?;

    let add_wasm_request = AddWasmRequest {
        wasm: Some(SnsWasm {
            proposal_id: Some(proposal_id),
            ..wasm
        }),
        ..add_wasm_request
    };

    let payload = Encode!(&add_wasm_request).unwrap();

    Ok(payload)
}

fn main() {
    // This block is intentionally left blank.
}

// In order for some of the test(s) within this mod to work,
// this MUST occur at the end.
#[cfg(test)]
mod tests;
