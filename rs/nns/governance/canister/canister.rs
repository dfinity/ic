// Note on `candid_method`: each canister method should have a function
// annotated with `#[candid_method]` that has the arguments and return type
// expected by the canister method, to be able to generate `governance.did`
// automatically.
//
// This often means we need a function with `#[export_name = "canister_query
// my_method"]` that doesn't take arguments and doesn't return anything (per IC
// spec), then another function the actual method arguments and return type,
// annotated with `#[candid_method(query/update)]` to be able to generate the
// did definition of the method.

use async_trait::async_trait;
use candid::{candid_method, Decode, Encode};
use dfn_candid::{candid, candid_one};
use dfn_core::{
    api::{arg_data, call_with_callbacks, caller, now, reject_message},
    over, over_async, println,
};
use dfn_protobuf::protobuf;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::{
    cmc::CMCCanister,
    ledger::IcpLedgerCanister,
    memory_manager_upgrade_storage::{load_protobuf, store_protobuf},
};
use ic_nervous_system_runtime::DfnRuntime;
use ic_nns_common::{
    access_control::{check_caller_is_gtc, check_caller_is_ledger},
    pb::v1::{NeuronId as NeuronIdProto, ProposalId as ProposalIdProto},
    types::{CallCanisterProposal, NeuronId, ProposalId},
};

use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_nns_governance::{
    decoder_config, encode_metrics,
    governance::{Environment, Governance, HeapGrowthPotential, TimeWarp},
    neuron_data_validation::NeuronDataValidationSummary,
    pb::{v1 as gov_pb, v1::Governance as InternalGovernanceProto},
    storage::{grow_upgrades_memory_to, validate_stable_storage, with_upgrades_memory},
};
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
use std::{borrow::Cow, boxed::Box, str::FromStr, time::SystemTime};

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

struct CanisterEnv {
    rng: ChaCha20Rng,
    time_warp: TimeWarp,
}

impl CanisterEnv {
    fn new() -> Self {
        CanisterEnv {
            // Seed the PRNG with the current time.
            //
            // This is safe since all replicas are guaranteed to see the same result of time()
            // and it isn't easily predictable from the outside.
            //
            // Using raw_rand from the ic00 api is an asynchronous call so can't really be
            // used to generate random numbers for most cases. It could be used to seed
            // the PRNG, but that wouldn't help much since after inception the pseudo-random
            // numbers could be predicted.
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

    fn random_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.rng.fill_bytes(&mut bytes);
        bytes
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
        let reject = move || {
            // There's no guarantee that the reject response is a string of character, and
            // it can also be potential large. Propagating error information
            // here is on a best-effort basis.
            let mut msg = reject_message();
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
                        "Error executing ExecuteNnsFunction proposal. Rejection message: {}",
                        msg
                    ),
                )),
            );
        };
        let (canister_id, method) = mt.canister_and_function()?;
        let proposal_timestamp_seconds = governance()
            .get_proposal_data(ProposalId(proposal_id))
            .map(|data| data.proposal_timestamp_seconds)
            .ok_or(GovernanceError::new(ErrorType::PreconditionFailed))?;
        let effective_payload =
            get_effective_payload(mt, &update.payload, proposal_id, proposal_timestamp_seconds)?;
        let err = call_with_callbacks(canister_id, method, &effective_payload, reply, reject);
        if err != 0 {
            Err(GovernanceError::new(ErrorType::PreconditionFailed))
        } else {
            Ok(())
        }
    }

    async fn call_canister_method(
        &mut self,
        target: CanisterId,
        method_name: &str,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        dfn_core::api::call_with_cleanup(target, method_name, on_wire::bytes, request).await
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

fn debug_log(s: &str) {
    if cfg!(feature = "test") {
        println!("{}{}", LOG_PREFIX, s);
    }
}

#[export_name = "canister_init"]
fn canister_init() {
    dfn_core::printer::hook();

    match ApiGovernanceProto::decode(&arg_data()[..]) {
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

    set_governance(Governance::new(
        InternalGovernanceProto::from(init_payload),
        Box::new(CanisterEnv::new()),
        Box::new(IcpLedgerCanister::new(LEDGER_CANISTER_ID)),
        Box::new(CMCCanister::<DfnRuntime>::new()),
    ));
}

#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    println!("{}Executing pre upgrade", LOG_PREFIX);

    with_upgrades_memory(|memory| {
        let governance_proto = governance_mut().take_heap_proto();
        store_protobuf(memory, &governance_proto).expect("Failed to encode protobuf pre_upgrade");
    });
}

#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
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
    set_governance(Governance::new_restored(
        restored_state,
        Box::new(CanisterEnv::new()),
        Box::new(IcpLedgerCanister::new(LEDGER_CANISTER_ID)),
        Box::new(CMCCanister::<DfnRuntime>::new()),
    ));

    validate_stable_storage();
}

#[cfg(feature = "test")]
#[export_name = "canister_update set_time_warp"]
fn set_time_warp() {
    over(candid_one, set_time_warp_);
}

#[cfg(feature = "test")]
fn set_time_warp_(new_time_warp: TimeWarp) {
    governance_mut().set_time_warp(new_time_warp);
}

/// DEPRECATED: Use manage_neuron directly instead.
#[export_name = "canister_update forward_vote"]
fn vote() {
    debug_log("forward_vote");
    over_async(
        candid,
        |(neuron_id, proposal_id, vote): (NeuronId, ProposalId, Vote)| async move {
            manage_neuron_(ManageNeuronRequest {
                id: Some(NeuronIdProto::from(neuron_id)),
                command: Some(ManageNeuronCommandRequest::RegisterVote(RegisterVote {
                    proposal: Some(ProposalIdProto::from(proposal_id)),
                    vote: vote as i32,
                })),
                neuron_id_or_subaccount: None,
            })
            .await
        },
    )
}

#[export_name = "canister_update transaction_notification"]
fn neuron_stake_transfer_notification() {
    debug_log("neuron_stake_transfer_notification");
    check_caller_is_ledger();
    panic!("Method removed. Please use ManageNeuron::ClaimOrRefresh.",)
}

#[export_name = "canister_update transaction_notification_pb"]
fn neuron_stake_transfer_notification_pb() {
    debug_log("neuron_stake_transfer_notification_pb");
    check_caller_is_ledger();
    panic!("Method removed. Please use ManageNeuron::ClaimOrRefresh.",)
}

// DEPRECATED: Please use ManageNeuron::ClaimOrRefresh.
#[export_name = "canister_update claim_or_refresh_neuron_from_account"]
fn claim_or_refresh_neuron_from_account() {
    debug_log("claim_or_refresh_neuron_from_account");
    over_async(candid_one, claim_or_refresh_neuron_from_account_)
}

// DEPRECATED: Please use ManageNeuron::ClaimOrRefresh.
//
// Just redirects to ManageNeuron.
#[candid_method(update, rename = "claim_or_refresh_neuron_from_account")]
async fn claim_or_refresh_neuron_from_account_(
    claim_or_refresh: ClaimOrRefreshNeuronFromAccount,
) -> ClaimOrRefreshNeuronFromAccountResponse {
    let manage_neuron_response = manage_neuron_(ManageNeuronRequest {
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

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method! {}

#[export_name = "canister_update claim_gtc_neurons"]
fn claim_gtc_neurons() {
    debug_log("claim_gtc_neurons");
    check_caller_is_gtc();
    over(
        candid,
        |(new_controller, neuron_ids): (PrincipalId, Vec<NeuronIdProto>)| -> Result<(), GovernanceError> {
            claim_gtc_neurons_(new_controller, neuron_ids)
        })
}

#[candid_method(update, rename = "claim_gtc_neurons")]
fn claim_gtc_neurons_(
    new_controller: PrincipalId,
    neuron_ids: Vec<NeuronIdProto>,
) -> Result<(), GovernanceError> {
    Ok(governance_mut().claim_gtc_neurons(&caller(), new_controller, neuron_ids)?)
}

#[export_name = "canister_update transfer_gtc_neuron"]
fn transfer_gtc_neuron() {
    debug_log("transfer_gtc_neuron");
    check_caller_is_gtc();
    over_async(
        candid,
        |(donor_neuron_id, recipient_neuron_id): (NeuronIdProto, NeuronIdProto)| async move {
            transfer_gtc_neuron_(donor_neuron_id, recipient_neuron_id).await
        },
    )
}

#[candid_method(update, rename = "transfer_gtc_neuron")]
async fn transfer_gtc_neuron_(
    donor_neuron_id: NeuronIdProto,
    recipient_neuron_id: NeuronIdProto,
) -> Result<(), GovernanceError> {
    Ok(governance_mut()
        .transfer_gtc_neuron(&caller(), &donor_neuron_id, &recipient_neuron_id)
        .await?)
}

#[export_name = "canister_update manage_neuron"]
fn manage_neuron() {
    debug_log("manage_neuron");
    over_async(candid_one, manage_neuron_)
}

#[candid_method(update, rename = "manage_neuron")]
async fn manage_neuron_(manage_neuron: ManageNeuronRequest) -> ManageNeuronResponse {
    let response = governance_mut()
        .manage_neuron(&caller(), &(gov_pb::ManageNeuron::from(manage_neuron)))
        .await;
    ManageNeuronResponse::from(response)
}

#[cfg(feature = "test")]
#[export_name = "canister_update update_neuron"]
/// Test only feature. Update neuron parameters.
fn update_neuron() {
    println!("{}update_neuron", LOG_PREFIX);
    over(candid_one, update_neuron_)
}

#[cfg(feature = "test")]
#[candid_method(update, rename = "update_neuron")]
/// Internal method for calling update_neuron.
fn update_neuron_(neuron: Neuron) -> Option<GovernanceError> {
    governance_mut()
        .update_neuron(gov_pb::Neuron::from(neuron))
        .err()
        .map(GovernanceError::from)
}

#[export_name = "canister_update simulate_manage_neuron"]
fn simulate_manage_neuron() {
    debug_log("simulate_manage_neuron");
    over(candid_one, simulate_manage_neuron_)
}

#[candid_method(update, rename = "simulate_manage_neuron")]
fn simulate_manage_neuron_(manage_neuron: ManageNeuronRequest) -> ManageNeuronResponse {
    let response =
        governance().simulate_manage_neuron(&caller(), gov_pb::ManageNeuron::from(manage_neuron));
    ManageNeuronResponse::from(response)
}

/// Returns the full neuron corresponding to the neuron id or subaccount.
#[export_name = "canister_query get_full_neuron_by_id_or_subaccount"]
fn get_full_neuron_by_id_or_subaccount() {
    debug_log("get_full_neuron_by_id_or_subaccount");
    over(candid_one, get_full_neuron_by_id_or_subaccount_)
}

#[candid_method(query, rename = "get_full_neuron_by_id_or_subaccount")]
fn get_full_neuron_by_id_or_subaccount_(
    by: NeuronIdOrSubaccount,
) -> Result<Neuron, GovernanceError> {
    governance()
        .get_full_neuron_by_id_or_subaccount(
            &(gov_pb::manage_neuron::NeuronIdOrSubaccount::from(by)),
            &caller(),
        )
        .map(Neuron::from)
        .map_err(GovernanceError::from)
}

/// Returns the full neuron corresponding to the neuron id.
#[export_name = "canister_query get_full_neuron"]
fn get_full_neuron() {
    debug_log("get_full_neuron");
    over(candid_one, get_full_neuron_)
}

#[candid_method(query, rename = "get_full_neuron")]
fn get_full_neuron_(neuron_id: NeuronId) -> Result<Neuron, GovernanceError> {
    governance()
        .get_full_neuron(&NeuronIdProto::from(neuron_id), &caller())
        .map(Neuron::from)
        .map_err(GovernanceError::from)
}

/// Returns the public neuron info corresponding to the neuron id.
#[export_name = "canister_query get_neuron_info"]
fn get_neuron_info() {
    debug_log("get_neuron_info");
    over(candid_one, get_neuron_info_)
}

#[candid_method(query, rename = "get_neuron_info")]
fn get_neuron_info_(neuron_id: NeuronId) -> Result<NeuronInfo, GovernanceError> {
    governance()
        .get_neuron_info(&NeuronIdProto::from(neuron_id), caller())
        .map(NeuronInfo::from)
        .map_err(GovernanceError::from)
}

/// Returns the public neuron info corresponding to the neuron id or subaccount.
#[export_name = "canister_query get_neuron_info_by_id_or_subaccount"]
fn get_neuron_info_by_id_or_subaccount() {
    debug_log("get_neuron_info_by_subaccount");
    over(candid_one, get_neuron_info_by_id_or_subaccount_)
}

#[candid_method(query, rename = "get_neuron_info_by_id_or_subaccount")]
fn get_neuron_info_by_id_or_subaccount_(
    by: NeuronIdOrSubaccount,
) -> Result<NeuronInfo, GovernanceError> {
    governance()
        .get_neuron_info_by_id_or_subaccount(
            &(gov_pb::manage_neuron::NeuronIdOrSubaccount::from(by)),
            caller(),
        )
        .map(NeuronInfo::from)
        .map_err(GovernanceError::from)
}

#[export_name = "canister_query get_proposal_info"]
fn get_proposal_info() {
    debug_log("get_proposal_info");
    over(candid_one, get_proposal_info_)
}

#[candid_method(query, rename = "get_proposal_info")]
fn get_proposal_info_(id: ProposalId) -> Option<ProposalInfo> {
    governance()
        .get_proposal_info(&caller(), id)
        .map(ProposalInfo::from)
}

#[export_name = "canister_query get_neurons_fund_audit_info"]
fn get_neurons_fund_audit_info() {
    debug_log("get_neurons_fund_audit_info");
    over(candid_one, get_neurons_fund_audit_info_)
}

#[candid_method(query, rename = "get_neurons_fund_audit_info")]
fn get_neurons_fund_audit_info_(
    request: GetNeuronsFundAuditInfoRequest,
) -> GetNeuronsFundAuditInfoResponse {
    let response = governance().get_neurons_fund_audit_info(request.into());
    let intermediate = gov_pb::GetNeuronsFundAuditInfoResponse::from(response);
    GetNeuronsFundAuditInfoResponse::from(intermediate)
}

#[export_name = "canister_query get_pending_proposals"]
fn get_pending_proposals() {
    debug_log("get_pending_proposals");
    over(candid, |()| -> Vec<ProposalInfo> {
        get_pending_proposals_()
    })
}

#[candid_method(query, rename = "get_pending_proposals")]
fn get_pending_proposals_() -> Vec<ProposalInfo> {
    governance()
        .get_pending_proposals(&caller())
        .into_iter()
        .map(ProposalInfo::from)
        .collect()
}

#[export_name = "canister_query list_proposals"]
fn list_proposals() {
    debug_log("list_proposals");
    over(candid_one, list_proposals_)
}

#[candid_method(query, rename = "list_proposals")]
fn list_proposals_(req: ListProposalInfo) -> ListProposalInfoResponse {
    governance().list_proposals(&caller(), &(req.into())).into()
}

#[export_name = "canister_query list_neurons"]
fn list_neurons() {
    debug_log("list_neurons");
    over(candid_one, list_neurons_)
}

#[candid_method(query, rename = "list_neurons")]
fn list_neurons_(req: ListNeurons) -> ListNeuronsResponse {
    governance().list_neurons(&(req.into()), caller()).into()
}

#[export_name = "canister_query get_metrics"]
fn get_metrics() {
    debug_log("get_metrics");
    over(candid, |()| get_metrics_())
}

#[candid_method(query, rename = "get_metrics")]
fn get_metrics_() -> Result<GovernanceCachedMetrics, GovernanceError> {
    governance()
        .get_metrics()
        .map(GovernanceCachedMetrics::from)
        .map_err(GovernanceError::from)
}

#[export_name = "canister_update get_monthly_node_provider_rewards"]
fn get_monthly_node_provider_rewards() {
    debug_log("get_monthly_node_provider_rewards");
    over_async(candid, |()| async move {
        get_monthly_node_provider_rewards_().await
    })
}

#[candid_method(update, rename = "get_monthly_node_provider_rewards")]
async fn get_monthly_node_provider_rewards_() -> Result<MonthlyNodeProviderRewards, GovernanceError>
{
    let rewards = governance_mut().get_monthly_node_provider_rewards().await?;
    Ok(MonthlyNodeProviderRewards::from(rewards))
}

#[export_name = "canister_query list_node_provider_rewards"]
fn list_node_provider_rewards() {
    debug_log("list_node_provider_rewards");
    over(candid_one, list_node_provider_rewards_)
}

#[candid_method(query, rename = "list_node_provider_rewards")]
fn list_node_provider_rewards_(
    req: ListNodeProviderRewardsRequest,
) -> ListNodeProviderRewardsResponse {
    let rewards = governance()
        .list_node_provider_rewards(req.date_filter.map(|d| d.into()))
        .into_iter()
        .map(MonthlyNodeProviderRewards::from)
        .collect();

    ListNodeProviderRewardsResponse { rewards }
}

#[export_name = "canister_query list_known_neurons"]
fn list_known_neurons() {
    debug_log("list_known_neurons");
    over(candid_one, |()| -> ListKnownNeuronsResponse {
        list_known_neurons_()
    })
}

#[candid_method(query, rename = "list_known_neurons")]
fn list_known_neurons_() -> ListKnownNeuronsResponse {
    let response = governance().list_known_neurons();
    ListKnownNeuronsResponse::from(response)
}

/// DEPRECATED: Always panics. Use manage_neuron instead.
/// TODO(NNS1-413): Remove this once we are sure that there are no callers.
#[export_name = "canister_update submit_proposal"]
fn submit_proposal() {
    over(
        candid,
        |(_proposer, _proposal, _caller): (NeuronId, Proposal, PrincipalId)| -> ProposalId {
            panic!(
                "{}submit_proposal is deprecated, and now always panics. \
               Use `manage_neuron` instead to submit a proposal.",
                LOG_PREFIX
            );
        },
    );
}

/// DEPRECATED: Proposals are now executed on every vote.
#[export_name = "canister_update execute_eligible_proposals"]
fn execute_eligible_proposals() {
    over(candid, |()| {
        println!(
            "{}execute_eligible_proposals -- This method does nothing!",
            LOG_PREFIX
        )
    });
}

/// Returns the latest reward event.
#[export_name = "canister_query get_latest_reward_event"]
fn get_latest_reward_event() {
    debug_log("get_latest_reward_event");
    over(candid, |()| get_latest_reward_event_());
}

#[candid_method(query, rename = "get_latest_reward_event")]
fn get_latest_reward_event_() -> RewardEvent {
    let response = governance().latest_reward_event().clone();
    RewardEvent::from(response)
}

/// Return the Neuron IDs of all Neurons that have `caller()` as their
/// controller or as one of their hot keys. Furthermore the Neuron IDs of all
/// Neurons that directly follow the former in the topic `NeuronManagement`
/// are included. Summarily, the Neuron IDs in the set returned can be queried
/// by `get_full_neuron` without getting an authorization error.
#[export_name = "canister_query get_neuron_ids"]
fn get_neuron_ids() {
    debug_log("get_neuron_ids");
    over(candid, |()| -> Vec<NeuronId> { get_neuron_ids_() })
}

#[candid_method(query, rename = "get_neuron_ids")]
fn get_neuron_ids_() -> Vec<NeuronId> {
    let votable = governance().get_neuron_ids_by_principal(&caller());

    governance()
        .get_managed_neuron_ids_for(votable)
        .into_iter()
        .map(NeuronId::from)
        .collect()
}

#[export_name = "canister_query get_network_economics_parameters"]
fn get_network_economics_parameters() {
    debug_log("get_network_economics_parameters");
    over(candid, |()| -> NetworkEconomics {
        get_network_economics_parameters_()
    })
}

#[candid_method(query, rename = "get_network_economics_parameters")]
fn get_network_economics_parameters_() -> NetworkEconomics {
    let response = governance()
        .heap_data
        .economics
        .as_ref()
        .expect("Governance must have network economics.")
        .clone();
    NetworkEconomics::from(response)
}

#[export_name = "canister_heartbeat"]
fn canister_heartbeat() {
    let future = governance_mut().run_periodic_tasks();

    // canister_heartbeat must be synchronous, so we cannot .await the future
    dfn_core::api::futures::spawn(future);
}

// Protobuf interface.

#[export_name = "canister_update manage_neuron_pb"]
fn manage_neuron_pb() {
    debug_log("manage_neuron_pb");
    over_async(protobuf, manage_neuron_)
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
    over(protobuf, list_neurons_)
}

#[export_name = "canister_update update_node_provider"]
fn update_node_provider() {
    debug_log("update_node_provider");
    over(candid_one, update_node_provider_)
}

#[candid_method(update, rename = "update_node_provider")]
fn update_node_provider_(req: UpdateNodeProvider) -> Result<(), GovernanceError> {
    Ok(governance_mut().update_node_provider(&caller(), gov_pb::UpdateNodeProvider::from(req))?)
}

#[export_name = "canister_update settle_community_fund_participation"]
fn settle_community_fund_participation() {
    debug_log("settle_community_fund_participation");
    over_async(candid_one, settle_community_fund_participation_)
}

/// Obsolete, so always returns an error. Please use `settle_neurons_fund_participation`
/// instead.
#[candid_method(update, rename = "settle_community_fund_participation")]
async fn settle_community_fund_participation_(
    _request: SettleCommunityFundParticipation,
) -> Result<(), GovernanceError> {
    Err(GovernanceError::new_with_message(
        ErrorType::Unavailable,
        "settle_community_fund_participation is obsolete; please \
        use settle_neurons_fund_participation instead."
            .to_string(),
    ))
}

#[export_name = "canister_update settle_neurons_fund_participation"]
fn settle_neurons_fund_participation() {
    debug_log("settle_neurons_fund_participation");
    over_async(candid_one, settle_neurons_fund_participation_)
}

#[candid_method(update, rename = "settle_neurons_fund_participation")]
async fn settle_neurons_fund_participation_(
    request: SettleNeuronsFundParticipationRequest,
) -> SettleNeuronsFundParticipationResponse {
    let response = governance_mut()
        .settle_neurons_fund_participation(caller(), request.into())
        .await;
    let intermediate = gov_pb::SettleNeuronsFundParticipationResponse::from(response);
    SettleNeuronsFundParticipationResponse::from(intermediate)
}

/// Return the NodeProvider record where NodeProvider.id == caller(), if such a
/// NodeProvider record exists.
#[export_name = "canister_query get_node_provider_by_caller"]
fn get_node_provider_by_caller() {
    debug_log("get_node_provider_by_caller");
    over(candid_one, get_node_provider_by_caller_)
}

#[candid_method(query, rename = "get_node_provider_by_caller")]
fn get_node_provider_by_caller_(_: ()) -> Result<NodeProvider, GovernanceError> {
    governance()
        .get_node_provider(&caller())
        .map(NodeProvider::from)
        .map_err(GovernanceError::from)
}

#[export_name = "canister_query list_node_providers"]
fn list_node_providers() {
    debug_log("list_node_providers");
    over(candid, |()| list_node_providers_());
}

#[candid_method(query, rename = "list_node_providers")]
fn list_node_providers_() -> ListNodeProvidersResponse {
    let node_providers = governance()
        .get_node_providers()
        .iter()
        .map(|np| NodeProvider::from(np.clone()))
        .collect::<Vec<_>>();
    ListNodeProvidersResponse { node_providers }
}

#[export_name = "canister_query get_most_recent_monthly_node_provider_rewards"]
fn get_most_recent_monthly_node_provider_rewards() {
    over(candid, |()| -> Option<MonthlyNodeProviderRewards> {
        get_most_recent_monthly_node_provider_rewards_()
    })
}

#[candid_method(query, rename = "get_most_recent_monthly_node_provider_rewards")]
fn get_most_recent_monthly_node_provider_rewards_() -> Option<MonthlyNodeProviderRewards> {
    governance()
        .get_most_recent_monthly_node_provider_rewards()
        .map(MonthlyNodeProviderRewards::from)
}

#[export_name = "canister_query get_neuron_data_validation_summary"]
fn get_neuron_data_validation_summary() {
    over(candid, |()| -> NeuronDataValidationSummary {
        governance().neuron_data_validation_summary()
    })
}

#[export_name = "canister_query get_migrations"]
fn get_migrations() {
    over(candid, |()| get_migrations_());
}

// Normally, we would do #[candid_method(query, rename = "get_migrations")] here, but we want to
// take this method away later. Therefore, this is done in order to avoid corresponding changes
// being made to our .did file. By doing things this way, we can "have our cake and eat it
// too". That is, we can have the functionality, but without promising to support it in the long
// term.
fn get_migrations_() -> Migrations {
    let response = governance()
        .heap_data
        .migrations
        .clone()
        .unwrap_or_default();
    Migrations::from(response)
}

#[export_name = "canister_query get_restore_aging_summary"]
fn get_restore_aging_summary() {
    over(candid, |()| -> RestoreAgingSummary {
        get_restore_aging_summary_()
    })
}

#[candid_method(query, rename = "get_restore_aging_summary")]
fn get_restore_aging_summary_() -> RestoreAgingSummary {
    let response = governance().get_restore_aging_summary().unwrap_or_default();
    RestoreAgingSummary::from(response)
}

#[export_name = "canister_query http_request"]
fn http_request() {
    dfn_http_metrics::serve_metrics(|metrics_encoder| {
        encode_metrics(governance(), metrics_encoder)
    });
}

// Processes the payload received and transforms it into a form the intended canister expects.
// The arguments `proposal_id` is used by AddSnsWasm proposals.
// `_proposal_timestamp_seconds` will be used in the future by subnet rental NNS proposals.
fn get_effective_payload(
    mt: gov_pb::NnsFunction,
    payload: &[u8],
    proposal_id: u64,
    proposal_timestamp_seconds: u64,
) -> Result<Cow<[u8]>, gov_pb::GovernanceError> {
    use gov_pb::{governance_error::ErrorType, GovernanceError, NnsFunction};

    const BITCOIN_SET_CONFIG_METHOD_NAME: &str = "set_config";
    const BITCOIN_MAINNET_CANISTER_ID: &str = "ghsi2-tqaaa-aaaan-aaaca-cai";
    const BITCOIN_TESTNET_CANISTER_ID: &str = "g4xu7-jiaaa-aaaan-aaaaq-cai";

    match mt {
        NnsFunction::BitcoinSetConfig => {
            // Decode the payload to get the network.
            let payload = match Decode!([decoder_config()]; payload, BitcoinSetConfigProposal) {
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

            Ok(Cow::Owned(encoded_payload))
        }
        NnsFunction::SubnetRentalRequest => {
            // Decode the payload to `SubnetRentalRequest`.
            let payload = match Decode!([decoder_config()]; payload, SubnetRentalRequest) {
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

            Ok(Cow::Owned(encoded_payload))
        }

        | NnsFunction::AddSnsWasm => {
            let payload = add_proposal_id_to_add_wasm_request(payload, proposal_id)?;

            Ok(Cow::Owned(payload))
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
        | NnsFunction::DeployGuestosToSomeApiBoundaryNodes => Ok(Cow::Borrowed(payload)),
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

// This makes this Candid service self-describing, so that for example Candid
// UI, but also other tools, can seamlessly integrate with it.
// The concrete interface (__get_candid_interface_tmp_hack) is provisional, but
// works.
//
// We include the .did file as committed, as means it is included verbatim in
// the .wasm; using `candid::export_service` here would involve unnecessary
// runtime computation

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

// When run on native this prints the candid service definition of this
// canister, from the methods annotated with `candid_method` above.
//
// Note that `cargo test` calls `main`, and `export_service` (which defines
// `__export_service` in the current scope) needs to be called exactly once. So
// in addition to `not(target_arch = "wasm32")` we have a `not(test)` guard here
// to avoid calling `export_service`, which we need to call in the test below.
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

#[cfg(not(feature = "test"))]
#[test]
fn check_governance_candid_file() {
    let did_path = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env var undefined"),
    )
    .join("canister/governance.did");
    let did_contents = String::from_utf8(std::fs::read(did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if did_contents != expected {
        panic!(
            "Generated candid definition does not match canister/governance.did. \
            Run `bazel run :generate_did > canister/governance.did` (no nix and/or direnv) in \
            rs/nns/governance to update canister/governance.did."
        )
    }
}

#[cfg(feature = "test")]
#[test]
fn check_governance_candid_file() {
    let did_path = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env var undefined"),
    )
    .join("canister/governance_test.did");
    let did_contents = String::from_utf8(std::fs::read(did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if did_contents != expected {
        panic!(
            "Generated candid definition does not match canister/governance_test.did. \
            Run `bazel run :generate_test_did > canister/governance_test.did` (no nix and/or direnv) in \
            rs/nns/governance to update canister/governance_test.did."
        )
    }
}

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
fn test_get_effective_payload_sets_proposal_id_for_add_wasm() {
    let mt = gov_pb::NnsFunction::AddSnsWasm;
    let proposal_id = 42;
    let wasm = vec![1, 2, 3];
    let canister_type = 3;
    let hash = vec![1, 2, 3, 4];
    let payload = Encode!(&AddWasmRequest {
        wasm: Some(SnsWasm {
            proposal_id: None,
            wasm: wasm.clone(),
            canister_type,
        }),
        hash: hash.clone(),
    })
    .unwrap();

    let effective_payload = get_effective_payload(mt, &payload, proposal_id, 0).unwrap();

    let decoded = Decode!(&effective_payload, AddWasmRequest).unwrap();
    assert_eq!(
        decoded,
        AddWasmRequest {
            wasm: Some(SnsWasm {
                proposal_id: Some(proposal_id), // The proposal_id should be set
                wasm,
                canister_type
            }),
            hash
        }
    );
}

#[test]
fn test_get_effective_payload_overrides_proposal_id_for_add_wasm() {
    let mt = gov_pb::NnsFunction::AddSnsWasm;
    let proposal_id = 42;
    let payload = Encode!(&AddWasmRequest {
        wasm: Some(SnsWasm {
            proposal_id: Some(proposal_id - 1),
            ..SnsWasm::default()
        }),
        ..AddWasmRequest::default()
    })
    .unwrap();

    let effective_payload = get_effective_payload(mt, &payload, proposal_id, 0).unwrap();

    let decoded = Decode!(&effective_payload, AddWasmRequest).unwrap();
    assert_eq!(decoded.wasm.unwrap().proposal_id.unwrap(), proposal_id);
}
