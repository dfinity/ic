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
    stable::stable64_read,
};
use dfn_protobuf::protobuf;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::{
    cmc::CMCCanister,
    dfn_core_stable_mem_utils::BufferedStableMemReader,
    ledger::IcpLedgerCanister,
    memory_manager_upgrade_storage::{load_protobuf, store_protobuf},
    MethodAuthzChange,
};
use ic_nervous_system_runtime::DfnRuntime;
use ic_nns_common::{
    access_control::{check_caller_is_gtc, check_caller_is_ledger, check_caller_is_root},
    pb::v1::{CanisterAuthzInfo, NeuronId as NeuronIdProto, ProposalId as ProposalIdProto},
    types::{CallCanisterProposal, NeuronId, ProposalId},
};
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_nns_governance::{
    encode_metrics,
    governance::{
        BitcoinNetwork, BitcoinSetConfigProposal, Environment, Governance, HeapGrowthPotential,
        TimeWarp,
    },
    pb::v1::{
        claim_or_refresh_neuron_from_account_response::Result as ClaimOrRefreshNeuronFromAccountResponseResult,
        governance::GovernanceCachedMetrics,
        governance_error::ErrorType,
        manage_neuron::{
            claim_or_refresh::{By, MemoAndController},
            ClaimOrRefresh, Command, NeuronIdOrSubaccount, RegisterVote,
        },
        manage_neuron_response, ClaimOrRefreshNeuronFromAccount,
        ClaimOrRefreshNeuronFromAccountResponse, ExecuteNnsFunction, Governance as GovernanceProto,
        GovernanceError, ListKnownNeuronsResponse, ListNeurons, ListNeuronsResponse,
        ListNodeProvidersResponse, ListProposalInfo, ListProposalInfoResponse, ManageNeuron,
        ManageNeuronResponse, MostRecentMonthlyNodeProviderRewards, NetworkEconomics, Neuron,
        NeuronInfo, NnsFunction, NodeProvider, Proposal, ProposalInfo, RewardEvent,
        RewardNodeProviders, SettleCommunityFundParticipation, UpdateNodeProvider, Vote,
    },
};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl,
};
use prost::Message;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{borrow::Cow, boxed::Box, cell::RefCell, ops::Deref, str::FromStr, time::SystemTime};

/// Constants to define memory segments.  Must not change.
const UPGRADES_MEMORY_ID: MemoryId = MemoryId::new(0);

thread_local! {

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    // The memory where the governance reads and writes its state during an upgrade.
    pub static UPGRADES_MEMORY: RefCell<VirtualMemory<DefaultMemoryImpl>> = MEMORY_MANAGER.with(|memory_manager|
        RefCell::new(memory_manager.borrow().get(UPGRADES_MEMORY_ID)));
}

/// Size of the buffer for stable memory reads and writes.
///
/// Smaller buffer size means more stable_write and stable_read calls. With
/// 100MiB buffer size, when the heap is near full, we need ~40 system calls.
/// Larger buffer size means we may not be able to serialize the heap fully in
/// some cases.
const STABLE_MEM_BUFFER_SIZE: u32 = 100 * 1024 * 1024; // 100MiB

pub(crate) const LOG_PREFIX: &str = "[Governance] ";

// https://dfinity.atlassian.net/browse/NNS1-1050: We are not following
// standard/best practices for canister globals here.
//
// Do not access these global variables directly. Instead, use accessor
// functions, which are defined immediately after.
static mut GOVERNANCE: Option<Governance> = None;

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
        update: &ExecuteNnsFunction,
    ) -> Result<(), GovernanceError> {
        let mt = NnsFunction::from_i32(update.nns_function).ok_or_else(||
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
        let effective_payload = get_effective_payload(mt, &update.payload);
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

#[export_name = "canister_init"]
fn canister_init() {
    dfn_core::printer::hook();

    match GovernanceProto::decode(&arg_data()[..]) {
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
fn canister_init_(init_payload: GovernanceProto) {
    println!(
        "{}canister_init: Initializing with: economics: \
              {:?}, genesis_timestamp_seconds: {}, neuron count: {}",
        LOG_PREFIX,
        init_payload.economics,
        init_payload.genesis_timestamp_seconds,
        init_payload.neurons.len()
    );

    unsafe {
        assert!(
            GOVERNANCE.is_none(),
            "{}Trying to initialize an already-initialized governance canister!",
            LOG_PREFIX
        );
        GOVERNANCE = Some(Governance::new(
            init_payload,
            Box::new(CanisterEnv::new()),
            Box::new(IcpLedgerCanister::new(LEDGER_CANISTER_ID)),
            Box::new(CMCCanister::<DfnRuntime>::new()),
        ));
    }
    governance()
        .validate()
        .expect("Error initializing the governance canister.");
}

#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    println!("{}Executing pre upgrade", LOG_PREFIX);

    UPGRADES_MEMORY.with(|um| {
        let memory = um.borrow();

        store_protobuf(memory.deref(), &governance().proto)
            .expect("Failed to encode protobuf pre_upgrade");
    });
}

#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}Executing post upgrade", LOG_PREFIX);

    // Look for MemoryManager magic bytes
    let mut magic_bytes = [0u8; 3];
    stable64_read(&mut magic_bytes, 0, 3);
    let mut mgr_version_byte = [0u8; 1];
    stable64_read(&mut mgr_version_byte, 3, 1);

    // For the version of MemoryManager we are using, the version byte will be 1
    // We use the magic bytes, along with this, to identify if we are before or after the migration
    // to MemoryManager.  Previously, the first 4 bytes contained a size.  b"MBR\1" evaluates to
    // 22169421 bytes (which is ~22MB, and is much smaller than governance in mainnet (about 500MB))
    // Meaning there is no real possibility of these bytes being misinterpreted
    // TODO NNS1-2357 Remove conditional after deploying the updated version to production
    let proto = if &magic_bytes == b"MGR" && mgr_version_byte[0] == 1 {
        UPGRADES_MEMORY
            .with(|um| {
                let result: Result<GovernanceProto, _> =
                    load_protobuf(um.borrow().deref());
                result
            })
            .expect(
                "Error deserializing canister state post-upgrade with MemoryManager memory segment. \
             CANISTER MIGHT HAVE BROKEN STATE!!!!.",
            )
    } else {
        let reader = BufferedStableMemReader::new(STABLE_MEM_BUFFER_SIZE);
        GovernanceProto::decode(reader).expect(
            "Error deserializing canister state post-upgrade. \
             CANISTER MIGHT HAVE BROKEN STATE!!!!.",
        )
    };

    canister_init_(proto);
}

#[cfg(feature = "test")]
#[export_name = "canister_update set_time_warp"]
fn set_time_warp() {
    over(candid_one, set_time_warp_);
}

#[cfg(feature = "test")]
fn set_time_warp_(new_time_warp: TimeWarp) {
    governance_mut().env.set_time_warp(new_time_warp);
}

#[export_name = "canister_update update_authz"]
fn update_authz() {
    check_caller_is_root();
    over(candid_one, |_: Vec<MethodAuthzChange>| {
        println!(
            "{}update_authz was called. \
                 This does not do anything, since the governance canister no longer has any \
                 function whose access is controlled using this mechanism. \
                 TODO(NNS1-413): Remove this once we are sure that there are no callers.",
            LOG_PREFIX,
        );
    })
}

#[export_name = "canister_query current_authz"]
fn current_authz() {
    over(candid, |_: ()| {
        println!(
            "{}current_authz was called. \
                 This always returns the default value, since the governance canister's state no \
                 longer contains a CanisterAuthzInfo. \
                 TODO(NNS1-413): Remove this once we are sure that there are no callers.",
            LOG_PREFIX,
        );
        CanisterAuthzInfo::default()
    })
}

/// DEPRECATED: Use manage_neuron directly instead.
#[export_name = "canister_update forward_vote"]
fn vote() {
    println!("{}forward_vote", LOG_PREFIX);
    over_async(
        candid,
        |(neuron_id, proposal_id, vote): (NeuronId, ProposalId, Vote)| async move {
            manage_neuron_(ManageNeuron {
                id: Some(NeuronIdProto::from(neuron_id)),
                command: Some(Command::RegisterVote(RegisterVote {
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
    println!("{}neuron_stake_transfer_notification", LOG_PREFIX);
    check_caller_is_ledger();
    panic!("Method removed. Please use ManageNeuron::ClaimOrRefresh.",)
}

#[export_name = "canister_update transaction_notification_pb"]
fn neuron_stake_transfer_notification_pb() {
    println!("{}neuron_stake_transfer_notification_pb", LOG_PREFIX);
    check_caller_is_ledger();
    panic!("Method removed. Please use ManageNeuron::ClaimOrRefresh.",)
}

// DEPRECATED: Please use ManageNeuron::ClaimOrRefresh.
#[export_name = "canister_update claim_or_refresh_neuron_from_account"]
fn claim_or_refresh_neuron_from_account() {
    println!("{}claim_or_refresh_neuron_from_account", LOG_PREFIX);
    over_async(candid_one, claim_or_refresh_neuron_from_account_)
}

// DEPRECATED: Please use ManageNeuron::ClaimOrRefresh.
//
// Just redirects to ManageNeuron.
#[candid_method(update, rename = "claim_or_refresh_neuron_from_account")]
async fn claim_or_refresh_neuron_from_account_(
    claim_or_refresh: ClaimOrRefreshNeuronFromAccount,
) -> ClaimOrRefreshNeuronFromAccountResponse {
    let manage_neuron_response = manage_neuron_(ManageNeuron {
        id: None,
        command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
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
    println!("{}claim_gtc_neurons", LOG_PREFIX);
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
    governance_mut().claim_gtc_neurons(&caller(), new_controller, neuron_ids)
}

#[export_name = "canister_update transfer_gtc_neuron"]
fn transfer_gtc_neuron() {
    println!("{}transfer_gtc_neuron", LOG_PREFIX);
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
    governance_mut()
        .transfer_gtc_neuron(&caller(), &donor_neuron_id, &recipient_neuron_id)
        .await
}

#[export_name = "canister_update manage_neuron"]
fn manage_neuron() {
    println!("{}manage_neuron", LOG_PREFIX);
    over_async(candid_one, manage_neuron_)
}

#[candid_method(update, rename = "manage_neuron")]
async fn manage_neuron_(manage_neuron: ManageNeuron) -> ManageNeuronResponse {
    governance_mut()
        .manage_neuron(&caller(), &manage_neuron)
        .await
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
    governance_mut().update_neuron(neuron).err()
}

#[export_name = "canister_update simulate_manage_neuron"]
fn simulate_manage_neuron() {
    println!("{}simulate_manage_neuron", LOG_PREFIX);
    over_async(candid_one, simulate_manage_neuron_)
}

#[candid_method(update, rename = "simulate_manage_neuron")]
async fn simulate_manage_neuron_(manage_neuron: ManageNeuron) -> ManageNeuronResponse {
    governance()
        .simulate_manage_neuron(&caller(), manage_neuron)
        .await
}

/// Returns the full neuron corresponding to the neuron id or subaccount.
#[export_name = "canister_query get_full_neuron_by_id_or_subaccount"]
fn get_full_neuron_by_id_or_subaccount() {
    println!("{}get_full_neuron_by_id_or_subaccount", LOG_PREFIX);
    over(candid_one, get_full_neuron_by_id_or_subaccount_)
}

#[candid_method(query, rename = "get_full_neuron_by_id_or_subaccount")]
fn get_full_neuron_by_id_or_subaccount_(
    by: NeuronIdOrSubaccount,
) -> Result<Neuron, GovernanceError> {
    governance().get_full_neuron_by_id_or_subaccount(&by, &caller())
}

/// Returns the full neuron corresponding to the neuron id.
#[export_name = "canister_query get_full_neuron"]
fn get_full_neuron() {
    println!("{}get_full_neuron", LOG_PREFIX);
    over(candid_one, get_full_neuron_)
}

#[candid_method(query, rename = "get_full_neuron")]
fn get_full_neuron_(neuron_id: NeuronId) -> Result<Neuron, GovernanceError> {
    governance().get_full_neuron(&NeuronIdProto::from(neuron_id), &caller())
}

/// Returns the public neuron info corresponding to the neuron id.
#[export_name = "canister_query get_neuron_info"]
fn get_neuron_info() {
    println!("{}get_neuron_info", LOG_PREFIX);
    over(candid_one, get_neuron_info_)
}

#[candid_method(query, rename = "get_neuron_info")]
fn get_neuron_info_(neuron_id: NeuronId) -> Result<NeuronInfo, GovernanceError> {
    governance().get_neuron_info(&NeuronIdProto::from(neuron_id))
}

/// Returns the public neuron info corresponding to the neuron id or subaccount.
#[export_name = "canister_query get_neuron_info_by_id_or_subaccount"]
fn get_neuron_info_by_id_or_subaccount() {
    println!("{}get_neuron_info_by_subaccount", LOG_PREFIX);
    over(candid_one, get_neuron_info_by_id_or_subaccount_)
}

#[candid_method(query, rename = "get_neuron_info_by_id_or_subaccount")]
fn get_neuron_info_by_id_or_subaccount_(
    by: NeuronIdOrSubaccount,
) -> Result<NeuronInfo, GovernanceError> {
    governance().get_neuron_info_by_id_or_subaccount(&by)
}

#[export_name = "canister_query get_proposal_info"]
fn get_proposal_info() {
    println!("{}get_proposal_info", LOG_PREFIX);
    over(candid_one, get_proposal_info_)
}

#[candid_method(query, rename = "get_proposal_info")]
fn get_proposal_info_(id: ProposalId) -> Option<ProposalInfo> {
    governance().get_proposal_info(&caller(), id)
}

#[export_name = "canister_query get_pending_proposals"]
fn get_pending_proposals() {
    println!("{}get_pending_proposals", LOG_PREFIX);
    over(candid, |()| -> Vec<ProposalInfo> {
        get_pending_proposals_()
    })
}

#[candid_method(query, rename = "get_pending_proposals")]
fn get_pending_proposals_() -> Vec<ProposalInfo> {
    governance().get_pending_proposals(&caller())
}

#[export_name = "canister_query list_proposals"]
fn list_proposals() {
    println!("{}list_proposals", LOG_PREFIX);
    over(candid_one, list_proposals_)
}

#[candid_method(query, rename = "list_proposals")]
fn list_proposals_(req: ListProposalInfo) -> ListProposalInfoResponse {
    governance().list_proposals(&caller(), &req)
}

#[export_name = "canister_query list_neurons"]
fn list_neurons() {
    println!("{}list_neurons", LOG_PREFIX);
    over(candid_one, list_neurons_)
}

#[candid_method(query, rename = "list_neurons")]
fn list_neurons_(req: ListNeurons) -> ListNeuronsResponse {
    governance().list_neurons_by_principal(&req, &caller())
}

#[export_name = "canister_query get_metrics"]
fn get_metrics() {
    println!("{}get_metrics", LOG_PREFIX);
    over(candid, |()| get_metrics_())
}

#[candid_method(query, rename = "get_metrics")]
fn get_metrics_() -> Result<GovernanceCachedMetrics, GovernanceError> {
    governance().get_metrics()
}

#[export_name = "canister_update get_monthly_node_provider_rewards"]
fn get_monthly_node_provider_rewards() {
    println!("{}get_monthly_node_provider_rewards", LOG_PREFIX);
    over_async(candid, |()| async move {
        get_monthly_node_provider_rewards_().await
    })
}

#[candid_method(update, rename = "get_monthly_node_provider_rewards")]
async fn get_monthly_node_provider_rewards_() -> Result<RewardNodeProviders, GovernanceError> {
    governance().get_monthly_node_provider_rewards().await
}

#[export_name = "canister_query list_known_neurons"]
fn list_known_neurons() {
    println!("{}list_known_neurons", LOG_PREFIX);
    over(candid_one, |()| -> ListKnownNeuronsResponse {
        list_known_neurons_()
    })
}

#[candid_method(query, rename = "list_known_neurons")]
fn list_known_neurons_() -> ListKnownNeuronsResponse {
    governance().list_known_neurons()
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
    println!("{}get_latest_reward_event", LOG_PREFIX);
    over(candid, |()| get_latest_reward_event_());
}

#[candid_method(query, rename = "get_latest_reward_event")]
fn get_latest_reward_event_() -> RewardEvent {
    governance().latest_reward_event().clone()
}

/// Return the Neuron IDs of all Neurons that have `caller()` as their
/// controller or as one of their hot keys. Furthermore the Neuron IDs of all
/// Neurons that directly follow the former in the topic `NeuronManagement`
/// are included. Summarily, the Neuron IDs in the set returned can be queried
/// by `get_full_neuron` without getting an authorization error.
#[export_name = "canister_query get_neuron_ids"]
fn get_neuron_ids() {
    println!("{}get_neuron_ids", LOG_PREFIX);
    over(candid, |()| -> Vec<NeuronId> { get_neuron_ids_() })
}

#[candid_method(query, rename = "get_neuron_ids")]
fn get_neuron_ids_() -> Vec<NeuronId> {
    let votable = governance().get_neuron_ids_by_principal(&caller());

    governance()
        .get_managed_neuron_ids_for(&votable)
        .into_iter()
        .map(NeuronId)
        .collect()
}

#[export_name = "canister_query get_network_economics_parameters"]
fn get_network_economics_parameters() {
    println!("{}get_network_economics_parameters", LOG_PREFIX);
    over(candid, |()| -> NetworkEconomics {
        get_network_economics_parameters_()
    })
}

#[candid_method(query, rename = "get_network_economics_parameters")]
fn get_network_economics_parameters_() -> NetworkEconomics {
    governance()
        .proto
        .economics
        .as_ref()
        .expect("Governance must have network economics.")
        .clone()
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
    println!("{}manage_neuron_pb", LOG_PREFIX);
    over_async(protobuf, manage_neuron_)
}

#[export_name = "canister_update claim_or_refresh_neuron_from_account_pb"]
fn claim_or_refresh_neuron_from_account_pb() {
    println!("{}claim_or_refresh_neuron_from_account_pb", LOG_PREFIX);
    over_async(protobuf, claim_or_refresh_neuron_from_account_)
}

#[export_name = "canister_query list_proposals_pb"]
fn list_proposals_pb() {
    println!("{}list_proposals_pb", LOG_PREFIX);
    over(protobuf, list_proposals_)
}

#[export_name = "canister_query list_neurons_pb"]
fn list_neurons_pb() {
    println!("{}list_neurons_pb", LOG_PREFIX);
    over(protobuf, list_neurons_)
}

#[export_name = "canister_update update_node_provider"]
fn update_node_provider() {
    println!("{}update_node_provider", LOG_PREFIX);
    over(candid_one, update_node_provider_)
}

#[candid_method(update, rename = "update_node_provider")]
fn update_node_provider_(req: UpdateNodeProvider) -> Result<(), GovernanceError> {
    governance_mut().update_node_provider(&caller(), req)
}

#[export_name = "canister_update settle_community_fund_participation"]
fn settle_community_fund_participation() {
    println!("{}settle_community_fund_participation", LOG_PREFIX);
    over_async(candid_one, settle_community_fund_participation_)
}

#[candid_method(update, rename = "settle_community_fund_participation")]
async fn settle_community_fund_participation_(
    request: SettleCommunityFundParticipation,
) -> Result<(), GovernanceError> {
    governance_mut()
        .settle_community_fund_participation(caller(), &request)
        .await
}

/// Return the NodeProvider record where NodeProvider.id == caller(), if such a
/// NodeProvider record exists.
#[export_name = "canister_query get_node_provider_by_caller"]
fn get_node_provider_by_caller() {
    println!("{}get_node_provider_by_caller", LOG_PREFIX);
    over(candid_one, get_node_provider_by_caller_)
}

#[candid_method(query, rename = "get_node_provider_by_caller")]
fn get_node_provider_by_caller_(_: ()) -> Result<NodeProvider, GovernanceError> {
    governance().get_node_provider(&caller())
}

#[export_name = "canister_query list_node_providers"]
fn list_node_providers() {
    println!("{}list_node_providers", LOG_PREFIX);
    over(candid, |()| list_node_providers_());
}

#[candid_method(query, rename = "list_node_providers")]
fn list_node_providers_() -> ListNodeProvidersResponse {
    let node_providers = governance().get_node_providers().to_vec();
    ListNodeProvidersResponse { node_providers }
}

#[export_name = "canister_query get_most_recent_monthly_node_provider_rewards"]
fn get_most_recent_monthly_node_provider_rewards() {
    over(
        candid,
        |()| -> Option<MostRecentMonthlyNodeProviderRewards> {
            get_most_recent_monthly_node_provider_rewards_()
        },
    )
}

#[candid_method(query, rename = "get_most_recent_monthly_node_provider_rewards")]
fn get_most_recent_monthly_node_provider_rewards_() -> Option<MostRecentMonthlyNodeProviderRewards>
{
    governance()
        .proto
        .most_recent_monthly_node_provider_rewards
        .clone()
}

#[export_name = "canister_query http_request"]
fn http_request() {
    dfn_http_metrics::serve_metrics(|metrics_encoder| {
        encode_metrics(governance(), metrics_encoder)
    });
}

// Processes the payload received and transforms it into a form the intended canister expects.
fn get_effective_payload(mt: NnsFunction, payload: &[u8]) -> Cow<[u8]> {
    const BITCOIN_SET_CONFIG_METHOD_NAME: &str = "set_config";
    const BITCOIN_MAINNET_CANISTER_ID: &str = "ghsi2-tqaaa-aaaan-aaaca-cai";
    const BITCOIN_TESTNET_CANISTER_ID: &str = "g4xu7-jiaaa-aaaan-aaaaq-cai";

    match mt {
        NnsFunction::BitcoinSetConfig => {
            // Decode the payload to get the network.
            let payload = Decode!(payload, BitcoinSetConfigProposal)
                .expect("payload must be a valid BitcoinSetConfigProposal.");

            // Convert it to a call canister payload.
            let canister_id = CanisterId::from_str(match payload.network {
                BitcoinNetwork::Mainnet => BITCOIN_MAINNET_CANISTER_ID,
                BitcoinNetwork::Testnet => BITCOIN_TESTNET_CANISTER_ID,
            })
            .expect("bitcoin canister id must be valid.");

            let encoded_payload = Encode!(&CallCanisterProposal {
                canister_id,
                method_name: BITCOIN_SET_CONFIG_METHOD_NAME.to_string(),
                payload: payload.payload
            })
            .unwrap();

            Cow::Owned(encoded_payload)
        }

        // NOTE: Methods are listed explicitly as opposed to using the `_` wildcard so
        // that adding a new function causes a compile error here, ensuring that the developer
        // makes an explicit decision on how the payload is handled.
        NnsFunction::Unspecified
        | NnsFunction::AddHostOsVersion
        | NnsFunction::UpdateNodesHostOsVersion
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
        | NnsFunction::UpdateElectedReplicaVersions
        | NnsFunction::UpdateNodeOperatorConfig
        | NnsFunction::UpdateSubnetReplicaVersion
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
        | NnsFunction::UpdateUnassignedNodesConfig
        | NnsFunction::RemoveNodeOperators
        | NnsFunction::RerouteCanisterRanges
        | NnsFunction::PrepareCanisterMigration
        | NnsFunction::CompleteCanisterMigration
        | NnsFunction::AddSnsWasm
        | NnsFunction::UpdateSubnetType
        | NnsFunction::ChangeSubnetTypeAssignment
        | NnsFunction::UpdateAllowedPrincipals
        | NnsFunction::UpdateSnsWasmSnsSubnetIds
        | NnsFunction::InsertSnsWasmUpgradePathEntries => Cow::Borrowed(payload),
    }
}

// This makes this Candid service self-describing, so that for example Candid
// UI, but also other tools, can seamlessly integrate with it.
// The concrete interface (__get_candid_interface_tmp_hack) is provisional, but
// works.
//
// We include the .did file as committed, as means it is included verbatim in
// the .wasm; using `candid::export_service` here would involve unecessary
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
