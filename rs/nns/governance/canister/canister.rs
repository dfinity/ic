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

use rand::rngs::StdRng;
use rand_core::{RngCore, SeedableRng};
use std::boxed::Box;
use std::time::SystemTime;

use async_trait::async_trait;
use prost::Message;

use candid::candid_method;
use dfn_candid::{candid, candid_one};
use dfn_core::{
    api::{arg_data, call, call_with_callbacks, caller, now},
    over, over_async, println,
};
use dfn_protobuf::protobuf;

use ic_base_types::PrincipalId;
use ic_nns_common::{
    access_control::{
        check_caller_authz_and_log, check_caller_is_ledger, check_caller_is_root,
        current_canister_authz, init_canister_authz, update_methods_authz,
    },
    pb::v1::{CanisterAuthzInfo, NeuronId as NeuronIdProto, ProposalId as ProposalIdProto},
    types::{MethodAuthzChange, NeuronId, ProposalId},
};
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_nns_governance::pb::v1::RewardEvent;
use ic_nns_governance::stable_mem_utils::{BufferedStableMemReader, BufferedStableMemWriter};
use ic_nns_governance::{
    governance::{Environment, Governance, Ledger},
    pb::v1::{
        governance_error::ErrorType, manage_neuron::Command, manage_neuron::RegisterVote,
        ExecuteNnsFunction, Governance as GovernanceProto, GovernanceError, ListNeurons,
        ListNeuronsResponse, ListProposalInfo, ListProposalInfoResponse, ManageNeuron,
        ManageNeuronResponse, Neuron, NeuronInfo, NeuronStakeTransfer, NnsFunction, Proposal,
        ProposalInfo, Vote,
    },
};

use ic_nns_common::access_control::check_caller_is_gtc;
use ledger_canister::{
    AccountIdentifier, ICPTs, Memo, SendArgs, Subaccount, TotalSupplyArgs, TransactionNotification,
};

/// Size of the buffer for stable memory reads and writes.
///
/// Smaller buffer size means more stable_write and stable_read calls. With
/// 100MiB buffer size, when the heap is near full, we need ~40 system calls.
/// Larger buffer size means we may not be able to serialize the heap fully in
/// some cases.
const STABLE_MEM_BUFFER_SIZE: u32 = 100 * 1024 * 1024; // 100MiB

pub(crate) const LOG_PREFIX: &str = "[Governance] ";

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
    rng: StdRng,
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
                StdRng::from_seed(seed)
            },
        }
    }
}

impl Environment for CanisterEnv {
    fn now(&self) -> u64 {
        now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Could not get the duration.")
            .as_secs()
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
        let payload = &update.payload;
        let reply = move || {
            governance_mut().set_proposal_execution_status(proposal_id, Ok(()));
        };
        let reject = move || {
            governance_mut().set_proposal_execution_status(
                proposal_id,
                Err(GovernanceError::new_with_message(
                    ErrorType::External,
                    "Error executing ExecuteNnsFunction proposal.",
                )),
            );
        };
        let (canister_id, method) = mt.canister_and_function()?;
        let err = call_with_callbacks(canister_id, method, payload, reply, reject);
        if err != 0 {
            Err(GovernanceError::new(ErrorType::PreconditionFailed))
        } else {
            Ok(())
        }
    }
}

struct LedgerCanister {}

#[async_trait]
impl Ledger for LedgerCanister {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: AccountIdentifier,
        memo: u64,
    ) -> Result<u64, GovernanceError> {
        // Send 'amount_e8s' to the target account.
        //
        // We deduct the transaction fee from the amount to transfer as in most
        // cases the neuron sub-account has exactly as much as was staked and if
        // we try to transfer that amount and charge the transaction fee in addition
        // the transfer will fail due to insufficient funds.
        let result: Result<u64, (Option<i32>, String)> = call(
            LEDGER_CANISTER_ID,
            "send_pb",
            protobuf,
            SendArgs {
                memo: Memo(memo),
                amount: ICPTs::from_e8s(amount_e8s),
                fee: ICPTs::from_e8s(fee_e8s),
                from_subaccount,
                to,
                created_at_time: None,
            },
        )
        .await;

        result.map_err(|(code, msg)| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Error calling method 'send' of the ledger canister. Code: {:?}. Message: {}",
                    code, msg
                ),
            )
        })
    }

    async fn total_supply(&self) -> Result<ICPTs, GovernanceError> {
        let result: Result<ICPTs, (Option<i32>, String)> = call(
            LEDGER_CANISTER_ID,
            "total_supply_pb",
            protobuf,
            TotalSupplyArgs {},
        )
        .await;

        result.map_err(|(code, msg)| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Error calling method 'total_supply' of the ledger canister. Code: {:?}. Message: {}",
                    code, msg
                )
            )
        })
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
            Box::new(LedgerCanister {}),
        ));
    }
    governance()
        .validate()
        .expect("Error initializing the governance canister.");
    init_canister_authz(
        governance()
            .proto
            .authz
            .as_ref()
            .expect("Missing required 'authz' in the governance proto ")
            .clone(),
    );
}

#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    println!("{}Executing pre upgrade", LOG_PREFIX);

    governance_mut().proto.authz = Some(current_canister_authz());

    let mut writer = BufferedStableMemWriter::new(STABLE_MEM_BUFFER_SIZE);

    governance()
        .proto
        .encode(&mut writer)
        .expect("Error. Couldn't serialize canister pre-upgrade.");

    writer.flush(); // or `drop(writer)`
}

#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}Executing post upgrade", LOG_PREFIX);

    let reader = BufferedStableMemReader::new(STABLE_MEM_BUFFER_SIZE);

    match GovernanceProto::decode(reader) {
        Err(err) => {
            println!(
                "Error deserializing canister state post-upgrade. \
             CANISTER MIGHT HAVE BROKEN STATE!!!!. Error: {:?}",
                err
            );
            Err(err)
        }
        Ok(proto) => {
            canister_init_(proto);
            Ok(())
        }
    }
    .expect("Couldn't upgrade canister.");
}

#[export_name = "canister_update update_authz"]
fn update_authz() {
    check_caller_is_root();
    over(candid_one, update_authz_)
}

#[candid_method(update, rename = "update_authz")]
fn update_authz_(methods_authz_change: Vec<MethodAuthzChange>) {
    update_methods_authz(methods_authz_change, LOG_PREFIX)
}

#[export_name = "canister_query current_authz"]
fn current_authz() {
    over(candid, |_: ()| -> CanisterAuthzInfo { current_authz_() })
}

#[candid_method(query, rename = "current_authz")]
fn current_authz_() -> CanisterAuthzInfo {
    current_canister_authz()
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
            })
            .await
        },
    )
}

#[export_name = "canister_update transaction_notification"]
fn neuron_stake_transfer_notification() {
    println!("{}neuron_stake_transfer_notification", LOG_PREFIX);
    check_caller_is_ledger();
    over_async(candid_one, create_or_refresh_neuron);
}

#[export_name = "canister_update transaction_notification_pb"]
fn neuron_stake_transfer_notification_pb() {
    println!("{}neuron_stake_transfer_notification_pb", LOG_PREFIX);
    check_caller_is_ledger();
    over_async(protobuf, create_or_refresh_neuron);
}

async fn create_or_refresh_neuron(txn: TransactionNotification) -> ic_nns_common::pb::v1::NeuronId {
    let now = governance_mut().env.now();
    let result = governance_mut()
        .create_or_refresh_neuron(NeuronStakeTransfer {
            transfer_timestamp: now,
            from: Some(txn.from),
            from_subaccount: txn.from_subaccount.map(|s| s.to_vec()).unwrap_or_default(),
            to_subaccount: txn.to_subaccount.map(|s| s.to_vec()).unwrap_or_default(),
            neuron_stake_e8s: txn.amount.get_e8s(),
            block_height: txn.block_height,
            memo: txn.memo.0,
        })
        .await;
    // Panic if we couldn' t create or refresh the stake. The ledger is expecting
    // this.
    result.unwrap_or_else(|err| {
        panic!(
            "Couldn\'t create or refresh the stake of the neuron. Error: {:?}",
            err
        )
    })
}

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

#[export_name = "canister_query get_proposal_info"]
fn get_proposal_info() {
    println!("{}get_proposal_info", LOG_PREFIX);
    over(candid_one, |id: ProposalId| -> Option<ProposalInfo> {
        get_proposal_info_(id)
    })
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

/// DEPRECATED: Only callable from the registry. Use manage_neuron instead.
#[export_name = "canister_update submit_proposal"]
fn submit_proposal() {
    check_caller_authz_and_log("submit_proposal", LOG_PREFIX);
    over(
        candid,
        |(proposer, proposal, caller): (NeuronId, Proposal, PrincipalId)| -> ProposalId {
            submit_proposal_(proposer, proposal, caller)
        },
    );
}

#[candid_method(update, rename = "submit_proposal")]
fn submit_proposal_(proposer: NeuronId, proposal: Proposal, caller: PrincipalId) -> ProposalId {
    let proposer_proto = NeuronIdProto::from(proposer);
    governance_mut()
        .make_proposal(&proposer_proto, &caller, &proposal)
        .expect("Couldn't create proposal")
        .into()
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

/// Provides information about the last reward event.
#[export_name = "canister_query get_latest_reward_event"]
fn get_latest_reward_event() {
    over(candid, |()| -> &RewardEvent {
        let event = governance().latest_reward_event();
        println!("{}get_latest_reward_event returns {}; ", LOG_PREFIX, event);
        event
    });
}

/// Return the Neuron IDs of all Neurons that have `caller()` as their
/// controller or as one of their hot keys
#[export_name = "canister_query get_neuron_ids"]
fn get_neuron_ids() {
    println!("{}get_neuron_ids", LOG_PREFIX);
    over(candid, |()| -> Vec<NeuronId> { get_neuron_ids_() })
}

#[candid_method(query, rename = "get_neuron_ids")]
fn get_neuron_ids_() -> Vec<NeuronId> {
    governance()
        .get_neuron_ids_by_principal(&caller())
        .into_iter()
        .map(NeuronId)
        .collect()
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
    println!("{}manage_neuron", LOG_PREFIX);
    over_async(protobuf, manage_neuron_)
}

#[export_name = "canister_query list_proposals_pb"]
fn list_proposals_pb() {
    println!("{}list_proposals", LOG_PREFIX);
    over(protobuf, list_proposals_)
}

#[export_name = "canister_query list_neurons_pb"]
fn list_neurons_pb() {
    println!("{}list_neurons", LOG_PREFIX);
    over(protobuf, list_neurons_)
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

#[test]
fn check_governance_candid_file() {
    let governance_did =
        String::from_utf8(std::fs::read("canister/governance.did").unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if governance_did != expected {
        panic!(
            "Generated candid definition does not match canister/governance.did. \
            Run `cargo run --bin governance-canister > canister/governance.did` in \
            rs/nns/governance to update canister/governance.did."
        )
    }
}
