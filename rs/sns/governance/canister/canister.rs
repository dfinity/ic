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
use ic_nns_governance::stable_mem_utils::{BufferedStableMemReader, BufferedStableMemWriter};
use rand::rngs::StdRng;
use rand_core::{RngCore, SeedableRng};
use std::boxed::Box;
use std::time::SystemTime;

use prost::Message;

use candid::candid_method;
use dfn_candid::{candid, candid_one, CandidOne};
use dfn_core::api::{call_bytes_with_cleanup, Funds};
use dfn_core::{
    api::{caller, id, now},
    over, over_async, over_init, println,
};

use ic_base_types::CanisterId;
use ic_nervous_system_common::ledger::LedgerCanister;
use ic_sns_governance::governance::{log_prefix, Governance, TimeWarp, ValidGovernanceProto};
use ic_sns_governance::pb::v1::{
    GetNeuron, GetNeuronResponse, GetProposal, GetProposalResponse, Governance as GovernanceProto,
    ListNeurons, ListNeuronsResponse, ListProposals, ListProposalsResponse, ManageNeuron,
    ManageNeuronResponse, NervousSystemParameters, RewardEvent,
};
use ic_sns_governance::types::{Environment, HeapGrowthPotential};

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
    rng: StdRng,
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
            // upredictability since the pseudo-random numbers could still be predicted after
            // inception.
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
}

#[export_name = "canister_init"]
fn canister_init() {
    over_init(|CandidOne(arg)| canister_init_(arg))
}

/// In contrast to canister_init(), this method does not do deserialization.
/// In addition to canister_init, this method is called by canister_post_upgrade.
#[candid_method(init)]
fn canister_init_(init_payload: GovernanceProto) {
    let init_payload = ValidGovernanceProto::new(init_payload).expect(
        "Cannot start canister, because the deserialized \
         GovernanceProto is invalid in some way",
    );

    println!(
        "{}canister_init_: Initializing with: {}",
        log_prefix(),
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
        ));
    }
}

/// Executes some logic before executing an upgrade, including serializing and writing the
/// governance's state to stable memory so that it is preserved during the upgrade and can
/// be deserialised again in canister_post_upgrade. That is, the stable memory allows
/// saving the state and restoring it after the upgrade.
#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    println!("{}Executing pre upgrade", log_prefix());

    let mut writer = BufferedStableMemWriter::new(STABLE_MEM_BUFFER_SIZE);

    governance()
        .proto
        .encode(&mut writer)
        .expect("Error. Couldn't serialize canister pre-upgrade.");

    writer.flush(); // or `drop(writer)`
}

/// Executes some logic after executing an upgrade, including deserialising what has been written
/// to stable memory in canister_pre_upgrade and initialising the governance's state with it.
#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}Executing post upgrade", log_prefix());

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
    println!("{}get_nervous_system_parameters", log_prefix());
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

/// Performs a command on a neuron if the caller is authorised to do so.
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
    println!("{}manage_neuron", log_prefix());
    over_async(candid_one, manage_neuron_)
}

/// Internal method for calling manage_neuron.
#[candid_method(update, rename = "manage_neuron")]
async fn manage_neuron_(manage_neuron: ManageNeuron) -> ManageNeuronResponse {
    governance_mut()
        .manage_neuron(&manage_neuron, &caller())
        .await
}

/// Returns the full neuron corresponding to the neuron with ID `neuron_id`.
#[export_name = "canister_query get_neuron"]
fn get_neuron() {
    println!("{}get_neuron", log_prefix());
    over(candid_one, get_neuron_)
}

/// Internal method for calling get_neuron.
#[candid_method(query, rename = "get_neuron")]
fn get_neuron_(get_neuron: GetNeuron) -> GetNeuronResponse {
    governance().get_neuron(&get_neuron)
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
    println!("{}list_neurons", log_prefix());
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
    println!("{}get_proposal", log_prefix());
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
    println!("{}list_proposals", log_prefix());
    over(candid_one, list_proposals_)
}

/// Internal method for calling list_proposals.
#[candid_method(query, rename = "list_proposals")]
fn list_proposals_(list_proposals: ListProposals) -> ListProposalsResponse {
    governance().list_proposals(&list_proposals)
}

/// Returns the latest reward event.
#[export_name = "canister_query get_latest_reward_event"]
fn get_latest_reward_event() {
    over(candid, |()| -> RewardEvent {
        let event = governance().latest_reward_event();
        println!(
            "{}get_latest_reward_event returns {}; ",
            log_prefix(),
            event
        );
        event
    });
}

/// Returns the root canister's status.
///
/// This is a specialized version of the root canister's `canister_status`
/// method. Getting the root canister's status is special, because root is the
/// canister that gets the status of all other canisters in the SNS.
///
/// The way the underlying system call works is that a principal can only
/// request the status of canisters that it controls. In theory, this interface
/// could be generalized to target any canister, but in practice, only the root
/// canister would ever be targeted, because that is the only canister that
/// governance controls.
#[export_name = "canister_update get_root_canister_status"]
fn get_root_canister_status() {
    println!("{}get_root_canister_status", log_prefix());
    over_async(candid_one, get_root_canister_status_)
}

/// Internal method for calling get_root_canister_status.
#[candid_method(update, rename = "get_root_canister_status")]
async fn get_root_canister_status_(_: ()) -> ic_nervous_system_root::CanisterStatusResult {
    governance().get_root_canister_status().await
}

/// The canister's heartbeat.
#[export_name = "canister_heartbeat"]
fn canister_heartbeat() {
    let future = governance_mut().run_periodic_tasks();

    // The canister_heartbeat must be synchronous, so we cannot .await the future.
    dfn_core::api::futures::spawn(future);
}

/// Encode the metrics in a format that can be understood by Prometheus.
fn encode_metrics(_w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    Ok(())
}

/// Resources to serve for a given http_request
#[export_name = "canister_query http_request"]
fn http_request() {
    dfn_http_metrics::serve_metrics(encode_metrics);
}

/// This makes this Candid service self-describing, so that for example Candid
/// UI, but also other tools, can seamlessly integrate with it.
/// The concrete interface (__get_candid_interface_tmp_hack) is provisional, but
/// works.
///
/// We include the .did file as committed, which means it is included verbatim in
/// the .wasm; using `candid::export_service` here would involve unnecessary
/// runtime computation.
#[export_name = "canister_query __get_candid_interface_tmp_hack"]
fn expose_candid() {
    over(candid, |_: ()| include_str!("governance.did").to_string())
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
            Run `cargo run --bin sns-governance-canister > canister/governance.did` in \
            rs/sns/governance to update canister/governance.did."
        )
    }
}

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
