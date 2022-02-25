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

use ic_nns_governance::stable_mem_utils::{BufferedStableMemReader, BufferedStableMemWriter};
use rand::rngs::StdRng;
use rand_core::{RngCore, SeedableRng};
use std::boxed::Box;
use std::convert::TryFrom;
use std::time::SystemTime;

use prost::Message;

use candid::candid_method;
use dfn_candid::{candid, candid_one};
use dfn_core::api::{call_with_callbacks, reject_message};
use dfn_core::{
    api::{arg_data, caller, id, now},
    over, over_async, println,
};

use ic_base_types::CanisterId;
use ic_nervous_system_common::ledger::LedgerCanister;
use ic_sns_governance::governance::{log_prefix, Governance};
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::{
    governance_error::ErrorType, ExecuteNervousSystemFunction, GetNeuron, GetNeuronResponse,
    GetProposal, GetProposalResponse, Governance as GovernanceProto, GovernanceError, ListNeurons,
    ListNeuronsResponse, ListProposals, ListProposalsResponse, ManageNeuron, ManageNeuronResponse,
    NervousSystemParameters, RewardEvent,
};
use ic_sns_governance::types::{Environment, HeapGrowthPotential};
use ledger_canister::metrics_encoder;

/// Size of the buffer for stable memory reads and writes.
///
/// Smaller buffer size means more stable_write and stable_read calls. With
/// 100MiB buffer size, when the heap is near full, we need ~40 system calls.
/// Larger buffer size means we may not be able to serialize the heap fully in
/// some cases.
const STABLE_MEM_BUFFER_SIZE: u32 = 100 * 1024 * 1024; // 100MiB

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

    fn execute_sns_external_proposal(
        &self,
        _proposal_id: u64,
        _update: &ExecuteNervousSystemFunction,
    ) -> Result<(), GovernanceError> {
        let mt = Action::from_u64(_update.function_id).ok_or_else(||
            // No update action specified.
            GovernanceError::new(ErrorType::PreconditionFailed))?;
        let payload = &_update.payload;
        let reply = move || governance_mut().set_proposal_execution_status(_proposal_id, Ok(()));
        let reject = move || {
            // There's no guarantee that the reject response is a string of character, and
            // it can potentially be large. Propagating error information
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
                _proposal_id,
                Err(GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Error executing ExecuteNervousSystemFunction proposal. Rejection message: {}",
                        msg
                    ),
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

    #[cfg(not(target_arch = "wasm32"))]
    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        unimplemented!("CanisterEnv can only be used with wasm32 environment.");
    }

    /// Return this canister's ID
    fn canister_id(&self) -> CanisterId {
        id()
    }
}

/// Initializes the canister by decoding the init
/// arguments and initializing internal state.
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
    init_payload
        .parameters
        .as_ref()
        .expect("NervousSystemParameters must be set")
        .validate()
        .expect("NervousSystemParameters are not valid");

    println!(
        "{}canister_init: Initializing with: \
              {:?}, genesis_timestamp_seconds: {}, neuron count: {}",
        log_prefix(),
        init_payload.parameters,
        init_payload.genesis_timestamp_seconds,
        init_payload.neurons.len()
    );

    let ledger_canister_id = CanisterId::try_from(
        init_payload
            .ledger_canister_id
            .expect("Governance must be initialized with a Ledger canister ID"),
    )
    .expect("Failed to parse ledger_canister_id as a CanisterId");

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
    governance()
        .validate()
        .expect("Error initializing the governance canister.");
}

/// Executes logic before executing the upgrade
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

/// Executes logic after executing the upgrade
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

/// Returns Governance's NervousSystemParameters
#[export_name = "canister_query get_nervous_system_parameters"]
fn get_nervous_system_parameters() {
    println!("{}get_nervous_system_parameters", log_prefix());
    over(candid_one, get_nervous_system_parameters_)
}

/// Returns Governance's NervousSystemParameters
#[candid_method(query, rename = "get_nervous_system_parameters")]
fn get_nervous_system_parameters_(_: ()) -> NervousSystemParameters {
    governance()
        .proto
        .parameters
        .clone()
        .expect("NervousSystemParameters are not set")
}

/// Performs the action of a neuron, such as voting,
/// disbursing, merging maturity, or changing dissolve state
/// if the caller is authorized.
#[export_name = "canister_update manage_neuron"]
fn manage_neuron() {
    println!("{}manage_neuron", log_prefix());
    over_async(candid_one, manage_neuron_)
}

/// Performs the action of a neuron, such as voting,
/// disbursing, merging maturity, or changing dissolve state
/// if the caller is authorized.
#[candid_method(update, rename = "manage_neuron")]
async fn manage_neuron_(manage_neuron: ManageNeuron) -> ManageNeuronResponse {
    governance_mut()
        .manage_neuron(&manage_neuron, &caller())
        .await
}

/// Returns the full neuron corresponding to the `neuron_id`.
#[export_name = "canister_query get_neuron"]
fn get_neuron() {
    println!("{}get_neuron", log_prefix());
    over(candid_one, get_neuron_)
}

/// Returns the full neuron corresponding to the `neuron_id`.
#[candid_method(query, rename = "get_neuron")]
fn get_neuron_(get_neuron: GetNeuron) -> GetNeuronResponse {
    governance().get_neuron(&get_neuron)
}

/// Returns a list of neurons of size `limit` starting at `first_neuron`.
/// Specifying `of_principal` will return Neurons of which the given
/// PrincipalId has permissions. The list returned is not certified.
#[export_name = "canister_query list_neurons"]
fn list_neurons() {
    println!("{}list_neurons", log_prefix());
    over(candid_one, list_neurons_)
}

/// Returns a list of neurons of size `limit` starting at `first_neuron`.
/// Specifying `of_principal` will return Neurons of which the given
/// PrincipalId has permissions. The list returned is not certified.
#[candid_method(query, rename = "list_neurons")]
fn list_neurons_(list_neurons: ListNeurons) -> ListNeuronsResponse {
    governance().list_neurons(&list_neurons, &caller())
}

/// Returns the full proposal corresponding to the `proposal_id`.
#[export_name = "canister_query get_proposal"]
fn get_proposal() {
    println!("{}get_proposal", log_prefix());
    over(candid_one, get_proposal_)
}

/// Returns the full proposal corresponding to the `proposal_id`.
#[candid_method(query, rename = "get_proposal")]
fn get_proposal_(get_proposal: GetProposal) -> GetProposalResponse {
    governance().get_proposal(&get_proposal)
}

/// Returns a list of proposals of size `limit` that are earlier than
/// `before_proposal`. Additional filter parameters can be set on the
/// request. The list returned is not certified.
#[export_name = "canister_query list_proposals"]
fn list_proposals() {
    println!("{}list_proposals", log_prefix());
    over(candid_one, list_proposals_)
}

/// Returns a list of proposals of size `limit` that are earlier than
/// `before_proposal`. Additional filter parameters can be set on the
/// request. The list returned is not certified.
#[candid_method(query, rename = "list_proposals")]
fn list_proposals_(list_proposals: ListProposals) -> ListProposalsResponse {
    governance().list_proposals(&list_proposals)
}

/// Provides information about the last reward event.
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

/// Heartbeat of the canister.
#[export_name = "canister_heartbeat"]
fn canister_heartbeat() {
    let future = governance_mut().run_periodic_tasks();

    // canister_heartbeat must be synchronous, so we cannot .await the future
    dfn_core::api::futures::spawn(future);
}

/// Encode metrics
fn encode_metrics(_w: &mut metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    Ok(())
}

/// Resources to serve for a given http_request
#[export_name = "canister_query http_request"]
fn http_request() {
    ledger_canister::http_request::serve_metrics(encode_metrics);
}

// This makes this Candid service self-describing, so that for example Candid
// UI, but also other tools, can seamlessly integrate with it.
// The concrete interface (__get_candid_interface_tmp_hack) is provisional, but
// works.
//
// We include the .did file as committed, which means it is included verbatim in
// the .wasm; using `candid::export_service` here would involve unnecessary
// runtime computation

#[export_name = "canister_query __get_candid_interface_tmp_hack"]
fn expose_candid() {
    over(candid, |_: ()| include_str!("governance.did").to_string())
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
            Run `cargo run --bin sns-governance-canister > canister/governance.did` in \
            rs/sns/governance to update canister/governance.did."
        )
    }
}
