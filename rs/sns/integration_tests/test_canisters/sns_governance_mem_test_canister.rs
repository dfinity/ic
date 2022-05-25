//! This is a special-purpose canister to create a large Governance proto and
//! serialize it to stable memory in a format that is compatible with the real
//! governance canister.
//!
//! It is intended to be used in tests verifying that the governance canister
//! can handle large state. In particular, that canister pre- and post-upgrade
//! can finish within the execution limit.

use dfn_core::println;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::stable_mem_utils::BufferedStableMemWriter;
use ic_sns_governance::governance::HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES;
use ic_sns_governance::pb::v1::governance::NeuronInFlightCommand;
use ic_sns_governance::pb::v1::nervous_system_function::{
    FunctionType, GenericNervousSystemFunction,
};
use ic_sns_governance::pb::v1::neuron::{DissolveState, Followees};
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::{
    Ballot, Governance as GovernanceProto, Motion, NervousSystemFunction, NervousSystemParameters,
    Neuron, NeuronId, NeuronPermission, NeuronPermissionType, Proposal, ProposalData, ProposalId,
    WaitForQuietState,
};
use ic_sns_governance::proposal::{
    MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS, PROPOSAL_SUMMARY_BYTES_MAX, PROPOSAL_TITLE_BYTES_MAX,
    PROPOSAL_URL_CHAR_MAX,
};
use ic_sns_governance::types::native_action_ids;
use ledger_canister::Subaccount;
use pretty_bytes::converter;
use prost::Message;
use rand::rngs::StdRng;
use rand_core::{RngCore, SeedableRng};
use std::collections::BTreeMap;

const LOG_PREFIX: &str = "[Governance mem test] ";

const MAX_POSSIBLE_HEAP_SIZE_IN_PAGES: usize = 4 * 1024 * 1024 / 64;

const WASM_PAGE_SIZE_BYTES: usize = 65536;

const BUFFER_SIZE: u32 = 100 * 1024 * 1024; // 100 MiB

const SIZE_OF_NEURON_ID: usize = std::mem::size_of::<Subaccount>();

/// The real sns-governance canister has a soft limit of the heap size. For this
/// test to be meaningful, we need to make sure that we can do upgrades with
/// much less memory than what is actually left when the soft limit is reached.
/// We choose test with having 1/3 of the soft limit.
const TARGET_HEAP_SIZE_IN_NUM_PAGES: usize = (MAX_POSSIBLE_HEAP_SIZE_IN_PAGES
    - (MAX_POSSIBLE_HEAP_SIZE_IN_PAGES - HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES))
    / 3;

/// When creating the large state, maximum following coupled with a large number of
/// NervousSystemFunctions lead to exponential growth of the state (~12 TB). For this
/// test to be effective, the number of GenericNervousSystemFunctions is limited.
const TARGET_GENERIC_NERVOUS_SYSTEM_FUNCTION_COUNT: u64 = 10;

/// A default controller which, when turned into a vector of bytes, is of
/// maximal length.
const DEFAULT_CONTROLLER: PrincipalId = PrincipalId::new(
    PrincipalId::MAX_LENGTH_IN_BYTES,
    [0; PrincipalId::MAX_LENGTH_IN_BYTES],
);

static mut GOVERNANCE: Option<GovernanceProto> = None;

/// Returns the number of wasm32 pages consumed.
#[cfg(target_arch = "wasm32")]
fn heap_size_num_pages() -> usize {
    core::arch::wasm32::memory_size(0)
}
#[cfg(not(target_arch = "wasm32"))]
fn heap_size_num_pages() -> usize {
    0
}

#[export_name = "canister_init"]
fn canister_init() {
    dfn_core::printer::hook();
    println!("{}Executing canister_init...", LOG_PREFIX);
    populate_canister_state();
    println!("{}Completed execution of canister_init", LOG_PREFIX);
}

#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    println!("{}Executing canister_pre_upgrade...", LOG_PREFIX);
    let mut writer = BufferedStableMemWriter::new(BUFFER_SIZE);
    unsafe {
        GOVERNANCE
            .as_ref()
            .unwrap()
            .encode(&mut writer)
            .expect("Could not serialize to stable memory");
    }
    writer.flush(); // or `drop(writer)`
    println!("{}Completed execution of canister_pre_upgrade", LOG_PREFIX);
}

/// Canister post_upgrade should never run
#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    unimplemented!()
}

fn main() {}

/// Provide an iterator of all the native_functions u64 ids except for unspecified.
fn proposal_action_iterator() -> impl Iterator<Item = u64> {
    Action::native_functions()
        .into_iter()
        .filter(|function| function.name != "Unspecified")
        .map(|function| function.id)
}

/// Provide human readable String given a count of bytes.
/// Ex: 4240000 -> "4.24 MB"
fn pretty_bytes(bytes: usize) -> String {
    converter::convert(bytes as f64)
}

/// Create a vector of NeuronIds. This is an expensive enough operation to do
/// once and reuse the list as needed.
fn generate_neuron_ids(max_number_of_neurons: u64) -> Vec<NeuronId> {
    // Seed required for randomness in canister execution environment
    let mut rng = StdRng::from_seed([0u8; 32]);

    let mut neuron_ids = vec![];
    for _ in 0..max_number_of_neurons {
        let mut bytes = [0u8; SIZE_OF_NEURON_ID];
        rng.fill_bytes(&mut bytes);
        neuron_ids.push(NeuronId {
            id: Vec::from(bytes),
        });
    }
    neuron_ids
}

/// Generate a vector of NeuronPermissions. Typically the principal must be unique, but since
/// this is constructed as part of the proto this requirement can be avoided.
fn generate_permissions_list(max_number_of_principals_per_neuron: u64) -> Vec<NeuronPermission> {
    let mut permissions = vec![];

    for _ in 0..max_number_of_principals_per_neuron {
        permissions.push(NeuronPermission {
            principal: Some(DEFAULT_CONTROLLER),
            permission_type: NeuronPermissionType::all(),
        });
    }
    permissions
}

/// Generate a map of NervousSystemFunctions. This is an expensive
/// enough operation to do once and reuse the map as needed.
fn generate_generic_nervous_system_functions(
    max_number_of_generic_functions: u64,
) -> BTreeMap<u64, NervousSystemFunction> {
    let mut functions_map = BTreeMap::new();
    for i in 0..max_number_of_generic_functions {
        let id = i as u64 + 1000; // Valid ids for GenericNervousSystemFunction start at 1000
        let nervous_system_function = NervousSystemFunction {
            id,
            name: "GenericNervousSystemFunction".to_string(),
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(CanisterId::from_u64(id).get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::from_u64(id).get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
            ..Default::default()
        };
        functions_map.insert(id, nervous_system_function);
    }
    functions_map
}

/// Generate a map of Followees assuming that the every function will have the same set of followees
/// used by every neuron. A Neuron in the SNS can follow on both Proposal Actions and on
/// GenericNervousSystemFunctions.
fn generate_followee_map(
    generic_nervous_system_functions: &BTreeMap<u64, NervousSystemFunction>,
    followee_neuron_ids: &[NeuronId],
) -> BTreeMap<u64, Followees> {
    let mut followees_map = BTreeMap::new();
    let followees = Followees {
        followees: Vec::from(followee_neuron_ids),
    };

    for function_id in generic_nervous_system_functions.keys() {
        followees_map.insert(*function_id, followees.clone());
    }

    for native_function_id in Action::native_function_ids() {
        followees_map.insert(native_function_id, followees.clone());
    }

    followees_map
}

/// Generate a map of Ballots for a set of NeuronIds. This is an expensive
/// enough operation to do once and reuse the map as needed.
fn generate_ballots(neuron_ids: &[NeuronId]) -> BTreeMap<String, Ballot> {
    let mut ballots = BTreeMap::new();
    for neuron_id in neuron_ids {
        ballots.insert(
            neuron_id.to_string(),
            Ballot {
                vote: 0,
                voting_power: 0,
                cast_timestamp_seconds: 0,
            },
        );
    }

    ballots
}

/// Generate a map of NeuronInFlightCommand assuming every neuron will have an in-flight-command.
/// This is an expensive enough operation to do once and reuse the map as needed.
fn generate_in_flight_commands(neuron_ids: &[NeuronId]) -> BTreeMap<String, NeuronInFlightCommand> {
    let mut map = BTreeMap::new();
    for neuron_id in neuron_ids {
        map.insert(
            neuron_id.to_string(),
            NeuronInFlightCommand {
                ..Default::default()
            },
        );
    }
    map
}

/// Allocate a Neuron
fn allocate_neuron(
    neuron_id: &NeuronId,
    neuron_permissions: &[NeuronPermission],
    followees: &BTreeMap<u64, Followees>,
) -> Neuron {
    Neuron {
        id: Some(neuron_id.clone()),
        permissions: Vec::from(neuron_permissions),
        followees: followees.clone(),
        dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(0)),
        ..Default::default()
    }
}

/// Allocate a Proposal
fn allocate_proposal_data(
    id: u64,
    action: u64,
    ballots: Option<&BTreeMap<String, Ballot>>,
) -> ProposalData {
    // As Proposal Actions are keyed on u64, below is a map of those keys to ~estimated~ payload size
    let payload_size: usize = match action {
        native_action_ids::UNSPECIFIED => 10_000, // Max size of motion_text payload = 10_000 bytes
        native_action_ids::MANAGE_NERVOUS_SYSTEM_PARAMETERS => 280, // sizeof(NervousSystemParameter) = 280 bytes
        native_action_ids::UPGRADE_SNS_CONTROLLER_CANISTER => 1_500_000, // Governance wasm is 1.5 MB
        native_action_ids::ADD_GENERIC_NERVOUS_SYSTEM_FUNCTION => 200, // sizeof(NervousSystemFunction) = ~200 bytes
        native_action_ids::REMOVE_GENERIC_NERVOUS_SYSTEM_FUNCTION => 8, // sizeof(u64) = 8 bytes
        native_action_ids::EXECUTE_GENERIC_NERVOUS_SYSTEM_FUNCTION => 1_000_000, // Estimate of average payload size = 1MB
        _ => panic!("Undefined proposal action"),
    };

    let mut proposal_data = ProposalData {
        action,
        id: Some(ProposalId { id }),
        proposal: Some(Proposal {
            title: ['t'; PROPOSAL_TITLE_BYTES_MAX].iter().collect(),
            summary: ['s'; PROPOSAL_SUMMARY_BYTES_MAX].iter().collect(),
            url: ['u'; PROPOSAL_URL_CHAR_MAX].iter().collect(),
            action: Some(Action::Motion(Motion {
                // We use "motion" for all actions for convenience. All that matters is the size.
                motion_text: "a".repeat(payload_size),
            })),
        }),
        wait_for_quiet_state: Some(WaitForQuietState {
            current_deadline_timestamp_seconds: 0,
        }),
        ..Default::default()
    };

    if let Some(b) = ballots {
        proposal_data.ballots = b.clone();
    }

    proposal_data
}

fn populate_canister_state() {
    println!(
        "{}Target state size in-memory = {}",
        LOG_PREFIX,
        pretty_bytes(TARGET_HEAP_SIZE_IN_NUM_PAGES * WASM_PAGE_SIZE_BYTES),
    );

    // Generate initial Governance data
    let nervous_system_parameters = NervousSystemParameters::with_default_values();

    let mut proto = GovernanceProto {
        neurons: Default::default(),
        proposals: Default::default(),
        parameters: Some(nervous_system_parameters.clone()),
        latest_reward_event: None,
        in_flight_commands: Default::default(),
        genesis_timestamp_seconds: 0,
        id_to_nervous_system_functions: Default::default(),
        ledger_canister_id: Some(CanisterId::from_u64(1).get()),
        root_canister_id: Some(CanisterId::from_u64(2).get()),
        ..Default::default()
    };

    let wasm_pages_with_minimal_proto = heap_size_num_pages();
    println!(
        "{}Proto approximate in-memory size = {}",
        LOG_PREFIX,
        pretty_bytes(wasm_pages_with_minimal_proto * WASM_PAGE_SIZE_BYTES)
    );

    // Generate the set of NeuronIds to be used in this canister state
    let max_number_of_neurons = nervous_system_parameters.max_number_of_neurons.unwrap();
    let neuron_ids = generate_neuron_ids(max_number_of_neurons);

    proto.in_flight_commands = generate_in_flight_commands(&neuron_ids);

    let wasm_pages_after_in_flight_commands = heap_size_num_pages();
    println!(
        "{}In flight commands approximate in-memory size (total: {}) = {}",
        LOG_PREFIX,
        proto.in_flight_commands.len(),
        pretty_bytes(
            (wasm_pages_after_in_flight_commands - wasm_pages_with_minimal_proto)
                * WASM_PAGE_SIZE_BYTES
        )
    );

    // Create the nervous_system_function map, which will be used to generate other structures.
    let nervous_system_functions =
        generate_generic_nervous_system_functions(TARGET_GENERIC_NERVOUS_SYSTEM_FUNCTION_COUNT);
    proto.id_to_nervous_system_functions = nervous_system_functions.clone();

    let wasm_pages_after_nervous_system_functions = heap_size_num_pages();
    println!(
        "{}GenericNervousSystemFunctions approximate in-memory size (total: {}) = {}",
        LOG_PREFIX,
        proto.id_to_nervous_system_functions.len(),
        pretty_bytes(
            (wasm_pages_after_nervous_system_functions - wasm_pages_after_in_flight_commands)
                * WASM_PAGE_SIZE_BYTES
        )
    );

    // Generate Neuron required data
    let max_number_of_principals_per_neuron = nervous_system_parameters
        .max_number_of_principals_per_neuron
        .unwrap();
    let neuron_permissions = generate_permissions_list(max_number_of_principals_per_neuron);

    let max_followee_per_function = nervous_system_parameters
        .max_followees_per_function
        .unwrap();
    assert!(max_followee_per_function as usize <= neuron_ids.len());

    let followee_slice = &neuron_ids[0..max_followee_per_function as usize];
    let followee_map = generate_followee_map(&nervous_system_functions, followee_slice);

    // Allocate and insert neurons into the proto. Make sure not to exceed the
    // target number of wasm pages for the test.
    for neuron_id in &neuron_ids {
        if heap_size_num_pages() > TARGET_HEAP_SIZE_IN_NUM_PAGES {
            break;
        }

        proto.neurons.insert(
            neuron_id.to_string(),
            allocate_neuron(neuron_id, &neuron_permissions, &followee_map),
        );
    }

    let wasm_pages_after_neurons = heap_size_num_pages();
    println!(
        "{}Neurons approximate in-memory size (total: {}, followees-per-function: {}, principals-per-neuron: {}) = {}",
        LOG_PREFIX,
        max_number_of_neurons,
        max_followee_per_function,
        max_number_of_principals_per_neuron,
        pretty_bytes((wasm_pages_after_neurons - wasm_pages_after_nervous_system_functions) * WASM_PAGE_SIZE_BYTES)
    );

    // Generate Proposal required data
    let ballots = generate_ballots(&neuron_ids);

    let settled_proposal_count_per_action = nervous_system_parameters
        .max_proposals_to_keep_per_action
        .unwrap() as u32;

    // Insert settled proposals first as they occupy less memory due to ballots being removed from
    // the proposal after settlement.
    let mut proposal_id = 0;
    for _ in 0..settled_proposal_count_per_action {
        for action in proposal_action_iterator() {
            if heap_size_num_pages() > TARGET_HEAP_SIZE_IN_NUM_PAGES {
                break;
            }

            // Closed proposals don't have ballots
            proto.proposals.insert(
                proposal_id,
                allocate_proposal_data(proposal_id, action, None),
            );
            proposal_id += 1;
        }
    }

    let num_settled_proposals = proto.proposals.len();
    assert_eq!(num_settled_proposals as u64, proposal_id);

    let wasm_pages_after_settled_proposals = heap_size_num_pages();
    println!(
        "{}Settled proposals approximate in-memory size (total: {}) = {}",
        LOG_PREFIX,
        num_settled_proposals,
        pretty_bytes(
            (wasm_pages_after_settled_proposals - wasm_pages_after_neurons) * WASM_PAGE_SIZE_BYTES
        ),
    );

    // Insert unsettled proposals. As ballots induce the most pressure on memory, insert proposals
    // in a round-robin fashion based on action until the target memory size is reached.
    let actions: Vec<u64> = proposal_action_iterator().collect();
    let mut action_iter = actions.iter().cycle();
    for _ in 0..MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS {
        if heap_size_num_pages() > TARGET_HEAP_SIZE_IN_NUM_PAGES {
            break;
        }
        // Open proposals have ballots, for the worst case we assume every neuron votes
        // on every open proposal
        proto.proposals.insert(
            proposal_id as u64,
            allocate_proposal_data(proposal_id, *action_iter.next().unwrap(), Some(&ballots)),
        );
        proposal_id += 1;
    }

    let num_unsettled_proposals = proto.proposals.len() - num_settled_proposals;
    let wasm_pages_after_all_proposals = heap_size_num_pages();
    println!(
        "{}Settled proposals approximate in-memory size (total: {}) = {}",
        LOG_PREFIX,
        num_unsettled_proposals,
        pretty_bytes(
            (wasm_pages_after_all_proposals - wasm_pages_after_settled_proposals)
                * WASM_PAGE_SIZE_BYTES
        ),
    );

    println!(
        "{}Total proto approximate in-memory size = {}.",
        LOG_PREFIX,
        pretty_bytes(heap_size_num_pages() * WASM_PAGE_SIZE_BYTES),
    );

    unsafe {
        GOVERNANCE = Some(proto);
    }
}
