//! This is a special-purpose canister to create a large Governance proto and
//! serialize it to stable memory in a format that is compatible with the real
//! governance canister.
//!
//! It is intended to be used in tests verifying that the governance canister
//! can handle large state. In particular, that canister pre- and post-upgrade
//! can finish within the execution limit.
use dfn_core::println;
use ic_base_types::PrincipalId;
use ic_nervous_system_common::memory_manager_upgrade_storage::store_protobuf;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL};
use ic_nns_common::pb::v1::{NeuronId as NeuronIdProto, ProposalId as ProposalIdProto};
use ic_nns_governance::governance::{
    HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES, MAX_FOLLOWEES_PER_TOPIC, MAX_NEURON_RECENT_BALLOTS,
    MAX_NUMBER_OF_NEURONS, MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS, MAX_NUM_HOT_KEYS_PER_NEURON,
};
use ic_nns_governance_api::pb::v1::{
    governance::NeuronInFlightCommand, neuron::DissolveState, proposal::Action,
    Governance as GovernanceProto, NetworkEconomics as NetworkEconomicsProto, Neuron, Proposal,
    ProposalData, Topic, *,
};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl,
};
use icp_ledger::Subaccount;
use lazy_static::lazy_static;
use std::{cell::RefCell, collections::HashMap};
use strum::IntoEnumIterator;

const LOG_PREFIX: &str = "[Governance mem test] ";

/// The real governance canister has a soft limit of the heap size. For this
/// test to be meaningful, we need to make sure that we can do upgrades with
/// much less memory than what is actually left when the soft limit is reached.
/// We choose test with having 1/3 of the free memory.
const MAX_POSSIBLE_HEAP_SIZE_IN_PAGES: usize = 4 * 1024 * 1024 / 64;
const TEST_TARGET_HEAP_SIZE_IN_NUM_PAGES: usize = (MAX_POSSIBLE_HEAP_SIZE_IN_PAGES
    - (MAX_POSSIBLE_HEAP_SIZE_IN_PAGES - HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES))
    / 3;

/// Total number of neurons the governance will have.
const ASSUMED_INACTIVE: u64 = 120_000;
const TEST_NUM_NEURONS: u64 = MAX_NUMBER_OF_NEURONS as u64 - ASSUMED_INACTIVE;

lazy_static! {
    /// Number of settled proposals to keep, per topic. Settled proposals have empty
    /// `ballots` list.
    static ref TEST_NUM_SETTLED_PROPOSALS_PER_TOPIC: usize =
        NetworkEconomics::with_default_values().max_proposals_to_keep_per_topic as usize;
}

/// Number of open proposals. Open proposals will have a `ballot` for each
/// neuron.
const TEST_NUM_NOT_YET_SETTLED_PROPOSALS: usize = MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS;

/// Size of the `account` vector in neurons
const TEST_NEURON_ACCOUNT_VEC_SIZE_IN_BYTES: usize = std::mem::size_of::<Subaccount>();

/// Length (not size!) of the `hot_key` vector in neurons
const TEST_NEURON_HOTKEY_VEC_LEN: usize = MAX_NUM_HOT_KEYS_PER_NEURON;

static mut GOVERNANCE: Option<GovernanceProto> = None;

/// A default controller which, when turned into a vector of bytes, is of
/// maximal length.
const DEFAULT_CONTROLLER: PrincipalId = PrincipalId::new(
    PrincipalId::MAX_LENGTH_IN_BYTES,
    [0; PrincipalId::MAX_LENGTH_IN_BYTES],
);

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

/// Returns the number of wasm32 pages consumed.
#[cfg(target_arch = "wasm32")]
fn heap_size_num_pages() -> usize {
    core::arch::wasm32::memory_size(0)
}
#[cfg(not(target_arch = "wasm32"))]
fn heap_size_num_pages() -> usize {
    0
}

fn memory_operations() -> usize {
    // A 4KB string
    const PAGE_PAYLOAD: &str = "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";
    const GB: usize = 1024 * 1024 * 1024;
    const TARGET_SIZE: usize = 15 * (GB / 8);

    let src_buf = PAGE_PAYLOAD
        .repeat(TARGET_SIZE / PAGE_PAYLOAD.len())
        .into_bytes();
    let mut dst_buf = Vec::with_capacity(src_buf.len());

    // memory.copy
    unsafe {
        std::ptr::copy_nonoverlapping(src_buf.as_ptr(), dst_buf.as_mut_ptr(), src_buf.len());
        dst_buf.set_len(src_buf.len());
    }

    // memory.fill
    dst_buf.as_mut_slice().fill(0xab);
    dst_buf.len()
}

#[export_name = "canister_init"]
fn canister_init() {
    dfn_core::printer::hook();
    println!("{}Populating canister state ...", LOG_PREFIX);
    let size = memory_operations();
    println!(
        "{}Memory test complete. Raw memory size copied {}",
        LOG_PREFIX, size
    );
    populate_canister_state();
}

#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    unsafe {
        UPGRADES_MEMORY
            .with(|um| store_protobuf(&*um.borrow(), GOVERNANCE.as_ref().unwrap()).unwrap());
    }
}

#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {}

fn main() {}

fn topic_iterator() -> impl Iterator<Item = Topic> {
    Topic::iter().filter(|t| *t != Topic::Unspecified)
}

const WASM_PAGE_SIZE_BYTES: usize = 65536;

fn comma_sep(bytes: u64) -> String {
    let bytes_str = bytes.to_string();
    let mut ret = vec![];

    let mut n = 0;
    for c in bytes_str.chars().rev() {
        if n == 3 {
            ret.push(',');
            n = 0;
        }

        ret.push(c);
        n += 1;
    }

    ret.reverse();
    ret.into_iter().collect()
}

fn create_in_flight_commands() -> HashMap<u64, NeuronInFlightCommand> {
    let mut map = HashMap::new();
    map.reserve(TEST_NUM_NEURONS as usize);
    for neuron in 0..TEST_NUM_NEURONS {
        map.insert(
            neuron,
            NeuronInFlightCommand {
                timestamp: 0,
                command: None,
            },
        );
    }
    map
}

fn populate_canister_state() {
    const TWELVE_MONTHS_SECONDS: u64 = 30 * 12 * 24 * 60 * 60;
    let neuron1 = {
        let neuron_id = NeuronIdProto {
            id: TEST_NEURON_1_ID,
        };
        let subaccount_bytes = vec![1; 32];
        Neuron {
            id: Some(neuron_id),
            controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            account: subaccount_bytes,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(TWELVE_MONTHS_SECONDS)),
            cached_neuron_stake_e8s: 1_000_000_000_000,
            ..Default::default()
        }
    };

    let mut proto = GovernanceProto {
        economics: Some(NetworkEconomicsProto::with_default_values()),
        in_flight_commands: create_in_flight_commands(),
        xdr_conversion_rate: Some(XdrConversionRate {
            timestamp_seconds: Some(
                dfn_core::api::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            xdr_permyriad_per_icp: Some(1000),
        }),
        ..Default::default()
    };

    let wasm_pages_before_neurons = heap_size_num_pages();

    proto.neurons.insert(TEST_NEURON_1_ID, neuron1);

    for i in 0..TEST_NUM_NEURONS - 1 {
        proto.neurons.insert(i, allocate_neuron(i));
    }

    let wasm_pages_after_neurons = heap_size_num_pages();
    println!(
        "{}Neurons approximate in-memory size (total: {}) = {} bytes",
        LOG_PREFIX,
        TEST_NUM_NEURONS,
        comma_sep(
            ((wasm_pages_after_neurons - wasm_pages_before_neurons) * WASM_PAGE_SIZE_BYTES) as u64
        )
    );

    let mut proposal_id = 0_u64;
    for _ in 0..*TEST_NUM_SETTLED_PROPOSALS_PER_TOPIC {
        for topic in topic_iterator() {
            // Closed proposals don't have ballots
            proto
                .proposals
                .insert(proposal_id, allocate_proposal_data(false, topic));
            proposal_id += 1;
        }
    }
    let num_settled_proposals = proto.proposals.len();

    let wasm_pages_after_settled_proposals = heap_size_num_pages();
    println!(
        "{}Settled proposals approximate in-memory size = \
         {} bytes for {} proposals.",
        LOG_PREFIX,
        comma_sep(
            ((wasm_pages_after_settled_proposals - wasm_pages_after_neurons) * WASM_PAGE_SIZE_BYTES)
                as u64
        ),
        num_settled_proposals,
    );

    // TODO(NNS1-521) - Use the actual distribution of topics instead of cycling
    // through them
    let topics: Vec<Topic> = topic_iterator().collect();
    let mut topic_iter = topics.iter().cycle();
    for _ in num_settled_proposals..num_settled_proposals + TEST_NUM_NOT_YET_SETTLED_PROPOSALS {
        if heap_size_num_pages() > TEST_TARGET_HEAP_SIZE_IN_NUM_PAGES {
            break;
        }
        // Open proposals have ballots, for the worst case we assume every neuron votes
        // on every open proposal
        proto.proposals.insert(
            proposal_id,
            allocate_proposal_data(true, *topic_iter.next().unwrap()),
        );
        proposal_id += 1;
    }

    let num_unsettled_proposals = proto.proposals.len() - num_settled_proposals;
    let wasm_pages_after_all_proposals = heap_size_num_pages();
    println!(
        "{}Unsettled proposals approximate in-memory size = \
         {} bytes for {} proposals.",
        LOG_PREFIX,
        comma_sep(
            ((wasm_pages_after_all_proposals - wasm_pages_after_settled_proposals)
                * WASM_PAGE_SIZE_BYTES) as u64
        ),
        num_unsettled_proposals,
    );

    unsafe {
        GOVERNANCE = Some(proto);
    }
}

lazy_static! {
    static ref FOLLOWEES_MAP: HashMap<i32, neuron::Followees> = {
        let mut map = HashMap::<i32, neuron::Followees>::new();
        for topic in topic_iterator() {
            let mut followees = Vec::<NeuronIdProto>::new();
            followees.reserve_exact(MAX_FOLLOWEES_PER_TOPIC);
            // Test following for votes in the upgrade test
            followees.push(NeuronIdProto {id: TEST_NEURON_1_ID});
            for i in 1..MAX_FOLLOWEES_PER_TOPIC {
                followees.push(NeuronIdProto { id: i as u64 })
            }
            map.insert(topic as i32, neuron::Followees { followees });
        }
        map
    };
}

fn allocate_neuron(id: u64) -> Neuron {
    Neuron {
        id: Some(NeuronIdProto { id }),
        account: {
            let mut v = id.to_le_bytes().to_vec();
            v.resize(TEST_NEURON_ACCOUNT_VEC_SIZE_IN_BYTES, 0);
            v
        },
        controller: Some(DEFAULT_CONTROLLER),
        hot_keys: vec![DEFAULT_CONTROLLER; TEST_NEURON_HOTKEY_VEC_LEN],
        cached_neuron_stake_e8s: 0,
        neuron_fees_e8s: 0,
        created_timestamp_seconds: 0,
        aging_since_timestamp_seconds: 0,
        followees: FOLLOWEES_MAP.clone(),
        recent_ballots: vec![
            BallotInfo {
                proposal_id: Some(ProposalIdProto { id: 1 }),
                vote: 0,
            };
            MAX_NEURON_RECENT_BALLOTS
        ],
        kyc_verified: false,
        transfer: None,
        maturity_e8s_equivalent: 0,
        staked_maturity_e8s_equivalent: None,
        auto_stake_maturity: None,
        dissolve_state: Some(neuron::DissolveState::DissolveDelaySeconds(1)),
        not_for_profit: true,
        joined_community_fund_timestamp_seconds: None,
        known_neuron_data: None,
        spawn_at_timestamp_seconds: None,
        neuron_type: None,
        visibility: None,
    }
}

lazy_static! {
    static ref BALLOTS: HashMap<u64, Ballot> = {
        let mut ballots = HashMap::<u64, Ballot>::new();
        // Even though this is executed only once, it still counts toward the cycles
        // used in canister_init, so we make sure to avoid any map resize.
        ballots.reserve(TEST_NUM_NEURONS as usize);
        for i in 0..TEST_NUM_NEURONS {
            ballots.insert(
                    i,
                    Ballot {
                        vote: 0,
                        voting_power: 0,
                    },
                );
        }
        ballots.shrink_to_fit();
        ballots
    };
}

fn allocate_proposal_data(with_ballots: bool, topic: Topic) -> ProposalData {
    let payload_size: usize = match topic {
        Topic::Governance => 3_000_000,
        _ => 200,
    };

    ProposalData {
        id: Some(ProposalIdProto { id: 0 }),
        proposer: Some(NeuronIdProto { id: 0 }),
        reject_cost_e8s: 0,
        proposal: Some(Proposal {
            title: Some(['t'; 256].iter().collect()), /* 256 bytes upper limit copied from the
                                                       * type
                                                       * definition. */
            summary: ['a'; 30000].iter().collect(), /* 30000-bytes upper limit copied from type
                                                     * definition */
            url: ['a'; 2000].iter().collect(), // 2000-bytes upper limit copied from type definition
            action: Some(Action::Motion(Motion {
                // We use "motion" for all topics for convenience. All that matters is the size.
                motion_text: "a".repeat(payload_size),
            })),
        }),
        ballots: if with_ballots {
            BALLOTS.clone()
        } else {
            HashMap::new()
        },
        ..Default::default()
    }
}
