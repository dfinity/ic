//! This is a special-purpose canister to create a large Governance proto and
//! serialize it to stable memory in a format that is compatible with the real
//! governance canister.
//!
//! It is intended to be used in tests verifying that the governance canister
//! can handle large state. In particular, that canister pre- and post-upgrade
//! can finish within the execution limit.
use dfn_core::println;
use lazy_static::lazy_static;
use prost::Message;
use std::collections::HashMap;
use strum::IntoEnumIterator;

use ic_base_types::PrincipalId;
use ic_nervous_system_common::stable_mem_utils::BufferedStableMemWriter;
use ic_nns_common::pb::v1::{NeuronId as NeuronIdProto, ProposalId as ProposalIdProto};
use ic_nns_governance::governance::{
    HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES, MAX_NUMBER_OF_NEURONS,
    MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS, MAX_NUM_HOT_KEYS_PER_NEURON,
};
use ic_nns_governance::pb::v1::proposal::Action;
use ic_nns_governance::pb::v1::*;
use ic_nns_governance::{
    governance::{MAX_FOLLOWEES_PER_TOPIC, MAX_NEURON_RECENT_BALLOTS},
    pb::v1::{
        governance::NeuronInFlightCommand, Governance as GovernanceProto,
        NetworkEconomics as NetworkEconomicsProto, Neuron, Proposal, ProposalData, Topic,
    },
};
use ledger_canister::Subaccount;

const LOG_PREFIX: &str = "[Governance mem test] ";

/// The real governance canister has a soft limit of the heap size. For this
/// test to be meaningful, we need to make sure that we can do upgrades with
/// much less memory than what is actually left when the soft limit is reached.
/// We choose test with having 1/3 of the free memory.
const MAX_POSSIBLE_HEAP_SIZE_IN_PAGES: usize = 4 * 1024 * 1024 / 64;
const TEST_TARGET_HEAP_SIZE_IN_NUM_PAGES: usize = MAX_POSSIBLE_HEAP_SIZE_IN_PAGES
    - ((MAX_POSSIBLE_HEAP_SIZE_IN_PAGES - HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES) / 3);

/// Total number of neurons the governance will have.
const TEST_NUM_NEURONS: u64 = MAX_NUMBER_OF_NEURONS as u64;

/// Number of settled proposals to keep, per topic. Settled proposals have empty
/// `ballots` list.
const TEST_NUM_SETTLED_PROPOSALS_PER_TOPIC: usize =
    NetworkEconomics::with_default_values().max_proposals_to_keep_per_topic as usize;

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
    println!("{}Populating canister state ...", LOG_PREFIX);
    populate_canister_state();
}

#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    let mut writer = BufferedStableMemWriter::new(1000);
    unsafe {
        GOVERNANCE
            .as_ref()
            .unwrap()
            .encode(&mut writer)
            .expect("Could not serialize to stable memory");
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
    let mut proto = GovernanceProto {
        economics: Some(NetworkEconomicsProto::with_default_values()),
        in_flight_commands: create_in_flight_commands(),
        ..Default::default()
    };

    let wasm_pages_before_neurons = heap_size_num_pages();

    proto.neurons.reserve(TEST_NUM_NEURONS as usize);
    for i in 0..TEST_NUM_NEURONS {
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

    for i in 0..TEST_NUM_SETTLED_PROPOSALS_PER_TOPIC {
        for topic in topic_iterator() {
            // Closed proposals don't have ballots
            proto
                .proposals
                .insert(i as u64, allocate_proposal_data(false, topic));
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
    for i in num_settled_proposals..num_settled_proposals + TEST_NUM_NOT_YET_SETTLED_PROPOSALS {
        if heap_size_num_pages() > TEST_TARGET_HEAP_SIZE_IN_NUM_PAGES {
            break;
        }
        // Open proposals have ballots, for the worst case we assume every neuron votes
        // on every open proposal
        proto.proposals.insert(
            i as u64,
            allocate_proposal_data(true, *topic_iter.next().unwrap()),
        );
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
        map.reserve(topic_iterator().count() * MAX_FOLLOWEES_PER_TOPIC);
        for topic in topic_iterator() {
            let mut followees = Vec::<NeuronIdProto>::new();
            followees.reserve_exact(MAX_FOLLOWEES_PER_TOPIC);
            for i in 0..MAX_FOLLOWEES_PER_TOPIC {
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
                proposal_id: None,
                vote: 0,
            };
            MAX_NEURON_RECENT_BALLOTS
        ],
        kyc_verified: false,
        transfer: None,
        maturity_e8s_equivalent: 0,
        dissolve_state: Some(neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
        not_for_profit: true,
        joined_community_fund_timestamp_seconds: None,
        known_neuron_data: None,
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
            summary: ['a'; 15000].iter().collect(), /* 15000-bytes upper limit copied from type
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
