use super::*;
use crate::{
    governance::{MAX_FOLLOWEES_PER_TOPIC, MAX_NEURON_RECENT_BALLOTS, MAX_NUM_HOT_KEYS_PER_NEURON},
    neuron::{DissolveStateAndAge, NeuronBuilder},
    neuron_data_validation::NeuronDataValidator,
    neurons_fund::{NeuronsFund, NeuronsFundNeuronPortion, NeuronsFundSnapshot},
    now_seconds,
    pb::v1::{neuron::Followees, BallotInfo, Vote},
    temporarily_disable_allow_active_neurons_in_stable_memory,
    temporarily_disable_migrate_active_neurons_to_stable_memory,
    temporarily_enable_allow_active_neurons_in_stable_memory,
    temporarily_enable_migrate_active_neurons_to_stable_memory,
    temporarily_enable_stable_memory_following_index,
};
use canbench_rs::{bench, bench_fn, BenchResult};
use ic_nervous_system_common::E8;
use ic_nns_common::pb::v1::ProposalId;
use maplit::hashmap;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::collections::BTreeSet;

/// Whether the neuron should be stored in heap or stable storage.
#[derive(Copy, Clone)]
enum NeuronLocation {
    Heap,
    Stable,
}

impl NeuronLocation {
    fn dissolve_state_and_age(self) -> DissolveStateAndAge {
        match self {
            NeuronLocation::Heap => DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 1_000_000,
                aging_since_timestamp_seconds: 1,
            },
            NeuronLocation::Stable => DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 1,
            },
        }
    }

    fn cached_neuron_stake_e8s(self) -> u64 {
        match self {
            NeuronLocation::Heap => 1_000_000_000,
            NeuronLocation::Stable => 0,
        }
    }
}

/// Whether the neuron is of a typical size or a maximum size.
#[derive(Copy, Clone)]
enum NeuronSize {
    Typical,
    Maximum,
}

impl NeuronSize {
    fn num_hot_keys(self) -> u32 {
        match self {
            NeuronSize::Typical => 1,
            NeuronSize::Maximum => MAX_NUM_HOT_KEYS_PER_NEURON as u32,
        }
    }

    fn num_recent_ballots(self) -> u32 {
        match self {
            NeuronSize::Typical => 25,
            NeuronSize::Maximum => MAX_NEURON_RECENT_BALLOTS as u32,
        }
    }

    fn num_followees(self) -> u32 {
        match self {
            NeuronSize::Typical => 11,
            NeuronSize::Maximum => MAX_FOLLOWEES_PER_TOPIC as u32 * num_topics(),
        }
    }
}

fn num_topics() -> u32 {
    use strum::IntoEnumIterator;

    Topic::iter().count() as u32
}

fn new_rng() -> StdRng {
    StdRng::seed_from_u64(42)
}

fn subaccount_from_id(id: u64) -> Subaccount {
    let mut account = vec![0; 32];
    // Populate account so that it's not all zeros.
    for (destination, data) in account.iter_mut().zip(id.to_le_bytes().iter().cycle()) {
        *destination = *data;
    }
    Subaccount::try_from(account.as_slice()).unwrap()
}

fn new_neuron_builder(
    rng: &mut impl RngCore,
    location: NeuronLocation,
    size: NeuronSize,
) -> NeuronBuilder {
    let id = rng.next_u64();

    let subaccount = subaccount_from_id(id);
    let hot_keys = (0..size.num_hot_keys())
        .map(|_| PrincipalId::new_user_test_id(rng.next_u64()))
        .collect();
    let followees = hashmap! {
        Topic::Unspecified as i32 => Followees {
            followees: (0..size.num_followees()).map(|_| NeuronId { id: rng.next_u64() }).collect(),
        },
    };
    let recent_ballots = (0..size.num_recent_ballots())
        .map(|_| BallotInfo {
            proposal_id: Some(ProposalId { id: rng.next_u64() }),
            vote: Vote::Yes as i32,
        })
        .collect();

    NeuronBuilder::new(
        NeuronId { id },
        subaccount,
        PrincipalId::new_user_test_id(id),
        location.dissolve_state_and_age(),
        123_456_789,
    )
    .with_cached_neuron_stake_e8s(location.cached_neuron_stake_e8s())
    .with_hot_keys(hot_keys)
    .with_followees(followees)
    .with_recent_ballots(recent_ballots)
}

fn set_up_neuron_store(
    rng: &mut impl RngCore,
    active_count: u64,
    inactive_count: u64,
) -> NeuronStore {
    // We insert 200 inactive neurons and 100 active neurons. They are not very realistic sizes, but
    // it would take too long to prepare those neurons for each benchmark.
    let inactive_neurons: Vec<_> = (0..inactive_count)
        .map(|_| new_neuron_builder(rng, NeuronLocation::Stable, NeuronSize::Typical).build())
        .collect();
    let active_neurons: Vec<_> = (0..active_count)
        .map(|_| new_neuron_builder(rng, NeuronLocation::Heap, NeuronSize::Typical).build())
        .collect();
    let neurons: BTreeMap<u64, Neuron> = inactive_neurons
        .into_iter()
        .chain(active_neurons)
        .map(|n| (n.id().id, n))
        .collect();

    NeuronStore::new(neurons)
}

#[bench(raw)]
fn add_neuron_active_typical() -> BenchResult {
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 100, 200);
    let neuron = new_neuron_builder(&mut rng, NeuronLocation::Heap, NeuronSize::Typical).build();

    bench_fn(|| {
        neuron_store.add_neuron(neuron).unwrap();
    })
}

#[bench(raw)]
fn add_neuron_active_maximum() -> BenchResult {
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 100, 200);
    let neuron = new_neuron_builder(&mut rng, NeuronLocation::Heap, NeuronSize::Maximum).build();

    bench_fn(|| {
        neuron_store.add_neuron(neuron).unwrap();
    })
}

#[bench(raw)]
fn add_neuron_inactive_typical() -> BenchResult {
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 100, 200);
    let neuron = new_neuron_builder(&mut rng, NeuronLocation::Stable, NeuronSize::Typical).build();

    bench_fn(|| {
        neuron_store.add_neuron(neuron).unwrap();
    })
}

#[bench(raw)]
fn add_neuron_inactive_maximum() -> BenchResult {
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 100, 200);
    let neuron = new_neuron_builder(&mut rng, NeuronLocation::Stable, NeuronSize::Maximum).build();

    bench_fn(|| {
        neuron_store.add_neuron(neuron).unwrap();
    })
}

#[bench(raw)]
fn update_recent_ballots_stable_memory() -> BenchResult {
    let _a = temporarily_enable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_enable_stable_memory_following_index();
    let _c = temporarily_enable_migrate_active_neurons_to_stable_memory();
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 100, 200);
    let neuron = new_neuron_builder(&mut rng, NeuronLocation::Heap, NeuronSize::Maximum).build();

    let id = neuron.id();

    assert_eq!(neuron.recent_ballots.len(), MAX_NEURON_RECENT_BALLOTS);

    neuron_store.add_neuron(neuron).unwrap();

    bench_fn(|| {
        neuron_store
            .register_recent_neuron_ballot(
                id,
                Topic::NetworkEconomics,
                ProposalId { id: rng.next_u64() },
                Vote::Yes,
            )
            .unwrap();
    })
}

#[bench(raw)]
fn range_neurons_performance() -> BenchResult {
    let mut rng = new_rng();
    let _neuron_store = set_up_neuron_store(&mut rng, 100, 200);

    bench_fn(|| {
        with_stable_neuron_store(|stable_store| {
            let iter = stable_store.range_neurons(..);
            for n in iter {
                n.id();
            }
        });
    })
}

#[bench(raw)]
fn neuron_metrics_calculation_heap() -> BenchResult {
    let _a = temporarily_disable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_disable_migrate_active_neurons_to_stable_memory();
    let mut rng = new_rng();
    let neuron_store = set_up_neuron_store(&mut rng, 100, 0);

    bench_fn(|| {
        neuron_store.compute_neuron_metrics(E8, &VotingPowerEconomics::DEFAULT, now_seconds())
    })
}

#[bench(raw)]
fn neuron_metrics_calculation_stable() -> BenchResult {
    let _a = temporarily_enable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_enable_migrate_active_neurons_to_stable_memory();

    let mut rng = new_rng();
    let neuron_store = set_up_neuron_store(&mut rng, 100, 0);

    bench_fn(|| {
        neuron_store.compute_neuron_metrics(E8, &VotingPowerEconomics::DEFAULT, now_seconds())
    })
}

fn add_neuron_ready_to_spawn(
    now_seconds: u64,
    rng: &mut impl RngCore,
    neuron_store: &mut NeuronStore,
) {
    let id = rng.next_u64();
    let subaccount = subaccount_from_id(id);
    let neuron = NeuronBuilder::new(
        NeuronId { id: rng.next_u64() },
        subaccount,
        PrincipalId::new_user_test_id(id),
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: now_seconds,
        },
        123_456_789,
    )
    .with_spawn_at_timestamp_seconds(now_seconds)
    .with_maturity_e8s_equivalent(1_000_000_000)
    .build();
    neuron_store.add_neuron(neuron).unwrap();
}

#[bench(raw)]
fn list_ready_to_spawn_neuron_ids_heap() -> BenchResult {
    let _a = temporarily_disable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_disable_migrate_active_neurons_to_stable_memory();
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 1_000, 2_000);
    add_neuron_ready_to_spawn(now_seconds(), &mut rng, &mut neuron_store);

    bench_fn(|| neuron_store.list_ready_to_spawn_neuron_ids(now_seconds()))
}

#[bench(raw)]
fn list_ready_to_spawn_neuron_ids_stable() -> BenchResult {
    let _a = temporarily_enable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_enable_migrate_active_neurons_to_stable_memory();
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 1_000, 2_000);
    add_neuron_ready_to_spawn(now_seconds(), &mut rng, &mut neuron_store);

    bench_fn(|| {
        neuron_store.list_ready_to_spawn_neuron_ids(now_seconds());
    })
}

fn add_neuron_ready_to_unstake_maturity(
    now_seconds: u64,
    rng: &mut impl RngCore,
    neuron_store: &mut NeuronStore,
) {
    let id = rng.next_u64();
    let subaccount = subaccount_from_id(id);
    let mut neuron = NeuronBuilder::new(
        NeuronId { id: rng.next_u64() },
        subaccount,
        PrincipalId::new_user_test_id(id),
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: now_seconds,
        },
        123_456_789,
    )
    .build();
    neuron.staked_maturity_e8s_equivalent = Some(1_000_000_000);
    neuron_store.add_neuron(neuron).unwrap();
}

#[bench(raw)]
fn list_neurons_ready_to_unstake_maturity_heap() -> BenchResult {
    let _a = temporarily_disable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_disable_migrate_active_neurons_to_stable_memory();
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 1_000, 2_000);
    add_neuron_ready_to_unstake_maturity(now_seconds(), &mut rng, &mut neuron_store);

    bench_fn(|| neuron_store.list_neurons_ready_to_unstake_maturity(now_seconds()))
}

#[bench(raw)]
fn list_neurons_ready_to_unstake_maturity_stable() -> BenchResult {
    let _a = temporarily_enable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_enable_migrate_active_neurons_to_stable_memory();
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 1_000, 2_000);
    add_neuron_ready_to_unstake_maturity(now_seconds(), &mut rng, &mut neuron_store);

    bench_fn(|| {
        neuron_store.list_neurons_ready_to_unstake_maturity(now_seconds());
    })
}

fn build_neurons_fund_portion(neuron: &Neuron, amount_icp_e8s: u64) -> NeuronsFundNeuronPortion {
    let maturity_equivalent_icp_e8s = neuron.maturity_e8s_equivalent;
    assert!(amount_icp_e8s <= maturity_equivalent_icp_e8s);
    let id = neuron.id();
    let controller = neuron.controller();
    let hotkeys = neuron.hot_keys.clone();
    let is_capped = false;

    NeuronsFundNeuronPortion {
        id,
        amount_icp_e8s,
        maturity_equivalent_icp_e8s,
        controller,
        hotkeys,
        is_capped,
    }
}

#[bench(raw)]
fn draw_maturity_from_neurons_fund_heap() -> BenchResult {
    let _a = temporarily_disable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_disable_migrate_active_neurons_to_stable_memory();
    let mut rng = new_rng();
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let mut neurons_fund_neurons = BTreeSet::new();
    for _ in 0..100 {
        let neuron = new_neuron_builder(&mut rng, NeuronLocation::Heap, NeuronSize::Typical)
            .with_maturity_e8s_equivalent(2_000_000_000)
            .build();
        neurons_fund_neurons.insert(build_neurons_fund_portion(&neuron, 1_000_000_000));
        neuron_store.add_neuron(neuron).unwrap();
    }
    let neurons_fund_snapshot = NeuronsFundSnapshot::new(neurons_fund_neurons);

    bench_fn(|| {
        neuron_store
            .draw_maturity_from_neurons_fund(&neurons_fund_snapshot)
            .unwrap();
    })
}

#[bench(raw)]
fn draw_maturity_from_neurons_fund_stable() -> BenchResult {
    let _a = temporarily_enable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_enable_migrate_active_neurons_to_stable_memory();
    let mut rng = new_rng();
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let mut neurons_fund_neurons = BTreeSet::new();
    // When extrapolating to `MAX_NEURONS_FUND_PARTICIPANTS` (5K) neurons, the current performance
    // of 12M instructions (as of the time of writing) becomes 600M instructions. This is relatively
    // small compared to the instruction limit of 50B (or the 40B limit for application subnets).
    for _ in 0..100 {
        let neuron = new_neuron_builder(&mut rng, NeuronLocation::Heap, NeuronSize::Typical)
            .with_maturity_e8s_equivalent(2_000_000_000)
            .build();
        neurons_fund_neurons.insert(build_neurons_fund_portion(&neuron, 1_000_000_000));
        neuron_store.add_neuron(neuron).unwrap();
    }
    let neurons_fund_snapshot = NeuronsFundSnapshot::new(neurons_fund_neurons);

    bench_fn(|| {
        neuron_store
            .draw_maturity_from_neurons_fund(&neurons_fund_snapshot)
            .unwrap();
    })
}

#[bench(raw)]
fn list_active_neurons_fund_neurons_heap() -> BenchResult {
    let _a = temporarily_disable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_disable_migrate_active_neurons_to_stable_memory();
    let mut rng = new_rng();
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    for _ in 0..100 {
        let neuron = new_neuron_builder(&mut rng, NeuronLocation::Heap, NeuronSize::Typical)
            .with_joined_community_fund_timestamp_seconds(Some(now_seconds()))
            .build();
        neuron_store.add_neuron(neuron).unwrap();
    }

    bench_fn(|| std::hint::black_box(neuron_store.list_active_neurons_fund_neurons()))
}

#[bench(raw)]
fn list_active_neurons_fund_neurons_stable() -> BenchResult {
    let _a = temporarily_enable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_enable_migrate_active_neurons_to_stable_memory();
    let mut rng = new_rng();
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    for _ in 0..100 {
        let neuron = new_neuron_builder(&mut rng, NeuronLocation::Heap, NeuronSize::Typical)
            .with_joined_community_fund_timestamp_seconds(Some(now_seconds()))
            .build();
        neuron_store.add_neuron(neuron).unwrap();
    }

    bench_fn(|| std::hint::black_box(neuron_store.list_active_neurons_fund_neurons()))
}

fn validate_all_neurons(neuron_store: &NeuronStore, validator: &mut NeuronDataValidator) {
    let mut now = now_seconds();
    loop {
        validator.maybe_validate(now, neuron_store);

        let still_validating = validator
            .summary()
            .current_validation_started_time_seconds
            .is_some();
        if !still_validating {
            break;
        }
        now += 1;
    }
}

#[bench(raw)]
fn neuron_data_validation_heap() -> BenchResult {
    let _a = temporarily_disable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_disable_migrate_active_neurons_to_stable_memory();
    let mut rng = new_rng();
    let neuron_store = set_up_neuron_store(&mut rng, 100, 200);
    let mut validator = NeuronDataValidator::new();

    bench_fn(|| {
        validate_all_neurons(&neuron_store, &mut validator);
    })
}

#[bench(raw)]
fn neuron_data_validation_stable() -> BenchResult {
    let _a = temporarily_enable_allow_active_neurons_in_stable_memory();
    let _b = temporarily_enable_migrate_active_neurons_to_stable_memory();
    let mut rng = new_rng();
    let neuron_store = set_up_neuron_store(&mut rng, 100, 200);
    let mut validator = NeuronDataValidator::new();

    bench_fn(|| {
        validate_all_neurons(&neuron_store, &mut validator);
    })
}
