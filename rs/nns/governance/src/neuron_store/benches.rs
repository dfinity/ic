use super::*;
use crate::{
    governance::{MAX_FOLLOWEES_PER_TOPIC, MAX_NEURON_RECENT_BALLOTS, MAX_NUM_HOT_KEYS_PER_NEURON},
    neuron::{DissolveStateAndAge, NeuronBuilder},
    now_seconds,
    pb::v1::{neuron::Followees, BallotInfo, Vote},
    temporarily_disable_active_neurons_in_stable_memory,
    temporarily_enable_active_neurons_in_stable_memory,
    temporarily_enable_stable_memory_following_index,
};
use canbench_rs::{bench, bench_fn, BenchResult};
use ic_nervous_system_common::E8;
use ic_nns_common::pb::v1::ProposalId;
use maplit::hashmap;
use rand::{rngs::StdRng, RngCore, SeedableRng};

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

fn build_neuron(rng: &mut impl RngCore, location: NeuronLocation, size: NeuronSize) -> Neuron {
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

    let mut neuron = NeuronBuilder::new(
        NeuronId { id },
        subaccount,
        PrincipalId::new_user_test_id(id),
        location.dissolve_state_and_age(),
        123_456_789,
    )
    .with_cached_neuron_stake_e8s(location.cached_neuron_stake_e8s())
    .with_hot_keys(hot_keys)
    .with_followees(followees)
    .build();

    neuron.recent_ballots = (0..size.num_recent_ballots())
        .map(|_| BallotInfo {
            proposal_id: Some(ProposalId { id: rng.next_u64() }),
            vote: Vote::Yes as i32,
        })
        .collect();
    neuron.recent_ballots_next_entry_index = Some(0);

    neuron
}

fn set_up_neuron_store(
    rng: &mut impl RngCore,
    active_count: u64,
    inactive_count: u64,
) -> NeuronStore {
    // We insert 200 inactive neurons and 100 active neurons. They are not very realistic sizes, but
    // it would take too long to prepare those neurons for each benchmark.
    let inactive_neurons: Vec<_> = (0..inactive_count)
        .map(|_| build_neuron(rng, NeuronLocation::Stable, NeuronSize::Typical))
        .collect();
    let active_neurons: Vec<_> = (0..active_count)
        .map(|_| build_neuron(rng, NeuronLocation::Heap, NeuronSize::Typical))
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
    let neuron = build_neuron(&mut rng, NeuronLocation::Heap, NeuronSize::Typical);

    bench_fn(|| {
        neuron_store.add_neuron(neuron).unwrap();
    })
}

#[bench(raw)]
fn add_neuron_active_maximum() -> BenchResult {
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 100, 200);
    let neuron = build_neuron(&mut rng, NeuronLocation::Heap, NeuronSize::Maximum);

    bench_fn(|| {
        neuron_store.add_neuron(neuron).unwrap();
    })
}

#[bench(raw)]
fn add_neuron_inactive_typical() -> BenchResult {
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 100, 200);
    let neuron = build_neuron(&mut rng, NeuronLocation::Stable, NeuronSize::Typical);

    bench_fn(|| {
        neuron_store.add_neuron(neuron).unwrap();
    })
}

#[bench(raw)]
fn update_recent_ballots_stable_memory() -> BenchResult {
    let _a = temporarily_enable_active_neurons_in_stable_memory();
    let _b = temporarily_enable_stable_memory_following_index();
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 100, 200);
    let neuron = build_neuron(&mut rng, NeuronLocation::Heap, NeuronSize::Maximum);

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
fn add_neuron_inactive_maximum() -> BenchResult {
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 100, 200);
    let neuron = build_neuron(&mut rng, NeuronLocation::Stable, NeuronSize::Maximum);

    bench_fn(|| {
        neuron_store.add_neuron(neuron).unwrap();
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
    let _f = temporarily_disable_active_neurons_in_stable_memory();
    let mut rng = new_rng();
    let neuron_store = set_up_neuron_store(&mut rng, 100, 0);

    bench_fn(|| neuron_store.compute_neuron_metrics(now_seconds(), E8))
}

#[bench(raw)]
fn neuron_metrics_calculation_stable() -> BenchResult {
    let _f = temporarily_enable_active_neurons_in_stable_memory();

    let mut rng = new_rng();
    let neuron_store = set_up_neuron_store(&mut rng, 100, 0);

    bench_fn(|| neuron_store.compute_neuron_metrics(now_seconds(), E8))
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
    let _t = temporarily_disable_active_neurons_in_stable_memory();
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 1_000, 2_000);
    add_neuron_ready_to_spawn(now_seconds(), &mut rng, &mut neuron_store);

    bench_fn(|| neuron_store.list_ready_to_spawn_neuron_ids(now_seconds()))
}

#[bench(raw)]
fn list_ready_to_spawn_neuron_ids_stable() -> BenchResult {
    let _t = temporarily_enable_active_neurons_in_stable_memory();
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
    let _t = temporarily_disable_active_neurons_in_stable_memory();
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 1_000, 2_000);
    add_neuron_ready_to_unstake_maturity(now_seconds(), &mut rng, &mut neuron_store);

    bench_fn(|| neuron_store.list_neurons_ready_to_unstake_maturity(now_seconds()))
}

#[bench(raw)]
fn list_neurons_ready_to_unstake_maturity_stable() -> BenchResult {
    let _t = temporarily_enable_active_neurons_in_stable_memory();
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng, 1_000, 2_000);
    add_neuron_ready_to_unstake_maturity(now_seconds(), &mut rng, &mut neuron_store);

    bench_fn(|| {
        neuron_store.list_neurons_ready_to_unstake_maturity(now_seconds());
    })
}
