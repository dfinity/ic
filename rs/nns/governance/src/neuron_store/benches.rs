use super::*;
use crate::{
    governance::{MAX_FOLLOWEES_PER_TOPIC, MAX_NEURON_RECENT_BALLOTS, MAX_NUM_HOT_KEYS_PER_NEURON},
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::{neuron::Followees, BallotInfo, Vote},
};
use canbench_rs::{bench, bench_fn, BenchResult};
use ic_nns_common::pb::v1::ProposalId;
use maplit::hashmap;
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// Whether the neuron should be stored in heap or stable storage.
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
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

fn build_neuron(rng: &mut impl RngCore, location: NeuronLocation, size: NeuronSize) -> Neuron {
    let id = rng.next_u64();

    let mut account = vec![0; 32];
    // Populate account so that it's not all zeros.
    for (destination, data) in account.iter_mut().zip(id.to_le_bytes().iter().cycle()) {
        *destination = *data;
    }
    let subaccount = Subaccount::try_from(account.as_slice()).unwrap();
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

    neuron
}

fn set_up_neuron_store(rng: &mut impl RngCore) -> NeuronStore {
    // We insert 200 inactive neurons and 100 active neurons. They are not very realistic sizes, but
    // it would take too long to prepare those neurons for each benchmark.
    let inactive_neurons: Vec<_> = (0..200)
        .map(|_| build_neuron(rng, NeuronLocation::Stable, NeuronSize::Typical))
        .collect();
    let active_neurons: Vec<_> = (0..100)
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
    let mut neuron_store = set_up_neuron_store(&mut rng);
    let neuron = build_neuron(&mut rng, NeuronLocation::Heap, NeuronSize::Typical);

    bench_fn(|| {
        neuron_store.add_neuron(neuron).unwrap();
    })
}

#[bench(raw)]
fn add_neuron_active_maximum() -> BenchResult {
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng);
    let neuron = build_neuron(&mut rng, NeuronLocation::Heap, NeuronSize::Maximum);

    bench_fn(|| {
        neuron_store.add_neuron(neuron).unwrap();
    })
}

#[bench(raw)]
fn add_neuron_inactive_typical() -> BenchResult {
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng);
    let neuron = build_neuron(&mut rng, NeuronLocation::Stable, NeuronSize::Typical);

    bench_fn(|| {
        neuron_store.add_neuron(neuron).unwrap();
    })
}

#[bench(raw)]
fn add_neuron_inactive_maximum() -> BenchResult {
    let mut rng = new_rng();
    let mut neuron_store = set_up_neuron_store(&mut rng);
    let neuron = build_neuron(&mut rng, NeuronLocation::Stable, NeuronSize::Maximum);

    bench_fn(|| {
        neuron_store.add_neuron(neuron).unwrap();
    })
}
