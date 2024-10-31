use crate::{
    governance::{Governance, MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS},
    neuron::{DissolveStateAndAge, Neuron, NeuronBuilder},
    neuron_store::NeuronStore,
    pb::v1::{
        neuron::Followees, proposal::Action, Ballot, BallotInfo, Governance as GovernanceProto,
        KnownNeuron, Neuron as NeuronProto, Topic, Vote,
    },
    temporarily_disable_active_neurons_in_stable_memory,
    temporarily_disable_stable_memory_following_index,
    temporarily_enable_active_neurons_in_stable_memory,
    temporarily_enable_stable_memory_following_index,
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};
use canbench_rs::{bench, bench_fn, BenchResult};
use ic_base_types::PrincipalId;
use ic_nns_common::{
    pb::v1::{NeuronId as NeuronIdProto, ProposalId},
    types::NeuronId,
};
use icp_ledger::Subaccount;
use maplit::{btreemap, hashmap};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::{BTreeMap, HashMap};

enum SetUpStrategy {
    // Every neuron follows a single neuron.
    Centralized {
        num_neurons: u64,
    },
    // Following is centralized, but the voter neuron isn't followed by any other neuron.
    SingleVote {
        num_neurons: u64,
    },
    // Neurons follow a chain of other neurons. One end of the chain votes triggering the chain all
    // the way to the other end, while every neuron has its allowed followees maximized. This is
    // close to the worst case scenario. TODO: an even worse case scenario would be that the
    // catch-all topic following are also maximized while contributing nothing to the voting. The
    // worse scenario can be improved by just changing the following index though.
    Chain {
        num_neurons: u64,
        num_followees: u64,
    },
}
fn set_up<R: Rng>(
    strategy: SetUpStrategy,
    rng: &mut R,
    neuron_store: &mut NeuronStore,
    ballots: &mut HashMap<u64, Ballot>,
    topic: Topic,
) -> NeuronId {
    match strategy {
        SetUpStrategy::Centralized { num_neurons } => {
            set_up_centralized(num_neurons, rng, neuron_store, ballots, topic)
        }
        SetUpStrategy::SingleVote { num_neurons } => {
            set_up_single_vote(num_neurons, rng, neuron_store, ballots, topic)
        }
        SetUpStrategy::Chain {
            num_neurons,
            num_followees,
        } => set_up_chain(
            num_neurons,
            num_followees,
            rng,
            neuron_store,
            ballots,
            topic,
        ),
    }
}

fn set_up_centralized<R: Rng>(
    num_neurons: u64,
    rng: &mut R,
    neuron_store: &mut NeuronStore,
    ballots: &mut HashMap<u64, Ballot>,
    topic: Topic,
) -> NeuronId {
    assert!(num_neurons > 1);
    let start_neuron_id = NeuronId(rng.next_u64());
    ballots.insert(
        start_neuron_id.0,
        Ballot {
            vote: Vote::Unspecified.into(),
            voting_power: 10_000_000,
        },
    );
    neuron_store
        .add_neuron(make_neuron(
            start_neuron_id.0,
            PrincipalId::new_user_test_id(start_neuron_id.0),
            10_000_000,
            hashmap! {topic.into() => Followees {followees: vec![]}},
        ))
        .expect("Could not add neuron");

    for _ in 1u64..=num_neurons {
        let neuron = make_neuron(
            rng.next_u64(),
            PrincipalId::new_user_test_id(rng.next_u64()),
            1_000_000_000,
            hashmap! {topic.into() => Followees {followees: vec![start_neuron_id.into()]}},
        );

        ballots.insert(
            neuron.id().id,
            Ballot {
                vote: Vote::Unspecified.into(),
                voting_power: 10_000_000,
            },
        );
        neuron_store
            .add_neuron(neuron)
            .expect("Could not add neuron");
    }

    start_neuron_id
}
fn set_up_single_vote<R: Rng>(
    num_neurons: u64,
    rng: &mut R,
    neuron_store: &mut NeuronStore,
    ballots: &mut HashMap<u64, Ballot>,
    topic: Topic,
) -> NeuronId {
    assert!(num_neurons > 1);
    let start_neuron_id = NeuronId(rng.next_u64());
    let central_neuron_id = NeuronId(rng.next_u64());
    ballots.insert(
        start_neuron_id.0,
        Ballot {
            vote: Vote::Unspecified.into(),
            voting_power: 10_000_000,
        },
    );
    ballots.insert(
        central_neuron_id.0,
        Ballot {
            vote: Vote::Unspecified.into(),
            voting_power: 10_000_000,
        },
    );

    for _ in 2u64..=num_neurons {
        let neuron_id = rng.next_u64();
        let neuron = make_neuron(
            neuron_id,
            PrincipalId::new_user_test_id(neuron_id),
            10_000_000,
            hashmap! {topic.into() => Followees {followees: vec![central_neuron_id.into()]}},
        );
        ballots.insert(
            neuron.id().id,
            Ballot {
                vote: Vote::Unspecified.into(),
                voting_power: 10_000_000,
            },
        );
        neuron_store
            .add_neuron(neuron)
            .expect("Could not add neuron");
    }
    start_neuron_id
}
fn set_up_chain<R: Rng>(
    num_neurons: u64,
    num_followees: u64,
    rng: &mut R,
    neuron_store: &mut NeuronStore,
    ballots: &mut HashMap<u64, Ballot>,
    topic: Topic,
) -> NeuronId {
    assert!(num_followees % 2 == 1, "Number of followees must be odd");
    assert!(
        num_neurons > num_followees,
        "Number of neurons must be greater than number of followees"
    );

    let num_half_followees = num_followees / 2;
    let neuron_ids: Vec<NeuronIdProto> = (0u64..num_neurons)
        .map(|_| NeuronIdProto { id: rng.next_u64() })
        .collect();

    let not_voting_neuron_ids = (0u64..num_half_followees)
        .map(|i| neuron_ids[i as usize])
        .collect::<Vec<_>>();

    for not_voting_neuron_id in not_voting_neuron_ids.iter() {
        let neuron = make_neuron(
            not_voting_neuron_id.id,
            PrincipalId::new_user_test_id(not_voting_neuron_id.id),
            10_000_000,
            hashmap! {topic.into() => Followees {followees: vec![]}},
        );
        ballots.insert(
            not_voting_neuron_id.id,
            Ballot {
                vote: Vote::Unspecified.into(),
                voting_power: 10_000_000,
            },
        );
        neuron_store
            .add_neuron(neuron)
            .expect("Could not add neuron");
    }

    let voted_neuron_ids = (num_half_followees..(num_half_followees * 2))
        .map(|i| neuron_ids[i as usize])
        .collect::<Vec<_>>();
    for voted_neuron_id in voted_neuron_ids.iter() {
        let neuron = make_neuron(
            voted_neuron_id.id,
            PrincipalId::new_user_test_id(voted_neuron_id.id),
            10_000_000,
            hashmap! {topic.into() => Followees {followees: vec![]}},
        );
        ballots.insert(
            voted_neuron_id.id,
            Ballot {
                vote: Vote::Yes.into(),
                voting_power: 10_000_000,
            },
        );
        neuron_store
            .add_neuron(neuron)
            .expect("Could not add neuron");
    }
    let start_neuron_id = neuron_ids[(num_half_followees * 2) as usize];
    let followees = not_voting_neuron_ids
        .iter()
        .cloned()
        .chain(voted_neuron_ids)
        .collect::<Vec<_>>();
    let neuron = make_neuron(
        start_neuron_id.id,
        PrincipalId::new_user_test_id(start_neuron_id.id),
        10_000_000,
        hashmap! {topic.into() => Followees {followees}},
    );
    ballots.insert(
        start_neuron_id.id,
        Ballot {
            vote: Vote::Unspecified.into(),
            voting_power: 10_000_000,
        },
    );
    neuron_store
        .add_neuron(neuron)
        .expect("Could not add neuron");

    for neuron_index in num_followees..num_neurons {
        let neuron_id = neuron_ids[neuron_index as usize];
        let previous_neuron_indices = (neuron_index - num_half_followees - 1)..neuron_index;
        let followee_neuron_ids = previous_neuron_indices
            .map(|index| neuron_ids[index as usize])
            .chain(not_voting_neuron_ids.clone().into_iter())
            .collect::<Vec<_>>();

        let followees = hashmap! {topic.into() => Followees {followees: followee_neuron_ids}};
        let neuron = make_neuron(
            neuron_id.id,
            PrincipalId::new_user_test_id(neuron_id.id),
            10_000_000,
            followees,
        );

        ballots.insert(
            neuron_id.id,
            Ballot {
                vote: Vote::Unspecified.into(),
                voting_power: 10_000_000,
            },
        );
        neuron_store
            .add_neuron(neuron)
            .expect("Could not add neuron");
    }
    start_neuron_id.into()
}

fn cast_vote_cascade_helper(strategy: SetUpStrategy, topic: Topic) -> BenchResult {
    let mut ballots = HashMap::new();
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let mut neuron_store = NeuronStore::new(btreemap! {});
    let neuron_id = set_up(strategy, &mut rng, &mut neuron_store, &mut ballots, topic);

    let proposal_id = ProposalId { id: 1 };
    bench_fn(|| {
        Governance::cast_vote_and_cascade_follow(
            &mut ballots,
            &neuron_id.into(),
            Vote::Yes,
            topic,
            &mut neuron_store,
        );
        // let yes_votes = ballots
        //     .iter()
        //     .filter(|(id, ballot)| ballot.vote == Vote::Yes as i32)
        //     .count();
        // panic!("Number of cascaded votes: {}, {}", ballots.len(), yes_votes)
    })
}

// Only some fields are relevant for the functionality, but because we're benchmarking we need
// neurons that have some heft to them, so we populate fields that aren't strictly necessary for
// the functionality.
fn make_neuron(
    id: u64,
    controller: PrincipalId,
    cached_neuron_stake_e8s: u64,
    followees: HashMap<i32, Followees>,
) -> Neuron {
    let mut account = vec![0; 32];
    for (destination, data) in account.iter_mut().zip(id.to_le_bytes().iter().cycle()) {
        *destination = *data;
    }
    let subaccount = Subaccount::try_from(account.as_slice()).unwrap();

    let now = 123_456_789;
    let dissolve_state_and_age = DissolveStateAndAge::NotDissolving {
        dissolve_delay_seconds: MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
        aging_since_timestamp_seconds: now - MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
    };

    let hot_keys = (0..15).map(PrincipalId::new_user_test_id).collect();

    let followees = if followees.is_empty() {
        hashmap! {
            Topic::Unspecified as i32 => Followees {
                followees: (0..15).map(|id| NeuronIdProto { id }).collect(),
            },
        }
    } else {
        followees
    };

    let mut neuron = NeuronBuilder::new(
        NeuronIdProto { id },
        subaccount,
        controller,
        dissolve_state_and_age,
        now,
    )
    .with_hot_keys(hot_keys)
    .with_followees(followees)
    .with_cached_neuron_stake_e8s(cached_neuron_stake_e8s)
    .build();

    neuron.recent_ballots = (0..100)
        .map(|id| BallotInfo {
            proposal_id: Some(ProposalId { id }),
            vote: Vote::Yes as i32,
        })
        .collect();

    neuron
}

/// Initial before changes
/// ---------------------------------------------------
//
// Benchmark: cascading_vote_stable_neurons_with_heap_index (new)
//   total:
//     instructions: 2.91 B (new)
//     heap_increase: 1 pages (new)
//     stable_memory_increase: 0 pages (new)
//
// ---------------------------------------------------
//
// Benchmark: cascading_vote_stable_everything (new)
//   total:
//     instructions: 2.94 B (new)
//     heap_increase: 1 pages (new)
//     stable_memory_increase: 0 pages (new)
//
// ---------------------------------------------------
//
// Benchmark: cascading_vote_all_heap (new)
//   total:
//     instructions: 35.88 M (new)
//     heap_increase: 0 pages (new)
//     stable_memory_increase: 0 pages (new)
//
// ---------------------------------------------------
//
// Benchmark: cascading_vote_heap_neurons_stable_index (new)
//   total:
//     instructions: 35.88 M (new)
//     heap_increase: 0 pages (new)
//     stable_memory_increase: 0 pages (new)
//
// ---------------------------------------------------
//
// Benchmark: compute_ballots_for_new_proposal_with_stable_neurons (new)
//   total:
//     instructions: 1.56 M (new)
//     heap_increase: 0 pages (new)
//     stable_memory_increase: 0 pages (new)

// With NeuronStore.neuron_would_follow_ballots
//---------------------------------------------------
//
// Benchmark: cascading_vote_stable_neurons_with_heap_index (new)
//   total:
//     instructions: 2.05 B (new)
//     heap_increase: 1 pages (new)
//     stable_memory_increase: 0 pages (new)
//
// ---------------------------------------------------
//
// Benchmark: cascading_vote_stable_everything (new)
//   total:
//     instructions: 2.07 B (new)
//     heap_increase: 1 pages (new)
//     stable_memory_increase: 0 pages (new)
//
// ---------------------------------------------------
//
// Benchmark: cascading_vote_all_heap (new)
//   total:
//     instructions: 35.87 M (new)
//     heap_increase: 0 pages (new)
//     stable_memory_increase: 0 pages (new)
//
// ---------------------------------------------------
//
// Benchmark: cascading_vote_heap_neurons_stable_index (new)
//   total:
//     instructions: 35.87 M (new)
//     heap_increase: 0 pages (new)
//     stable_memory_increase: 0 pages (new)
//
// ---------------------------------------------------
//
// Benchmark: compute_ballots_for_new_proposal_with_stable_neurons (new)
//   total:
//     instructions: 1.56 M (new)
//     heap_increase: 0 pages (new)
//     stable_memory_increase: 0 pages (new)

#[bench(raw)]
fn cascading_vote_stable_neurons_with_heap_index() -> BenchResult {
    let _a = temporarily_enable_active_neurons_in_stable_memory();
    let _b = temporarily_disable_stable_memory_following_index();

    cast_vote_cascade_helper(
        SetUpStrategy::Chain {
            num_neurons: 151,
            num_followees: 15,
        },
        Topic::NetworkEconomics,
    )
}

#[bench(raw)]
fn cascading_vote_stable_everything() -> BenchResult {
    let _a = temporarily_enable_active_neurons_in_stable_memory();
    let _b = temporarily_enable_stable_memory_following_index();

    cast_vote_cascade_helper(
        SetUpStrategy::Chain {
            num_neurons: 151,
            num_followees: 15,
        },
        Topic::NetworkEconomics,
    )
}

#[bench(raw)]
fn cascading_vote_all_heap() -> BenchResult {
    let _a = temporarily_disable_active_neurons_in_stable_memory();
    let _b = temporarily_disable_stable_memory_following_index();

    cast_vote_cascade_helper(
        SetUpStrategy::Chain {
            num_neurons: 151,
            num_followees: 15,
        },
        Topic::NetworkEconomics,
    )
}

#[bench(raw)]
fn cascading_vote_heap_neurons_stable_index() -> BenchResult {
    let _a = temporarily_disable_active_neurons_in_stable_memory();
    let _b = temporarily_enable_stable_memory_following_index();

    cast_vote_cascade_helper(
        SetUpStrategy::Chain {
            num_neurons: 151,
            num_followees: 15,
        },
        Topic::NetworkEconomics,
    )
}

#[bench(raw)]
fn single_vote_all_stable() -> BenchResult {
    let _a = temporarily_enable_active_neurons_in_stable_memory();
    let _b = temporarily_enable_stable_memory_following_index();

    cast_vote_cascade_helper(
        SetUpStrategy::SingleVote { num_neurons: 1 },
        Topic::NetworkEconomics,
    )
}

#[bench(raw)]
fn centralized_following_all_stable() -> BenchResult {
    let _a = temporarily_enable_active_neurons_in_stable_memory();
    let _b = temporarily_enable_stable_memory_following_index();

    cast_vote_cascade_helper(
        SetUpStrategy::Centralized { num_neurons: 151 },
        Topic::NetworkEconomics,
    )
}

/// Benchmark the `cascading_vote` function with stable neurons and a heap index.
/// Before we do the migration of the ballots function to be more efficient:
/// Benchmark: compute_ballots_for_new_proposal_with_stable_neurons (new)
//   total:
//     instructions: 78.49 M (new)
//     heap_increase: 0 pages (new)
//     stable_memory_increase: 0 pages (new)
//
// After we migrate to be more efficient:
// Benchmark: compute_ballots_for_new_proposal_with_stable_neurons (new)
//   total:
//     instructions: 1.50 M (new)
//     heap_increase: 0 pages (new)
//     stable_memory_increase: 0 pages (new)
//
#[bench(raw)]
fn compute_ballots_for_new_proposal_with_stable_neurons() -> BenchResult {
    let _f = temporarily_enable_active_neurons_in_stable_memory();
    let neurons = (0..100)
        .map(|id| {
            (
                id,
                make_neuron(
                    id,
                    PrincipalId::new_user_test_id(id),
                    1_000_000_000,
                    hashmap! {}, // get the default followees
                )
                .into(),
            )
        })
        .collect::<BTreeMap<u64, NeuronProto>>();

    let governance_proto = GovernanceProto {
        neurons,
        ..GovernanceProto::default()
    };

    let mut governance = Governance::new(
        governance_proto,
        Box::new(MockEnvironment::new(Default::default(), 0)),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );

    bench_fn(|| {
        governance
            .compute_ballots_for_new_proposal(
                &Action::RegisterKnownNeuron(KnownNeuron {
                    id: None,
                    known_neuron_data: None,
                }),
                &NeuronIdProto { id: 1 },
                123_456_789,
            )
            .expect("Failed!");
    })
}
