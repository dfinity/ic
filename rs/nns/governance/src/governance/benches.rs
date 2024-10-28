use crate::{
    governance::{
        Governance, MAX_FOLLOWEES_PER_TOPIC, MAX_NEURON_RECENT_BALLOTS,
        MAX_NUM_HOT_KEYS_PER_NEURON, MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
    },
    neuron::{DissolveStateAndAge, Neuron, NeuronBuilder},
    now_seconds,
    pb::v1::{
        neuron::Followees, proposal::Action, BallotInfo, Governance as GovernanceProto,
        KnownNeuron, Neuron as NeuronProto, Topic, Vote,
    },
    temporarily_disable_active_neurons_in_stable_memory,
    temporarily_enable_active_neurons_in_stable_memory,
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};
use canbench_rs::{bench, bench_fn, BenchResult};
use ic_base_types::PrincipalId;
use ic_nervous_system_common::E8;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use icp_ledger::Subaccount;
use maplit::{btreemap, hashmap};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::collections::BTreeMap;

// Only some fields are relevant for the functionality, but because we're benchmarking we need
// neurons that have some heft to them, so we populate fields that aren't strictly necessary for
// the functionality.
fn neuron(id: u64, controller: PrincipalId, cached_neuron_stake_e8s: u64) -> Neuron {
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

    let hot_keys = (0..15)
        .map(|id| PrincipalId::new_user_test_id(id))
        .collect();
    let followees = hashmap! {
        Topic::Unspecified as i32 => Followees {
            followees: (0..15).map(|id| NeuronId { id }).collect(),
        },
    };

    let mut neuron = NeuronBuilder::new(
        NeuronId { id },
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
//
// #[bench(raw)]
// fn cascading_vote_stable_neurons_with_heap_index() -> BenchResult {todo!()}
//
// #[bench(raw)]
// fn cascading_vote_stable_everything() -> BenchResult {todo!()}

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
                neuron(id, PrincipalId::new_user_test_id(id), 1_000_000_000).into(),
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
                &NeuronId { id: 1 },
                123_456_789,
            )
            .expect("Failed!");
    })
}
