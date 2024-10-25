use crate::{
    governance::{Governance, MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS},
    neuron::{dissolve_state_and_age::DissolveStateAndAge, Neuron, NeuronBuilder},
    pb::v1::{proposal::Action, Governance as GovernanceProto, KnownNeuron, Neuron as NeuronProto},
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};
use canbench_rs::{bench, bench_fn, BenchResult};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use icp_ledger::Subaccount;
use maplit::btreemap;
use std::collections::BTreeMap;

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

    NeuronBuilder::new(
        NeuronId { id },
        subaccount,
        controller,
        dissolve_state_and_age,
        now,
    )
    .with_cached_neuron_stake_e8s(cached_neuron_stake_e8s)
    .build()
}

#[bench(raw)]
fn cascading_vote_stable_neurons_with_heap_index() {}

#[bench(raw)]
fn cascading_vote_stable_everything() {}

#[bench(raw)]
fn compute_ballots_for_new_proposal_with_stable_neurons() -> BenchResult {
    let neurons = (0..100)
        .map(|id| {
            (
                id,
                neuron(1, PrincipalId::new_user_test_id(1), 1_000_000_000).into(),
            )
        })
        .collect::<BTreeMap<u64, NeuronProto>>();

    let governance_proto = GovernanceProto {
        neurons: btreemap! {},
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
