//! Benchmark to measure the scalability of `Governance` in case of
//! many neurons, dense followee relationships, and many proposals.
//!
//! Data from February 19, 2021: time is for making a proposal, make
//! all neurons vote through followers and execute the proposal (of
//! type 'Motion', so no work to actually execute).
//!
//! The number of neurons is 20k or 200k. See below for information on
//! what 'linear' and 'tree' following means.
//!
//! linear 20k  time:   32.160 ms 32.249 ms 32.355 ms
//! tree 20k    time:   20.754 ms 20.973 ms 21.197 ms
//! linear 200k time:   336.56 ms 340.84 ms 343.90 ms
//! tree 200k   time:   250.08 ms 254.14 ms 256.39 ms

use async_trait::async_trait;
use criterion::{criterion_group, criterion_main, Criterion};
use futures::future::FutureExt;
use std::convert::TryFrom;

use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::governance::{Environment, Governance, HeapGrowthPotential, Ledger};

use ic_nns_governance::pb::v1::neuron;
use ic_nns_governance::pb::v1::proposal;
use ic_nns_governance::pb::v1::{
    ExecuteNnsFunction, Governance as GovernanceProto, GovernanceError, Motion, NetworkEconomics,
    Neuron, Proposal, Topic,
};
use ledger_canister::{AccountIdentifier, Subaccount, Tokens};

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = linear_20k, tree_20k, linear_200k, tree_200k
}

criterion_main!(benches);

/// Mock of the required interface of `Governance`.
struct MockEnvironment {
    secs: u64,
}

impl Environment for MockEnvironment {
    fn now(&self) -> u64 {
        self.secs
    }

    fn random_u64(&mut self) -> u64 {
        todo!()
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        todo!()
    }

    fn execute_nns_function(
        &self,
        _proposal_id: u64,
        _update: &ExecuteNnsFunction,
    ) -> Result<(), GovernanceError> {
        panic!("unexpected call")
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        HeapGrowthPotential::NoIssue
    }
}

struct MockLedger {}

#[async_trait]
impl Ledger for MockLedger {
    async fn transfer_funds(
        &self,
        _amount_e8s: u64,
        _fee_e8s: u64,
        _from_subaccount: Option<Subaccount>,
        _to: AccountIdentifier,
        _memo: u64,
    ) -> Result<u64, GovernanceError> {
        unimplemented!()
    }

    async fn total_supply(&self) -> Result<Tokens, GovernanceError> {
        unimplemented!()
    }

    async fn account_balance(
        &self,
        _account: AccountIdentifier,
    ) -> Result<Tokens, GovernanceError> {
        unimplemented!()
    }
}

// Make a proposal for neuron 0 and call proccess proposals. The
// following graph is set up to cascade following, so the proposal
// will be accepted when submitted and executed in the call to process
// proposals.
fn make_and_process_proposal(gov: &mut Governance) {
    gov.make_proposal(
        &NeuronId { id: 0 },
        // Must match neuron 1's serialized_id.
        &PrincipalId::try_from(b"SID0".to_vec()).unwrap(),
        &Proposal {
            title: Some("Celebrate Good Times".to_string()),
            summary: "test".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "dummy text".to_string(),
            })),
            ..Default::default()
        },
    )
    .unwrap();
    gov.run_periodic_tasks().now_or_never();
}

fn linear_20k(c: &mut Criterion) {
    let secs = 1;
    let mut gov = Governance::new(
        fixture_for_scale(20_000, true),
        Box::new(MockEnvironment { secs }),
        Box::new(MockLedger {}),
    );
    c.bench_function("linear 20k", |b| {
        b.iter(|| make_and_process_proposal(&mut gov))
    });
}

fn tree_20k(c: &mut Criterion) {
    let secs = 1;
    let mut gov = Governance::new(
        fixture_for_scale(20_000, false),
        Box::new(MockEnvironment { secs }),
        Box::new(MockLedger {}),
    );
    c.bench_function("tree 20k", |b| {
        b.iter(|| make_and_process_proposal(&mut gov))
    });
}

fn linear_200k(c: &mut Criterion) {
    let secs = 1;
    let mut gov = Governance::new(
        fixture_for_scale(200_000, true),
        Box::new(MockEnvironment { secs }),
        Box::new(MockLedger {}),
    );
    c.bench_function("linear 200k", |b| {
        b.iter(|| make_and_process_proposal(&mut gov))
    });
}

fn tree_200k(c: &mut Criterion) {
    let secs = 1;
    let mut gov = Governance::new(
        fixture_for_scale(200_000, false),
        Box::new(MockEnvironment { secs }),
        Box::new(MockLedger {}),
    );
    c.bench_function("tree 200k", |b| {
        b.iter(|| make_and_process_proposal(&mut gov))
    });
}

// Create a 'GovernanceProto' with 'num_neurons' neurons and a
// following graph such that all neurons will vote according to the
// vote of neuron 0.
//
// If linear_following:
// - Neuron i+3 follows neurons i, i+1, and i+2.
// - Neuron 2 follows 0, 1
// - Neuron 1 follows 0
// - So, when neuron 0 votes, it should cascade to accept.
//
// Otherwise:
// - Each neuron i follows "previous power of two".
// - So, when neuron 0 votes, it should cascade to accept in log steps.
fn fixture_for_scale(num_neurons: u32, linear_following: bool) -> GovernanceProto {
    let mut gov = GovernanceProto {
        economics: Some(NetworkEconomics::with_default_values()),
        ..Default::default()
    };
    for i in 0..(num_neurons as u64) {
        let mut followees = Vec::new();
        if linear_following {
            match i {
                0 => (),
                1 => followees.push(NeuronId { id: 0 }),
                2 => {
                    followees.push(NeuronId { id: 0 });
                    followees.push(NeuronId { id: 1 });
                }
                _ => {
                    followees.push(NeuronId { id: i - 1 });
                    followees.push(NeuronId { id: i - 2 });
                    followees.push(NeuronId { id: i - 3 })
                }
            }
        } else {
            let prev_pow = i.next_power_of_two() / 2;
            if prev_pow < i {
                followees.push(NeuronId { id: prev_pow });
            }
        }
        // Use i as neuron ID.
        let n = Neuron {
            id: Some(NeuronId { id: i }),
            // 10 + i ICP
            cached_neuron_stake_e8s: (10 + i) * 100_000_000,
            // One year
            dissolve_state: Some(neuron::DissolveState::DissolveDelaySeconds(31557600)),
            //
            controller: Some(
                PrincipalId::try_from(format!("SID{}", i).as_bytes().to_vec()).unwrap(),
            ),
            //
            followees: [(Topic::Unspecified as i32, neuron::Followees { followees })]
                .to_vec()
                .into_iter()
                .collect(),
            ..Default::default()
        };
        gov.neurons.insert(i, n);
    }
    gov
}
