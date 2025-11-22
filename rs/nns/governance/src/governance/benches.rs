use crate::benches_util::check_projected_instructions;
use crate::governance::REWARD_DISTRIBUTION_PERIOD_SECONDS;
use crate::pb::v1::{Motion, VotingPowerEconomics};
use crate::test_utils::MockRandomness;
use crate::{
    governance::{
        Governance, MAX_NUMBER_OF_NEURONS,
        test_data::CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING,
    },
    neuron::{DissolveStateAndAge, Neuron, NeuronBuilder},
    neuron_store::NeuronStore,
    pb::v1::{
        Ballot, BallotInfo, CreateServiceNervousSystem, ExecuteNnsFunction, Followees, InstallCode,
        NnsFunction, Proposal, ProposalData, Topic, Vote, install_code::CanisterInstallMode,
        proposal::Action,
    },
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};
use canbench_rs::{BenchResult, bench, bench_fn};
use futures::FutureExt;
use ic_base_types::PrincipalId;
use ic_crypto_sha2::Sha256;
use ic_ledger_core::Tokens;
use ic_nervous_system_proto::pb::v1::Image;
use ic_nns_common::{
    pb::v1::{NeuronId as NeuronIdProto, ProposalId},
    types::NeuronId,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api as api;
use icp_ledger::Subaccount;
use maplit::{btreemap, hashmap};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::sync::Arc;

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
    governance: &mut Governance,
    topic: Topic,
) -> NeuronId {
    let neuron_store = &mut governance.neuron_store;
    governance.heap_data.proposals.insert(
        1,
        ProposalData {
            id: Some(ProposalId { id: 1 }),
            proposal: Some(Proposal {
                summary: "Summary".to_string(),
                url: "".to_string(),
                title: Some("Title".to_string()),
                action: Some(Action::Motion(Motion {
                    motion_text: "Motion".to_string(),
                })),
                self_describing_action: None,
            }),
            ..Default::default()
        },
    );
    let ballots = &mut governance.heap_data.proposals.get_mut(&1).unwrap().ballots;

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

    let neuron = make_neuron(
        start_neuron_id.0,
        PrincipalId::new_user_test_id(start_neuron_id.0),
        10_000_000,
        hashmap! {topic.into() => Followees {followees: vec![central_neuron_id.into()]}},
    );
    ballots.insert(
        start_neuron_id.0,
        Ballot {
            vote: Vote::Unspecified.into(),
            voting_power: 10_000_000,
        },
    );
    neuron_store
        .add_neuron(neuron)
        .expect("Could not add neuron");
    let neuron = make_neuron(
        central_neuron_id.0,
        PrincipalId::new_user_test_id(central_neuron_id.0),
        10_000_000,
        hashmap! {topic.into() => Followees {followees: vec![]}},
    );
    ballots.insert(
        central_neuron_id.0,
        Ballot {
            vote: Vote::Unspecified.into(),
            voting_power: 10_000_000,
        },
    );
    neuron_store
        .add_neuron(neuron)
        .expect("Could not add neuron");

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
    let mut rng = ChaCha20Rng::seed_from_u64(0);

    let mut governance = Governance::new(
        Default::default(),
        Arc::new(MockEnvironment::new(Default::default(), 0)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    let neuron_id = set_up(strategy, &mut rng, &mut governance, topic);

    let proposal_id = ProposalId { id: 1 };
    bench_fn(|| {
        governance
            .cast_vote_and_cascade_follow(proposal_id, neuron_id.into(), Vote::Yes, topic)
            .now_or_never()
            .unwrap();
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
    let dissolve_delay_seconds =
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
    let aging_since_timestamp_seconds = now - dissolve_delay_seconds;

    let dissolve_state_and_age = DissolveStateAndAge::NotDissolving {
        dissolve_delay_seconds,
        aging_since_timestamp_seconds,
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
    neuron.recent_ballots_next_entry_index = Some(0);

    neuron
}

#[bench(raw)]
fn cascading_vote_stable_everything() -> BenchResult {
    cast_vote_cascade_helper(
        SetUpStrategy::Chain {
            num_neurons: 151,
            num_followees: 15,
        },
        Topic::NetworkEconomics,
    )
}

#[bench(raw)]
fn single_vote_all() -> BenchResult {
    cast_vote_cascade_helper(
        SetUpStrategy::SingleVote { num_neurons: 151 },
        Topic::NetworkEconomics,
    )
}

#[bench(raw)]
fn centralized_following_all() -> BenchResult {
    cast_vote_cascade_helper(
        SetUpStrategy::Centralized { num_neurons: 151 },
        Topic::NetworkEconomics,
    )
}

#[bench(raw)]
fn compute_ballots_for_new_proposal_with_stable_neurons() -> BenchResult {
    let now_seconds = 1732817584;
    let num_neurons = 100;

    let mut governance = Governance::new(
        Default::default(),
        Arc::new(MockEnvironment::new(vec![], now_seconds)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    for id in 1..=num_neurons {
        governance
            .add_neuron(
                id,
                make_neuron(
                    id,
                    PrincipalId::new_user_test_id(id),
                    1_000_000_000,
                    hashmap! {}, // get the default followees
                ),
            )
            .unwrap();
    }

    let bench_result = bench_fn(|| {
        governance
            .compute_ballots_for_standard_proposal(123_456_789)
            .expect("Failed!");
    });

    check_projected_instructions(
        bench_result,
        num_neurons,
        MAX_NUMBER_OF_NEURONS as u64,
        25_000_000_000,
    )
}

#[bench(raw)]
fn distribute_rewards_with_stable_neurons() -> BenchResult {
    let now_seconds = 1732817584;
    let neurons = (1..=100)
        .map(|id| {
            make_neuron(
                id,
                PrincipalId::new_user_test_id(id),
                1_000_000_000,
                hashmap! {}, // get the default followees
            )
        })
        .collect::<Vec<_>>();

    let ballots = neurons
        .iter()
        .map(|n| {
            (
                n.id().id,
                api::Ballot {
                    vote: Vote::Yes.into(),
                    voting_power: n.cached_neuron_stake_e8s,
                },
            )
        })
        .collect();
    let governance_api = api::Governance {
        genesis_timestamp_seconds: now_seconds - REWARD_DISTRIBUTION_PERIOD_SECONDS * 101,
        latest_reward_event: Some(api::RewardEvent {
            day_after_genesis: 100,
            actual_timestamp_seconds: now_seconds - REWARD_DISTRIBUTION_PERIOD_SECONDS - 1,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
            total_available_e8s_equivalent: 0,
            latest_round_available_e8s_equivalent: None,
            rounds_since_last_distribution: Some(0),
        }),
        proposals: btreemap! {
            1 => api::ProposalData {
                id: Some(ProposalId { id: 1 }),
                wait_for_quiet_state: Some(api::WaitForQuietState {current_deadline_timestamp_seconds: now_seconds - 200}),
                decided_timestamp_seconds: now_seconds - 100,
                executed_timestamp_seconds: now_seconds - 100,
                ballots,
                proposal: Some(api::Proposal {
                    summary: "Summary".to_string(),
                    url: "".to_string(),
                    title: Some("Title".to_string()),
                    action: Some(api::proposal::Action::Motion(api::Motion {
                        motion_text: "Motion".to_string(),
                    })),
                    self_describing_action: None,
                }),
                ..Default::default()
            }
        },
        ..Default::default()
    };

    let mut governance = Governance::new(
        governance_api,
        Arc::new(MockEnvironment::new(vec![], now_seconds)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    for neuron in neurons {
        governance.add_neuron(neuron.id().id, neuron).unwrap();
    }

    bench_fn(|| {
        governance.distribute_voting_rewards_to_neurons(Tokens::new(10_000_000, 0).unwrap())
    })
}

#[bench(raw)]
fn list_neurons() -> BenchResult {
    let mut governance = Governance::new(
        Default::default(),
        Arc::new(MockEnvironment::new(Default::default(), 0)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    for id in 1..=100 {
        let mut neuron = make_neuron(
            id,
            PrincipalId::new_user_test_id(id),
            1_000_000_000,
            hashmap! {}, // get the default followees
        );
        neuron.hot_keys = vec![PrincipalId::new_user_test_id(1)];
        governance.add_neuron(id, neuron).unwrap();
    }

    let request = api::ListNeurons {
        neuron_ids: vec![],
        include_neurons_readable_by_caller: true,
        include_empty_neurons_readable_by_caller: Some(false),
        include_public_neurons_in_full_neurons: None,
        page_number: None,
        page_size: None,
        neuron_subaccounts: None,
    };

    bench_fn(|| {
        governance.list_neurons(&request, PrincipalId::new_user_test_id(1));
    })
}

#[bench(raw)]
fn list_neurons_by_subaccount() -> BenchResult {
    let num_neurons = 100;
    let neurons = (1..=num_neurons)
        .map(|id| {
            let mut neuron = make_neuron(
                id,
                PrincipalId::new_user_test_id(id),
                1_000_000_000,
                hashmap! {}, // get the default followees
            );
            neuron.hot_keys = vec![PrincipalId::new_user_test_id(1)];
            neuron
        })
        .collect::<Vec<_>>();

    let subaccounts = neurons
        .iter()
        .map(|neuron| api::list_neurons::NeuronSubaccount {
            subaccount: neuron.subaccount().to_vec(),
        })
        .collect();

    let mut governance = Governance::new(
        Default::default(),
        Arc::new(MockEnvironment::new(Default::default(), 0)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    for neuron in neurons {
        governance.add_neuron(neuron.id().id, neuron).unwrap();
    }

    let request = api::ListNeurons {
        neuron_ids: vec![],
        include_neurons_readable_by_caller: false,
        include_empty_neurons_readable_by_caller: Some(false),
        include_public_neurons_in_full_neurons: None,
        page_number: None,
        page_size: None,
        neuron_subaccounts: Some(subaccounts),
    };

    bench_fn(|| {
        governance.list_neurons(&request, PrincipalId::new_user_test_id(1));
    })
}

fn create_service_nervous_system_action_with_large_payload() -> CreateServiceNervousSystem {
    let mut action = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone();

    let large_image = Some(Image {
        base64_encoding: Some(format!("data:image/png;base64,{}", "A".repeat(1 << 18))), // 256 KiB
    });

    action.logo = large_image.clone();
    action.ledger_parameters.as_mut().unwrap().token_logo = large_image;

    action
}

fn list_proposals_benchmark() -> BenchResult {
    let mut governance = Governance::new(
        api::Governance {
            economics: Some(api::NetworkEconomics::with_default_values()),
            ..Default::default()
        },
        Arc::new(MockEnvironment::new(Default::default(), 0)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    for id in 1..=100 {
        governance
            .add_neuron(
                id,
                make_neuron(
                    id,
                    PrincipalId::new_user_test_id(id),
                    1_000_000_000,
                    hashmap! {}, // get the default followees
                ),
            )
            .unwrap();
    }

    let request = api::ListProposalInfoRequest {
        limit: 100,
        omit_large_fields: Some(true),
        ..Default::default()
    };

    let proposal_actions = vec![
        Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::HardResetNnsRootToVersion as i32,
            payload: vec![0u8; 1 << 20], // 1 MiB
        }),
        Action::InstallCode(InstallCode {
            canister_id: Some(GOVERNANCE_CANISTER_ID.get()),
            wasm_module: Some(vec![0u8; 1 << 20]), // 1 MiB
            arg: Some(vec![0u8; 1 << 20]),         // 1 MiB
            install_mode: Some(CanisterInstallMode::Install as i32),
            wasm_module_hash: Some(Sha256::hash(&vec![0u8; 1 << 20]).to_vec()),
            arg_hash: Some(Sha256::hash(&vec![0u8; 1 << 20]).to_vec()),
            skip_stopping_before_installing: None,
        }),
        Action::CreateServiceNervousSystem(
            create_service_nervous_system_action_with_large_payload(),
        ),
    ];

    for proposal_action in proposal_actions {
        governance
            .make_proposal(
                &NeuronIdProto { id: 1 },
                &PrincipalId::new_user_test_id(1),
                &Proposal {
                    summary: "Summary".to_string(),
                    url: "".to_string(),
                    title: Some("Title".to_string()),
                    action: Some(proposal_action),
                    self_describing_action: None,
                },
            )
            .now_or_never()
            .expect("Failed to await for making proposal")
            .expect("Failed to make proposal");
    }

    bench_fn(|| {
        let _ = governance.list_proposals(&PrincipalId::new_anonymous(), request);
    })
}

#[bench(raw)]
fn list_proposals() -> BenchResult {
    list_proposals_benchmark()
}

/// Used for benchmarking compilation/instrumentation/execution changes in the
/// embedders crate.
#[unsafe(export_name = "canister_update update_empty")]
fn update_empty() {
    ic_cdk::api::msg_reply([]);
}

/// Used for benchmarking compilation/instrumentation/execution changes in the
/// embedders crate.
#[unsafe(export_name = "canister_query go")]
fn go() {
    let _ = list_neurons();
    ic_cdk::api::msg_reply([]);
}
