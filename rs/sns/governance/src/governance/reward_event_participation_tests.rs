use super::{test_helpers::*, *};
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_sns_governance_api::pb::v1 as pb_api;
use maplit::{btreemap, btreeset};
use prost::Message;

use crate::pb::v1::{Motion, Uint128, VotingRewardsParameters};
use crate::types::test_helpers::NativeEnvironment;

fn neuron_id(id: u8) -> NeuronId {
    NeuronId { id: vec![id; 32] }
}

fn neuron(id: &NeuronId) -> Neuron {
    Neuron {
        id: Some(id.clone()),
        permissions: A_NEURON.permissions.clone(),
        cached_neuron_stake_e8s: 100,
        aging_since_timestamp_seconds: 1,
        dissolve_state: Some(DissolveState::DissolveDelaySeconds(ONE_DAY_SECONDS)),
        voting_power_percentage_multiplier: 100,
        ..Default::default()
    }
}

fn proposal_data(id: u64, ballots: BTreeMap<String, Ballot>) -> ProposalData {
    ProposalData {
        id: Some(ProposalId { id }),
        proposal: Some(Proposal {
            action: Some(Action::Motion(Motion::default())),
            ..Default::default()
        }),
        ballots,
        wait_for_quiet_state: Some(WaitForQuietState::default()),
        is_eligible_for_rewards: true,
        ..Default::default()
    }
}

fn governance_with_neurons(neurons: Vec<Neuron>) -> (Governance, u64) {
    let round_duration_seconds = ONE_DAY_SECONDS;
    let mut environment = NativeEnvironment::new(Some(CanisterId::from_u64(1)));
    environment.now = 11 * round_duration_seconds;
    let mut proto = basic_governance_proto();
    proto.neurons = neurons
        .into_iter()
        .map(|neuron| (neuron.id.as_ref().unwrap().to_string(), neuron))
        .collect();
    proto.parameters.as_mut().unwrap().voting_rewards_parameters = Some(VotingRewardsParameters {
        round_duration_seconds: Some(round_duration_seconds),
        reward_rate_transition_duration_seconds: Some(1),
        initial_reward_rate_basis_points: Some(0),
        final_reward_rate_basis_points: Some(0),
    });

    let mut governance = Governance::new(
        proto.try_into().unwrap(),
        Box::new(environment),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );
    governance.env.set_time_warp(TimeWarp {
        delta_s: i64::try_from(round_duration_seconds).unwrap(),
    });

    (governance, round_duration_seconds)
}

fn reward_shares(neuron: &Neuron) -> Option<u128> {
    neuron
        .latest_reward_event_participation
        .as_ref()
        .and_then(|participation| participation.reward_shares)
        .map(u128::from)
}

fn cascaded_ballots(
    proposal_id: u64,
    neurons: &BTreeMap<String, Neuron>,
    voting_powers: &BTreeMap<NeuronId, u64>,
    alice_id: &NeuronId,
    bob_id: &NeuronId,
    follower_id: &NeuronId,
    alice_vote: Vote,
    bob_vote: Vote,
) -> BTreeMap<String, Ballot> {
    let motion_function_id = u64::from(&Action::Motion(Motion::default()));
    let function_followee_index = btreemap! {
        motion_function_id => btreemap! {
            alice_id.to_string() => btreeset! { follower_id.clone() },
        },
    };
    let mut ballots = voting_powers
        .iter()
        .map(|(neuron_id, voting_power)| {
            (
                neuron_id.to_string(),
                Ballot {
                    vote: Vote::Unspecified as i32,
                    voting_power: *voting_power,
                    cast_timestamp_seconds: 1,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    Governance::cast_vote_and_cascade_follow(
        &ProposalId { id: proposal_id },
        alice_id,
        alice_vote,
        motion_function_id,
        &function_followee_index,
        &btreemap! {},
        neurons,
        1,
        &mut ballots,
        Topic::Governance,
    );
    Governance::cast_vote_and_cascade_follow(
        &ProposalId { id: proposal_id },
        bob_id,
        bob_vote,
        motion_function_id,
        &function_followee_index,
        &btreemap! {},
        neurons,
        1,
        &mut ballots,
        Topic::Governance,
    );

    ballots
}

#[test]
fn test_records_exact_canonical_reward_shares_when_native_rewards_are_zero() {
    // Step 1: Prepare neurons and two proposals. The follower's ballots are populated through
    // the production cascade implementation.
    let alice_id = neuron_id(1);
    let bob_id = neuron_id(2);
    let carol_id = neuron_id(3);
    let follower_id = neuron_id(4);
    let mut follower = neuron(&follower_id);
    let motion_function_id = u64::from(&Action::Motion(Motion::default()));
    follower.followees = btreemap! {
        motion_function_id => Followees { followees: vec![alice_id.clone()] },
    };
    let (mut governance, _) = governance_with_neurons(vec![
        neuron(&alice_id),
        neuron(&bob_id),
        neuron(&carol_id),
        follower,
    ]);
    let proposal_1_ballots = cascaded_ballots(
        1,
        &governance.proto.neurons,
        &btreemap! {
            alice_id.clone() => 10,
            bob_id.clone() => 20,
            carol_id.clone() => 30,
            follower_id.clone() => 40,
        },
        &alice_id,
        &bob_id,
        &follower_id,
        Vote::Yes,
        Vote::No,
    );
    let proposal_2_ballots = cascaded_ballots(
        2,
        &governance.proto.neurons,
        &btreemap! {
            alice_id.clone() => 15,
            bob_id.clone() => 25,
            carol_id.clone() => 35,
            follower_id.clone() => 45,
        },
        &alice_id,
        &bob_id,
        &follower_id,
        Vote::No,
        Vote::Yes,
    );
    governance
        .proto
        .proposals
        .insert(1, proposal_data(1, proposal_1_ballots));
    governance
        .proto
        .proposals
        .insert(2, proposal_data(2, proposal_2_ballots));

    // Step 2: Distribute the zero-value native reward purse.
    governance.distribute_rewards(Tokens::from_e8s(1_000_000));

    // Step 3: Verify exact participation, unchanged maturity, settlement, and ballot clearing.
    let reward_event = governance.proto.latest_reward_event.as_ref().unwrap();
    assert_eq!(reward_event.distributed_e8s_equivalent, 0);
    assert_eq!(
        reward_event.settled_proposals,
        vec![ProposalId { id: 1 }, ProposalId { id: 2 }]
    );
    let event_timestamp_seconds = reward_event.end_timestamp_seconds.unwrap();

    for (neuron_id, expected_shares) in [
        (&alice_id, Some(25)),
        (&bob_id, Some(45)),
        (&carol_id, None),
        (&follower_id, Some(85)),
    ] {
        let neuron = governance
            .proto
            .neurons
            .get(&neuron_id.to_string())
            .unwrap();
        assert_eq!(reward_shares(neuron), expected_shares);
        assert_eq!(neuron.maturity_e8s_equivalent, 0);
        assert_eq!(neuron.staked_maturity_e8s_equivalent.unwrap_or_default(), 0);
        if expected_shares.is_some() {
            assert_eq!(
                neuron
                    .latest_reward_event_participation
                    .as_ref()
                    .unwrap()
                    .reward_event_end_timestamp_seconds,
                event_timestamp_seconds,
            );
        }
    }
    assert!(
        governance
            .proto
            .proposals
            .get(&1)
            .unwrap()
            .ballots
            .is_empty()
    );
    assert!(
        governance
            .proto
            .proposals
            .get(&2)
            .unwrap()
            .ballots
            .is_empty()
    );
}

#[test]
fn test_replaces_only_positive_participants_and_retains_older_event_tags() {
    // Step 1: Prepare two neurons and an event in which only Alice participates.
    let alice_id = neuron_id(1);
    let bob_id = neuron_id(2);
    let (mut governance, round_duration_seconds) =
        governance_with_neurons(vec![neuron(&alice_id), neuron(&bob_id)]);
    governance.proto.proposals.insert(
        1,
        proposal_data(
            1,
            btreemap! {
                alice_id.to_string() => Ballot { vote: Vote::Yes as i32, voting_power: 10, ..Default::default() },
                bob_id.to_string() => Ballot { vote: Vote::Unspecified as i32, voting_power: 20, ..Default::default() },
            },
        ),
    );
    governance.distribute_rewards(Tokens::from_e8s(0));
    let event_1_timestamp_seconds = governance
        .latest_reward_event()
        .end_timestamp_seconds
        .unwrap();

    // Step 2: Advance one event and settle a proposal in which only Bob participates.
    governance.env.set_time_warp(TimeWarp {
        delta_s: i64::try_from(round_duration_seconds).unwrap(),
    });
    governance.proto.proposals.insert(
        2,
        proposal_data(
            2,
            btreemap! {
                alice_id.to_string() => Ballot { vote: Vote::Unspecified as i32, voting_power: 30, ..Default::default() },
                bob_id.to_string() => Ballot { vote: Vote::No as i32, voting_power: 40, ..Default::default() },
            },
        ),
    );
    governance.distribute_rewards(Tokens::from_e8s(0));

    // Step 3: Alice retains event 1; Bob is tagged with event 2.
    let event_2_timestamp_seconds = governance
        .latest_reward_event()
        .end_timestamp_seconds
        .unwrap();
    assert_ne!(event_1_timestamp_seconds, event_2_timestamp_seconds);
    let alice = governance.proto.neurons.get(&alice_id.to_string()).unwrap();
    let bob = governance.proto.neurons.get(&bob_id.to_string()).unwrap();
    assert_eq!(reward_shares(alice), Some(10));
    assert_eq!(
        alice
            .latest_reward_event_participation
            .as_ref()
            .unwrap()
            .reward_event_end_timestamp_seconds,
        event_1_timestamp_seconds,
    );
    assert_eq!(reward_shares(bob), Some(40));
    assert_eq!(
        bob.latest_reward_event_participation
            .as_ref()
            .unwrap()
            .reward_event_end_timestamp_seconds,
        event_2_timestamp_seconds,
    );
}

#[test]
fn test_zero_eligible_shares_and_no_proposals_retain_older_participation() {
    // Step 1: Prepare an older participation value and an all-Unspecified proposal.
    let alice_id = neuron_id(1);
    let mut alice = neuron(&alice_id);
    let old_participation = RewardEventParticipation {
        reward_event_end_timestamp_seconds: 123,
        reward_shares: Some(Uint128::from(99_u128)),
    };
    alice.latest_reward_event_participation = Some(old_participation);
    let (mut governance, round_duration_seconds) = governance_with_neurons(vec![alice]);
    governance.proto.proposals.insert(
        1,
        proposal_data(
            1,
            btreemap! {
                alice_id.to_string() => Ballot { vote: Vote::Unspecified as i32, voting_power: 10, ..Default::default() },
            },
        ),
    );

    // Step 2: Settle the no-eligible-vote event, then create an event with no proposals.
    governance.distribute_rewards(Tokens::from_e8s(0));
    assert_eq!(
        governance.latest_reward_event().settled_proposals,
        vec![ProposalId { id: 1 }]
    );
    let unspecified_event_timestamp_seconds = governance
        .latest_reward_event()
        .end_timestamp_seconds
        .unwrap();
    assert!(
        governance
            .proto
            .proposals
            .get(&1)
            .unwrap()
            .ballots
            .is_empty()
    );
    assert_eq!(
        governance
            .proto
            .neurons
            .get(&alice_id.to_string())
            .unwrap()
            .latest_reward_event_participation,
        Some(old_participation),
    );
    governance.env.set_time_warp(TimeWarp {
        delta_s: i64::try_from(round_duration_seconds).unwrap(),
    });
    governance.distribute_rewards(Tokens::from_e8s(0));

    // Step 3: Both events retain the older value, and the second settles no proposals.
    assert_eq!(
        governance
            .proto
            .neurons
            .get(&alice_id.to_string())
            .unwrap()
            .latest_reward_event_participation,
        Some(old_participation),
    );
    assert_eq!(governance.latest_reward_event().settled_proposals, vec![]);
    assert_ne!(
        governance
            .latest_reward_event()
            .end_timestamp_seconds
            .unwrap(),
        unspecified_event_timestamp_seconds,
    );
}

#[test]
fn test_exact_numeric_conversions() {
    // Step 1: Prepare exactly representable Decimal values.
    let maximum_decimal = Decimal::MAX;
    let values = [
        (Decimal::ZERO, 0_u128),
        (Decimal::from(42_u64), 42_u128),
        (Decimal::new(42_000, 3), 42_u128),
        (Decimal::from(u64::MAX), u128::from(u64::MAX)),
        (
            Decimal::from(u64::MAX) + Decimal::ONE,
            u128::from(u64::MAX) + 1,
        ),
        (
            maximum_decimal,
            u128::try_from(maximum_decimal.mantissa()).unwrap(),
        ),
    ];

    // Step 2: Convert the values.
    let converted = values
        .iter()
        .map(|(value, _)| try_convert_reward_shares_to_u128(*value).unwrap())
        .collect::<Vec<_>>();

    // Step 3: Verify exact values and rejection of invalid inputs.
    assert_eq!(
        converted,
        values
            .iter()
            .map(|(_, expected)| *expected)
            .collect::<Vec<_>>()
    );
    assert!(try_convert_reward_shares_to_u128(Decimal::NEGATIVE_ONE).is_err());
    assert!(try_convert_reward_shares_to_u128(Decimal::new(15, 1)).is_err());
    for value in [0, u128::from(u64::MAX), u128::from(u64::MAX) + 1, u128::MAX] {
        assert_eq!(u128::from(Uint128::from(value)), value);
    }
}

#[test]
fn test_neuron_apis_preserve_participation_and_pagination() {
    // Step 1: Prepare five neurons with distinct participation values.
    let neurons = (1_u8..=5)
        .map(|id| {
            let neuron_id = neuron_id(id);
            let mut neuron = neuron(&neuron_id);
            neuron.latest_reward_event_participation = Some(RewardEventParticipation {
                reward_event_end_timestamp_seconds: 100,
                reward_shares: Some(Uint128::from(u128::from(id))),
            });
            neuron
        })
        .collect::<Vec<_>>();
    let (mut governance, round_duration_seconds) = governance_with_neurons(neurons);

    // Step 2: Page through list_neurons while the reward-event snapshot is unchanged.
    let event_timestamp_before_pages = governance
        .latest_reward_event()
        .end_timestamp_seconds
        .unwrap();
    let mut listed_neurons = vec![];
    let mut start_page_at = None;
    loop {
        let page = governance.list_neurons(&ListNeurons {
            limit: 2,
            start_page_at: start_page_at.clone(),
            of_principal: None,
        });
        if page.neurons.is_empty() {
            break;
        }
        start_page_at = page.neurons.last().unwrap().id.clone();
        listed_neurons.extend(page.neurons);
    }
    let event_timestamp_after_pages = governance
        .latest_reward_event()
        .end_timestamp_seconds
        .unwrap();
    assert_eq!(event_timestamp_before_pages, event_timestamp_after_pages);

    // Step 3: Verify deterministic, complete pagination and lossless public API conversion.
    let expected_neuron_ids = governance
        .proto
        .neurons
        .values()
        .map(|neuron| neuron.id.clone().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        listed_neurons
            .iter()
            .map(|neuron| neuron.id.clone().unwrap())
            .collect::<Vec<_>>(),
        expected_neuron_ids,
    );
    for listed_neuron in &listed_neurons {
        let neuron_id = listed_neuron.id.clone().unwrap();
        let fetched_neuron = governance
            .get_neuron(GetNeuron {
                neuron_id: Some(neuron_id),
            })
            .result
            .unwrap()
            .unwrap();
        assert_eq!(&fetched_neuron, listed_neuron);
        let public_neuron = pb_api::Neuron::from(listed_neuron.clone());
        assert_eq!(&Neuron::from(public_neuron), listed_neuron);
    }

    // Step 4: A client rejects pages when a reward event occurs between page reads.
    let event_timestamp_before_pages = governance
        .latest_reward_event()
        .end_timestamp_seconds
        .unwrap();
    let first_page = governance.list_neurons(&ListNeurons {
        limit: 2,
        start_page_at: None,
        of_principal: None,
    });
    governance.env.set_time_warp(TimeWarp {
        delta_s: i64::try_from(round_duration_seconds).unwrap(),
    });
    governance.distribute_rewards(Tokens::from_e8s(0));
    let _second_page = governance.list_neurons(&ListNeurons {
        limit: 2,
        start_page_at: first_page.neurons.last().unwrap().id.clone(),
        of_principal: None,
    });
    let event_timestamp_after_pages = governance
        .latest_reward_event()
        .end_timestamp_seconds
        .unwrap();
    assert_ne!(event_timestamp_before_pages, event_timestamp_after_pages);
}

#[test]
fn test_legacy_neuron_decodes_without_participation() {
    // Step 1: Define the relevant subsets of the previous stable-state protobuf schema.
    #[derive(Clone, PartialEq, Message)]
    struct LegacyNeuron {
        #[prost(message, optional, tag = "1")]
        id: Option<NeuronId>,
        #[prost(uint64, tag = "3")]
        cached_neuron_stake_e8s: u64,
    }
    #[derive(Clone, PartialEq, Message)]
    struct LegacyGovernance {
        #[prost(btree_map = "string, message", tag = "1")]
        neurons: BTreeMap<String, LegacyNeuron>,
    }
    let neuron_id = neuron_id(7);
    let legacy_neuron = LegacyNeuron {
        id: Some(neuron_id.clone()),
        cached_neuron_stake_e8s: 123_456,
    };
    let legacy_governance = LegacyGovernance {
        neurons: btreemap! {
            neuron_id.to_string() => legacy_neuron,
        },
    };
    let encoded = legacy_governance.encode_to_vec();

    // Step 2: Decode the legacy stable state with the current Governance schema.
    let decoded = GovernanceProto::decode(encoded.as_slice()).unwrap();
    let decoded_neuron = &decoded.neurons[&neuron_id.to_string()];

    // Step 3: Verify old neuron fields survive the real Governance.neurons path and the new field
    // has protobuf absence semantics.
    assert_eq!(decoded_neuron.id, Some(neuron_id));
    assert_eq!(decoded_neuron.cached_neuron_stake_e8s, 123_456);
    assert_eq!(decoded_neuron.latest_reward_event_participation, None);
}
