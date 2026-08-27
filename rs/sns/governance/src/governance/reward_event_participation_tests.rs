use super::{test_helpers::*, *};
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_sns_governance_api::pb::v1 as pb_api;
use maplit::{btreemap, btreeset};
use num_bigint::BigUint;
use prost::Message;

use crate::pb::v1::{Motion, VotingRewardsParameters};
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

fn reward_shares(neuron: &Neuron) -> Option<BigUint> {
    neuron
        .latest_reward_event_participation
        .as_ref()
        .map(|participation| BigUint::from_bytes_be(&participation.reward_shares))
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
    // Step 1: Prepare neurons and three proposals. The follower's ballots are populated through
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
    // i2d(ballot.voting_power) currently requires each voting power to fit in i64,
    // so three proposals are needed to exercise an aggregate above u64::MAX.
    let maximum_reward_share_contribution = i64::MAX.unsigned_abs();
    let proposal_1_ballots = cascaded_ballots(
        1,
        &governance.proto.neurons,
        &btreemap! {
            alice_id.clone() => maximum_reward_share_contribution,
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
            alice_id.clone() => maximum_reward_share_contribution,
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
    let proposal_3_ballots = cascaded_ballots(
        3,
        &governance.proto.neurons,
        &btreemap! {
            alice_id.clone() => 2,
            bob_id.clone() => 0,
            carol_id.clone() => 0,
            follower_id.clone() => 0,
        },
        &alice_id,
        &bob_id,
        &follower_id,
        Vote::Yes,
        Vote::No,
    );
    governance
        .proto
        .proposals
        .insert(1, proposal_data(1, proposal_1_ballots));
    governance
        .proto
        .proposals
        .insert(2, proposal_data(2, proposal_2_ballots));
    governance
        .proto
        .proposals
        .insert(3, proposal_data(3, proposal_3_ballots));

    // Step 2: Distribute the zero-value native reward purse.
    governance.distribute_rewards(Tokens::from_e8s(1_000_000));

    // Step 3: Verify exact participation, unchanged maturity, settlement, and ballot clearing.
    let reward_event = governance.proto.latest_reward_event.as_ref().unwrap();
    assert_eq!(reward_event.distributed_e8s_equivalent, 0);
    assert_eq!(
        reward_event.settled_proposals,
        vec![
            ProposalId { id: 1 },
            ProposalId { id: 2 },
            ProposalId { id: 3 },
        ]
    );
    let event_timestamp_seconds = reward_event.end_timestamp_seconds.unwrap();

    for (neuron_id, expected_shares) in [
        (
            &alice_id,
            Some(BigUint::from(u64::MAX) + BigUint::from(1_u8)),
        ),
        (&bob_id, Some(BigUint::from(45_u8))),
        (&carol_id, None),
        (&follower_id, Some(BigUint::from(85_u8))),
    ] {
        let neuron = governance
            .proto
            .neurons
            .get(&neuron_id.to_string())
            .unwrap();
        let participated = expected_shares.is_some();
        assert_eq!(reward_shares(neuron), expected_shares);
        assert_eq!(neuron.maturity_e8s_equivalent, 0);
        assert_eq!(neuron.staked_maturity_e8s_equivalent.unwrap_or_default(), 0);
        if participated {
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
    assert!(
        governance
            .proto
            .proposals
            .get(&3)
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
    assert_eq!(reward_shares(alice), Some(BigUint::from(10_u8)));
    assert_eq!(
        alice
            .latest_reward_event_participation
            .as_ref()
            .unwrap()
            .reward_event_end_timestamp_seconds,
        event_1_timestamp_seconds,
    );
    assert_eq!(reward_shares(bob), Some(BigUint::from(40_u8)));
    assert_eq!(
        bob.latest_reward_event_participation
            .as_ref()
            .unwrap()
            .reward_event_end_timestamp_seconds,
        event_2_timestamp_seconds,
    );
}

#[test]
fn test_neuron_apis_and_pb_api_conversion_preserve_participation() {
    // Step 1: Prepare.
    let alice_id = neuron_id(1);
    let bob_id = neuron_id(2);
    let reward_shares = BigUint::from(u64::MAX) + BigUint::from(1_u8);
    let participation = RewardEventParticipation {
        reward_event_end_timestamp_seconds: 123,
        reward_shares: reward_shares.to_bytes_be(),
    };
    let mut alice = neuron(&alice_id);
    alice.latest_reward_event_participation = Some(participation.clone());
    let (governance, _) = governance_with_neurons(vec![alice, neuron(&bob_id)]);

    // Step 2: Run.
    let fetched_alice = governance
        .get_neuron(GetNeuron {
            neuron_id: Some(alice_id.clone()),
        })
        .result
        .unwrap()
        .unwrap();
    let listed_alice = governance
        .list_neurons(&ListNeurons {
            limit: 2,
            start_page_at: None,
            of_principal: None,
        })
        .neurons
        .into_iter()
        .find(|neuron| neuron.id.as_ref() == Some(&alice_id))
        .unwrap();

    // Step 3: Verify.
    assert_eq!(
        fetched_alice.latest_reward_event_participation,
        Some(participation.clone()),
    );
    assert_eq!(
        listed_alice.latest_reward_event_participation,
        Some(participation.clone()),
    );

    let public_alice = pb_api::Neuron::from(listed_alice);
    let public_participation = public_alice
        .latest_reward_event_participation
        .as_ref()
        .unwrap();
    assert_eq!(
        public_participation.reward_event_end_timestamp_seconds,
        Some(123),
    );
    assert_eq!(
        public_participation.reward_shares,
        Some(candid::Nat(reward_shares)),
    );
    assert_eq!(
        Neuron::from(public_alice).latest_reward_event_participation,
        Some(participation),
    );
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
