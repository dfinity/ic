use super::{test_helpers::*, *};
use crate::{
    pb::v1::{Motion, VotingRewardsParameters},
    types::test_helpers::NativeEnvironment,
};
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_nervous_system_common::{E8, ONE_DAY_SECONDS};
use ic_sns_governance_api::pb::v1 as pb_api;
use lazy_static::lazy_static;
use maplit::{btreemap, btreeset};
use num_bigint::BigUint;

// 1 day is the usual value, at least for SNSs that take after NNS.
const ROUND_DURATION_SECONDS: u64 = ONE_DAY_SECONDS;
const NEURON_STAKE_E8S: u64 = 100 * E8;

lazy_static! {
    static ref ALICE_ID: NeuronId = neuron_id(1);
    static ref BOB_ID: NeuronId = neuron_id(2);
    static ref CAROL_ID: NeuronId = neuron_id(3);
    static ref FOLLOWER_ID: NeuronId = neuron_id(4);
}

fn neuron_id(id: u8) -> NeuronId {
    NeuronId { id: vec![id; 32] }
}

fn neuron(id: &NeuronId) -> Neuron {
    Neuron {
        id: Some(id.clone()),
        permissions: A_NEURON.permissions.clone(),
        cached_neuron_stake_e8s: NEURON_STAKE_E8S,
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

fn governance_with_neurons(neurons: Vec<Neuron>) -> Governance {
    let previous_reward_event_timestamp_seconds = 10 * ROUND_DURATION_SECONDS;
    let mut environment = NativeEnvironment::new(Some(CanisterId::from_u64(1)));
    environment.now = previous_reward_event_timestamp_seconds + ROUND_DURATION_SECONDS;
    let mut proto = basic_governance_proto();
    proto.genesis_timestamp_seconds = previous_reward_event_timestamp_seconds;
    proto.latest_reward_event = Some(RewardEvent {
        actual_timestamp_seconds: previous_reward_event_timestamp_seconds,
        end_timestamp_seconds: Some(previous_reward_event_timestamp_seconds),
        rounds_since_last_distribution: Some(0),
        total_available_e8s_equivalent: Some(0),
        ..Default::default()
    });
    proto.neurons = neurons
        .into_iter()
        .map(|neuron| (neuron.id.as_ref().unwrap().to_string(), neuron))
        .collect();
    proto.parameters.as_mut().unwrap().voting_rewards_parameters = Some(VotingRewardsParameters {
        round_duration_seconds: Some(ROUND_DURATION_SECONDS),
        reward_rate_transition_duration_seconds: Some(1),
        initial_reward_rate_basis_points: Some(0),
        final_reward_rate_basis_points: Some(0),
    });

    Governance::new(
        proto.try_into().unwrap(),
        Box::new(environment),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    )
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
                    cast_timestamp_seconds: 0,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    // Alice casts her vote. Follower follows.
    Governance::cast_vote_and_cascade_follow(
        &ProposalId { id: proposal_id },
        alice_id,
        alice_vote,
        motion_function_id,
        &function_followee_index,
        &btreemap! {}, // topic_follower_index
        neurons,
        1, // now_seconds
        &mut ballots,
        Topic::Governance,
    );
    // Bob casts his vote.
    Governance::cast_vote_and_cascade_follow(
        &ProposalId { id: proposal_id },
        bob_id,
        bob_vote,
        motion_function_id,
        &function_followee_index,
        &btreemap! {}, // topic_follower_index
        neurons,
        1, // now_seconds
        &mut ballots,
        Topic::Governance,
    );

    ballots
}

#[test]
fn test_records_exact_reward_shares_when_native_rewards_are_zero() {
    // Step 1: Prepare neurons and three proposals. The follower's ballots are populated through
    // the production cascade implementation.
    let mut follower = neuron(&FOLLOWER_ID);
    let motion_function_id = u64::from(&Action::Motion(Motion::default()));
    follower.followees = btreemap! {
        motion_function_id => Followees { followees: vec![ALICE_ID.clone()] },
    };
    let mut governance = governance_with_neurons(vec![
        neuron(&ALICE_ID),
        neuron(&BOB_ID),
        neuron(&CAROL_ID),
        follower,
    ]);
    // i2d(ballot.voting_power) currently requires each voting power to fit in i64,
    // so three proposals are needed to exercise an aggregate above u64::MAX.
    let maximum_reward_share_contribution = i64::MAX.unsigned_abs();
    let proposal_1_ballots = cascaded_ballots(
        1,
        &governance.proto.neurons,
        &btreemap! {
            ALICE_ID.clone() => maximum_reward_share_contribution,
            BOB_ID.clone() => 20 * E8,
            CAROL_ID.clone() => 30 * E8,
            FOLLOWER_ID.clone() => 40 * E8,
        },
        &ALICE_ID,
        &BOB_ID,
        &FOLLOWER_ID,
        Vote::Yes,
        Vote::No,
    );
    let proposal_2_ballots = cascaded_ballots(
        2,
        &governance.proto.neurons,
        &btreemap! {
            ALICE_ID.clone() => maximum_reward_share_contribution,
            BOB_ID.clone() => 25 * E8,
            CAROL_ID.clone() => 35 * E8,
            FOLLOWER_ID.clone() => 45 * E8,
        },
        &ALICE_ID,
        &BOB_ID,
        &FOLLOWER_ID,
        Vote::No,
        Vote::Yes,
    );
    let proposal_3_ballots = cascaded_ballots(
        3,
        &governance.proto.neurons,
        &btreemap! {
            ALICE_ID.clone() => NEURON_STAKE_E8S,
            BOB_ID.clone() => 30 * E8,
            CAROL_ID.clone() => 40 * E8,
            FOLLOWER_ID.clone() => 50 * E8,
        },
        &ALICE_ID,
        &BOB_ID,
        &FOLLOWER_ID,
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
            &*ALICE_ID,
            Some(
                BigUint::from(maximum_reward_share_contribution) * 2_u8
                    + BigUint::from(NEURON_STAKE_E8S),
            ),
        ),
        (&*BOB_ID, Some(BigUint::from(75 * E8))),
        (&*CAROL_ID, None),
        (&*FOLLOWER_ID, Some(BigUint::from(135 * E8))),
    ] {
        let neuron = governance
            .proto
            .neurons
            .get(&neuron_id.to_string())
            .unwrap();
        let expected_participation =
            expected_shares.map(|reward_shares| RewardEventParticipation {
                reward_event_end_timestamp_seconds: event_timestamp_seconds,
                reward_shares: reward_shares.to_bytes_be(),
            });
        assert_eq!(
            neuron.latest_reward_event_participation,
            expected_participation,
        );
        assert_eq!(neuron.maturity_e8s_equivalent, 0);
        assert_eq!(neuron.staked_maturity_e8s_equivalent.unwrap_or_default(), 0);
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
fn test_updates_only_participants_in_each_reward_event() {
    // Step 1: Prepare the world: two neurons and a voting reward round in which both participate.
    let mut governance = governance_with_neurons(vec![neuron(&ALICE_ID), neuron(&BOB_ID)]);
    governance.proto.proposals.insert(
        1,
        proposal_data(
            1,
            btreemap! {
                ALICE_ID.to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: 10 * E8,
                    cast_timestamp_seconds: 1,
                },
                BOB_ID.to_string() => Ballot {
                    vote: Vote::No as i32,
                    voting_power: 20 * E8,
                    cast_timestamp_seconds: 1,
                },
            },
        ),
    );
    governance.distribute_rewards(Tokens::from_e8s(0));
    let event_1_timestamp_seconds = governance
        .latest_reward_event()
        .end_timestamp_seconds
        .unwrap();
    assert_eq!(
        governance
            .proto
            .neurons
            .get(&BOB_ID.to_string())
            .unwrap()
            .latest_reward_event_participation,
        Some(RewardEventParticipation {
            reward_event_end_timestamp_seconds: event_1_timestamp_seconds,
            reward_shares: BigUint::from(20 * E8).to_bytes_be(),
        }),
    );

    // Step 2: Run code under test. Here, another voting reward round occurs, except this time,
    // only Bob participates.
    governance.env.set_time_warp(TimeWarp {
        delta_s: i64::try_from(ROUND_DURATION_SECONDS).unwrap(),
    });
    governance.proto.proposals.insert(
        2,
        proposal_data(
            2,
            btreemap! {
                ALICE_ID.to_string() => Ballot {
                    vote: Vote::Unspecified as i32,
                    voting_power: 30 * E8,
                    cast_timestamp_seconds: 0,
                },
                BOB_ID.to_string() => Ballot {
                    vote: Vote::No as i32,
                    voting_power: 40 * E8,
                    cast_timestamp_seconds: 2,
                },
            },
        ),
    );
    governance.distribute_rewards(Tokens::from_e8s(0));

    // Step 3: Verify results: Bob's participation gets updated. Alice's does not.
    let event_2_timestamp_seconds = governance
        .latest_reward_event()
        .end_timestamp_seconds
        .unwrap();
    assert_eq!(
        event_2_timestamp_seconds,
        event_1_timestamp_seconds + ROUND_DURATION_SECONDS,
    );
    let alice = governance.proto.neurons.get(&ALICE_ID.to_string()).unwrap();
    let bob = governance.proto.neurons.get(&BOB_ID.to_string()).unwrap();
    assert_ne!(
        alice
            .latest_reward_event_participation
            .as_ref()
            .map(|participation| participation.reward_event_end_timestamp_seconds),
        Some(event_2_timestamp_seconds),
    );
    assert_eq!(
        bob.latest_reward_event_participation,
        Some(RewardEventParticipation {
            reward_event_end_timestamp_seconds: event_2_timestamp_seconds,
            reward_shares: BigUint::from(40 * E8).to_bytes_be(),
        }),
    );
}

#[test]
fn test_neuron_apis_and_pb_api_conversion_preserve_participation() {
    // Step 1: Prepare.
    let reward_shares = BigUint::from(u64::MAX) + BigUint::from(1_u8);
    let participation = RewardEventParticipation {
        reward_event_end_timestamp_seconds: 123,
        reward_shares: reward_shares.to_bytes_be(),
    };
    let mut alice = neuron(&ALICE_ID);
    alice.latest_reward_event_participation = Some(participation.clone());
    let governance = governance_with_neurons(vec![alice, neuron(&BOB_ID)]);

    // Step 2: Run.
    let fetched_alice = governance
        .get_neuron(GetNeuron {
            neuron_id: Some(ALICE_ID.clone()),
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
        .find(|neuron| neuron.id.as_ref() == Some(&ALICE_ID))
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

    let api_alice = pb_api::Neuron::from(listed_alice);
    assert_eq!(
        api_alice.latest_reward_event_participation,
        Some(pb_api::neuron::RewardEventParticipation {
            reward_event_end_timestamp_seconds: Some(123),
            reward_shares: Some(candid::Nat(reward_shares)),
        }),
    );
    assert_eq!(
        Neuron::from(api_alice).latest_reward_event_participation,
        Some(participation),
    );
}
