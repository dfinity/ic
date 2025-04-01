use ic_nervous_system_common::E8;
use maplit::btreeset;

use super::*;

/// Main Narrative:
///
/// 1. There are three neurons. One votes directly. The other two follow the (direct) voter.
/// 2. The difference between the two follower neurons is what they follow on:
///   * catch-all/fallback: This neuron does nothing on critical proposals.
///   * TransferSnsTreasuryFunds: This neuron only acts on TransferSnsTreasuryFunds proposals.
/// 3. There are two proposals that the (direct) voter neuron votes on:
///   * Motion: Here, only the first follower neuron follows.
///   * TransferSnsTreasuryFunds: Here, only the second follower neuron follows, even though
///     the first follower neuron uses catch-all/fallback following.
///
/// What the first follower neuron does is the most interesting, because what we are trying to
/// demonstrate here is that catch-all/fallback following applies iff the proposal is
/// normal/non-critical. Whereas, the second follower neuron is there more as a sanity check, to
/// witness that specific (i.e. non-catch-all/non-fallback) following still happens.
///
/// There is actually a third follower neuron, but this one is even less interesting than the
/// second. This one is a "super follower" in that this uses a (disjoint) union of the following
/// of the first two follower neurons.
///
/// There is also a third proposal: a critical proposal, but with a different function ID that
/// nobody specifically follows. Here, only direct voting causes a ballot to be filled in. This
/// is another sanity test, which we throw in as a "bonus", because it's pretty cheap to add.
#[test]
fn test_cast_vote_and_cascade_follow_critical_vs_normal_proposals() {
    // Step 1: Prepare the world.

    let proposal_id = ProposalId { id: 42 };

    let voting_neuron_id = NeuronId { id: vec![1] };
    let follows_on_catch_all_neuron_id = NeuronId { id: vec![2] };
    let follows_on_transfer_sns_treasury_funds_neuron_id = NeuronId { id: vec![3] };
    let follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id = NeuronId { id: vec![4] };

    let non_critical_function_id = u64::from(&Action::Motion(Default::default()));
    let critical_function_id = u64::from(&Action::TransferSnsTreasuryFunds(Default::default()));

    let fallback_pseudo_function_id = u64::from(&Action::Unspecified(Default::default()));
    // This needs to be consistent with neurons (below).
    let function_followee_index = btreemap! {
        fallback_pseudo_function_id => btreemap! {
            voting_neuron_id.to_string() => btreeset! {
                follows_on_catch_all_neuron_id.clone(),
                follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.clone(),
            },
        },

        critical_function_id => btreemap! {
            voting_neuron_id.to_string() => btreeset! {
                follows_on_transfer_sns_treasury_funds_neuron_id.clone(),
                follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.clone(),
            },
        },
    };

    let voting_neuron = Neuron {
        id: Some(voting_neuron_id.clone()),
        cached_neuron_stake_e8s: E8, // voting power
        ..Default::default()
    };
    let follows_on_catch_all_neuron = Neuron {
        id: Some(follows_on_catch_all_neuron_id.clone()),
        cached_neuron_stake_e8s: E8, // voting power
        followees: btreemap! {
            fallback_pseudo_function_id => Followees {
                followees: vec![voting_neuron_id.clone()],
            },
        },
        ..Default::default()
    };
    let follows_on_transfer_sns_treasury_funds_neuron = Neuron {
        id: Some(follows_on_transfer_sns_treasury_funds_neuron_id.clone()),
        cached_neuron_stake_e8s: E8, // voting power
        followees: btreemap! {
            critical_function_id => Followees {
                followees: vec![voting_neuron_id.clone()],
            },
        },
        ..Default::default()
    };
    let follows_on_catch_all_and_transfer_sns_treasury_funds_neuron = Neuron {
        id: Some(follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.clone()),
        cached_neuron_stake_e8s: E8, // voting power
        followees: btreemap! {
            fallback_pseudo_function_id => Followees {
                followees: vec![voting_neuron_id.clone()],
            },
            critical_function_id => Followees {
                followees: vec![voting_neuron_id.clone()],
            },
        },
        ..Default::default()
    };
    let neurons = btreemap! {
        voting_neuron_id.to_string()
            => voting_neuron,

        follows_on_catch_all_neuron_id.to_string()
            => follows_on_catch_all_neuron,

        follows_on_transfer_sns_treasury_funds_neuron_id.to_string()
            => follows_on_transfer_sns_treasury_funds_neuron,

        follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.to_string()
            => follows_on_catch_all_and_transfer_sns_treasury_funds_neuron,
    };

    // Step 2: Run code under test.

    // We loop over Votes, because the behavior is "the same" in both cases: under following,
    // the direction of the vote is consistent (it would be a bit insane if voting Yes caused
    // another neuron to vote No, and vice versa).
    for vote_of_neuron in [Vote::Yes, Vote::No] {
        let now_seconds = 123_456_789;

        let empty_ballot = Ballot {
            vote: Vote::Unspecified as i32,
            voting_power: E8,
            cast_timestamp_seconds: now_seconds,
        };
        let filled_in_ballot = Ballot {
            vote: vote_of_neuron as i32,
            ..empty_ballot
        };

        // Code under test.
        let cast_vote_and_cascade_follow = |function_id, proposal_criticality| {
            // Give all neurons an empty ballot.
            let mut ballots = [
                &voting_neuron_id,
                &follows_on_catch_all_neuron_id,
                &follows_on_transfer_sns_treasury_funds_neuron_id,
                &follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id,
            ]
            .into_iter()
            .map(|neuron_id| (neuron_id.to_string(), empty_ballot))
            .collect::<BTreeMap<String, Ballot>>();

            // voter neuron votes, and the code under test deduces all of the implications of
            // following (or at least, tries to).
            Governance::cast_vote_and_cascade_follow(
                &proposal_id,
                &voting_neuron_id,
                vote_of_neuron,
                function_id,
                &function_followee_index,
                &btreemap! {},
                &neurons,
                now_seconds,
                &mut ballots,
                proposal_criticality,
                Default::default(),
            );

            ballots
        };

        // Step 2A: Consider following on non-critical proposal. Here catch-all/fallback
        // following should be used.
        let non_critical_ballots =
            cast_vote_and_cascade_follow(non_critical_function_id, ProposalCriticality::Normal);

        // Step 3: Inspect results.

        // Step 3A: Non-critical proposal.
        assert_eq!(
            non_critical_ballots,
            btreemap! {
                voting_neuron_id.to_string()
                    // Direct vote.
                    => filled_in_ballot,

                follows_on_catch_all_neuron_id.to_string()
                    // Thanks to catch-all/fallback following.
                    => filled_in_ballot,

                follows_on_transfer_sns_treasury_funds_neuron_id.to_string()
                    // Because this only follows specifically on TransferSnsTreasuryFunds.
                    => empty_ballot,

                follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.to_string()
                    // Thanks to catch-all/fallback following, although from just this case, it
                    // is unclear why this happens (you need to look at behavior on many
                    // different proposals to explain the behavior of this neuron).
                    => filled_in_ballot,
            }
        );

        // Step 2B: Critical proposal following. Here catch-all/fallback following should NOT be
        // used.
        let critical_ballots =
            cast_vote_and_cascade_follow(critical_function_id, ProposalCriticality::Critical);

        // Step 3B: Critical proposal.
        assert_eq!(
            critical_ballots,
            btreemap! {
                voting_neuron_id.to_string()
                    => filled_in_ballot,

                // Perhaps, surprisingly, even though this neuron follows on
                // "catch-all/fallback", that does not apply here, because the proposal is
                // "critical".
                follows_on_catch_all_neuron_id.to_string()
                    => empty_ballot,

                // Unsurprisingly, this neuron follows, because it specifically follows on
                // proposals of this type.
                follows_on_transfer_sns_treasury_funds_neuron_id.to_string()
                    => filled_in_ballot,

                // Even less surprisingly, this also follows for similar reasons.
                follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.to_string()
                    => filled_in_ballot,
            }
        );

        // Step 2C: A different critical proposal -> only direct voting happens here.
        let function_id = u64::from(&Action::DeregisterDappCanisters(Default::default()));
        let no_following_ballots =
            cast_vote_and_cascade_follow(function_id, ProposalCriticality::Critical);

        // Step 3C: A different critical proposal.
        assert_eq!(
            no_following_ballots,
            btreemap! {
                // Only direct vote.
                voting_neuron_id.to_string()
                    => filled_in_ballot,

                // No following.
                follows_on_catch_all_neuron_id.to_string()
                    => empty_ballot,
                follows_on_transfer_sns_treasury_funds_neuron_id.to_string()
                    => empty_ballot,
                // Even this "super follower" doesn't follow here.
                follows_on_catch_all_and_transfer_sns_treasury_funds_neuron_id.to_string()
                    => empty_ballot,
            }
        );
    }
}
