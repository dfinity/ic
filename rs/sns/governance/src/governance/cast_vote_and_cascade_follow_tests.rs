use crate::pb::v1::{Followee, neuron::FolloweesForTopic};
use ic_nervous_system_common::E8;
use itertools::Itertools;
use maplit::btreeset;
use pretty_assertions::assert_eq;

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
        let cast_vote_and_cascade_follow = |function_id, topic| {
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
                topic,
            );

            ballots
        };

        // Step 2A: Consider following on non-critical proposal. Here catch-all/fallback
        // following should be used.
        let non_critical_ballots =
            cast_vote_and_cascade_follow(non_critical_function_id, Topic::Governance);

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
            cast_vote_and_cascade_follow(critical_function_id, Topic::TreasuryAssetManagement);

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
            cast_vote_and_cascade_follow(function_id, Topic::CriticalDappOperations);

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

fn nid(id: u64) -> NeuronId {
    NeuronId { id: vec![id as u8] }
}

#[test]
fn test_cast_vote_and_cascade_follow_with_topic_and_proposal_following() {
    let voting_neuron_id = nid(0);

    // Boilerplate variables.
    let now_seconds = 123_456_789;
    let cast_timestamp_seconds = now_seconds;

    let cached_neuron_stake_e8s = E8;
    let voting_power = cached_neuron_stake_e8s;

    let proposal_id = ProposalId { id: 42 };

    let neuron = |id, followees, topic_followees| Neuron {
        id: Some(id),
        followees,
        topic_followees,
        cached_neuron_stake_e8s,
        ..Default::default()
    };

    let voting_neuron = neuron(nid(0), btreemap! {}, None);

    #[allow(clippy::type_complexity)]
    let test_cases: &[(
        &str,
        Action,
        Topic,
        Vec<Neuron>,
        Box<dyn Fn(Vote) -> BTreeMap<String, Ballot>>,
    )] = &[
        (
            "Trivial case: One neuron votes; no following involved.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![voting_neuron.clone()],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Two neurons:  One neuron votes, another one does not follow and thus does not vote.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![voting_neuron.clone(), neuron(nid(1), btreemap! {}, None)],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: Vote::Unspecified as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Two neurons:  One neuron votes, another one follows this neuron, but on a different topic.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {},
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::ApplicationBusinessLogic as i32 => FolloweesForTopic {
                                topic: Some(Topic::ApplicationBusinessLogic as i32),
                                followees: vec![Followee { neuron_id: Some(nid(0)), alias: None }],
                            },
                        },
                    }),
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: Vote::Unspecified as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Two neurons:  One neuron votes, another one follows this neuron, but on a different proposal type.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {
                        u64::from(&Action::RegisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(0)],
                        },
                    },
                    None,
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: Vote::Unspecified as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Two neurons:  One neuron votes, another one follows an unrelated neuron on this topic.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {},
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                topic: Some(Topic::CriticalDappOperations as i32),
                                followees: vec![Followee { neuron_id: Some(nid(2)), alias: None }],
                            },
                        },
                    }),
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: Vote::Unspecified as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Two neurons:  One neuron votes, another one follows an unrelated neuron on this proposal type.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {
                        u64::from(&Action::RegisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(0)],
                        },
                    },
                    None,
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: Vote::Unspecified as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Two neurons:  One neuron votes, another one follows it on the same topic.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {},
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                topic: Some(Topic::CriticalDappOperations as i32),
                                followees: vec![Followee { neuron_id: Some(nid(0)), alias: None }],
                            },
                        },
                    }),
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Two neurons:  One neuron votes, another one follows it on the same function.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {
                        u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(0)],
                        },
                    },
                    None,
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Two neurons:  One neuron votes, another one follows on the same function.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {
                        u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(0)],
                        },
                    },
                    None,
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Two neurons:  One neuron votes, another one follows on the same function and topic.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {
                        u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(0)],
                        },
                    },
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                topic: Some(Topic::CriticalDappOperations as i32),
                                followees: vec![Followee { neuron_id: Some(nid(0)), alias: None }],
                            },
                        },
                    }),
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Two neurons:  One neuron votes, another one follows on the same function (and has unrelated topic-following).",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {
                        u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(0)],
                        },
                    },
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::ApplicationBusinessLogic as i32 => FolloweesForTopic {
                                topic: Some(Topic::ApplicationBusinessLogic as i32),
                                followees: vec![Followee { neuron_id: Some(nid(0)), alias: None }],
                            },
                        },
                    }),
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Two neurons:  One neuron votes, another one follows on the same topic (and has unrelated function type-based following).",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {
                        u64::from(&Action::RegisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(0)],
                        },
                    },
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                topic: Some(Topic::CriticalDappOperations as i32),
                                followees: vec![Followee { neuron_id: Some(nid(0)), alias: None }],
                            },
                        },
                    }),
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Three neurons:  N0 -- type --> N1 -- type --> N2.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {},
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                topic: Some(Topic::CriticalDappOperations as i32),
                                followees: vec![Followee { neuron_id: Some(nid(0)), alias: None }],
                            },
                        },
                    }),
                ),
                neuron(
                    nid(2),
                    btreemap! {},
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                topic: Some(Topic::CriticalDappOperations as i32),
                                followees: vec![Followee { neuron_id: Some(nid(1)), alias: None }],
                            },
                        },
                    }),
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(2).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Three neurons:  N0 -- type --> N1 -- function --> N2.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {},
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                topic: Some(Topic::CriticalDappOperations as i32),
                                followees: vec![Followee { neuron_id: Some(nid(0)), alias: None }],
                            },
                        },
                    }),
                ),
                neuron(
                    nid(2),
                    btreemap! {
                        u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(1)],
                        },
                    },
                    None,
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(2).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Three neurons:  N0 -- function --> N1 -- type --> N2.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {
                        u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(0)],
                        },
                    },
                    None,
                ),
                neuron(
                    nid(2),
                    btreemap! {},
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                topic: Some(Topic::CriticalDappOperations as i32),
                                followees: vec![Followee { neuron_id: Some(nid(1)), alias: None }],
                            },
                        },
                    }),
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(2).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Three neurons:  N0 -- function --> N1 -- function --> N2.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {
                        u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(0)],
                        },
                    },
                    None,
                ),
                neuron(
                    nid(2),
                    btreemap! {
                        u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(1)],
                        },
                    },
                    None,
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(2).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Three neurons:  N0 -- type --> N1; N0 -- type --> N2.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {},
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                topic: Some(Topic::CriticalDappOperations as i32),
                                followees: vec![Followee { neuron_id: Some(nid(0)), alias: None }],
                            },
                        },
                    }),
                ),
                neuron(
                    nid(2),
                    btreemap! {},
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                topic: Some(Topic::CriticalDappOperations as i32),
                                followees: vec![Followee { neuron_id: Some(nid(0)), alias: None }],
                            },
                        },
                    }),
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(2).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Three neurons:  N0 -- type --> N1; N0 -- function --> N2.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {},
                    Some(TopicFollowees {
                        topic_id_to_followees: btreemap! {
                            Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                topic: Some(Topic::CriticalDappOperations as i32),
                                followees: vec![Followee { neuron_id: Some(nid(0)), alias: None }],
                            },
                        },
                    }),
                ),
                neuron(
                    nid(2),
                    btreemap! {
                        u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(0)],
                        },
                    },
                    None,
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(2).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
        (
            "Three neurons:  N0 -- function --> N1; N0 -- function --> N2.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                voting_neuron.clone(),
                neuron(
                    nid(1),
                    btreemap! {
                        u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(0)],
                        },
                    },
                    None,
                ),
                neuron(
                    nid(2),
                    btreemap! {
                        u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                            followees: vec![nid(0)],
                        },
                    },
                    None,
                ),
            ],
            Box::new(|directly_cast_vote| {
                btreemap! {
                    nid(0).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(1).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                    nid(2).to_string() => Ballot {
                        vote: directly_cast_vote as i32,
                        voting_power,
                        cast_timestamp_seconds,
                    },
                }
            }),
        ),
    ];

    for (label, action, topic, neurons, expected_ballots) in test_cases {
        let function_id = u64::from(action);

        let neurons = neurons
            .iter()
            .map(|neuron| (neuron.id.clone().unwrap().to_string(), neuron.clone()))
            .collect();

        let function_followee_index =
            legacy::build_function_followee_index(&btreemap! {}, &neurons);

        let topic_follower_index = build_follower_index(&neurons);

        for vote_of_neuron in [Vote::Yes, Vote::No] {
            let label = format!("{} ({})", label, vote_of_neuron.as_str_name());

            // Give all neurons an empty ballot.
            let mut ballots = neurons
                .values()
                .cloned()
                .map(|neuron| {
                    (
                        neuron.id.unwrap().to_string(),
                        Ballot {
                            vote: Vote::Unspecified as i32,
                            voting_power,
                            cast_timestamp_seconds,
                        },
                    )
                })
                .collect();

            Governance::cast_vote_and_cascade_follow(
                &proposal_id,
                &voting_neuron_id,
                vote_of_neuron,
                function_id,
                &function_followee_index,
                &topic_follower_index,
                &neurons,
                now_seconds,
                &mut ballots,
                *topic,
            );

            let expected_ballots = expected_ballots(vote_of_neuron);

            assert_eq!(ballots, expected_ballots, "{}", label);
        }
    }
}

/// Unlike `test_cast_vote_and_cascade_follow_with_topic_and_proposal_following`, this test
/// covers the scenario in which neurons have multiple followees that need to be taken into account
/// for determining their following-based vote. In particular, this allows checking that topic-based
/// following has higher priority, with function-based following being a fallback.
#[test]
fn test_cast_vote_and_cascade_follow_with_multiple_followees() {
    // Boilerplate variables.
    let now_seconds = 123_456_789;
    let cast_timestamp_seconds = now_seconds;
    let cached_neuron_stake_e8s = E8;
    let proposal_id = ProposalId { id: 42 };

    let neuron = |id, followees, topic_followees| Neuron {
        id: Some(id),
        followees,
        topic_followees,
        cached_neuron_stake_e8s,
        ..Default::default()
    };

    let test_cases = [
        (
            "Three neurons:  N0:YES -- function --> N2; \
                             N1:YES -- topic    --> N2 (topic following has higher prio).",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                (neuron(nid(0), btreemap! {}, None), Vote::Yes, E8),
                (neuron(nid(1), btreemap! {}, None), Vote::Yes, E8),
                (
                    neuron(
                        nid(2),
                        btreemap! {
                            u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                                followees: vec![nid(0)],
                            },
                        },
                        Some(TopicFollowees {
                            topic_id_to_followees: btreemap! {
                                Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                    topic: Some(Topic::CriticalDappOperations as i32),
                                    followees: vec![Followee { neuron_id: Some(nid(1)), alias: None }],
                                },
                            },
                        }),
                    ),
                    Vote::Unspecified,
                    E8,
                ),
            ],
            btreemap! {
                nid(0).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                nid(1).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                // Main postcondition: N2's vote follows that of N1, since it is the only followee
                // that is taken into account (since N0 is followed on a specific function).
                nid(2).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
            },
        ),
        (
            "Three neurons:  N0:NO  -- function --> N2; \
                             N1:YES -- topic    --> N2 (topic following has higher prio).",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                (neuron(nid(0), btreemap! {}, None), Vote::No, E8),
                (neuron(nid(1), btreemap! {}, None), Vote::Yes, E8),
                (
                    neuron(
                        nid(2),
                        btreemap! {
                            u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                                followees: vec![nid(0)],
                            },
                        },
                        Some(TopicFollowees {
                            topic_id_to_followees: btreemap! {
                                Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                    topic: Some(Topic::CriticalDappOperations as i32),
                                    followees: vec![Followee { neuron_id: Some(nid(1)), alias: None }],
                                },
                            },
                        }),
                    ),
                    Vote::Unspecified,
                    E8,
                ),
            ],
            btreemap! {
                nid(0).to_string() => Ballot {
                    vote: Vote::No as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                nid(1).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                // Main postcondition: N2's vote follows that of N1, since it is the only followee
                // that is taken into account (since N0 is followed on a specific function).
                nid(2).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
            },
        ),
        (
            "Three neurons:  N0:YES -- function --> N2; \
                             N1:NO  -- topic    --> N2 (topic following has higher prio).",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                (neuron(nid(0), btreemap! {}, None), Vote::Yes, E8),
                (neuron(nid(1), btreemap! {}, None), Vote::No, E8),
                (
                    neuron(
                        nid(2),
                        btreemap! {
                            u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                                followees: vec![nid(0)],
                            },
                        },
                        Some(TopicFollowees {
                            topic_id_to_followees: btreemap! {
                                Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                    topic: Some(Topic::CriticalDappOperations as i32),
                                    followees: vec![Followee { neuron_id: Some(nid(1)), alias: None }],
                                },
                            },
                        }),
                    ),
                    Vote::Unspecified,
                    E8,
                ),
            ],
            btreemap! {
                nid(0).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                nid(1).to_string() => Ballot {
                    vote: Vote::No as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                // Main postcondition: N2's vote follows that of N1, since it is the only followee
                // that is taken into account (since N0 is followed on a specific function).
                nid(2).to_string() => Ballot {
                    vote: Vote::No as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
            },
        ),
        (
            "Three neurons:  N0:NO -- function --> N2; \
                             N1:NO -- topic    --> N2 (topic following has higher prio).",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                (neuron(nid(0), btreemap! {}, None), Vote::No, E8),
                (neuron(nid(1), btreemap! {}, None), Vote::No, E8),
                (
                    neuron(
                        nid(2),
                        btreemap! {
                            u64::from(&Action::DeregisterDappCanisters(Default::default())) => Followees {
                                followees: vec![nid(0)],
                            },
                        },
                        Some(TopicFollowees {
                            topic_id_to_followees: btreemap! {
                                Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                    topic: Some(Topic::CriticalDappOperations as i32),
                                    followees: vec![Followee { neuron_id: Some(nid(1)), alias: None }],
                                },
                            },
                        }),
                    ),
                    Vote::Unspecified,
                    E8,
                ),
            ],
            btreemap! {
                nid(0).to_string() => Ballot {
                    vote: Vote::No as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                nid(1).to_string() => Ballot {
                    vote: Vote::No as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                // Main postcondition: N2's vote follows that of N1, since it is the only followee
                // that is taken into account (since N0 is followed on a specific function).
                nid(2).to_string() => Ballot {
                    vote: Vote::No as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
            },
        ),
        (
            "Three neurons:  N0:YES -- topic --> N2; \
                             N1:YES -- topic --> N2.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                (neuron(nid(0), btreemap! {}, None), Vote::Yes, E8),
                (neuron(nid(1), btreemap! {}, None), Vote::Yes, E8),
                (
                    neuron(
                        nid(2),
                        btreemap! {},
                        Some(TopicFollowees {
                            topic_id_to_followees: btreemap! {
                                Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                    topic: Some(Topic::CriticalDappOperations as i32),
                                    followees: vec![
                                        Followee { neuron_id: Some(nid(0)), alias: None },
                                        Followee { neuron_id: Some(nid(1)), alias: None },
                                    ],
                                },
                            },
                        }),
                    ),
                    Vote::Unspecified,
                    E8,
                ),
            ],
            btreemap! {
                nid(0).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                nid(1).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                // Main postcondition: N2's vote follows that of N0 and N1, since they agree.
                nid(2).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
            },
        ),
        (
            "Three neurons:  N0:YES -- topic --> N2 (N1 did not vote yet).",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                (neuron(nid(0), btreemap! {}, None), Vote::Yes, E8),
                (neuron(nid(1), btreemap! {}, None), Vote::Unspecified, E8),
                (
                    neuron(
                        nid(2),
                        btreemap! {},
                        Some(TopicFollowees {
                            topic_id_to_followees: btreemap! {
                                Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                    topic: Some(Topic::CriticalDappOperations as i32),
                                    followees: vec![
                                        Followee { neuron_id: Some(nid(0)), alias: None },
                                        Followee { neuron_id: Some(nid(1)), alias: None },
                                    ],
                                },
                            },
                        }),
                    ),
                    Vote::Unspecified,
                    E8,
                ),
            ],
            btreemap! {
                nid(0).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                nid(1).to_string() => Ballot {
                    vote: Vote::Unspecified as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                // Main postcondition: N2's is not swayed by N0's vote,
                // as N1's vote is not yet cast.
                nid(2).to_string() => Ballot {
                    vote: Vote::Unspecified as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
            },
        ),
        (
            "Three neurons:  N0:YES -- topic --> N2 (N1 did not vote yet, but it's followed on a different topic).",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                (neuron(nid(0), btreemap! {}, None), Vote::Yes, E8),
                (neuron(nid(1), btreemap! {}, None), Vote::Unspecified, E8),
                (
                    neuron(
                        nid(2),
                        btreemap! {},
                        Some(TopicFollowees {
                            topic_id_to_followees: btreemap! {
                                Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                    topic: Some(Topic::CriticalDappOperations as i32),
                                    followees: vec![
                                        Followee { neuron_id: Some(nid(0)), alias: None },
                                    ],
                                },
                                Topic::ApplicationBusinessLogic as i32 => FolloweesForTopic {
                                    topic: Some(Topic::ApplicationBusinessLogic as i32),
                                    followees: vec![
                                        Followee { neuron_id: Some(nid(1)), alias: None },
                                    ],
                                },
                            },
                        }),
                    ),
                    Vote::Unspecified,
                    E8,
                ),
            ],
            btreemap! {
                nid(0).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                nid(1).to_string() => Ballot {
                    vote: Vote::Unspecified as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                // Main postcondition: N2's is swayed by N0's vote, as N1 (which didn't vote yet)
                // is followed on a different topic.
                nid(2).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
            },
        ),
        (
            "Three neurons:  N0:YES -- topic --> N2; \
                             N1:NO  -- topic --> N2.",
            Action::DeregisterDappCanisters(Default::default()),
            Topic::CriticalDappOperations,
            vec![
                (neuron(nid(0), btreemap! {}, None), Vote::Yes, E8),
                (neuron(nid(1), btreemap! {}, None), Vote::No, E8),
                (
                    neuron(
                        nid(2),
                        btreemap! {},
                        Some(TopicFollowees {
                            topic_id_to_followees: btreemap! {
                                Topic::CriticalDappOperations as i32 => FolloweesForTopic {
                                    topic: Some(Topic::CriticalDappOperations as i32),
                                    followees: vec![
                                        Followee { neuron_id: Some(nid(0)), alias: None },
                                        Followee { neuron_id: Some(nid(1)), alias: None },
                                    ],
                                },
                            },
                        }),
                    ),
                    Vote::Unspecified,
                    E8,
                ),
            ],
            btreemap! {
                nid(0).to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                nid(1).to_string() => Ballot {
                    vote: Vote::No as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
                // Main postcondition: N2's is not swayed by N0's vote but swayed by N1's vote,
                // as this is an equal split of YES and NO votes amongst the two followees.
                nid(2).to_string() => Ballot {
                    vote: Vote::No as i32,
                    voting_power: E8,
                    cast_timestamp_seconds,
                },
            },
        ),
    ];

    for (label, action, topic, neuron_vote_powers, expected_ballots) in test_cases {
        let function_id = u64::from(&action);

        let neurons = neuron_vote_powers
            .iter()
            .map(|(neuron, _, _)| (neuron.id.clone().unwrap().to_string(), neuron.clone()))
            .collect();

        let function_followee_index =
            legacy::build_function_followee_index(&btreemap! {}, &neurons);

        let topic_follower_index = build_follower_index(&neurons);

        let mut ballots = btreemap! {};
        let mut actively_voting_neurons = vec![];

        for (neuron, vote, voting_power) in neuron_vote_powers {
            let neuron_id = neuron.id.clone().unwrap();

            if vote != Vote::Unspecified {
                actively_voting_neurons.push((neuron_id.clone(), vote));
            }

            // Give all neurons an empty ballot.
            ballots.insert(
                neuron_id.to_string(),
                Ballot {
                    vote: Vote::Unspecified as i32,
                    voting_power,
                    cast_timestamp_seconds,
                },
            );
        }

        assert_ne!(
            actively_voting_neurons.len(),
            0,
            "There must be at least one actively voting neuron. {label}"
        );

        // The order of votes should not matter, as the `cast_vote_and_cascade_follow` function
        // should have a single fixedpoint.
        for permutation in actively_voting_neurons
            .iter()
            .permutations(actively_voting_neurons.len())
            .unique()
        {
            let mut ballots = ballots.clone();

            for (voting_neuron_id, vote_of_neuron) in permutation {
                Governance::cast_vote_and_cascade_follow(
                    &proposal_id,
                    voting_neuron_id,
                    *vote_of_neuron,
                    function_id,
                    &function_followee_index,
                    &topic_follower_index,
                    &neurons,
                    now_seconds,
                    &mut ballots,
                    topic,
                );
            }

            assert_eq!(ballots, expected_ballots, "{}", label);
        }
    }
}
