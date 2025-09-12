use fixtures::{NNSBuilder, NeuronBuilder};
use futures::FutureExt;
use ic_base_types::PrincipalId;
use ic_nervous_system_common::E8;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::pb::v1::{
    Followees, ManageNeuron, Topic, VotingPowerEconomics,
    governance_error::ErrorType,
    manage_neuron::{
        Command, NeuronIdOrSubaccount, SetFollowing, set_following::FolloweesForTopic,
    },
};
use ic_nns_governance_api as api;
use maplit::hashmap;

pub mod fixtures;

#[test]
fn test_set_following() {
    // Step 1: Prepare the world.

    let mut nns_builder = NNSBuilder::new();

    // Add some neurons. The first one (42) will follow the others on different topics.
    for neuron_id in [42, 57, 99].into_iter().chain(1001..=1050) {
        // This test does not really care about these values; however, it is
        // more realistic for them to be distinct.
        let staked_amount_e8s = neuron_id * E8;
        let controller = PrincipalId::new_user_test_id(neuron_id);

        nns_builder = nns_builder.add_neuron(
            NeuronBuilder::new(neuron_id, staked_amount_e8s, controller).set_dissolve_delay(
                VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
            ),
        );
    }

    let mut nns = nns_builder.create();

    // Step 2: Call the code under test.

    // Step 2.1: Call SetFollowing. This will be done again right after, but with different argument(s).
    let set_following_result_1 = nns
        .governance
        .manage_neuron(
            &PrincipalId::new_user_test_id(42),
            &ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 42 })),
                command: Some(Command::SetFollowing(SetFollowing {
                    topic_following: vec![
                        FolloweesForTopic {
                            topic: None, // Catch all.
                            followees: vec![NeuronId { id: 57 }],
                        },
                        FolloweesForTopic {
                            topic: Some(Topic::NetworkEconomics as i32),
                            followees: vec![NeuronId { id: 99 }],
                        },
                        FolloweesForTopic {
                            topic: Some(Topic::NodeAdmin as i32),
                            followees: vec![NeuronId { id: 57 }, NeuronId { id: 99 }],
                        },
                    ],
                })),
                id: None,
            },
        )
        .now_or_never()
        .unwrap()
        .command
        .unwrap();
    let observed_followees_1 = nns
        .governance
        .with_neuron(&NeuronId { id: 42 }, |neuron| neuron.followees.clone());

    // Step 2.2: Call SetFollowing again, but with different argument(s).
    let set_following_result_2 = nns
        .governance
        .manage_neuron(
            &PrincipalId::new_user_test_id(42),
            &ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 42 })),
                command: Some(Command::SetFollowing(SetFollowing {
                    topic_following: vec![
                        FolloweesForTopic {
                            topic: Some(Topic::Unspecified as i32), // An alternative way to specify catch-all.
                            followees: vec![],
                        },
                        FolloweesForTopic {
                            topic: Some(Topic::NetworkEconomics as i32),
                            followees: vec![NeuronId { id: 57 }],
                        },
                        FolloweesForTopic {
                            topic: Some(Topic::ApiBoundaryNodeManagement as i32),
                            followees: vec![NeuronId { id: 99 }],
                        },
                    ],
                })),
                id: None,
            },
        )
        .now_or_never()
        .unwrap()
        .command
        .unwrap();
    let observed_followees_2 = nns
        .governance
        .with_neuron(&NeuronId { id: 42 }, |neuron| neuron.followees.clone());

    // Step 2.3: Call SetFollowing with invalid argument: garbage topic.
    let set_following_result_3 = nns
        .governance
        .manage_neuron(
            &PrincipalId::new_user_test_id(42),
            &ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 42 })),
                command: Some(Command::SetFollowing(SetFollowing {
                    topic_following: vec![FolloweesForTopic {
                        topic: Some(123_456_789),
                        followees: vec![NeuronId { id: 57 }],
                    }],
                })),
                id: None,
            },
        )
        .now_or_never()
        .unwrap()
        .command
        .unwrap();
    let observed_followees_3 = nns
        .governance
        .with_neuron(&NeuronId { id: 42 }, |neuron| neuron.followees.clone());

    // Step 2.4: Call SetFollowing with invalid argument: duplicate topic
    let set_following_result_4 = nns
        .governance
        .manage_neuron(
            &PrincipalId::new_user_test_id(42),
            &ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 42 })),
                command: Some(Command::SetFollowing(SetFollowing {
                    topic_following: vec![
                        FolloweesForTopic {
                            topic: Some(Topic::ApiBoundaryNodeManagement as i32),
                            followees: vec![NeuronId { id: 57 }],
                        },
                        FolloweesForTopic {
                            topic: Some(Topic::ApiBoundaryNodeManagement as i32),
                            followees: vec![NeuronId { id: 57 }],
                        },
                    ],
                })),
                id: None,
            },
        )
        .now_or_never()
        .unwrap()
        .command
        .unwrap();
    let observed_followees_4 = nns
        .governance
        .with_neuron(&NeuronId { id: 42 }, |neuron| neuron.followees.clone());

    // Step 2.5: Call SetFollowing with invalid argument: too many followees.
    let set_following_result_5 = nns
        .governance
        .manage_neuron(
            &PrincipalId::new_user_test_id(42),
            &ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 42 })),
                command: Some(Command::SetFollowing(SetFollowing {
                    topic_following: vec![FolloweesForTopic {
                        topic: Some(Topic::ApiBoundaryNodeManagement as i32),
                        followees: (1001..=1050).map(|id| NeuronId { id }).collect(),
                    }],
                })),
                id: None,
            },
        )
        .now_or_never()
        .unwrap()
        .command
        .unwrap();
    let observed_followees_5 = nns
        .governance
        .with_neuron(&NeuronId { id: 42 }, |neuron| neuron.followees.clone());

    // Step 3: Verify result(s).

    let ok_set_following_response = api::manage_neuron_response::Command::SetFollowing(
        api::manage_neuron_response::SetFollowingResponse {},
    );

    // Step 3.1: Verify result(s) of first SetFollowing.
    assert_eq!(
        observed_followees_1,
        Ok(hashmap! {
            Topic::Unspecified as i32 => Followees {
                followees: vec![
                    NeuronId { id: 57 },
                ],
            },
            Topic::NetworkEconomics as i32 => Followees {
                followees: vec![
                    NeuronId { id: 99 },
                ],
            },
            Topic::NodeAdmin as i32 => Followees {
                followees: vec![
                    NeuronId { id: 57 },
                    NeuronId { id: 99 },
                ],
            }
        }),
    );
    assert_eq!(set_following_result_1, ok_set_following_response);

    // Step 3.2: Verify result(s) of second SetFollowing.
    let final_following = Ok(hashmap! {
        Topic::NetworkEconomics as i32 => Followees {
            followees: vec![
                NeuronId { id: 57 },
            ],
        },
        Topic::NodeAdmin as i32 => Followees {
            followees: vec![
                NeuronId { id: 57 },
                NeuronId { id: 99 },
            ],
        },
        Topic::ApiBoundaryNodeManagement as i32 => Followees {
            followees: vec![
                NeuronId { id: 99 },
            ],
        },
    });
    assert_eq!(observed_followees_2, final_following);
    assert_eq!(set_following_result_2, ok_set_following_response);

    // Step 3.3: Verify that the 3rd call had no effect on the neuron's following.
    assert_eq!(observed_followees_3, final_following);
    match set_following_result_3 {
        api::manage_neuron_response::Command::Error(error) => {
            let api::GovernanceError {
                error_type,
                error_message,
            } = error;

            assert_eq!(
                ErrorType::try_from(error_type),
                Ok(ErrorType::InvalidCommand)
            );

            let error_message = error_message.to_lowercase();
            for key_word in ["invalid", "topic", "code", "123", "456", "789"] {
                assert!(
                    error_message.contains(key_word),
                    "{key_word:?} not in {error_message:?}",
                );
            }
        }
        _ => panic!("{set_following_result_3:?}"),
    }

    // Step 3.4: Verify that the 4th call (also) had no effect on the neuron's following.
    assert_eq!(observed_followees_4, final_following);
    match set_following_result_4 {
        api::manage_neuron_response::Command::Error(error) => {
            let api::GovernanceError {
                error_type,
                error_message,
            } = error;

            assert_eq!(
                ErrorType::try_from(error_type),
                Ok(ErrorType::InvalidCommand)
            );

            let error_message = error_message.to_lowercase();
            for key_word in [
                "same",
                "topic",
                "more",
                "than",
                "once",
                "apiboundarynodemanagement",
            ] {
                assert!(
                    error_message.contains(key_word),
                    "{key_word:?} not in {error_message:?}",
                );
            }
        }
        _ => panic!("{set_following_result_4:?}"),
    }

    // Step 3.5: Verify that the 5th call (also) had no effect on the neuron's following.
    assert_eq!(observed_followees_5, final_following);
    match set_following_result_5 {
        api::manage_neuron_response::Command::Error(error) => {
            let api::GovernanceError {
                error_type,
                error_message,
            } = error;

            assert_eq!(
                ErrorType::try_from(error_type),
                Ok(ErrorType::InvalidCommand)
            );

            let error_message = error_message.to_lowercase();
            for key_word in ["too", "many", "followees"] {
                assert!(
                    error_message.contains(key_word),
                    "{key_word:?} not in {error_message:?}",
                );
            }
        }
        _ => panic!("{set_following_result_5:?}"),
    }
}
