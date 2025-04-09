use assert_matches::assert_matches;
use ic_nervous_system_agent::pocketic_impl::PocketIcAgent;
use ic_nervous_system_agent::sns::governance::GovernanceCanister;
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{nns, sns, NnsInstaller};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::add_wasms_to_sns_wasm,
};
use ic_sns_governance_api::pb::v1::manage_neuron::{Follow, SetFollowing};
use ic_sns_governance_api::pb::v1::manage_neuron_response::{
    Command, FollowResponse, SetFollowingResponse,
};
use ic_sns_governance_api::pb::v1::neuron::{Followees, FolloweesForTopic, TopicFollowees};
use ic_sns_governance_api::pb::v1::topics::Topic;
use ic_sns_governance_api::pb::v1::{
    get_neuron_response, Followee, GetNeuronResponse, ManageNeuronResponse, Neuron,
};
use ic_sns_swap::pb::v1::Lifecycle;
use maplit::btreemap;
use pocket_ic::PocketIcBuilder;
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_set_following() {
    run_set_following_test().await;
}

async fn run_set_following_test() {
    // Prepare the world
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    // Install the NNS canisters.
    {
        let mut nns_installer = NnsInstaller::default();
        nns_installer.with_current_nns_canister_versions();
        nns_installer.install(&pocket_ic).await;
    }

    // Publish SNS Wasms to SNS-W.
    let with_mainnet_sns_canisters = false;
    add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
        .await
        .unwrap();

    let sns = {
        // Setting these two values to over 5 and 2.5 days, resp., so that critical proposals have
        // a different `initial_voting_period` than normal proposals.
        // See `Action.voting_duration_parameters`.
        let initial_voting_period_seconds = 4 * ONE_DAY_SECONDS;
        let wait_for_quiet_deadline_increase_seconds = 2 * ONE_DAY_SECONDS;

        let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
            .with_governance_parameters_proposal_initial_voting_period(
                initial_voting_period_seconds,
            )
            .with_governance_parameters_proposal_wait_for_quiet_deadline_increase(
                wait_for_quiet_deadline_increase_seconds,
            )
            .build();

        let swap_parameters = create_service_nervous_system
            .swap_parameters
            .clone()
            .unwrap();

        let sns_instance_label = "1";
        let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
            &pocket_ic,
            create_service_nervous_system,
            sns_instance_label,
        )
        .await;

        sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
            .await
            .unwrap();
        sns::swap::smoke_test_participate_and_finalize(
            &pocket_ic,
            sns.swap.canister_id,
            swap_parameters,
        )
        .await;

        sns
    };

    // Get an ID of an SNS neuron that can submit proposals. We rely on the fact that this
    // neuron either holds the majority of the voting power or the follow graph is set up
    // s.t. when this neuron submits a proposal, that proposal gets through without the need
    // for any voting.
    let (my_sns_neuron_id, sender) = sns::governance::find_neuron_with_majority_voting_power(
        &pocket_ic,
        sns.governance.canister_id,
    )
    .await
    .expect("cannot find SNS neuron with dissolve delay over 6 months.");

    let another_sns_neuron_id = sns::governance::find_another_neuron(
        &pocket_ic,
        sns.governance.canister_id,
        my_sns_neuron_id.clone(),
    )
    .await
    .expect("cannot find a second SNS neuron.");

    // Smoke test
    assert_ne!(another_sns_neuron_id, my_sns_neuron_id);

    let expected_followee = Followee {
        neuron_id: Some(another_sns_neuron_id.clone()),
        alias: Some("Bob Dylan".to_string()),
    };

    let pocket_ic_agent = PocketIcAgent {
        pocket_ic: &pocket_ic,
        sender: sender.into(),
    };

    let governance_canister = GovernanceCanister {
        canister_id: sns.governance.canister_id,
    };

    let ManageNeuronResponse { command } = governance_canister
        .follow(
            &pocket_ic_agent,
            my_sns_neuron_id.clone(),
            Follow {
                function_id: 0, // catch-all
                followees: vec![another_sns_neuron_id.clone()],
            },
        )
        .await
        .unwrap();

    assert_eq!(command, Some(Command::Follow(FollowResponse {})));

    let ManageNeuronResponse { command } = governance_canister
        .follow(
            &pocket_ic_agent,
            my_sns_neuron_id.clone(),
            Follow {
                function_id: 1, // E.g., MOTION (essentially, any non-critical proposal type)
                followees: vec![another_sns_neuron_id.clone()],
            },
        )
        .await
        .unwrap();

    assert_eq!(command, Some(Command::Follow(FollowResponse {})));

    // Follow someone on 4 out of 5 non-critical topics and all critical topics.
    // Topic::ApplicationBusinessLogic is not yet followed, as this topic contains the proposal
    // type `MOTION` (ID 1), for which we have legacy following.
    for topic in [
        Topic::DaoCommunitySettings,
        Topic::SnsFrameworkManagement,
        Topic::DappCanisterManagement,
        // `Topic::ApplicationBusinessLogic` is the only one missing from the list.
        Topic::Governance,
        Topic::TreasuryAssetManagement,
        Topic::CriticalDappOperations,
    ] {
        let ManageNeuronResponse { command } = governance_canister
            .set_following(
                &pocket_ic_agent,
                my_sns_neuron_id.clone(),
                SetFollowing {
                    topic_following: vec![FolloweesForTopic {
                        followees: vec![expected_followee.clone()],
                        topic: Some(topic),
                    }],
                },
            )
            .await
            .unwrap();

        assert_eq!(
            command,
            Some(Command::SetFollowing(SetFollowingResponse {}))
        );
    }

    // Check that the neuron still has the catch-all following.
    {
        let GetNeuronResponse { result } = governance_canister
            .get_neuron(&pocket_ic_agent, my_sns_neuron_id.clone())
            .await
            .unwrap();

        let (observed_followees, observed_topic_followees) = assert_matches!(
            result,
            Some(get_neuron_response::Result::Neuron(Neuron {
                followees,
                topic_followees,
                ..
            })) => {
                (followees, topic_followees)
            }
        );

        assert_eq!(
            observed_followees,
            btreemap! {
                0_u64 => Followees { followees: vec![another_sns_neuron_id.clone()] },
            }
        );

        assert_eq!(
            observed_topic_followees,
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::DaoCommunitySettings as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::DaoCommunitySettings) },
                    Topic::SnsFrameworkManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::SnsFrameworkManagement) },
                    Topic::DappCanisterManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::DappCanisterManagement) },
                    // `Topic::ApplicationBusinessLogic` is the only one missing from the list.
                    Topic::Governance as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::Governance) },
                    Topic::TreasuryAssetManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::TreasuryAssetManagement) },
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::CriticalDappOperations) },
                }
            })
        );
    }

    // Now follow also on the Governance topic.
    let ManageNeuronResponse { command } = governance_canister
        .set_following(
            &pocket_ic_agent,
            my_sns_neuron_id.clone(),
            SetFollowing {
                topic_following: vec![FolloweesForTopic {
                    followees: vec![expected_followee.clone()],
                    topic: Some(Topic::ApplicationBusinessLogic),
                }],
            },
        )
        .await
        .unwrap();

    assert_eq!(
        command,
        Some(Command::SetFollowing(SetFollowingResponse {}))
    );

    // Check that the neuron no longer has the catch-all following.
    {
        let GetNeuronResponse { result } = governance_canister
            .get_neuron(&pocket_ic_agent, my_sns_neuron_id.clone())
            .await
            .unwrap();

        let (observed_followees, observed_topic_followees) = assert_matches!(
            result,
            Some(get_neuron_response::Result::Neuron(Neuron {
                followees,
                topic_followees,
                ..
            })) => (followees, topic_followees)
        );

        assert_eq!(observed_followees, btreemap! {});

        assert_eq!(
            observed_topic_followees,
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::DaoCommunitySettings as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::DaoCommunitySettings) },
                    Topic::SnsFrameworkManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::SnsFrameworkManagement) },
                    Topic::DappCanisterManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::DappCanisterManagement) },
                    Topic::ApplicationBusinessLogic as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::ApplicationBusinessLogic) },
                    Topic::Governance as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::Governance) },
                    Topic::TreasuryAssetManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::TreasuryAssetManagement) },
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::CriticalDappOperations) },
                }
            })
        );
    }

    // Check that legacy following can still be added via the legacy follow command.

    let ManageNeuronResponse { command } = governance_canister
        .follow(
            &pocket_ic_agent,
            my_sns_neuron_id.clone(),
            Follow {
                function_id: 0, // catch-all
                followees: vec![another_sns_neuron_id.clone()],
            },
        )
        .await
        .unwrap();

    assert_eq!(command, Some(Command::Follow(FollowResponse {})));

    let ManageNeuronResponse { command } = governance_canister
        .follow(
            &pocket_ic_agent,
            my_sns_neuron_id.clone(),
            Follow {
                function_id: 1, // Again, we use MOTION (essentially, any non-critical proposal type)
                followees: vec![another_sns_neuron_id.clone()],
            },
        )
        .await
        .unwrap();

    assert_eq!(command, Some(Command::Follow(FollowResponse {})));

    // Check that the neuron has legacy following again.
    {
        let GetNeuronResponse { result } = governance_canister
            .get_neuron(&pocket_ic_agent, my_sns_neuron_id.clone())
            .await
            .unwrap();

        let (observed_followees, observed_topic_followees) = assert_matches!(
            result,
            Some(get_neuron_response::Result::Neuron(Neuron {
                followees,
                topic_followees,
                ..
            })) => (followees, topic_followees)
        );

        assert_eq!(
            observed_followees,
            btreemap! {
                0_u64 => Followees { followees: vec![another_sns_neuron_id.clone()] },
                1_u64 => Followees { followees: vec![another_sns_neuron_id.clone()] },
            }
        );

        assert_eq!(
            observed_topic_followees,
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::DaoCommunitySettings as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::DaoCommunitySettings) },
                    Topic::SnsFrameworkManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::SnsFrameworkManagement) },
                    Topic::DappCanisterManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::DappCanisterManagement) },
                    Topic::ApplicationBusinessLogic as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::ApplicationBusinessLogic) },
                    Topic::Governance as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::Governance) },
                    Topic::TreasuryAssetManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::TreasuryAssetManagement) },
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::CriticalDappOperations) },
                }
            })
        );
    }

    // Check that specifying following that does not cover one non-critical topic does not remove
    // legacy following.
    {
        let ManageNeuronResponse { command } = governance_canister
            .set_following(
                &pocket_ic_agent,
                my_sns_neuron_id.clone(),
                SetFollowing {
                    topic_following: vec![FolloweesForTopic {
                        followees: vec![],
                        // DaoCommunitySettings does not include the MOTION proposal type,
                        // so this specification by itself should not remove legacy following
                        // for the MOTION proposal type.
                        topic: Some(Topic::DaoCommunitySettings),
                    }],
                },
            )
            .await
            .unwrap();

        assert_eq!(
            command,
            Some(Command::SetFollowing(SetFollowingResponse {}))
        );
    }

    {
        let GetNeuronResponse { result } = governance_canister
            .get_neuron(&pocket_ic_agent, my_sns_neuron_id.clone())
            .await
            .unwrap();

        let (observed_followees, observed_topic_followees) = assert_matches!(
            result,
            Some(get_neuron_response::Result::Neuron(Neuron {
                followees,
                topic_followees,
                ..
            })) => (followees, topic_followees)
        );

        assert_eq!(
            observed_followees,
            btreemap! {
                0_u64 => Followees { followees: vec![another_sns_neuron_id.clone()] },
                1_u64 => Followees { followees: vec![another_sns_neuron_id.clone()] },
            }
        );

        assert_eq!(
            observed_topic_followees,
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    // `Topic::DaoCommunitySettings` has been unset.
                    Topic::SnsFrameworkManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::SnsFrameworkManagement) },
                    Topic::DappCanisterManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::DappCanisterManagement) },
                    Topic::ApplicationBusinessLogic as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::ApplicationBusinessLogic) },
                    Topic::Governance as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::Governance) },
                    Topic::TreasuryAssetManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::TreasuryAssetManagement) },
                    Topic::CriticalDappOperations as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::CriticalDappOperations) },
                }
            })
        );
    }

    // Remove the rest of topic-based following to prepate for the next step.
    {
        let topic_following = [
            // This topic has been cleared above, but it should be harmless to try to clean it again.
            Topic::DaoCommunitySettings,
            Topic::SnsFrameworkManagement,
            Topic::DappCanisterManagement,
            Topic::ApplicationBusinessLogic,
            Topic::Governance,
            Topic::TreasuryAssetManagement,
            Topic::CriticalDappOperations,
        ]
        .iter()
        .map(|topic| FolloweesForTopic {
            followees: vec![],
            topic: Some(*topic),
        })
        .collect();

        let ManageNeuronResponse { command } = governance_canister
            .set_following(
                &pocket_ic_agent,
                my_sns_neuron_id.clone(),
                SetFollowing { topic_following },
            )
            .await
            .unwrap();

        assert_eq!(
            command,
            Some(Command::SetFollowing(SetFollowingResponse {}))
        );
    }

    // Check that specifying *all* non-critical topics in one proposal is enough to remove legacy
    // catch-all following.
    {
        let topic_following = [
            Topic::DaoCommunitySettings,
            Topic::SnsFrameworkManagement,
            Topic::DappCanisterManagement,
            Topic::ApplicationBusinessLogic,
            Topic::Governance,
        ]
        .iter()
        .map(|topic| FolloweesForTopic {
            followees: vec![expected_followee.clone()],
            topic: Some(*topic),
        })
        .collect();

        let ManageNeuronResponse { command } = governance_canister
            .set_following(
                &pocket_ic_agent,
                my_sns_neuron_id.clone(),
                SetFollowing { topic_following },
            )
            .await
            .unwrap();

        assert_eq!(
            command,
            Some(Command::SetFollowing(SetFollowingResponse {}))
        );
    }

    // Final state: No more legacy following, and topic-following on all non-critical proposals.
    {
        let GetNeuronResponse { result } = governance_canister
            .get_neuron(&pocket_ic_agent, my_sns_neuron_id)
            .await
            .unwrap();

        let (observed_followees, observed_topic_followees) = assert_matches!(
            result,
            Some(get_neuron_response::Result::Neuron(Neuron {
                followees,
                topic_followees,
                ..
            })) => (followees, topic_followees)
        );

        assert_eq!(observed_followees, btreemap! {});

        assert_eq!(
            observed_topic_followees,
            Some(TopicFollowees {
                topic_id_to_followees: btreemap! {
                    Topic::DaoCommunitySettings as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::DaoCommunitySettings) },
                    Topic::SnsFrameworkManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::SnsFrameworkManagement) },
                    Topic::DappCanisterManagement as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::DappCanisterManagement) },
                    Topic::ApplicationBusinessLogic as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::ApplicationBusinessLogic) },
                    Topic::Governance as i32 => FolloweesForTopic { followees: vec![expected_followee.clone()], topic: Some(Topic::Governance) },
                }
            })
        );
    }
}
