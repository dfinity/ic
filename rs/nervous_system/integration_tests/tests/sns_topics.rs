use ic_base_types::PrincipalId;
use ic_nervous_system_agent::pocketic_impl::PocketIcAgent;
use ic_nervous_system_agent::sns::governance::{GovernanceCanister, SubmittedProposal};
use ic_nervous_system_integration_tests::pocket_ic_helpers::{nns, sns, NnsInstaller};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::add_wasms_to_sns_wasm,
};
use ic_sns_governance_api::pb::v1::nervous_system_function::{
    FunctionType, GenericNervousSystemFunction,
};
use ic_sns_governance_api::pb::v1::proposal::Action;
use ic_sns_governance_api::pb::v1::topics::{ListTopicsResponse, Topic};
use ic_sns_governance_api::pb::v1::{NervousSystemFunction, Proposal, SetCustomProposalTopics};
use ic_sns_swap::pb::v1::Lifecycle;
use maplit::btreemap;
use pocket_ic::PocketIcBuilder;

const DUMMY_URL_FOR_PROPOSALS: &str = "https://forum.dfinity.org";

#[tokio::test]
async fn test_set_custom_sns_topics() {
    // 1. Prepare the world
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
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
        let create_service_nervous_system = CreateServiceNervousSystemBuilder::default().build();

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

        sns
    };

    // Get an ID of an SNS neuron that can submit proposals. We rely on the fact that this
    // neuron either holds the majority of the voting power or the follow graph is set up
    // s.t. when this neuron submits a proposal, that proposal gets through without the need
    // for any voting.
    let (sns_neuron_id, sender) = sns::governance::find_neuron_with_majority_voting_power(
        &pocket_ic,
        sns.governance.canister_id,
    )
    .await
    .expect("cannot find SNS neuron with dissolve delay over 6 months.");

    let pocket_ic_agent = PocketIcAgent {
        pocket_ic: &pocket_ic,
        sender: sender.into(),
    };

    let governance_canister = GovernanceCanister {
        canister_id: sns.governance.canister_id,
    };

    let initial_generic_function = GenericNervousSystemFunction {
        target_canister_id: Some(PrincipalId::new_user_test_id(42)),
        target_method_name: Some("do_things".to_string()),
        validator_canister_id: Some(PrincipalId::new_user_test_id(43)),
        validator_method_name: Some("validate_things".to_string()),
        topic: Some(Topic::DaoCommunitySettings),
    };

    let expected_generic_function = GenericNervousSystemFunction {
        topic: Some(Topic::ApplicationBusinessLogic),
        ..initial_generic_function.clone()
    };

    let initial_function = NervousSystemFunction {
        id: 1111,
        name: "Test Custom Proposal Type".to_string(),
        description: Some("This is a custom proposal type for testing.".to_string()),
        function_type: Some(FunctionType::GenericNervousSystemFunction(
            initial_generic_function,
        )),
    };

    let expected_function = NervousSystemFunction {
        function_type: Some(FunctionType::GenericNervousSystemFunction(
            expected_generic_function,
        )),
        ..initial_function.clone()
    };

    // AddGenericNervousSystemFunction
    {
        let response = governance_canister
            .submit_proposal(
                &pocket_ic_agent,
                sns_neuron_id.clone(),
                Proposal {
                    title: "Add custom proposal under the DaoCommunitySettings topic.".to_string(),
                    summary: "Add custom proposal under the DaoCommunitySettings topic."
                        .to_string(),
                    url: DUMMY_URL_FOR_PROPOSALS.to_string(),
                    action: Some(Action::AddGenericNervousSystemFunction(initial_function)),
                },
            )
            .await
            .unwrap();

        let proposal_id = SubmittedProposal::try_from(response)
            .unwrap()
            .proposal_id
            .id;

        nns::governance::wait_for_proposal_execution(&pocket_ic, proposal_id)
            .await
            .unwrap();
    }

    // SetCustomProposalTopics
    {
        let response = governance_canister
            .submit_proposal(
                &pocket_ic_agent,
                sns_neuron_id,
                Proposal {
                    title: "Set custom SNS proposal topics.".to_string(),
                    summary: "Set custom SNS proposal topics.".to_string(),
                    url: DUMMY_URL_FOR_PROPOSALS.to_string(),
                    action: Some(Action::SetCustomProposalTopics(SetCustomProposalTopics {
                        custom_function_id_to_topic: btreemap! {
                            1111_u64 => Topic::ApplicationBusinessLogic,
                        },
                    })),
                },
            )
            .await
            .unwrap();

        let proposal_id = SubmittedProposal::try_from(response)
            .unwrap()
            .proposal_id
            .id;

        nns::governance::wait_for_proposal_execution(&pocket_ic, proposal_id)
            .await
            .unwrap();
    }

    // Assert that the intended changes took place.
    let ListTopicsResponse {
        topics,
        uncategorized_functions,
    } = governance_canister.list_topics(&pocket_ic).await.unwrap();

    assert_eq!(uncategorized_functions, Some(vec![]));

    let custom_proposal_topics = topics
        .unwrap()
        .into_iter()
        .map(|topic_info| (topic_info.name.unwrap(), topic_info.custom_functions))
        .collect::<Vec<_>>();

    assert_eq!(
        custom_proposal_topics,
        vec![
            ("DAO community settings".to_string(), Some(vec![])),
            ("SNS framework management".to_string(), Some(vec![])),
            ("Dapp canister management".to_string(), Some(vec![])),
            (
                "Application Business Logic".to_string(),
                Some(vec![expected_function])
            ),
            ("Governance".to_string(), Some(vec![])),
            ("Treasury & asset management".to_string(), Some(vec![])),
            ("Critical Dapp Operations".to_string(), Some(vec![])),
        ],
    );
}
