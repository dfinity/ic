use assert_matches::assert_matches;
use candid::Encode;
use canister_test::Wasm;
use ic_base_types::PrincipalId;
use ic_nervous_system_agent::pocketic_impl::PocketIcAgent;
use ic_nervous_system_agent::sns::governance::{GovernanceCanister, SubmittedProposal};
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    NnsInstaller, install_canister_on_subnet, nns, sns, universal_canister,
};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::add_wasms_to_sns_wasm,
};
use ic_nervous_system_proto::pb::v1::Percentage;
use ic_sns_governance_api::pb::v1::get_proposal_response;
use ic_sns_governance_api::pb::v1::nervous_system_function::{
    FunctionType, GenericNervousSystemFunction,
};
use ic_sns_governance_api::pb::v1::proposal::Action;
use ic_sns_governance_api::pb::v1::topics::{ListTopicsResponse, Topic};
use ic_sns_governance_api::pb::v1::{
    ExecuteGenericNervousSystemFunction, GetProposalResponse, NervousSystemFunction, Proposal,
    ProposalData, SetTopicsForCustomProposals,
};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use maplit::btreemap;
use pocket_ic::PocketIcBuilder;
use pretty_assertions::assert_eq;

const DUMMY_URL_FOR_PROPOSALS: &str = "https://forum.dfinity.org";

/// Runbook:
/// 1. Custom proposal type can be added to an SNS under a critical topic.
/// 2. Listing topics of that SNS indicates the expected information.
/// 3. Topic of a custom proposal can be changed, in particular, from critical to non-critical.
/// 4. Proposals on this custom type can actually be submitted, and their criticality
///    (and the voting parameters affected by criticality) are defined as expected, both
///    before and after the change of topic.
#[tokio::test]
async fn set_custom_sns_topics_test() {
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

    // Install the validator canister on an application subnet.
    let (validator_canister_id, proposal_payload) = {
        let topology = pocket_ic.topology().await;
        let app_subnet = topology.get_app_subnets()[0];

        let validator_controller = PrincipalId::new_user_test_id(43);

        // This is needed to ensure the validator canister has enough stable memory to store
        // the bytes we'd like to to serve upon a validation request.
        let init_payload = universal_canister::init_payload(1);

        let validator_canister_id = install_canister_on_subnet(
            &pocket_ic,
            app_subnet,
            init_payload,
            Some(Wasm::from_bytes(&UNIVERSAL_CANISTER_WASM[..])),
            vec![validator_controller],
        )
        .await
        .get();

        // The SNS expects the response to be an encoding of `Result<String, String>`.
        let written_data = Encode!(&Ok::<String, String>("Aloha!".to_string())).unwrap();

        universal_canister::stable_write(&pocket_ic, validator_canister_id, 0, &written_data)
            .await
            .unwrap();

        let read_data = universal_canister::stable_read(
            &pocket_ic,
            validator_canister_id,
            0,
            written_data.len() as u32,
        )
        .await
        .unwrap();

        assert_eq!(read_data, written_data);

        let proposal_payload =
            universal_canister::stable_read_payload(0, written_data.len() as u32);

        (validator_canister_id, proposal_payload)
    };

    let initial_generic_function = GenericNervousSystemFunction {
        target_canister_id: Some(PrincipalId::new_user_test_id(42)),
        target_method_name: Some("do_things".to_string()),
        // To avoid having to deploy a dapp canister for this SNS, use Index.status for validation.
        validator_canister_id: Some(validator_canister_id),
        validator_method_name: Some("query".to_string()),
        topic: Some(Topic::CriticalDappOperations),
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

    // Add a generic SNS proposal under the initial topic (`CriticalDappOperations`).
    {
        let response = governance_canister
            .submit_proposal(
                &pocket_ic_agent,
                sns_neuron_id.clone(),
                Proposal {
                    title: "Add custom proposal under the CriticalDappOperations topic."
                        .to_string(),
                    summary: "Add custom proposal under the CriticalDappOperations topic."
                        .to_string(),
                    url: DUMMY_URL_FOR_PROPOSALS.to_string(),
                    action: Some(Action::AddGenericNervousSystemFunction(
                        initial_function.clone(),
                    )),
                },
            )
            .await
            .unwrap();

        let proposal_id = SubmittedProposal::try_from(response).unwrap().proposal_id;

        sns::governance::wait_for_proposal_execution(
            &pocket_ic,
            sns.governance.canister_id,
            proposal_id,
        )
        .await
        .unwrap();
    }

    // Assert that the proposal is originally under the `CriticalDappOperations` topic.
    let ListTopicsResponse {
        topics,
        uncategorized_functions,
    } = governance_canister.list_topics(&pocket_ic).await.unwrap();

    assert_eq!(uncategorized_functions, Some(vec![]));

    let custom_proposal_topics = topics
        .unwrap()
        .into_iter()
        .map(|topic_info| {
            (
                topic_info.name.unwrap(),
                topic_info.custom_functions,
                topic_info.is_critical.unwrap(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        custom_proposal_topics,
        vec![
            ("DAO community settings".to_string(), Some(vec![]), true),
            ("SNS framework management".to_string(), Some(vec![]), false),
            ("Dapp canister management".to_string(), Some(vec![]), false),
            (
                "Application Business Logic".to_string(),
                Some(vec![]),
                false
            ),
            ("Governance".to_string(), Some(vec![]), false),
            (
                "Treasury & asset management".to_string(),
                Some(vec![]),
                true
            ),
            (
                "Critical Dapp Operations".to_string(),
                Some(vec![initial_function]),
                true,
            ),
        ],
    );

    // Check that the newly added custom proposal can be submitted.
    let first_custom_proposal_id = {
        let response = governance_canister
            .submit_proposal(
                &pocket_ic_agent,
                sns_neuron_id.clone(),
                Proposal {
                    title: "Execute custom proposal (1).".to_string(),
                    summary: "Execute custom proposal (1).".to_string(),
                    url: DUMMY_URL_FOR_PROPOSALS.to_string(),
                    action: Some(Action::ExecuteGenericNervousSystemFunction(
                        ExecuteGenericNervousSystemFunction {
                            function_id: 1111,
                            payload: proposal_payload.clone(),
                        },
                    )),
                },
            )
            .await
            .unwrap();

        SubmittedProposal::try_from(response).unwrap().proposal_id
    };

    // Run code under test (change the custom SNS proposal's topic to `ApplicationBusinessLogic`).
    {
        let response = governance_canister
            .submit_proposal(
                &pocket_ic_agent,
                sns_neuron_id.clone(),
                Proposal {
                    title: "Set custom SNS proposal topics.".to_string(),
                    summary: "Set custom SNS proposal topics.".to_string(),
                    url: DUMMY_URL_FOR_PROPOSALS.to_string(),
                    action: Some(Action::SetTopicsForCustomProposals(
                        SetTopicsForCustomProposals {
                            custom_function_id_to_topic: btreemap! {
                                1111 => Topic::ApplicationBusinessLogic,
                            },
                        },
                    )),
                },
            )
            .await
            .unwrap();

        let proposal_id = SubmittedProposal::try_from(response).unwrap().proposal_id;

        sns::governance::wait_for_proposal_execution(
            &pocket_ic,
            sns.governance.canister_id,
            proposal_id,
        )
        .await
        .unwrap();
    }

    // Assert that the intended changes took place in the list of topics.
    let ListTopicsResponse {
        topics,
        uncategorized_functions,
    } = governance_canister.list_topics(&pocket_ic).await.unwrap();

    assert_eq!(uncategorized_functions, Some(vec![]));

    let custom_proposal_topics = topics
        .unwrap()
        .into_iter()
        .map(|topic_info| {
            (
                topic_info.name.unwrap(),
                topic_info.custom_functions,
                topic_info.is_critical.unwrap(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        custom_proposal_topics,
        vec![
            ("DAO community settings".to_string(), Some(vec![]), true),
            ("SNS framework management".to_string(), Some(vec![]), false),
            ("Dapp canister management".to_string(), Some(vec![]), false),
            (
                "Application Business Logic".to_string(),
                Some(vec![expected_function]),
                false,
            ),
            ("Governance".to_string(), Some(vec![]), false),
            (
                "Treasury & asset management".to_string(),
                Some(vec![]),
                true
            ),
            ("Critical Dapp Operations".to_string(), Some(vec![]), true),
        ],
    );

    // Check that the custom proposal can still be submitted.
    let second_custom_proposal_id = {
        let response = governance_canister
            .submit_proposal(
                &pocket_ic_agent,
                sns_neuron_id,
                Proposal {
                    title: "Execute custom proposal (2).".to_string(),
                    summary: "Execute custom proposal (2).".to_string(),
                    url: DUMMY_URL_FOR_PROPOSALS.to_string(),
                    action: Some(Action::ExecuteGenericNervousSystemFunction(
                        ExecuteGenericNervousSystemFunction {
                            function_id: 1111,
                            payload: proposal_payload,
                        },
                    )),
                },
            )
            .await
            .unwrap();

        SubmittedProposal::try_from(response).unwrap().proposal_id
    };

    // Inspect the two proposals: Before and after the topic (and criticality) were changed for
    // the custom proposal type.

    let first_custom_proposal = {
        let GetProposalResponse { result } = governance_canister
            .get_proposal(&pocket_ic, first_custom_proposal_id)
            .await
            .unwrap();

        let result = result.unwrap();

        assert_matches!(result, get_proposal_response::Result::Proposal(proposal) => proposal)
    };

    let second_custom_proposal = {
        let GetProposalResponse { result } = governance_canister
            .get_proposal(&pocket_ic, second_custom_proposal_id)
            .await
            .unwrap();

        let result = result.unwrap();

        assert_matches!(result, get_proposal_response::Result::Proposal(proposal) => proposal)
    };

    assert_matches!(
        first_custom_proposal,
        ProposalData {
            action: 1111,
            topic: Some(Topic::CriticalDappOperations),
            // The following fields are affected by proposal criticality, so we assert that they
            // ended up having the expected values.
            initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds,
            minimum_yes_proportion_of_total: Some(Percentage {
                basis_points: Some(2000),
            }),
            minimum_yes_proportion_of_exercised: Some(Percentage {
                basis_points: Some(6700),
            }),
            ..
        } => {
            // Critical proposals have the following two parameters at least 5 and 2.5 days, resp.
            // See `Action.voting_duration_parameters`.
            assert_eq!(initial_voting_period_seconds, 5 * ONE_DAY_SECONDS);
            assert_eq!(wait_for_quiet_deadline_increase_seconds, 2 * ONE_DAY_SECONDS + ONE_DAY_SECONDS / 2);
        }
    );

    assert_matches!(
        second_custom_proposal,
        ProposalData {
            action: 1111,
            topic: Some(Topic::ApplicationBusinessLogic),
            // The following fields are affected by proposal criticality, so we assert that they
            // ended up having the expected values.
            initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds,
            minimum_yes_proportion_of_total: Some(Percentage {
                basis_points: Some(300),
            }),
            minimum_yes_proportion_of_exercised: Some(Percentage {
                basis_points: Some(5000),
            }),
            ..
        } => {
            assert_eq!(initial_voting_period_seconds, 4 * ONE_DAY_SECONDS);
            assert_eq!(wait_for_quiet_deadline_increase_seconds, 2 * ONE_DAY_SECONDS);
        }
    );
}
