use ic_base_types::PrincipalId;
use ic_nervous_system_agent::pocketic_impl::PocketIcAgent;
use ic_nervous_system_agent::sns::governance::{GovernanceCanister, SubmittedProposal};
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    NnsInstaller, add_wasms_to_sns_wasm, nns, sns,
};
use ic_nervous_system_integration_tests::create_service_nervous_system_builder::CreateServiceNervousSystemBuilder;
use ic_nervous_system_proto::pb::v1::{Duration as DurationPb, Tokens as TokensPb};
use ic_nns_governance_api::create_service_nervous_system::governance_parameters::CustomProposalCriticality;
use ic_nns_governance_api::create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution;
use ic_sns_governance_api::pb::v1::{
    get_proposal_response, proposal::Action, CustomProposalCriticality as SnsCustomProposalCriticality,
    GetProposalResponse, Motion, NervousSystemParameters, Proposal, Vote,
};
use ic_sns_swap::pb::v1::Lifecycle;
use pocket_ic::PocketIcBuilder;

/// Runbook:
/// 1. Set up an SNS with Motion as "additional critical proposal type",
///    with 3 neurons: 51%, 17%, and 32% of voting power.
/// 2. Submit a motion proposal with neuron 1 (51%) and assert it is NOT
///    executed, since critical proposals need >67% of total for early decision.
/// 3. Have neuron 2 (17%) vote yes. Now 51% + 17% = 68% > 67%, so the
///    proposal should be adopted and executed.
/// 4. Submit a ManageNervousSystemParameters proposal to remove Motion from
///    the critical proposal types.
/// 5. Submit another motion proposal with neuron 1 (51%) and assert it is
///    executed immediately, since it now only needs >50% for early decision.
#[tokio::test]
async fn custom_proposal_criticality_test() {
    // Step 0: Set up the world.
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

    // Define neuron controllers.
    let controller1 = PrincipalId::new_user_test_id(101);
    let controller2 = PrincipalId::new_user_test_id(102);
    let controller3 = PrincipalId::new_user_test_id(103);

    // Define neuron stakes proportional to 51%, 17%, 32%.
    let stake1 = 510_000_000u64;
    let stake2 = 170_000_000u64;
    let stake3 = 320_000_000u64;

    let dissolve_delay_seconds = ONE_MONTH_SECONDS * 6;

    let developer_neurons = vec![
        NeuronDistribution {
            controller: Some(controller1),
            memo: Some(1),
            dissolve_delay: Some(DurationPb::from_secs(dissolve_delay_seconds)),
            stake: Some(TokensPb::from_e8s(stake1)),
            vesting_period: Some(DurationPb::from_secs(0)),
        },
        NeuronDistribution {
            controller: Some(controller2),
            memo: Some(2),
            dissolve_delay: Some(DurationPb::from_secs(dissolve_delay_seconds)),
            stake: Some(TokensPb::from_e8s(stake2)),
            vesting_period: Some(DurationPb::from_secs(0)),
        },
        NeuronDistribution {
            controller: Some(controller3),
            memo: Some(3),
            dissolve_delay: Some(DurationPb::from_secs(dissolve_delay_seconds)),
            stake: Some(TokensPb::from_e8s(stake3)),
            vesting_period: Some(DurationPb::from_secs(0)),
        },
    ];

    // Build the CreateServiceNervousSystem with Motion (action id 1) as critical.
    let mut create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .initial_token_distribution_developer_neurons(developer_neurons)
        .build();

    create_service_nervous_system
        .governance_parameters
        .as_mut()
        .unwrap()
        .custom_proposal_criticality = Some(CustomProposalCriticality {
        additional_critical_native_action_ids: Some(vec![1]), // Motion = 1
    });

    let swap_parameters = create_service_nervous_system
        .swap_parameters
        .clone()
        .unwrap();

    // Deploy the SNS.
    let sns_instance_label = "1";
    let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    )
    .await;

    // Wait for swap to open and complete it.
    // Swap neurons have short dissolve delays (<<6 months) so they cannot vote,
    // meaning voting power proportions remain 51%/17%/32%.
    sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
        .await
        .unwrap();

    sns::swap::smoke_test_participate_and_finalize(
        &pocket_ic,
        sns.swap.canister_id,
        swap_parameters,
    )
    .await;

    // Find developer neurons by their controller principal.
    let neurons = sns::governance::list_neurons(&pocket_ic, sns.governance.canister_id)
        .await
        .neurons;

    let find_neuron_id =
        |controller: PrincipalId| -> ic_sns_governance_api::pb::v1::NeuronId {
            neurons
                .iter()
                .find(|n| n.permissions.iter().any(|p| p.principal == Some(controller)))
                .unwrap_or_else(|| panic!("Neuron for controller {controller} not found"))
                .id
                .clone()
                .unwrap()
        };

    let neuron1_id = find_neuron_id(controller1);
    let neuron2_id = find_neuron_id(controller2);

    let governance_canister = GovernanceCanister {
        canister_id: sns.governance.canister_id,
    };

    // --- Step 2: Submit motion proposal with neuron 1 (51%), assert NOT executed ---
    //
    // For critical proposals, early decision requires >67% of total voting power.
    // 51% < 67%, so the proposal should remain open.
    let motion_proposal_id = {
        let agent1 = PocketIcAgent {
            pocket_ic: &pocket_ic,
            sender: controller1.into(),
        };
        let response = governance_canister
            .submit_proposal(
                &agent1,
                neuron1_id.clone(),
                Proposal {
                    title: "Critical motion proposal".to_string(),
                    summary: "Testing that critical motion needs >67% to pass".to_string(),
                    url: "https://forum.dfinity.org".to_string(),
                    action: Some(Action::Motion(Motion {
                        motion_text: "This is a critical motion.".to_string(),
                    })),
                },
            )
            .await
            .unwrap();
        SubmittedProposal::try_from(response).unwrap().proposal_id
    };

    // Tick to allow proposal processing.
    for _ in 0..10 {
        pocket_ic.tick().await;
    }

    // Verify the proposal is NOT decided or executed.
    {
        let GetProposalResponse { result } = governance_canister
            .get_proposal(&pocket_ic, motion_proposal_id)
            .await
            .unwrap();
        let proposal_data = match result.unwrap() {
            get_proposal_response::Result::Proposal(p) => p,
            other => panic!("Expected Proposal, got: {other:?}"),
        };
        assert_eq!(
            proposal_data.decided_timestamp_seconds, 0,
            "Critical motion with 51% yes should NOT be decided (needs >67% of total for early decision)"
        );
        assert_eq!(
            proposal_data.executed_timestamp_seconds, 0,
            "Critical motion with 51% yes should NOT be executed"
        );
    }

    // --- Step 3: Neuron 2 votes yes, total = 68% > 67%, assert proposal IS executed ---
    {
        let agent2 = PocketIcAgent {
            pocket_ic: &pocket_ic,
            sender: controller2.into(),
        };
        governance_canister
            .register_vote(&agent2, neuron2_id.clone(), motion_proposal_id, Vote::Yes as i32)
            .await
            .unwrap();
    }

    sns::governance::wait_for_proposal_execution(
        &pocket_ic,
        sns.governance.canister_id,
        motion_proposal_id,
    )
    .await
    .unwrap();

    {
        let GetProposalResponse { result } = governance_canister
            .get_proposal(&pocket_ic, motion_proposal_id)
            .await
            .unwrap();
        let proposal_data = match result.unwrap() {
            get_proposal_response::Result::Proposal(p) => p,
            other => panic!("Expected Proposal, got: {other:?}"),
        };
        assert!(
            proposal_data.decided_timestamp_seconds > 0,
            "Critical motion with 68% yes should be decided"
        );
        assert!(
            proposal_data.executed_timestamp_seconds > 0,
            "Critical motion with 68% yes should be executed"
        );
    }

    // --- Step 4: Remove Motion from critical proposal types ---
    //
    // ManageNervousSystemParameters is under the DaoCommunitySettings topic which
    // is critical, so it also needs >67% of total. Submit with neuron 1 (51%),
    // then have neuron 2 (17%) vote yes to reach 68%.
    {
        let manage_proposal_id = {
            let agent1 = PocketIcAgent {
                pocket_ic: &pocket_ic,
                sender: controller1.into(),
            };
            let response = governance_canister
                .submit_proposal(
                    &agent1,
                    neuron1_id.clone(),
                    Proposal {
                        title: "Remove Motion from critical proposal types".to_string(),
                        summary: "Set custom_proposal_criticality to empty".to_string(),
                        url: "https://forum.dfinity.org".to_string(),
                        action: Some(Action::ManageNervousSystemParameters(
                            NervousSystemParameters {
                                custom_proposal_criticality: Some(SnsCustomProposalCriticality {
                                    additional_critical_native_action_ids: vec![],
                                }),
                                ..Default::default()
                            },
                        )),
                    },
                )
                .await
                .unwrap();
            SubmittedProposal::try_from(response).unwrap().proposal_id
        };

        // Neuron 2 votes yes to push past the 67% threshold.
        {
            let agent2 = PocketIcAgent {
                pocket_ic: &pocket_ic,
                sender: controller2.into(),
            };
            governance_canister
                .register_vote(&agent2, neuron2_id, manage_proposal_id, Vote::Yes as i32)
                .await
                .unwrap();
        }

        let proposal_data = sns::governance::wait_for_proposal_execution(
            &pocket_ic,
            sns.governance.canister_id,
            manage_proposal_id,
        )
        .await
        .unwrap();

        assert!(
            proposal_data.executed_timestamp_seconds > 0,
            "ManageNervousSystemParameters proposal should be executed"
        );
    }

    // --- Step 5: Submit another motion with neuron 1, assert executed immediately ---
    //
    // Motion is no longer critical, so 51% > 50% is enough for early decision.
    {
        let proposal_data = sns::governance::propose_and_wait(
            &pocket_ic,
            sns.governance.canister_id,
            controller1,
            neuron1_id,
            Proposal {
                title: "Non-critical motion proposal".to_string(),
                summary: "After removing criticality, 51% should be enough".to_string(),
                url: "https://forum.dfinity.org".to_string(),
                action: Some(Action::Motion(Motion {
                    motion_text: "This motion should pass immediately.".to_string(),
                })),
            },
        )
        .await
        .unwrap();

        assert!(
            proposal_data.executed_timestamp_seconds > 0,
            "Non-critical motion with 51% yes should be executed immediately"
        );
    }
}
