use ic_canister_client::Sender;
use ic_nns_common::types::{NeuronId, ProposalId, UpdateIcpXdrConversionRatePayload};
use ic_nns_constants::ids::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL,
    TEST_USER4_PRINCIPAL, TEST_USER5_PRINCIPAL, TEST_USER6_PRINCIPAL, TEST_USER7_PRINCIPAL,
};
use ic_nns_governance::pb::v1::{
    add_or_remove_node_provider::Change,
    manage_neuron::{Command, NeuronIdOrSubaccount},
    manage_neuron_response::Command as CommandResponse,
    proposal::Action,
    AddOrRemoveNodeProvider, GovernanceError, ManageNeuron, ManageNeuronResponse, NnsFunction,
    NodeProvider, Proposal, ProposalStatus, RewardNodeProvider, RewardNodeProviders,
};
use ic_nns_test_utils::governance::submit_external_update_proposal;
use ic_nns_test_utils::{
    governance::{get_pending_proposals, wait_for_final_state},
    ids::TEST_NEURON_1_ID,
    itest_helpers::{local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder},
};
use ic_protobuf::registry::dc::v1::{AddOrRemoveDataCentersProposalPayload, DataCenterRecord};
use ic_protobuf::registry::node_rewards::v2::{
    NodeRewardRate, NodeRewardRates, UpdateNodeRewardsTableProposalPayload,
};
use maplit::btreemap;
use registry_canister::mutations::do_add_node_operator::AddNodeOperatorPayload;

use cycles_minting_canister::IcpXdrConversionRateCertifiedResponse;
use dfn_candid::candid_one;
use ic_nns_governance::pb::v1::reward_node_provider::{RewardMode, RewardToAccount};
use ic_types::PrincipalId;
use ledger_canister::{AccountIdentifier, TOKEN_SUBDIVIDABLE_BY};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_get_monthly_node_provider_rewards() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        add_data_centers(&nns_canisters).await;
        add_node_rewards_table(&nns_canisters).await;

        // Define the set of node operators and node providers
        let node_operator_id_1 = *TEST_USER1_PRINCIPAL;
        let node_provider_id_1 = *TEST_USER2_PRINCIPAL;
        let node_provider_1 = NodeProvider {
            id: Some(node_provider_id_1),
            reward_account: None,
        };
        let reward_mode_1 = Some(RewardMode::RewardToAccount(RewardToAccount {
            to_account: Some(AccountIdentifier::from(node_provider_id_1).into()),
        }));
        let expected_rewards_e8s_1 =
            (((10 * 24_000) + (21 * 68_000) + (6 * 11_000)) * TOKEN_SUBDIVIDABLE_BY) / 155_000;
        assert_eq!(expected_rewards_e8s_1, 1118709677);
        let expected_node_provider_reward_1 = RewardNodeProvider {
            node_provider: Some(node_provider_1.clone()),
            amount_e8s: expected_rewards_e8s_1,
            reward_mode: reward_mode_1,
        };

        let node_operator_id_2 = *TEST_USER3_PRINCIPAL;
        let node_provider_id_2 = *TEST_USER4_PRINCIPAL;
        let node_provider_2 = NodeProvider {
            id: Some(node_provider_id_2),
            reward_account: None,
        };
        let reward_mode_2 = Some(RewardMode::RewardToAccount(RewardToAccount {
            to_account: Some(AccountIdentifier::from(node_provider_id_2).into()),
        }));
        let expected_rewards_e8s_2 =
            (((35 * 68_000) + (17 * 11_000)) * TOKEN_SUBDIVIDABLE_BY) / 155_000;
        assert_eq!(expected_rewards_e8s_2, 1656129032);
        let expected_node_provider_reward_2 = RewardNodeProvider {
            node_provider: Some(node_provider_2.clone()),
            amount_e8s: expected_rewards_e8s_2,
            reward_mode: reward_mode_2,
        };

        let node_operator_id_3 = *TEST_USER5_PRINCIPAL;
        let node_provider_id_3 = *TEST_USER6_PRINCIPAL;
        let node_provider_3 = NodeProvider {
            id: Some(node_provider_id_3),
            reward_account: Some(AccountIdentifier::from(*TEST_USER7_PRINCIPAL).into()),
        };
        let reward_mode_3 = Some(RewardMode::RewardToAccount(RewardToAccount {
            to_account: Some(AccountIdentifier::from(*TEST_USER7_PRINCIPAL).into()),
        }));
        let expected_rewards_e8s_3 =
            (((19 * 234_000) + (33 * 907_000) + (4 * 103_000)) * TOKEN_SUBDIVIDABLE_BY) / 155_000;
        assert_eq!(expected_rewards_e8s_3, 22444516129);
        let expected_node_provider_reward_3 = RewardNodeProvider {
            node_provider: Some(node_provider_3.clone()),
            amount_e8s: expected_rewards_e8s_3,
            reward_mode: reward_mode_3,
        };

        let node_operator_id_4 = *TEST_USER7_PRINCIPAL;

        // Add Node Providers
        add_node_provider(&nns_canisters, node_provider_1).await;
        add_node_provider(&nns_canisters, node_provider_2).await;
        add_node_provider(&nns_canisters, node_provider_3).await;

        // Add Node Operator 1
        let rewardable_nodes_1 = btreemap! { "default".to_string() => 10 };
        add_node_operator(
            &nns_canisters,
            &node_operator_id_1,
            &node_provider_id_1,
            "AN1",
            rewardable_nodes_1,
        )
        .await;

        // Add Node Operator 2
        let rewardable_nodes_2 = btreemap! {
            "default".to_string() => 35,
            "small".to_string() => 17,
        };
        add_node_operator(
            &nns_canisters,
            &node_operator_id_2,
            &node_provider_id_2,
            "BC1",
            rewardable_nodes_2,
        )
        .await;

        // Add Node Operator 3
        let rewardable_nodes_3 = btreemap! {
            "default".to_string() => 19,
            "small".to_string() => 33,
            "storage_upgrade".to_string() => 4,
        };
        add_node_operator(
            &nns_canisters,
            &node_operator_id_3,
            &node_provider_id_3,
            "FM1",
            rewardable_nodes_3,
        )
        .await;

        // Add Node Operator 4
        let rewardable_nodes_4 = btreemap! {
            "default".to_string() => 21,
            "small".to_string() => 6,
        };
        add_node_operator(
            &nns_canisters,
            &node_operator_id_4,
            &node_provider_id_1,
            "BC1",
            rewardable_nodes_4,
        )
        .await;

        // Add conversion rates to populate the average conversion rate
        let mut payload = UpdateIcpXdrConversionRatePayload {
            timestamp_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            xdr_permyriad_per_icp: 10_000,
            ..Default::default()
        };

        for _ in 0..30 {
            set_icp_xdr_conversion_rate(&nns_canisters, payload.clone()).await;
            payload.timestamp_seconds += 86400;
            payload.xdr_permyriad_per_icp += 10_000;
        }

        let average_rate_result: IcpXdrConversionRateCertifiedResponse = nns_canisters
            .cycles_minting
            .query_("get_average_icp_xdr_conversion_rate", candid_one, ())
            .await
            .expect("Error calling get_average_icp_xdr_conversion_rate");

        let average_xdr_permyriad_per_icp = average_rate_result.data.xdr_permyriad_per_icp;
        assert_eq!(average_xdr_permyriad_per_icp, 155_000);

        // Call get_monthly_node_provider_rewards assert the value is as expected
        let monthly_node_provider_rewards_result: Result<RewardNodeProviders, GovernanceError> =
            nns_canisters
                .governance
                .update_("get_monthly_node_provider_rewards", candid_one, ())
                .await
                .expect("Error calling get_monthly_node_provider_rewards");

        let monthly_node_provider_rewards = monthly_node_provider_rewards_result.unwrap();
        assert_eq!(monthly_node_provider_rewards.rewards.len(), 3);
        assert!(monthly_node_provider_rewards
            .rewards
            .contains(&expected_node_provider_reward_1));
        assert!(monthly_node_provider_rewards
            .rewards
            .contains(&expected_node_provider_reward_2));
        assert!(monthly_node_provider_rewards
            .rewards
            .contains(&expected_node_provider_reward_3));

        Ok(())
    });
}

/// Add test Data Centers to the Registry
async fn add_data_centers(nns_canisters: &NnsCanisters<'_>) {
    let data_centers = vec![
        DataCenterRecord {
            id: "AN1".into(),
            region: "EU,Belgium,Antwerp".into(),
            owner: "Alice".into(),
            gps: None,
        },
        DataCenterRecord {
            id: "BC1".into(),
            region: "Canada".into(),
            owner: "Bob".into(),
            gps: None,
        },
        DataCenterRecord {
            id: "FM1".into(),
            region: "US,Fremont".into(),
            owner: "Carol".into(),
            gps: None,
        },
    ];

    let payload = AddOrRemoveDataCentersProposalPayload {
        data_centers_to_add: data_centers,
        data_centers_to_remove: vec![],
    };

    let proposal_id: ProposalId = submit_external_update_proposal(
        &nns_canisters.governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::AddOrRemoveDataCenters,
        payload.clone(),
        "<proposal created by test_get_monthly_node_provider_rewards>".to_string(),
        "".to_string(),
    )
    .await;

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns_canisters.governance, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );

    // No proposals should be pending now.
    let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
    assert_eq!(pending_proposals, vec![]);
}

/// Add a test rewards table to the Registry
async fn add_node_rewards_table(nns_canisters: &NnsCanisters<'_>) {
    let new_entries = btreemap! {
        "Antwerp".to_string() =>  NodeRewardRates {
            rates: btreemap!{
                "default".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 24_000,
                },
                "small".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 35_000,
                },
            }
        },
        "Canada".to_string() =>  NodeRewardRates {
            rates: btreemap!{
                "default".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 68_000,
                },
                "small".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 11_000,
                },
            }
        },
        "Fremont".to_string() =>  NodeRewardRates {
            rates: btreemap!{
                "default".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 234_000,
                },
                "small".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 907_000,
                },
                "storage_upgrade".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 103_000,
                },
            }
        }
    };

    let payload = UpdateNodeRewardsTableProposalPayload { new_entries };

    let proposal_id: ProposalId = submit_external_update_proposal(
        &nns_canisters.governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::UpdateNodeRewardsTable,
        payload.clone(),
        "<proposal created by test_get_monthly_node_provider_rewards>".to_string(),
        "".to_string(),
    )
    .await;

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns_canisters.governance, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );

    // No proposals should be pending now.
    let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
    assert_eq!(pending_proposals, vec![]);
}

/// Submit and execute a proposal to add the given node operator
async fn add_node_operator(
    nns_canisters: &NnsCanisters<'_>,
    no_id: &PrincipalId,
    np_id: &PrincipalId,
    dc_id: &str,
    rewardable_nodes: BTreeMap<String, u32>,
) {
    let proposal_payload = AddNodeOperatorPayload {
        node_operator_principal_id: Some(*no_id),
        node_allowance: 5,
        node_provider_principal_id: Some(*np_id),
        dc_id: dc_id.into(),
        rewardable_nodes,
    };

    let proposal_id: ProposalId = submit_external_update_proposal(
        &nns_canisters.governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::AssignNoid,
        proposal_payload.clone(),
        "<proposal created by test_get_monthly_node_provider_rewards>".to_string(),
        "".to_string(),
    )
    .await;

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns_canisters.governance, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );

    // No proposals should be pending now.
    let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
    assert_eq!(pending_proposals, vec![]);
}

/// Submit and execute a proposal to add the given node provider
async fn add_node_provider(nns_canisters: &NnsCanisters<'_>, np: NodeProvider) {
    let result: ManageNeuronResponse = nns_canisters
        .governance
        .update_from_sender(
            "manage_neuron",
            candid_one,
            ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    ic_nns_common::pb::v1::NeuronId {
                        id: TEST_NEURON_1_ID,
                    },
                )),
                id: None,
                command: Some(Command::MakeProposal(Box::new(Proposal {
                    title: Some("".to_string()),
                    summary: "".to_string(),
                    url: "".to_string(),
                    action: Some(Action::AddOrRemoveNodeProvider(AddOrRemoveNodeProvider {
                        change: Some(Change::ToAdd(np)),
                    })),
                }))),
            },
            &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        )
        .await
        .expect("Error calling the manage_neuron api.");

    let pid = match result.expect("Error making proposal").command.unwrap() {
        CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns_canisters.governance, ProposalId::from(pid))
            .await
            .status(),
        ProposalStatus::Executed
    );
}

/// Submit and execute a proposal to set the given conversion rate
async fn set_icp_xdr_conversion_rate(
    nns_canisters: &NnsCanisters<'_>,
    payload: UpdateIcpXdrConversionRatePayload,
) {
    let proposal_id: ProposalId = submit_external_update_proposal(
        &nns_canisters.governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::IcpXdrConversionRate,
        payload.clone(),
        "<proposal created by test_get_monthly_node_provider_rewards>".to_string(),
        "".to_string(),
    )
    .await;

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns_canisters.governance, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );

    // No proposals should be pending now.
    let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
    assert_eq!(pending_proposals, vec![]);
}
