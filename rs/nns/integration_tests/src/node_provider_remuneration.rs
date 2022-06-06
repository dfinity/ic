use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL,
    TEST_USER4_PRINCIPAL, TEST_USER5_PRINCIPAL, TEST_USER6_PRINCIPAL, TEST_USER7_PRINCIPAL,
};
use ic_nns_common::types::{NeuronId, ProposalId, UpdateIcpXdrConversionRatePayload};
use ic_nns_governance::pb::v1::{
    manage_neuron::{Command, NeuronIdOrSubaccount},
    manage_neuron_response::Command as CommandResponse,
    proposal::Action,
    GovernanceError, ManageNeuron, ManageNeuronResponse, MostRecentMonthlyNodeProviderRewards,
    NnsFunction, NodeProvider, Proposal, ProposalStatus, RewardNodeProvider, RewardNodeProviders,
};
use ic_nns_test_utils::governance::{add_node_provider, submit_external_update_proposal};
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
use dfn_protobuf::protobuf;
use ic_nns_common::pb::v1::NeuronId as ProtoNeuronId;
use ic_nns_governance::governance::TimeWarp;
use ic_nns_governance::pb::v1::reward_node_provider::{RewardMode, RewardToAccount};
use ic_types::PrincipalId;
use ledger_canister::{AccountBalanceArgs, AccountIdentifier, Tokens, TOKEN_SUBDIVIDABLE_BY};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_automated_node_provider_remuneration() {
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
        let node_provider_1_account = AccountIdentifier::from(node_provider_id_1);
        let node_provider_1 = NodeProvider {
            id: Some(node_provider_id_1),
            reward_account: None,
        };
        let reward_mode_1 = Some(RewardMode::RewardToAccount(RewardToAccount {
            to_account: Some(node_provider_1_account.into()),
        }));
        let expected_rewards_e8s_1 =
            (((10 * 24_000) + (21 * 68_000) + (6 * 11_000)) * TOKEN_SUBDIVIDABLE_BY) / 155_000;
        assert_eq!(expected_rewards_e8s_1, 1118709677);
        let expected_node_provider_reward_1 = RewardNodeProvider {
            node_provider: Some(node_provider_1.clone()),
            amount_e8s: expected_rewards_e8s_1,
            reward_mode: reward_mode_1.clone(),
        };

        let node_operator_id_2 = *TEST_USER3_PRINCIPAL;
        let node_provider_id_2 = *TEST_USER4_PRINCIPAL;
        let node_provider_2_account = AccountIdentifier::from(node_provider_id_2);
        let node_provider_2 = NodeProvider {
            id: Some(node_provider_id_2),
            reward_account: None,
        };
        let reward_mode_2 = Some(RewardMode::RewardToAccount(RewardToAccount {
            to_account: Some(node_provider_2_account.into()),
        }));
        let expected_rewards_e8s_2 =
            (((35 * 68_000) + (17 * 11_000)) * TOKEN_SUBDIVIDABLE_BY) / 155_000;
        assert_eq!(expected_rewards_e8s_2, 1656129032);
        let expected_node_provider_reward_2 = RewardNodeProvider {
            node_provider: Some(node_provider_2.clone()),
            amount_e8s: expected_rewards_e8s_2,
            reward_mode: reward_mode_2.clone(),
        };

        let node_operator_id_3 = *TEST_USER5_PRINCIPAL;
        let node_provider_id_3 = *TEST_USER6_PRINCIPAL;
        let node_provider_3_account = AccountIdentifier::from(*TEST_USER7_PRINCIPAL);
        let node_provider_3 = NodeProvider {
            id: Some(node_provider_id_3),
            reward_account: Some(node_provider_3_account.into()),
        };
        let reward_mode_3 = Some(RewardMode::RewardToAccount(RewardToAccount {
            to_account: Some(node_provider_3_account.into()),
        }));
        let expected_rewards_e8s_3 =
            (((19 * 234_000) + (33 * 907_000) + (4 * 103_000)) * TOKEN_SUBDIVIDABLE_BY) / 155_000;
        assert_eq!(expected_rewards_e8s_3, 22444516129);
        let expected_node_provider_reward_3 = RewardNodeProvider {
            node_provider: Some(node_provider_3.clone()),
            amount_e8s: expected_rewards_e8s_3,
            reward_mode: reward_mode_3.clone(),
        };

        let node_operator_id_4 = *TEST_USER7_PRINCIPAL;

        // Add Node Providers
        add_node_provider(&nns_canisters, node_provider_1.clone()).await;
        add_node_provider(&nns_canisters, node_provider_2.clone()).await;
        add_node_provider(&nns_canisters, node_provider_3.clone()).await;

        // Add Node Operator 1
        let rewardable_nodes_1 = btreemap! { "default".to_string() => 10 };
        add_node_operator(
            &nns_canisters,
            &node_operator_id_1,
            &node_provider_id_1,
            "AN1",
            rewardable_nodes_1,
            "0:0:0:0:0:0:0:0",
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
            "0:0:0:0:0:0:0:0",
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
            "0:0:0:0:0:0:0:0",
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
            "0:0:0:0:0:0:0:0",
        )
        .await;

        // Set the average conversion rate
        set_average_icp_xdr_conversion_rate(&nns_canisters, 155_000).await;

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

        // Assert account balances are 0
        assert_account_balance(&nns_canisters, node_provider_1_account, 0).await;
        assert_account_balance(&nns_canisters, node_provider_2_account, 0).await;
        assert_account_balance(&nns_canisters, node_provider_3_account, 0).await;

        // Assert there is no most recent monthly Node Provider reward
        let most_recent_rewards = get_most_recent_rewards(&nns_canisters).await;
        assert!(most_recent_rewards.is_none());

        // Submit and execute proposal to pay NPs via Registry-driven rewards
        reward_node_providers_via_registry(&nns_canisters).await;

        // Assert account balances are as expected
        assert_account_balance(
            &nns_canisters,
            node_provider_1_account,
            expected_node_provider_reward_1.amount_e8s,
        )
        .await;
        assert_account_balance(
            &nns_canisters,
            node_provider_2_account,
            expected_node_provider_reward_2.amount_e8s,
        )
        .await;
        assert_account_balance(
            &nns_canisters,
            node_provider_3_account,
            expected_node_provider_reward_3.amount_e8s,
        )
        .await;

        // Assert the most recent monthly Node Provider reward was set as expected
        let most_recent_rewards = get_most_recent_rewards(&nns_canisters).await.unwrap();
        let np_rewards_from_proposal_timestamp = most_recent_rewards.timestamp;

        assert!(most_recent_rewards
            .rewards
            .contains(&expected_node_provider_reward_1));
        assert!(most_recent_rewards
            .rewards
            .contains(&expected_node_provider_reward_2));
        assert!(most_recent_rewards
            .rewards
            .contains(&expected_node_provider_reward_3));

        // Assert advancing time less than a month doesn't trigger monthly NP rewards
        let _: () = nns_canisters
            .governance
            .update_("set_time_warp", candid_one, TimeWarp { delta_s: 60 })
            .await
            .expect("Error calling set_time_warp");

        let most_recent_rewards = get_most_recent_rewards(&nns_canisters).await.unwrap();
        assert_eq!(
            most_recent_rewards.timestamp,
            np_rewards_from_proposal_timestamp
        );

        // Assert account balances haven't changed
        assert_account_balance(
            &nns_canisters,
            node_provider_1_account,
            expected_node_provider_reward_1.amount_e8s,
        )
        .await;

        assert_account_balance(
            &nns_canisters,
            node_provider_2_account,
            expected_node_provider_reward_2.amount_e8s,
        )
        .await;

        assert_account_balance(
            &nns_canisters,
            node_provider_3_account,
            expected_node_provider_reward_3.amount_e8s,
        )
        .await;

        // Set a new average conversion rate so that we can assert that the automated monthly
        // NP rewards paid a different reward than the proposal-based reward.
        let average_icp_xdr_conversion_rate_for_automated_rewards = 345_000;
        set_average_icp_xdr_conversion_rate(
            &nns_canisters,
            average_icp_xdr_conversion_rate_for_automated_rewards,
        )
        .await;

        // Assert that advancing time by a month triggers an automated monthly NP reward event
        let _: () = nns_canisters
            .governance
            .update_("set_time_warp", candid_one, TimeWarp { delta_s: 2629800 })
            .await
            .expect("Error calling set_time_warp");

        let most_recent_rewards = get_most_recent_rewards(&nns_canisters).await.unwrap();
        let np_rewards_from_automation_timestamp = most_recent_rewards.timestamp;
        assert_ne!(
            np_rewards_from_automation_timestamp,
            np_rewards_from_proposal_timestamp
        );

        let expected_automated_rewards_e8s_1 = (((10 * 24_000) + (21 * 68_000) + (6 * 11_000))
            * TOKEN_SUBDIVIDABLE_BY)
            / average_icp_xdr_conversion_rate_for_automated_rewards;

        let expected_automated_node_provider_reward_1 = RewardNodeProvider {
            node_provider: Some(node_provider_1),
            amount_e8s: expected_automated_rewards_e8s_1,
            reward_mode: reward_mode_1,
        };

        let expected_automated_rewards_e8s_2 = (((35 * 68_000) + (17 * 11_000))
            * TOKEN_SUBDIVIDABLE_BY)
            / average_icp_xdr_conversion_rate_for_automated_rewards;

        let expected_automated_node_provider_reward_2 = RewardNodeProvider {
            node_provider: Some(node_provider_2),
            amount_e8s: expected_automated_rewards_e8s_2,
            reward_mode: reward_mode_2,
        };

        let expected_automated_rewards_e8s_3 = (((19 * 234_000) + (33 * 907_000) + (4 * 103_000))
            * TOKEN_SUBDIVIDABLE_BY)
            / average_icp_xdr_conversion_rate_for_automated_rewards;

        let expected_automated_node_provider_reward_3 = RewardNodeProvider {
            node_provider: Some(node_provider_3),
            amount_e8s: expected_automated_rewards_e8s_3,
            reward_mode: reward_mode_3,
        };

        assert!(most_recent_rewards
            .rewards
            .contains(&expected_automated_node_provider_reward_1));

        assert!(most_recent_rewards
            .rewards
            .contains(&expected_automated_node_provider_reward_2));

        assert!(most_recent_rewards
            .rewards
            .contains(&expected_automated_node_provider_reward_3));

        // Assert additional rewards have been transfered to the Node Provider accounts
        assert_account_balance(
            &nns_canisters,
            node_provider_1_account,
            expected_node_provider_reward_1.amount_e8s + expected_automated_rewards_e8s_1,
        )
        .await;

        assert_account_balance(
            &nns_canisters,
            node_provider_2_account,
            expected_node_provider_reward_2.amount_e8s + expected_automated_rewards_e8s_2,
        )
        .await;

        assert_account_balance(
            &nns_canisters,
            node_provider_3_account,
            expected_node_provider_reward_3.amount_e8s + expected_automated_rewards_e8s_3,
        )
        .await;

        Ok(())
    });
}

/// Set the average ICP/XDR conversion rate
async fn set_average_icp_xdr_conversion_rate(
    nns_canisters: &NnsCanisters<'_>,
    average_icp_xdr_conversion_rate: u64,
) {
    let latest_conversion_rate_timestamp: u64 = nns_canisters
        .cycles_minting
        .query_("get_average_icp_xdr_conversion_rate", candid_one, ())
        .await
        .map(|response: IcpXdrConversionRateCertifiedResponse| response.data.timestamp_seconds)
        .unwrap_or_else(|_| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

    let mut payload = UpdateIcpXdrConversionRatePayload {
        timestamp_seconds: latest_conversion_rate_timestamp,
        xdr_permyriad_per_icp: average_icp_xdr_conversion_rate,
        ..Default::default()
    };

    for _ in 0..31 {
        payload.timestamp_seconds += 86400;
        set_icp_xdr_conversion_rate(nns_canisters, payload.clone()).await;
    }

    let average_rate_result: IcpXdrConversionRateCertifiedResponse = nns_canisters
        .cycles_minting
        .query_("get_average_icp_xdr_conversion_rate", candid_one, ())
        .await
        .expect("Error calling get_average_icp_xdr_conversion_rate");

    let actual_average_icp_xdr_conversion_rate = average_rate_result.data.xdr_permyriad_per_icp;
    assert_eq!(
        actual_average_icp_xdr_conversion_rate,
        average_icp_xdr_conversion_rate
    );
}

/// Return the most recent monthly Node Provider rewards
async fn get_most_recent_rewards(
    nns_canisters: &NnsCanisters<'_>,
) -> Option<MostRecentMonthlyNodeProviderRewards> {
    nns_canisters
        .governance
        .query_(
            "get_most_recent_monthly_node_provider_rewards",
            candid_one,
            (),
        )
        .await
        .expect("Error calling get_most_recent_monthly_node_provider_rewards")
}

/// Submit and execute a RewardNodeProviders proposal with the `use_registry_derived_rewards`
/// flag set to `true`. This causes Node Providers to be rewarded with the rewards returned
/// by Governance's `get_monthly_node_provider_rewards` method.
async fn reward_node_providers_via_registry(nns_canisters: &NnsCanisters<'_>) {
    let sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);

    let result: ManageNeuronResponse = nns_canisters
        .governance
        .update_from_sender(
            "manage_neuron",
            candid_one,
            ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(ProtoNeuronId {
                    id: TEST_NEURON_1_ID,
                })),
                id: None,
                command: Some(Command::MakeProposal(Box::new(Proposal {
                    title: Some("Reward NPs".to_string()),
                    summary: "".to_string(),
                    url: "".to_string(),
                    action: Some(Action::RewardNodeProviders(RewardNodeProviders {
                        rewards: vec![],
                        use_registry_derived_rewards: Some(true),
                    })),
                }))),
            },
            &sender,
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

/// Assert the given account has the given token balance on the Ledger
async fn assert_account_balance(
    nns_canisters: &NnsCanisters<'_>,
    account: AccountIdentifier,
    e8s: u64,
) {
    let user_balance: Tokens = nns_canisters
        .ledger
        .query_(
            "account_balance_pb",
            protobuf,
            AccountBalanceArgs { account },
        )
        .await
        .unwrap();
    assert_eq!(Tokens::from_e8s(e8s), user_balance);
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
            region: "North America,Canada,BC".into(),
            owner: "Bob".into(),
            gps: None,
        },
        DataCenterRecord {
            id: "FM1".into(),
            region: "North America,US,CA,Fremont".into(),
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
        "EU".to_string() =>  NodeRewardRates {
            rates: btreemap!{
                "default".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 24_000,
                },
                "small".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 35_000,
                },
            }
        },
        "North America,Canada".to_string() =>  NodeRewardRates {
            rates: btreemap!{
                "default".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 68_000,
                },
                "small".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 11_000,
                },
            }
        },
        "North America,US,CA".to_string() =>  NodeRewardRates {
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
    ipv6: &str,
) {
    let proposal_payload = AddNodeOperatorPayload {
        node_operator_principal_id: Some(*no_id),
        node_allowance: 5,
        node_provider_principal_id: Some(*np_id),
        dc_id: dc_id.into(),
        rewardable_nodes,
        ipv6: Some(ipv6.into()),
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
