use candid::{Decode, Encode};
use cycles_minting_canister::IcpXdrConversionRateCertifiedResponse;
use dfn_candid::candid_one;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common::{ONE_DAY_SECONDS, ONE_MONTH_SECONDS};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL,
    TEST_USER3_PRINCIPAL, TEST_USER4_PRINCIPAL, TEST_USER5_PRINCIPAL, TEST_USER6_PRINCIPAL,
    TEST_USER7_PRINCIPAL,
};
use ic_nns_common::{pb::v1::NeuronId as ProtoNeuronId, types::UpdateIcpXdrConversionRatePayload};
use ic_nns_constants::{CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID};
use ic_nns_governance_api::pb::v1::{
    add_or_remove_node_provider::Change,
    manage_neuron_response::Command as CommandResponse,
    reward_node_provider::{RewardMode, RewardToAccount},
    AddOrRemoveNodeProvider, DateRangeFilter, ExecuteNnsFunction, GovernanceError,
    ListNodeProviderRewardsRequest, MakeProposalRequest, NetworkEconomics, NnsFunction,
    NodeProvider, ProposalActionRequest, RewardNodeProvider, RewardNodeProviders,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        get_pending_proposals, ledger_account_balance, nns_get_monthly_node_provider_rewards,
        nns_get_most_recent_monthly_node_provider_rewards, nns_get_network_economics_parameters,
        nns_governance_get_proposal_info, nns_governance_make_proposal,
        nns_list_node_provider_rewards, nns_wait_for_proposal_execution, query,
        setup_nns_canisters, state_machine_builder_for_nns_tests, update_with_sender,
    },
};
use ic_protobuf::registry::{
    dc::v1::{AddOrRemoveDataCentersProposalPayload, DataCenterRecord},
    node_rewards::v2::{NodeRewardRate, NodeRewardRates, UpdateNodeRewardsTableProposalPayload},
};
use ic_state_machine_tests::StateMachine;
use ic_types::PrincipalId;
use icp_ledger::{AccountIdentifier, BinaryAccountBalanceArgs, Tokens, TOKEN_SUBDIVIDABLE_BY};
use maplit::btreemap;
use registry_canister::mutations::do_add_node_operator::AddNodeOperatorPayload;
use std::{
    collections::BTreeMap,
    time::{Duration, UNIX_EPOCH},
};

struct NodeInfo {
    pub operator_id: PrincipalId,
    pub provider_id: PrincipalId,
    pub provider_account: AccountIdentifier,
    pub provider: NodeProvider,
}

impl NodeInfo {
    pub fn new(
        operator_id: PrincipalId,
        provider_id: PrincipalId,
        provider_account: AccountIdentifier,
        reward_account: Option<icp_ledger::protobuf::AccountIdentifier>,
    ) -> Self {
        NodeInfo {
            operator_id,
            provider_id,
            provider_account,
            provider: NodeProvider {
                id: Some(provider_id),
                reward_account,
            },
        }
    }
}

#[test]
fn test_list_node_provider_rewards() {
    let state_machine = state_machine_builder_for_nns_tests().build();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .build();
    setup_nns_canisters(&state_machine, nns_init_payload);

    add_data_centers(&state_machine);
    add_node_rewards_table(&state_machine);

    // Define the set of node operators and node providers
    let node_info_1 = NodeInfo::new(
        *TEST_USER1_PRINCIPAL,
        *TEST_USER2_PRINCIPAL,
        AccountIdentifier::from(*TEST_USER2_PRINCIPAL),
        None,
    );
    let reward_mode_1 = Some(RewardMode::RewardToAccount(RewardToAccount {
        to_account: Some(node_info_1.provider_account.into()),
    }));
    let expected_rewards_e8s_1 = ((10 * 24_000) * TOKEN_SUBDIVIDABLE_BY) / 155_000;
    let expected_node_provider_reward_1 = RewardNodeProvider {
        node_provider: Some(node_info_1.provider.clone()),
        amount_e8s: expected_rewards_e8s_1,
        reward_mode: reward_mode_1.clone(),
    };

    // Add Node Providers
    add_node_provider(&state_machine, node_info_1.provider.clone());

    // Add Node Operator 1
    let rewardable_nodes_1 = btreemap! { "default".to_string() => 10 };
    add_node_operator(
        &state_machine,
        &node_info_1.operator_id,
        &node_info_1.provider_id,
        "AN1",
        rewardable_nodes_1,
        "0:0:0:0:0:0:0:0",
    );

    // Set the average conversion rate
    set_average_icp_xdr_conversion_rate(&state_machine, 155_000);

    // Call get_monthly_node_provider_rewards assert the value is as expected
    let monthly_node_provider_rewards_result: Result<RewardNodeProviders, GovernanceError> =
        nns_get_monthly_node_provider_rewards(&state_machine);

    let monthly_node_provider_rewards = monthly_node_provider_rewards_result.unwrap();
    assert!(monthly_node_provider_rewards
        .rewards
        .contains(&expected_node_provider_reward_1));

    // Assert account balances are 0
    assert_account_balance(&state_machine, node_info_1.provider_account, 0);

    // Assert there is no most recent monthly Node Provider reward
    let most_recent_rewards = nns_get_most_recent_monthly_node_provider_rewards(&state_machine);
    assert!(most_recent_rewards.is_none());

    // Submit and execute proposal to pay NPs via Registry-driven rewards
    reward_node_providers_via_registry(&state_machine);

    // Assert account balances are as expected
    assert_account_balance(
        &state_machine,
        node_info_1.provider_account,
        expected_node_provider_reward_1.amount_e8s,
    );

    // Assert the most recent monthly Node Provider reward was set as expected
    let most_recent_rewards =
        nns_get_most_recent_monthly_node_provider_rewards(&state_machine).unwrap();
    let this_rewards_timestamp = most_recent_rewards.timestamp;

    assert!(most_recent_rewards
        .rewards
        .contains(&expected_node_provider_reward_1));

    // Assert advancing time less than a month doesn't trigger monthly NP rewards
    let mut rewards_were_triggered = false;
    for _ in 0..5 {
        state_machine.advance_time(Duration::from_secs(60));
        let most_recent_rewards =
            nns_get_most_recent_monthly_node_provider_rewards(&state_machine).unwrap();
        if most_recent_rewards.timestamp != this_rewards_timestamp {
            rewards_were_triggered = true;
            break;
        }
    }

    assert!(
        !rewards_were_triggered,
        "Automated rewards were triggered even though less than 1 month has passed."
    );

    // Assert account balances haven't changed
    assert_account_balance(
        &state_machine,
        node_info_1.provider_account,
        expected_node_provider_reward_1.amount_e8s,
    );

    // Set a new average conversion rate so that we can assert that the automated monthly
    // NP rewards paid a different reward than the proposal-based reward.
    let average_icp_xdr_conversion_rate_for_automated_rewards = 345_000;
    set_average_icp_xdr_conversion_rate(
        &state_machine,
        average_icp_xdr_conversion_rate_for_automated_rewards,
    );

    let mut minted_rewards = vec![most_recent_rewards.clone()];
    for _ in 0..12 {
        // Assert that advancing time by a month triggers an automated monthly NP reward event
        state_machine.advance_time(Duration::from_secs(ONE_MONTH_SECONDS + 1));
        state_machine.advance_time(Duration::from_secs(60));
        state_machine.tick();

        let rewards = nns_get_most_recent_monthly_node_provider_rewards(&state_machine).unwrap();

        minted_rewards.push(rewards.clone());
    }

    let response = nns_list_node_provider_rewards(
        &state_machine,
        ListNodeProviderRewardsRequest { date_filter: None },
    );

    assert_eq!(response.rewards.len(), 13);

    let received_ts: Vec<u64> = response.rewards.iter().map(|r| r.timestamp).collect();
    let minted_rewards_timestamps: Vec<u64> = minted_rewards.iter().map(|r| r.timestamp).collect();

    // First we test getting all the results with no filters.
    assert_eq!(
        received_ts,
        minted_rewards_timestamps[..]
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>()
    );

    // check rewards are as expected
    assert_eq!(
        response.rewards,
        minted_rewards[..].iter().rev().cloned().collect::<Vec<_>>()
    );

    // Next we test the date filter with no start_date
    let response = nns_list_node_provider_rewards(
        &state_machine,
        ListNodeProviderRewardsRequest {
            date_filter: Some(DateRangeFilter {
                start_timestamp_seconds: None,
                end_timestamp_seconds: Some(minted_rewards_timestamps[11]),
            }),
        },
    );
    let received_ts: Vec<u64> = response.rewards.iter().map(|r| r.timestamp).collect();
    assert_eq!(
        received_ts,
        minted_rewards_timestamps[0..=11]
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>()
    );

    // Next we test the date filter with no end_date
    let response = nns_list_node_provider_rewards(
        &state_machine,
        ListNodeProviderRewardsRequest {
            date_filter: Some(DateRangeFilter {
                start_timestamp_seconds: Some(minted_rewards_timestamps[9]),
                end_timestamp_seconds: None,
            }),
        },
    );
    let received_ts: Vec<u64> = response.rewards.iter().map(|r| r.timestamp).collect();
    assert_eq!(
        received_ts,
        minted_rewards_timestamps[9..]
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>()
    );

    // Next we test the date filter with a start and end_date
    let response = nns_list_node_provider_rewards(
        &state_machine,
        ListNodeProviderRewardsRequest {
            date_filter: Some(DateRangeFilter {
                start_timestamp_seconds: Some(minted_rewards_timestamps[9]),
                end_timestamp_seconds: Some(minted_rewards_timestamps[11]),
            }),
        },
    );
    let received_ts: Vec<u64> = response.rewards.iter().map(|r| r.timestamp).collect();
    assert_eq!(
        received_ts,
        minted_rewards_timestamps[9..=11]
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>()
    );
}
#[test]
fn test_automated_node_provider_remuneration() {
    let state_machine = state_machine_builder_for_nns_tests().build();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .build();
    setup_nns_canisters(&state_machine, nns_init_payload);

    add_data_centers(&state_machine);
    add_node_rewards_table(&state_machine);

    // Define the set of node operators and node providers
    let node_info_1 = NodeInfo::new(
        *TEST_USER1_PRINCIPAL,
        *TEST_USER2_PRINCIPAL,
        AccountIdentifier::from(*TEST_USER2_PRINCIPAL),
        None,
    );
    let reward_mode_1 = Some(RewardMode::RewardToAccount(RewardToAccount {
        to_account: Some(node_info_1.provider_account.into()),
    }));
    let expected_rewards_e8s_1 =
        (((10 * 24_000) + (21 * 68_000) + (6 * 11_000)) * TOKEN_SUBDIVIDABLE_BY) / 155_000;
    assert_eq!(expected_rewards_e8s_1, 1_118_709_677);
    let expected_node_provider_reward_1 = RewardNodeProvider {
        node_provider: Some(node_info_1.provider.clone()),
        amount_e8s: expected_rewards_e8s_1,
        reward_mode: reward_mode_1.clone(),
    };
    let node_info_2 = NodeInfo::new(
        *TEST_USER3_PRINCIPAL,
        *TEST_USER4_PRINCIPAL,
        AccountIdentifier::from(*TEST_USER4_PRINCIPAL),
        None,
    );
    let reward_mode_2 = Some(RewardMode::RewardToAccount(RewardToAccount {
        to_account: Some(node_info_2.provider_account.into()),
    }));
    let expected_rewards_e8s_2 =
        (((35 * 68_000) + (17 * 11_000)) * TOKEN_SUBDIVIDABLE_BY) / 155_000;
    assert_eq!(expected_rewards_e8s_2, 1_656_129_032);
    let expected_node_provider_reward_2 = RewardNodeProvider {
        node_provider: Some(node_info_2.provider.clone()),
        amount_e8s: expected_rewards_e8s_2,
        reward_mode: reward_mode_2.clone(),
    };

    let node_info_3 = NodeInfo::new(
        *TEST_USER5_PRINCIPAL,
        *TEST_USER6_PRINCIPAL,
        AccountIdentifier::from(*TEST_USER7_PRINCIPAL),
        Some(AccountIdentifier::from(*TEST_USER7_PRINCIPAL).into()),
    );
    let reward_mode_3 = Some(RewardMode::RewardToAccount(RewardToAccount {
        to_account: Some(node_info_3.provider_account.into()),
    }));
    let expected_rewards_e8s_3 =
        (((19 * 234_000) + (33 * 907_000) + (4 * 103_000)) * TOKEN_SUBDIVIDABLE_BY) / 155_000;
    assert_eq!(expected_rewards_e8s_3, 22_444_516_129);
    let expected_node_provider_reward_3 = RewardNodeProvider {
        node_provider: Some(node_info_3.provider.clone()),
        amount_e8s: expected_rewards_e8s_3,
        reward_mode: reward_mode_3.clone(),
    };

    let node_operator_id_4 = *TEST_USER7_PRINCIPAL;

    // Add Node Providers
    add_node_provider(&state_machine, node_info_1.provider.clone());
    add_node_provider(&state_machine, node_info_2.provider.clone());
    add_node_provider(&state_machine, node_info_3.provider.clone());

    // Add Node Operator 1
    let rewardable_nodes_1 = btreemap! { "default".to_string() => 10 };
    add_node_operator(
        &state_machine,
        &node_info_1.operator_id,
        &node_info_1.provider_id,
        "AN1",
        rewardable_nodes_1,
        "0:0:0:0:0:0:0:0",
    );

    // Add Node Operator 2
    let rewardable_nodes_2 = btreemap! {
        "default".to_string() => 35,
        "small".to_string() => 17,
    };
    add_node_operator(
        &state_machine,
        &node_info_2.operator_id,
        &node_info_2.provider_id,
        "BC1",
        rewardable_nodes_2,
        "0:0:0:0:0:0:0:0",
    );

    // Add Node Operator 3
    let rewardable_nodes_3 = btreemap! {
        "default".to_string() => 19,
        "small".to_string() => 33,
        "storage_upgrade".to_string() => 4,
    };
    add_node_operator(
        &state_machine,
        &node_info_3.operator_id,
        &node_info_3.provider_id,
        "FM1",
        rewardable_nodes_3,
        "0:0:0:0:0:0:0:0",
    );

    // Add Node Operator 4
    let rewardable_nodes_4 = btreemap! {
        "default".to_string() => 21,
        "small".to_string() => 6,
    };
    add_node_operator(
        &state_machine,
        &node_operator_id_4,
        &node_info_1.provider_id,
        "BC1",
        rewardable_nodes_4,
        "0:0:0:0:0:0:0:0",
    );

    // Set the average conversion rate
    set_average_icp_xdr_conversion_rate(&state_machine, 155_000);

    // Call get_monthly_node_provider_rewards assert the value is as expected
    let monthly_node_provider_rewards_result: Result<RewardNodeProviders, GovernanceError> =
        nns_get_monthly_node_provider_rewards(&state_machine);

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
    assert_account_balance(&state_machine, node_info_1.provider_account, 0);
    assert_account_balance(&state_machine, node_info_2.provider_account, 0);
    assert_account_balance(&state_machine, node_info_3.provider_account, 0);

    // Assert there is no most recent monthly Node Provider reward
    let most_recent_rewards = nns_get_most_recent_monthly_node_provider_rewards(&state_machine);
    assert!(most_recent_rewards.is_none());

    // Submit and execute proposal to pay NPs via Registry-driven rewards
    reward_node_providers_via_registry(&state_machine);

    // Assert account balances are as expected
    assert_account_balance(
        &state_machine,
        node_info_1.provider_account,
        expected_node_provider_reward_1.amount_e8s,
    );
    assert_account_balance(
        &state_machine,
        node_info_2.provider_account,
        expected_node_provider_reward_2.amount_e8s,
    );
    assert_account_balance(
        &state_machine,
        node_info_3.provider_account,
        expected_node_provider_reward_3.amount_e8s,
    );

    // Assert the most recent monthly Node Provider reward was set as expected
    let mut most_recent_rewards =
        nns_get_most_recent_monthly_node_provider_rewards(&state_machine).unwrap();
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
    let mut rewards_were_triggered = false;
    for _ in 0..5 {
        state_machine.advance_time(Duration::from_secs(60));
        let most_recent_rewards =
            nns_get_most_recent_monthly_node_provider_rewards(&state_machine).unwrap();
        if most_recent_rewards.timestamp != np_rewards_from_proposal_timestamp {
            rewards_were_triggered = true;
            break;
        }
    }

    assert!(
        !rewards_were_triggered,
        "Automated rewards were triggered even though less than 1 month has passed."
    );

    // Assert account balances haven't changed
    assert_account_balance(
        &state_machine,
        node_info_1.provider_account,
        expected_node_provider_reward_1.amount_e8s,
    );

    assert_account_balance(
        &state_machine,
        node_info_2.provider_account,
        expected_node_provider_reward_2.amount_e8s,
    );

    assert_account_balance(
        &state_machine,
        node_info_3.provider_account,
        expected_node_provider_reward_3.amount_e8s,
    );

    // Set a new average conversion rate so that we can assert that the automated monthly
    // NP rewards paid a different reward than the proposal-based reward.
    let average_icp_xdr_conversion_rate_for_automated_rewards = 345_000;
    set_average_icp_xdr_conversion_rate(
        &state_machine,
        average_icp_xdr_conversion_rate_for_automated_rewards,
    );

    // Assert that advancing time by a month triggers an automated monthly NP reward event
    state_machine.advance_time(Duration::from_secs(ONE_MONTH_SECONDS));

    let mut rewards_were_triggered = false;
    let mut np_rewards_from_automation_timestamp = most_recent_rewards.timestamp;
    for _ in 0..10 {
        state_machine.advance_time(Duration::from_secs(60));
        most_recent_rewards =
            nns_get_most_recent_monthly_node_provider_rewards(&state_machine).unwrap();
        np_rewards_from_automation_timestamp = most_recent_rewards.timestamp;
        if np_rewards_from_automation_timestamp == np_rewards_from_proposal_timestamp {
            continue;
        }
        rewards_were_triggered = true;
    }

    assert!(
        rewards_were_triggered,
        "Automated rewards were not triggered even though more than 1 month has passed."
    );

    assert_ne!(
        np_rewards_from_automation_timestamp,
        np_rewards_from_proposal_timestamp
    );

    let expected_automated_rewards_e8s_1 = (((10 * 24_000) + (21 * 68_000) + (6 * 11_000))
        * TOKEN_SUBDIVIDABLE_BY)
        / average_icp_xdr_conversion_rate_for_automated_rewards;

    let expected_automated_node_provider_reward_1 = RewardNodeProvider {
        node_provider: Some(node_info_1.provider.clone()),
        amount_e8s: expected_automated_rewards_e8s_1,
        reward_mode: reward_mode_1.clone(),
    };

    let expected_automated_rewards_e8s_2 = (((35 * 68_000) + (17 * 11_000))
        * TOKEN_SUBDIVIDABLE_BY)
        / average_icp_xdr_conversion_rate_for_automated_rewards;

    let expected_automated_node_provider_reward_2 = RewardNodeProvider {
        node_provider: Some(node_info_2.provider.clone()),
        amount_e8s: expected_automated_rewards_e8s_2,
        reward_mode: reward_mode_2.clone(),
    };

    let expected_automated_rewards_e8s_3 = (((19 * 234_000) + (33 * 907_000) + (4 * 103_000))
        * TOKEN_SUBDIVIDABLE_BY)
        / average_icp_xdr_conversion_rate_for_automated_rewards;

    let expected_automated_node_provider_reward_3 = RewardNodeProvider {
        node_provider: Some(node_info_3.provider.clone()),
        amount_e8s: expected_automated_rewards_e8s_3,
        reward_mode: reward_mode_3.clone(),
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

    // Assert additional rewards have been transferred to the Node Provider accounts
    assert_account_balance(
        &state_machine,
        node_info_1.provider_account,
        expected_node_provider_reward_1.amount_e8s + expected_automated_rewards_e8s_1,
    );

    assert_account_balance(
        &state_machine,
        node_info_2.provider_account,
        expected_node_provider_reward_2.amount_e8s + expected_automated_rewards_e8s_2,
    );

    assert_account_balance(
        &state_machine,
        node_info_3.provider_account,
        expected_node_provider_reward_3.amount_e8s + expected_automated_rewards_e8s_3,
    );

    let actual_minimum_xdr_permyriad_per_icp = nns_get_network_economics_parameters(&state_machine)
        .minimum_icp_xdr_rate
        * NetworkEconomics::ICP_XDR_RATE_TO_BASIS_POINT_MULTIPLIER;

    // Set a new average conversion that is far below the `actual_minimum_xdr_permyriad_per_icp`
    // to trigger the limit.
    let average_icp_xdr_conversion_rate_for_automated_rewards = 1;
    set_average_icp_xdr_conversion_rate(
        &state_machine,
        average_icp_xdr_conversion_rate_for_automated_rewards,
    );

    // Assert that advancing time by a month triggers an automated monthly NP reward event
    state_machine.advance_time(Duration::from_secs(ONE_MONTH_SECONDS));

    let mut rewards_were_triggered = false;
    for _ in 0..10 {
        state_machine.advance_time(Duration::from_secs(60));
        most_recent_rewards =
            nns_get_most_recent_monthly_node_provider_rewards(&state_machine).unwrap();
        np_rewards_from_automation_timestamp = most_recent_rewards.timestamp;
        if np_rewards_from_automation_timestamp == np_rewards_from_proposal_timestamp {
            continue;
        }
        rewards_were_triggered = true;
    }

    assert!(
        rewards_were_triggered,
        "Automated rewards were not triggered even though more than 1 month has passed."
    );

    let expected_automated_rewards_e8s_1 = (((10 * 24_000) + (21 * 68_000) + (6 * 11_000))
        * TOKEN_SUBDIVIDABLE_BY)
        / actual_minimum_xdr_permyriad_per_icp;

    let expected_automated_node_provider_reward_1 = RewardNodeProvider {
        node_provider: Some(node_info_1.provider),
        amount_e8s: expected_automated_rewards_e8s_1,
        reward_mode: reward_mode_1,
    };

    let expected_automated_rewards_e8s_2 = (((35 * 68_000) + (17 * 11_000))
        * TOKEN_SUBDIVIDABLE_BY)
        / actual_minimum_xdr_permyriad_per_icp;

    let expected_automated_node_provider_reward_2 = RewardNodeProvider {
        node_provider: Some(node_info_2.provider),
        amount_e8s: expected_automated_rewards_e8s_2,
        reward_mode: reward_mode_2,
    };

    let expected_automated_rewards_e8s_3 = (((19 * 234_000) + (33 * 907_000) + (4 * 103_000))
        * TOKEN_SUBDIVIDABLE_BY)
        / actual_minimum_xdr_permyriad_per_icp;

    let expected_automated_node_provider_reward_3 = RewardNodeProvider {
        node_provider: Some(node_info_3.provider),
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
}

/// Helper function for making NNS proposals for this test
fn submit_nns_proposal(state_machine: &StateMachine, action: ProposalActionRequest) {
    let response = nns_governance_make_proposal(
        state_machine,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR).get_principal_id(),
        ProtoNeuronId {
            id: TEST_NEURON_1_ID,
        },
        &MakeProposalRequest {
            title: Some(
                "<proposal created by test_automated_node_provider_remuneration>".to_string(),
            ),
            action: Some(action),
            ..Default::default()
        },
    );

    let proposal_id = match response.command.unwrap() {
        CommandResponse::MakeProposal(x) => x.proposal_id.unwrap(),
        response => panic!(
            "Unexpected response returned from NNS governance: {:?}",
            response
        ),
    };

    nns_wait_for_proposal_execution(state_machine, proposal_id.id);

    let proposal_info = nns_governance_get_proposal_info(
        state_machine,
        proposal_id.id,
        PrincipalId::new_anonymous(),
    );
    assert_eq!(proposal_info.failure_reason, None);

    // No proposals should be pending now.
    let pending_proposals = get_pending_proposals(state_machine);
    assert_eq!(pending_proposals, vec![]);
}

/// Set the average ICP/XDR conversion rate
fn set_average_icp_xdr_conversion_rate(
    state_machine: &StateMachine,
    average_icp_xdr_conversion_rate: u64,
) {
    // Add conversion rate proposals for the past 31 days.
    for _ in 0..31 {
        let current_timestamp_seconds = state_machine
            .time()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let payload = UpdateIcpXdrConversionRatePayload {
            timestamp_seconds: current_timestamp_seconds,
            xdr_permyriad_per_icp: average_icp_xdr_conversion_rate,
            ..Default::default()
        };
        set_icp_xdr_conversion_rate(state_machine, payload);
        state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS));
    }

    let actual_average_icp_xdr_conversion_rate: u64 = query(
        state_machine,
        CYCLES_MINTING_CANISTER_ID,
        "get_average_icp_xdr_conversion_rate",
        Encode!().unwrap(),
    )
    .map(|response| Decode!(&response, IcpXdrConversionRateCertifiedResponse).unwrap())
    .map(|response| response.data.xdr_permyriad_per_icp)
    .expect("Could not query the average_icp_xdr_conversion_rate from the CMC Canister");

    assert_eq!(
        actual_average_icp_xdr_conversion_rate,
        average_icp_xdr_conversion_rate
    );
}

/// Submit and execute a proposal to set the given conversion rate
fn set_icp_xdr_conversion_rate(
    state_machine: &StateMachine,
    payload: UpdateIcpXdrConversionRatePayload,
) {
    // If we do this via proposal (which will be removed in the future) we cannot set it
    // below the allowable threshold, which negates part of the test
    let _: Result<(), String> = update_with_sender(
        state_machine,
        CYCLES_MINTING_CANISTER_ID,
        "set_icp_xdr_conversion_rate",
        candid_one,
        payload,
        GOVERNANCE_CANISTER_ID.get(),
    )
    .unwrap();
}

/// Assert the given account has the given token balance on the Ledger
fn assert_account_balance(state_machine: &StateMachine, account: AccountIdentifier, e8s: u64) {
    let user_balance: Tokens = ledger_account_balance(
        state_machine,
        LEDGER_CANISTER_ID,
        &BinaryAccountBalanceArgs {
            account: account.to_address(),
        },
    );
    assert_eq!(Tokens::from_e8s(e8s), user_balance);
}

/// Submit and execute a RewardNodeProviders proposal with the `use_registry_derived_rewards`
/// flag set to `true`. This causes Node Providers to be rewarded with the rewards returned
/// by Governance's `get_monthly_node_provider_rewards` method.
fn reward_node_providers_via_registry(state_machine: &StateMachine) {
    submit_nns_proposal(
        state_machine,
        ProposalActionRequest::RewardNodeProviders(RewardNodeProviders {
            rewards: vec![],
            use_registry_derived_rewards: Some(true),
        }),
    );
}

/// Add test Data Centers to the Registry
fn add_data_centers(state_machine: &StateMachine) {
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
    submit_nns_proposal(
        state_machine,
        ProposalActionRequest::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::AddOrRemoveDataCenters as i32,
            payload: Encode!(&payload).unwrap(),
        }),
    );
}

/// Add a test rewards table to the Registry
fn add_node_rewards_table(state_machine: &StateMachine) {
    let new_entries = btreemap! {
        "EU".to_string() =>  NodeRewardRates {
            rates: btreemap!{
                "default".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 24_000,
                    reward_coefficient_percent: None,
                },
                "small".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 35_000,
                    reward_coefficient_percent: None,
                },
            }
        },
        "North America,Canada".to_string() =>  NodeRewardRates {
            rates: btreemap!{
                "default".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 68_000,
                    reward_coefficient_percent: None,
                },
                "small".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 11_000,
                    reward_coefficient_percent: None,
                },
            }
        },
        "North America,US,CA".to_string() =>  NodeRewardRates {
            rates: btreemap!{
                "default".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 234_000,
                    reward_coefficient_percent: None,
                },
                "small".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 907_000,
                    reward_coefficient_percent: None,
                },
                "storage_upgrade".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 103_000,
                    reward_coefficient_percent: None,
                },
            }
        }
    };

    let payload = UpdateNodeRewardsTableProposalPayload { new_entries };

    submit_nns_proposal(
        state_machine,
        ProposalActionRequest::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::UpdateNodeRewardsTable as i32,
            payload: Encode!(&payload).unwrap(),
        }),
    );
}

fn add_node_provider(state_machine: &StateMachine, node_provider: NodeProvider) {
    submit_nns_proposal(
        state_machine,
        ProposalActionRequest::AddOrRemoveNodeProvider(AddOrRemoveNodeProvider {
            change: Some(Change::ToAdd(node_provider)),
        }),
    );
}

/// Submit and execute a proposal to add the given node operator
fn add_node_operator(
    state_machine: &StateMachine,
    no_id: &PrincipalId,
    np_id: &PrincipalId,
    dc_id: &str,
    rewardable_nodes: BTreeMap<String, u32>,
    ipv6: &str,
) {
    let payload = AddNodeOperatorPayload {
        node_operator_principal_id: Some(*no_id),
        node_allowance: 5,
        node_provider_principal_id: Some(*np_id),
        dc_id: dc_id.into(),
        rewardable_nodes,
        ipv6: Some(ipv6.into()),
    };

    submit_nns_proposal(
        state_machine,
        ProposalActionRequest::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::AssignNoid as i32,
            payload: Encode!(&payload).unwrap(),
        }),
    );
}
