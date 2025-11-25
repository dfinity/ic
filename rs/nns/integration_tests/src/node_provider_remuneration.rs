use candid::{Decode, Encode};
use chrono::DateTime;
use cycles_minting_canister::IcpXdrConversionRateCertifiedResponse;
use ic_base_types::NodeId;
use ic_canister_client_sender::Sender;
use ic_management_canister_types_private::NodeMetrics;
use ic_nervous_system_common::{ONE_DAY_SECONDS, ONE_MONTH_SECONDS};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL,
    TEST_USER3_PRINCIPAL, TEST_USER4_PRINCIPAL, TEST_USER5_PRINCIPAL, TEST_USER6_PRINCIPAL,
    TEST_USER7_PRINCIPAL,
};
use ic_nns_common::{pb::v1::NeuronId as ProtoNeuronId, types::UpdateIcpXdrConversionRatePayload};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID,
    NODE_REWARDS_CANISTER_ID, REGISTRY_CANISTER_ID,
};
use ic_nns_governance::governance::NODE_PROVIDER_REWARD_PERIOD_SECONDS;
use ic_nns_governance_api::{
    AddOrRemoveNodeProvider, DateRangeFilter, ExecuteNnsFunction, GovernanceError,
    ListNodeProviderRewardsRequest, MakeProposalRequest, MonthlyNodeProviderRewards,
    NetworkEconomics, NnsFunction, NodeProvider, ProposalActionRequest, RewardNodeProvider,
    RewardNodeProviders,
    add_or_remove_node_provider::Change,
    manage_neuron_response::Command as CommandResponse,
    reward_node_provider::{RewardMode, RewardToAccount},
};
use ic_nns_governance_init::GovernanceCanisterInitPayloadBuilder;
use ic_nns_test_utils::registry::{TEST_ID, prepare_add_node_payload};
use ic_nns_test_utils::state_test_helpers::setup_nns_canisters_with_features;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        get_pending_proposals, ledger_account_balance,
        nns_get_most_recent_monthly_node_provider_rewards, nns_get_network_economics_parameters,
        nns_get_node_provider_rewards, nns_governance_get_proposal_info,
        nns_governance_make_proposal, nns_list_node_provider_rewards,
        nns_wait_for_proposal_execution, query, state_machine_builder_for_nns_tests,
        update_with_sender,
    },
};
use ic_node_rewards_canister_api::DateUtc;
use ic_node_rewards_canister_api::provider_rewards_calculation::{
    GetNodeProvidersRewardsCalculationRequest, GetNodeProvidersRewardsCalculationResponse,
};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::{
    dc::v1::{AddOrRemoveDataCentersProposalPayload, DataCenterRecord},
    node_rewards::v2::{NodeRewardRate, NodeRewardRates, UpdateNodeRewardsTableProposalPayload},
};
use ic_registry_canister_api::AddNodePayload;
use ic_state_machine_tests::{PayloadBuilder, StateMachine};
use ic_types::PrincipalId;
use ic_types::batch::BlockmakerMetrics;
use ic_types::time::current_time;
use ic_types_test_utils::ids::subnet_test_id;
use icp_ledger::{AccountIdentifier, BinaryAccountBalanceArgs, TOKEN_SUBDIVIDABLE_BY, Tokens};
use maplit::btreemap;
use registry_canister::mutations::do_add_node_operator::AddNodeOperatorPayload;
use rewards_calculation::REWARDS_TABLE_DAYS;
use rewards_calculation::types::NodeMetricsDailyRaw;
use std::time::SystemTime;
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
        reward_account: Option<AccountIdentifier>,
    ) -> Self {
        NodeInfo {
            operator_id,
            provider_id,
            provider_account,
            provider: NodeProvider {
                id: Some(provider_id),
                reward_account: reward_account.map(|id| id.into_proto_with_checksum()),
            },
        }
    }
}

#[test]
fn test_list_node_provider_rewards() {
    let nns_subnet = subnet_test_id(TEST_ID);

    let state_machine = state_machine_builder_for_nns_tests()
        .with_nns_subnet_id(nns_subnet)
        .with_subnet_id(nns_subnet)
        .build();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .build();
    setup_nns_canisters_with_features(&state_machine, nns_init_payload, &[]);

    add_data_centers(&state_machine);
    add_node_rewards_table(&state_machine);

    // Define the set of node operators and node providers
    let node_info_1 = NodeInfo::new(
        *TEST_USER1_PRINCIPAL,
        *TEST_USER2_PRINCIPAL,
        AccountIdentifier::from(*TEST_USER2_PRINCIPAL),
        None,
    );

    // Add Node Providers
    add_node_provider(&state_machine, node_info_1.provider.clone());

    // Add Node Operator 1
    let max_rewardable_nodes_1 = btreemap! { NodeRewardType::Type1.to_string() => 1 };
    add_node_operator(
        &state_machine,
        &node_info_1.operator_id,
        &node_info_1.provider_id,
        "AN1",
        max_rewardable_nodes_1,
        "0:0:0:0:0:0:0:w",
    );

    // Add Nodes for Node Operator 1
    let node_id = add_node(
        &state_machine,
        node_info_1.operator_id,
        1,
        NodeRewardType::Type1,
    );

    // Set the conversion rate
    let current_timestamp_seconds = state_machine.get_time().as_secs_since_unix_epoch();
    let payload = UpdateIcpXdrConversionRatePayload {
        timestamp_seconds: current_timestamp_seconds,
        xdr_permyriad_per_icp: 155_000,
        ..Default::default()
    };

    // Cover 31 days of blockmaker metrics to make sure we cover a full month 30 or 31 days
    // All success failure rate is 0
    let node_metrics_daily = vec![NodeMetricsDailyRaw {
        node_id,
        num_blocks_failed: 0,
        num_blocks_proposed: 1,
    }];

    for _ in 0..31 {
        set_icp_xdr_conversion_rate(&state_machine, payload.clone());

        tick_with_blockmaker_metrics(&state_machine, &node_metrics_daily);
        state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS));
        wait_for_nrc_metrics_sync(&state_machine);
    }

    let mut rewards_days = 30;

    let seconds_since_day_start =
        state_machine.get_time().as_secs_since_unix_epoch() % ONE_DAY_SECONDS;

    // If we are before the decimal point in REWARDS_TABLE_DAYS, rewarding period is of 31 days
    if (seconds_since_day_start as f64) < REWARDS_TABLE_DAYS % 30.0 * 24.0 * 3600.0 {
        rewards_days += 1;
    };
    // Call nns_get_node_provider_rewards assert the value is as expected
    let monthly_node_provider_rewards_result: Result<RewardNodeProviders, GovernanceError> =
        nns_get_node_provider_rewards(&state_machine);

    let monthly_node_provider_rewards = monthly_node_provider_rewards_result.unwrap();

    let reward_mode_1 = Some(RewardMode::RewardToAccount(RewardToAccount {
        to_account: Some(node_info_1.provider_account.into_proto_with_checksum()),
    }));
    let expected_rewards_e8s_1 =
        ((24_000.0 / REWARDS_TABLE_DAYS) as u64 * rewards_days * TOKEN_SUBDIVIDABLE_BY) / 155_000;
    let expected_node_provider_reward_1 = RewardNodeProvider {
        node_provider: Some(node_info_1.provider.clone()),
        amount_e8s: expected_rewards_e8s_1,
        reward_mode: reward_mode_1.clone(),
    };

    assert!(
        monthly_node_provider_rewards
            .rewards
            .contains(&expected_node_provider_reward_1)
    );

    // Assert account balances are 0
    assert_account_balance(&state_machine, node_info_1.provider_account, 0);

    // Assert there is no most recent monthly Node Provider reward
    let most_recent_rewards = nns_get_most_recent_monthly_node_provider_rewards(&state_machine);
    assert!(most_recent_rewards.is_none());

    // Submit and execute proposal to pay NPs via Proposal
    // From this moment rewards will be paid via automated monthly NP remuneration
    reward_node_providers_via_proposal(&state_machine);

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

    assert!(
        most_recent_rewards
            .rewards
            .contains(&expected_node_provider_reward_1)
    );

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

    let mut minted_rewards = vec![most_recent_rewards.clone()];

    let average_icp_xdr_conversion_rate_for_automated_rewards = 345_000;

    // Set a new average conversion rate so that we can assert that the automated monthly
    // NP rewards paid a different reward than the proposal-based reward.
    let current_timestamp_seconds = state_machine.get_time().as_secs_since_unix_epoch();
    let payload = UpdateIcpXdrConversionRatePayload {
        timestamp_seconds: current_timestamp_seconds,
        xdr_permyriad_per_icp: average_icp_xdr_conversion_rate_for_automated_rewards,
        ..Default::default()
    };

    let node_metrics_daily = vec![NodeMetricsDailyRaw {
        node_id,
        num_blocks_failed: 0,
        num_blocks_proposed: 1,
    }];

    for _ in 0..12 {
        // Assert that advancing time by a month triggers an automated monthly NP reward event
        // Cover 31 days of blockmaker metrics
        for _ in 0..31 {
            set_icp_xdr_conversion_rate(&state_machine, payload.clone());

            tick_with_blockmaker_metrics(&state_machine, &node_metrics_daily);

            state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS));

            wait_for_nrc_metrics_sync(&state_machine);
        }

        // Tick to allow Gov. to perform rewards minting
        state_machine.tick();
        state_machine.tick();

        let rewards = nns_get_most_recent_monthly_node_provider_rewards(&state_machine).unwrap();

        minted_rewards.push(rewards);
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
    let nns_subnet = subnet_test_id(TEST_ID);

    let state_machine = state_machine_builder_for_nns_tests()
        .with_nns_subnet_id(nns_subnet)
        .with_subnet_id(nns_subnet)
        .build();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .build();
    setup_nns_canisters_with_features(&state_machine, nns_init_payload, &[]);

    add_data_centers(&state_machine);

    add_node_rewards_table(&state_machine);
    let mut nodes: BTreeMap<PrincipalId, Vec<NodeId>> = BTreeMap::new();

    // Define the set of node operators and node providers
    let node_info_1 = NodeInfo::new(
        *TEST_USER1_PRINCIPAL,
        *TEST_USER2_PRINCIPAL,
        AccountIdentifier::from(*TEST_USER2_PRINCIPAL),
        None,
    );
    let node_operator_id_4 = *TEST_USER7_PRINCIPAL;

    let node_info_2 = NodeInfo::new(
        *TEST_USER3_PRINCIPAL,
        *TEST_USER4_PRINCIPAL,
        AccountIdentifier::from(*TEST_USER4_PRINCIPAL),
        None,
    );

    let node_info_3 = NodeInfo::new(
        *TEST_USER5_PRINCIPAL,
        *TEST_USER6_PRINCIPAL,
        AccountIdentifier::from(*TEST_USER7_PRINCIPAL),
        Some(AccountIdentifier::from(*TEST_USER7_PRINCIPAL)),
    );

    // Add Node Providers
    add_node_provider(&state_machine, node_info_1.provider.clone());
    add_node_provider(&state_machine, node_info_2.provider.clone());
    add_node_provider(&state_machine, node_info_3.provider.clone());

    // Add Node Operator 1
    let max_rewardable_nodes_1 = btreemap! { NodeRewardType::Type1.to_string() => 1 };
    add_node_operator(
        &state_machine,
        &node_info_1.operator_id,
        &node_info_1.provider_id,
        "AN1",
        max_rewardable_nodes_1,
        "0:0:0:0:0:0:0:0",
    );

    // Add Node Operator 4
    let rewardable_nodes_4 = btreemap! {
        NodeRewardType::Type1.to_string() => 2,
        NodeRewardType::Type3.to_string() => 1,
    };
    add_node_operator(
        &state_machine,
        &node_operator_id_4,
        &node_info_1.provider_id,
        "BC1",
        rewardable_nodes_4,
        "0:0:0:0:0:0:0:0",
    );

    // Add Nodes for Node Provider 1
    let np_1_nodes = vec![
        add_node(
            &state_machine,
            node_info_1.operator_id,
            1,
            NodeRewardType::Type1,
        ),
        add_node(&state_machine, node_operator_id_4, 2, NodeRewardType::Type1),
        add_node(&state_machine, node_operator_id_4, 3, NodeRewardType::Type1),
        add_node(&state_machine, node_operator_id_4, 4, NodeRewardType::Type3),
    ];

    nodes
        .entry(node_info_1.provider_id)
        .or_default()
        .extend(np_1_nodes);

    // Add Node Operator 2
    let max_rewardable_nodes_2 = btreemap! {
        NodeRewardType::Type1.to_string() => 3,
        NodeRewardType::Type3.to_string() => 1,
    };
    add_node_operator(
        &state_machine,
        &node_info_2.operator_id,
        &node_info_2.provider_id,
        "BC1",
        max_rewardable_nodes_2,
        "0:0:0:0:0:0:0:0",
    );

    // Add Nodes for Node Provider 2
    let np_2_nodes = vec![
        add_node(
            &state_machine,
            node_info_2.operator_id,
            5,
            NodeRewardType::Type1,
        ),
        add_node(
            &state_machine,
            node_info_2.operator_id,
            6,
            NodeRewardType::Type1,
        ),
        add_node(
            &state_machine,
            node_info_2.operator_id,
            7,
            NodeRewardType::Type1,
        ),
        add_node(
            &state_machine,
            node_info_2.operator_id,
            8,
            NodeRewardType::Type3,
        ),
    ];
    nodes
        .entry(node_info_2.provider_id)
        .or_default()
        .extend(np_2_nodes);

    // Add Node Operator 3
    let max_rewardable_nodes_3 = btreemap! {
        NodeRewardType::Type1.to_string() => 2,
        NodeRewardType::Type3.to_string() => 2,
        NodeRewardType::Type3dot1.to_string() => 3,
    };
    add_node_operator(
        &state_machine,
        &node_info_3.operator_id,
        &node_info_3.provider_id,
        "FM1",
        max_rewardable_nodes_3,
        "0:0:0:0:0:0:0:0",
    );

    // Add Nodes for Node Provider 3
    let np_3_nodes = vec![
        add_node(
            &state_machine,
            node_info_3.operator_id,
            9,
            NodeRewardType::Type1,
        ),
        add_node(
            &state_machine,
            node_info_3.operator_id,
            10,
            NodeRewardType::Type1,
        ),
        add_node(
            &state_machine,
            node_info_3.operator_id,
            11,
            NodeRewardType::Type3,
        ),
        add_node(
            &state_machine,
            node_info_3.operator_id,
            12,
            NodeRewardType::Type3,
        ),
        add_node(
            &state_machine,
            node_info_3.operator_id,
            13,
            NodeRewardType::Type3dot1,
        ),
        add_node(
            &state_machine,
            node_info_3.operator_id,
            14,
            NodeRewardType::Type3dot1,
        ),
        add_node(
            &state_machine,
            node_info_3.operator_id,
            15,
            NodeRewardType::Type3dot1,
        ),
    ];
    nodes
        .entry(node_info_3.provider_id)
        .or_default()
        .extend(np_3_nodes);

    // All success failure rate is 0
    let node_metrics_daily: Vec<NodeMetricsDailyRaw> = nodes
        .clone()
        .into_iter()
        .flat_map(|(_, node_ids)| {
            node_ids.into_iter().map(|node_id| NodeMetricsDailyRaw {
                node_id,
                num_blocks_failed: 0,
                num_blocks_proposed: 1,
            })
        })
        .collect();

    // Cover 31 days of blockmaker metrics to make sure we cover a full month 30 or 31 days
    for _ in 0..31 {
        // Set the conversion rate
        let current_timestamp_seconds = state_machine.get_time().as_secs_since_unix_epoch();
        let payload = UpdateIcpXdrConversionRatePayload {
            timestamp_seconds: current_timestamp_seconds,
            xdr_permyriad_per_icp: 155_000,
            ..Default::default()
        };

        set_icp_xdr_conversion_rate(&state_machine, payload.clone());

        tick_with_blockmaker_metrics(&state_machine, &node_metrics_daily);
        state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS));
        wait_for_nrc_metrics_sync(&state_machine);
    }

    // Call get_monthly_node_provider_rewards assert the value is as expected
    let monthly_node_provider_rewards_result: Result<RewardNodeProviders, GovernanceError> =
        nns_get_node_provider_rewards(&state_machine);

    let monthly_node_provider_rewards = monthly_node_provider_rewards_result.unwrap();
    assert_eq!(monthly_node_provider_rewards.rewards.len(), 3);

    // Calculate the number of reward days covered by the reward period it might be 30 or 31 days
    // depending on the time of the day the test is executed
    let now_seconds = state_machine.get_time().as_secs_since_unix_epoch();
    let full_days_count = NODE_PROVIDER_REWARD_PERIOD_SECONDS / ONE_DAY_SECONDS;
    let spill_over_seconds = NODE_PROVIDER_REWARD_PERIOD_SECONDS % ONE_DAY_SECONDS;

    let start_timestamp_1 = now_seconds - NODE_PROVIDER_REWARD_PERIOD_SECONDS;
    let end_timestamp_1 = now_seconds;
    let expected_reward_days_covered_1 =
        calculate_expected_rewards_days(start_timestamp_1, end_timestamp_1);

    let start_timestamp_2 = end_timestamp_1;
    let end_timestamp_2 = start_timestamp_2 + NODE_PROVIDER_REWARD_PERIOD_SECONDS;
    let expected_reward_days_covered_2 =
        calculate_expected_rewards_days(start_timestamp_2, end_timestamp_2);

    let start_timestamp_3 = end_timestamp_2;
    let end_timestamp_3 = start_timestamp_3 + NODE_PROVIDER_REWARD_PERIOD_SECONDS;
    let expected_reward_days_covered_3 =
        calculate_expected_rewards_days(start_timestamp_3, end_timestamp_3);

    // Rewards Table:
    // EU: Type 1: 24,000 XDR/month, Type 3: 35,000 XDR/month
    // North America, Canada: Type 1: 68,000 XDR/month, Type 3: 11,000 XDR/month
    // North America, US, CA: Type 1: 234,000 XDR/month, Type 3: 907,000 XDR/month, Type 3.1: 103,000 XDR/month
    let reward_mode_1 = Some(RewardMode::RewardToAccount(RewardToAccount {
        to_account: Some(node_info_1.provider_account.into_proto_with_checksum()),
    }));
    let expected_daily_rewards_e8s_1 =
        (((1.0 * 24_000.0) + (2.0 * 68_000.0) + (1.0 * 11_000.0)) / REWARDS_TABLE_DAYS) as u64;
    let expected_rewards_e8s_1 =
        expected_daily_rewards_e8s_1 * TOKEN_SUBDIVIDABLE_BY * expected_reward_days_covered_1
            / 155_000;
    assert_eq!(expected_rewards_e8s_1, 108735483);
    let expected_node_provider_reward_1 = RewardNodeProvider {
        node_provider: Some(node_info_1.provider.clone()),
        amount_e8s: expected_rewards_e8s_1,
        reward_mode: reward_mode_1.clone(),
    };
    assert!(
        monthly_node_provider_rewards
            .rewards
            .contains(&expected_node_provider_reward_1),
        "Expected reward 1: {expected_node_provider_reward_1:?} not found in monthly rewards: {monthly_node_provider_rewards:?}"
    );

    // Rewards Table:
    // EU: Type 1: 24,000 XDR/month, Type 3: 35,000 XDR/month
    // North America, Canada: Type 1: 68,000 XDR/month, Type 3: 11,000 XDR/month
    // North America, US, CA: Type 1: 234,000 XDR/month, Type 3: 907,000 XDR/month, Type 3.1: 103,000 XDR/month
    let reward_mode_2 = Some(RewardMode::RewardToAccount(RewardToAccount {
        to_account: Some(node_info_2.provider_account.into_proto_with_checksum()),
    }));
    let expected_daily_rewards_e8s_2 =
        (((3.0 * 68_000.0) + (1.0 * 11_000.0)) / REWARDS_TABLE_DAYS) as u64;
    let expected_rewards_e8s_2 =
        expected_daily_rewards_e8s_2 * TOKEN_SUBDIVIDABLE_BY * expected_reward_days_covered_1
            / 155_000;
    assert_eq!(expected_rewards_e8s_2, 136703225);
    let expected_node_provider_reward_2 = RewardNodeProvider {
        node_provider: Some(node_info_2.provider.clone()),
        amount_e8s: expected_rewards_e8s_2,
        reward_mode: reward_mode_2.clone(),
    };
    assert!(
        monthly_node_provider_rewards
            .rewards
            .contains(&expected_node_provider_reward_2),
        "Expected reward 2: {expected_node_provider_reward_2:?} not found in monthly rewards: {monthly_node_provider_rewards:?}"
    );

    // Rewards Table:
    // EU: Type 1: 24,000 XDR/month, Type 3: 35,000 XDR/month
    // North America, Canada: Type 1: 68,000 XDR/month, Type 3: 11,000 XDR/month
    // North America, US, CA: Type 1: 234,000 XDR/month, Type 3: 907,000 XDR/month, Type 3.1: 103,000 XDR/month

    // This node provider owns more than 1 Type3* node
    // Average reward rate will be applied for Type3* nodes
    let reward_mode_3 = Some(RewardMode::RewardToAccount(RewardToAccount {
        to_account: Some(node_info_3.provider.reward_account.clone().unwrap()),
    }));
    let average_type3_reward = (2.0 * 907_000.0 + 3.0 * 103_000.0) / 5.0;
    let average_type3_reduced_rewards = (average_type3_reward
        + 0.8 * average_type3_reward
        + 0.8 * 0.8 * average_type3_reward
        + 0.8 * 0.8 * 0.8 * average_type3_reward
        + 0.8 * 0.8 * 0.8 * 0.8 * average_type3_reward)
        / 5.0;

    let expected_daily_rewards_e8s_3 =
        (((2.0 * 234_000.0) + (5.0 * average_type3_reduced_rewards)) / REWARDS_TABLE_DAYS) as u64;
    let expected_rewards_e8s_3 =
        expected_daily_rewards_e8s_3 * TOKEN_SUBDIVIDABLE_BY * expected_reward_days_covered_1
            / 155_000;
    assert_eq!(expected_rewards_e8s_3, 1205206451);
    let expected_node_provider_reward_3 = RewardNodeProvider {
        node_provider: Some(node_info_3.provider.clone()),
        amount_e8s: expected_rewards_e8s_3,
        reward_mode: reward_mode_3.clone(),
    };

    assert!(
        monthly_node_provider_rewards
            .rewards
            .contains(&expected_node_provider_reward_3),
        "Expected reward 3: {expected_node_provider_reward_3:?} not found in monthly rewards: {monthly_node_provider_rewards:?}"
    );

    // Assert account balances are 0
    assert_account_balance(&state_machine, node_info_1.provider_account, 0);
    assert_account_balance(&state_machine, node_info_2.provider_account, 0);
    assert_account_balance(&state_machine, node_info_3.provider_account, 0);

    // Assert there is no most recent monthly Node Provider reward
    let most_recent_rewards = nns_get_most_recent_monthly_node_provider_rewards(&state_machine);
    assert!(most_recent_rewards.is_none());

    // --------------------------------------------------------
    // FIRST REWARD PERIOD VIA PROPOSAL
    // --------------------------------------------------------

    // Submit and execute proposal to pay NPs via Registry-driven rewards
    reward_node_providers_via_proposal(&state_machine);

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

    assert!(
        most_recent_rewards
            .rewards
            .contains(&expected_node_provider_reward_1)
    );
    assert!(
        most_recent_rewards
            .rewards
            .contains(&expected_node_provider_reward_2)
    );
    assert!(
        most_recent_rewards
            .rewards
            .contains(&expected_node_provider_reward_3)
    );

    // Assert advancing time less than a month doesn't trigger monthly NP rewards
    let mut rewards_were_triggered = false;
    let mut seconds_advanced_test_1 = 0;
    for _ in 0..5 {
        seconds_advanced_test_1 += 60;
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

    // --------------------------------------------------------
    // SECOND REWARD PERIOD VIA AUTOMATED REMUNERATION
    // --------------------------------------------------------

    // Set a new average conversion rate so that we can assert that the automated monthly
    // NP rewards paid a different reward than the proposal-based reward.
    let average_icp_xdr_conversion_rate_for_automated_rewards = 345_000;

    // All success failure rate is 0
    let node_metrics_daily: Vec<NodeMetricsDailyRaw> = nodes
        .clone()
        .into_iter()
        .flat_map(|(_, node_ids)| {
            node_ids.into_iter().map(|node_id| NodeMetricsDailyRaw {
                node_id,
                num_blocks_failed: 0,
                num_blocks_proposed: 1,
            })
        })
        .collect();

    // Cover full_days_count days of blockmaker metrics
    for _ in 0..full_days_count {
        let current_timestamp_seconds = state_machine.get_time().as_secs_since_unix_epoch();
        let payload = UpdateIcpXdrConversionRatePayload {
            timestamp_seconds: current_timestamp_seconds,
            xdr_permyriad_per_icp: average_icp_xdr_conversion_rate_for_automated_rewards,
            ..Default::default()
        };
        set_icp_xdr_conversion_rate(&state_machine, payload.clone());

        tick_with_blockmaker_metrics(&state_machine, &node_metrics_daily);
        state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS));
        wait_for_nrc_metrics_sync(&state_machine);
    }

    // Cover remaining seconds to complete the NODE_PROVIDER_REWARD_PERIOD_SECONDS
    tick_with_blockmaker_metrics(&state_machine, &node_metrics_daily);
    state_machine.advance_time(Duration::from_secs(
        spill_over_seconds - seconds_advanced_test_1,
    ));
    wait_for_nrc_metrics_sync(&state_machine);

    // Tick to allow Gov. to perform rewards minting
    state_machine.tick();
    state_machine.tick();

    let mut rewards_were_triggered = false;
    let mut np_rewards_from_automation_timestamp = most_recent_rewards.timestamp;
    let mut seconds_advanced_test_2 = 0;
    for _ in 0..10 {
        seconds_advanced_test_2 += 60;
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

    let expected_automated_rewards_e8s_1 =
        expected_daily_rewards_e8s_1 * TOKEN_SUBDIVIDABLE_BY * expected_reward_days_covered_2
            / average_icp_xdr_conversion_rate_for_automated_rewards;
    let expected_automated_node_provider_reward_1 = RewardNodeProvider {
        node_provider: Some(node_info_1.provider.clone()),
        amount_e8s: expected_automated_rewards_e8s_1,
        reward_mode: reward_mode_1.clone(),
    };

    let expected_automated_rewards_e8s_2 =
        expected_daily_rewards_e8s_2 * TOKEN_SUBDIVIDABLE_BY * expected_reward_days_covered_2
            / average_icp_xdr_conversion_rate_for_automated_rewards;
    let expected_automated_node_provider_reward_2 = RewardNodeProvider {
        node_provider: Some(node_info_2.provider.clone()),
        amount_e8s: expected_automated_rewards_e8s_2,
        reward_mode: reward_mode_2.clone(),
    };

    let expected_automated_rewards_e8s_3 =
        expected_daily_rewards_e8s_3 * TOKEN_SUBDIVIDABLE_BY * expected_reward_days_covered_2
            / average_icp_xdr_conversion_rate_for_automated_rewards;
    let expected_automated_node_provider_reward_3 = RewardNodeProvider {
        node_provider: Some(node_info_3.provider.clone()),
        amount_e8s: expected_automated_rewards_e8s_3,
        reward_mode: reward_mode_3.clone(),
    };

    assert!(
        most_recent_rewards
            .rewards
            .contains(&expected_automated_node_provider_reward_1)
    );

    assert!(
        most_recent_rewards
            .rewards
            .contains(&expected_automated_node_provider_reward_2)
    );

    assert!(
        most_recent_rewards
            .rewards
            .contains(&expected_automated_node_provider_reward_3)
    );

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

    // --------------------------------------------------------
    // THIRD REWARD PERIOD VIA AUTOMATED REMUNERATION
    // --------------------------------------------------------

    let actual_minimum_xdr_permyriad_per_icp = nns_get_network_economics_parameters(&state_machine)
        .minimum_icp_xdr_rate
        * NetworkEconomics::ICP_XDR_RATE_TO_BASIS_POINT_MULTIPLIER;

    // Set a new average conversion that is far below the `actual_minimum_xdr_permyriad_per_icp`
    // to trigger the limit.
    let average_icp_xdr_conversion_rate_for_automated_rewards = 1;

    // All success failure rate is 0
    let node_metrics_daily: Vec<NodeMetricsDailyRaw> = nodes
        .clone()
        .into_iter()
        .flat_map(|(_, node_ids)| {
            node_ids.into_iter().map(|node_id| NodeMetricsDailyRaw {
                node_id,
                num_blocks_failed: 0,
                num_blocks_proposed: 1,
            })
        })
        .collect();

    // Cover full_days_count days of blockmaker metrics to make sure we cover a full month 30 or 31 days
    for _ in 0..full_days_count {
        let current_timestamp_seconds = state_machine.get_time().as_secs_since_unix_epoch();

        let payload = UpdateIcpXdrConversionRatePayload {
            timestamp_seconds: current_timestamp_seconds,
            xdr_permyriad_per_icp: average_icp_xdr_conversion_rate_for_automated_rewards,
            ..Default::default()
        };
        set_icp_xdr_conversion_rate(&state_machine, payload);

        tick_with_blockmaker_metrics(&state_machine, &node_metrics_daily);
        state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS));
        wait_for_nrc_metrics_sync(&state_machine);
    }

    // Cover remaining seconds to complete the NODE_PROVIDER_REWARD_PERIOD_SECONDS
    tick_with_blockmaker_metrics(&state_machine, &node_metrics_daily);
    state_machine.advance_time(Duration::from_secs(
        spill_over_seconds - seconds_advanced_test_2,
    ));
    wait_for_nrc_metrics_sync(&state_machine);

    // Tick to allow Gov. to perform rewards minting
    state_machine.tick();
    state_machine.tick();

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

    ic_cdk::println!(
        "expected_reward_days_covered_3: {}",
        expected_reward_days_covered_3
    );
    let expected_automated_rewards_e8s_1 =
        expected_daily_rewards_e8s_1 * TOKEN_SUBDIVIDABLE_BY * expected_reward_days_covered_3
            / actual_minimum_xdr_permyriad_per_icp;

    let expected_automated_node_provider_reward_1 = RewardNodeProvider {
        node_provider: Some(node_info_1.provider),
        amount_e8s: expected_automated_rewards_e8s_1,
        reward_mode: reward_mode_1,
    };

    let expected_automated_rewards_e8s_2 =
        expected_daily_rewards_e8s_2 * TOKEN_SUBDIVIDABLE_BY * expected_reward_days_covered_3
            / actual_minimum_xdr_permyriad_per_icp;

    let expected_automated_node_provider_reward_2 = RewardNodeProvider {
        node_provider: Some(node_info_2.provider),
        amount_e8s: expected_automated_rewards_e8s_2,
        reward_mode: reward_mode_2,
    };

    let expected_automated_rewards_e8s_3 =
        expected_daily_rewards_e8s_3 * TOKEN_SUBDIVIDABLE_BY * expected_reward_days_covered_3
            / actual_minimum_xdr_permyriad_per_icp;

    let expected_automated_node_provider_reward_3 = RewardNodeProvider {
        node_provider: Some(node_info_3.provider),
        amount_e8s: expected_automated_rewards_e8s_3,
        reward_mode: reward_mode_3,
    };

    ic_cdk::println!(
        "Expected automated NP reward 1: {:?}",
        expected_automated_node_provider_reward_1
    );
    ic_cdk::println!("most recent rewards: {:?}", most_recent_rewards.rewards);

    assert!(
        most_recent_rewards
            .rewards
            .contains(&expected_automated_node_provider_reward_1)
    );

    assert!(
        most_recent_rewards
            .rewards
            .contains(&expected_automated_node_provider_reward_2)
    );

    assert!(
        most_recent_rewards
            .rewards
            .contains(&expected_automated_node_provider_reward_3)
    );
}

fn calculate_expected_rewards_days(
    start_rewards_timestamp: u64,
    end_rewards_timestamp: u64,
) -> u64 {
    let rewards_start_date = DateTime::from_timestamp(start_rewards_timestamp as i64, 0)
        .unwrap()
        .date_naive();
    let reward_end_date =
        DateTime::from_timestamp((end_rewards_timestamp - ONE_DAY_SECONDS) as i64, 0)
            .unwrap()
            .date_naive();
    (reward_end_date - rewards_start_date).num_days() as u64 + 1
}

// Helper function to add a node and return its NodeId
fn add_node(
    state_machine: &StateMachine,
    node_operator: PrincipalId,
    mutation_id: u8,
    node_type: NodeRewardType,
) -> NodeId {
    let (add_node_payload, _) = prepare_add_node_payload(mutation_id, node_type);
    state_machine
        .execute_ingress_as(
            node_operator,
            REGISTRY_CANISTER_ID,
            "add_node",
            Encode!(&add_node_payload).unwrap(),
        )
        .map(|result| Decode!(&result.bytes(), NodeId).unwrap())
        .unwrap()
}

// Helper function to wait until Node Rewards Canister has synced metrics for yesterday
fn wait_for_nrc_metrics_sync(state_machine: &StateMachine) {
    let now_yesterday = state_machine.get_time().as_secs_since_unix_epoch() - ONE_DAY_SECONDS;
    let request = GetNodeProvidersRewardsCalculationRequest {
        day: DateUtc::from_unix_timestamp_seconds(now_yesterday),
        algorithm_version: None,
    };

    // Tick until Node Rewards Canister has synced metrics for yesterday
    while query(
        state_machine,
        NODE_REWARDS_CANISTER_ID,
        "get_node_providers_rewards_calculation",
        Encode!(&request).unwrap(),
    )
    .map(|result| Decode!(&result, GetNodeProvidersRewardsCalculationResponse).unwrap())
    .unwrap()
    .is_err()
    {
        state_machine.tick();
    }
}

/// Helper function to tick the state machine with blockmaker metrics
fn tick_with_blockmaker_metrics(
    state_machine: &StateMachine,
    nodes_metrics: &[NodeMetricsDailyRaw],
) {
    let all_nodes: Vec<NodeId> = nodes_metrics
        .iter()
        .map(|n| NodeId::from(n.node_id))
        .collect();

    for nm in nodes_metrics {
        let node = NodeId::from(nm.node_id);

        // find fallback (different from this node)
        let fallback = all_nodes.iter().copied().find(|id| *id != node);

        // if this node fails even once but no fallback exists → invalid input
        if nm.num_blocks_failed > 0 && fallback.is_none() {
            panic!(
                "Node {:?} has {} failures but no fallback node exists.",
                nm.node_id, nm.num_blocks_failed
            );
        }

        let fallback = fallback.unwrap_or(node); // safe: fallback only used for failures

        // SUCCESS ROUNDS
        for _ in 0..nm.num_blocks_proposed {
            let metrics = BlockmakerMetrics {
                blockmaker: node,
                failed_blockmakers: vec![],
            };
            let payload = PayloadBuilder::new().with_blockmaker_metrics(metrics);
            state_machine.tick_with_config(payload);
        }

        // FAILURE ROUNDS
        for _ in 0..nm.num_blocks_failed {
            let metrics = BlockmakerMetrics {
                blockmaker: fallback,
                failed_blockmakers: vec![node],
            };
            let payload = PayloadBuilder::new().with_blockmaker_metrics(metrics);
            state_machine.tick_with_config(payload);
        }
    }
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
        response => panic!("Unexpected response returned from NNS governance: {response:?}"),
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
fn reward_node_providers_via_proposal(state_machine: &StateMachine) {
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
                "type1".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 24_000,
                    reward_coefficient_percent: None,
                },
                "type3".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 35_000,
                    reward_coefficient_percent: None,
                },
            }
        },
        "North America,Canada".to_string() =>  NodeRewardRates {
            rates: btreemap!{
                "type1".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 68_000,
                    reward_coefficient_percent: None,
                },
                "type3".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 11_000,
                    reward_coefficient_percent: None,
                },
            }
        },
        "North America,US,CA".to_string() =>  NodeRewardRates {
            rates: btreemap!{
                "type1".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 234_000,
                    reward_coefficient_percent: None,
                },
                "type3".to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 907_000,
                    reward_coefficient_percent: None,
                },
                "type3.1".to_string() => NodeRewardRate {
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
    max_rewardable_nodes: BTreeMap<String, u32>,
    ipv6: &str,
) {
    let payload = AddNodeOperatorPayload {
        node_operator_principal_id: Some(*no_id),
        node_allowance: 5,
        node_provider_principal_id: Some(*np_id),
        dc_id: dc_id.into(),
        rewardable_nodes: max_rewardable_nodes.clone(),
        ipv6: Some(ipv6.into()),
        max_rewardable_nodes: Some(max_rewardable_nodes),
    };

    submit_nns_proposal(
        state_machine,
        ProposalActionRequest::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::AssignNoid as i32,
            payload: Encode!(&payload).unwrap(),
        }),
    );
}
