use ic_protobuf::registry::node_rewards::v2::NodeRewardRates;
use maplit::btreemap;
use pretty_assertions::assert_eq;
use std::str::FromStr;

use super::*;

#[test]
fn test_rewards_table() {
    let type1_xdr_permyriad_per_node_per_month = 16960000;
    run_rewards_table_with_type1_rewards_test(type1_xdr_permyriad_per_node_per_month);
}

#[test]
fn test_rewards_table_with_zero_type1_rewards() {
    let type1_xdr_permyriad_per_node_per_month = 0;
    run_rewards_table_with_type1_rewards_test(type1_xdr_permyriad_per_node_per_month);
}

/// Test type1 nodes because they are being deprecated, setting the corresponding rewards
/// to zero is part of that process.
/// Test type3 nodes because they involve more a complex calculation that all other types.
fn run_rewards_table_with_type1_rewards_test(type1_xdr_permyriad_per_node_per_month: u64) {
    let type3_xdr_permyriad_per_node_per_month = 27491250;

    let rewards_table = NodeRewardsTable {
        table: btreemap! {
            "Africa,ZA".to_string() => NodeRewardRates {
                rates: btreemap! {
                    "type3".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: type3_xdr_permyriad_per_node_per_month,
                        reward_coefficient_percent: Some(98),
                    }
                }
            },
            "Europe,CH".to_string() => NodeRewardRates {
                rates: btreemap! {
                    "type1".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: type1_xdr_permyriad_per_node_per_month,
                        reward_coefficient_percent: None,
                    }
                }
            }
        },
    };

    let node_operator_a_id = PrincipalId::from_str("djduj-3qcaa-aaaaa-aaaap-4ai").unwrap();
    let node_operator_b_id = PrincipalId::from_str("ykqw2-6tyam-aaaaa-aaaap-4ai").unwrap();

    let node_operators = [
        (
            "node_operator_a".to_string(),
            NodeOperatorRecord {
                node_operator_principal_id: PrincipalId::new_user_test_id(42).to_vec(),
                node_allowance: 0,
                node_provider_principal_id: node_operator_a_id.to_vec(),
                dc_id: "dc1".to_string(),
                rewardable_nodes: btreemap! {
                    "type3".to_string() => 3,
                },
                ipv6: None,
                max_rewardable_nodes: BTreeMap::new(),
            },
        ),
        (
            "node_operator_b".to_string(),
            NodeOperatorRecord {
                node_operator_principal_id: PrincipalId::new_user_test_id(44).to_vec(),
                node_allowance: 0,
                node_provider_principal_id: node_operator_b_id.to_vec(),
                dc_id: "dc2".to_string(),
                rewardable_nodes: btreemap! {
                    "type1".to_string() => 2,
                },
                ipv6: None,
                max_rewardable_nodes: BTreeMap::new(),
            },
        ),
    ];

    let data_centers = btreemap! {
        "dc1".to_string() => DataCenterRecord {
            id: "dc1".to_string(),
            region: "Africa,ZA".to_string(),
            owner: "David Bowie".to_string(),
            gps: None,
        },
        "dc2".to_string() => DataCenterRecord {
            id: "dc2".to_string(),
            region: "Europe,CH".to_string(),
            owner: "Taylor Swift".to_string(),
            gps: None,
        },
    };

    let result = calculate_rewards_v0(&rewards_table, &node_operators, &data_centers);

    let expected_node_operator_a_rewards = 80835271;
    // Smoke test - type3 adds fewer rewards to subsequent nodes.
    assert!(expected_node_operator_a_rewards < 3 * type3_xdr_permyriad_per_node_per_month);

    let expected_node_operator_b_rewards = 2 * type1_xdr_permyriad_per_node_per_month;

    assert_eq!(
        result,
        Ok(RewardsPerNodeProvider {
            rewards_per_node_provider: btreemap! {
                node_operator_a_id => expected_node_operator_a_rewards,
                node_operator_b_id => expected_node_operator_b_rewards,
            },
            computation_log: btreemap! {
                node_operator_a_id => RewardsPerNodeProviderLog {
                    node_provider_id: node_operator_a_id,
                    entries: vec![
                        LogEntry::NodeRewards {
                            node_type: "type3".to_string(),
                            node_idx: 0,
                            dc_id: "dc1".to_string(),
                            rewardable_count: 3,
                            rewards_xdr_permyriad: 27491250,
                        },
                        LogEntry::NodeRewards {
                            node_type: "type3".to_string(),
                            node_idx: 1,
                            dc_id: "dc1".to_string(),
                            rewardable_count: 3,
                            rewards_xdr_permyriad: 26941425,
                        },
                        LogEntry::NodeRewards {
                            node_type: "type3".to_string(),
                            node_idx: 2,
                            dc_id: "dc1".to_string(),
                            rewardable_count: 3,
                            rewards_xdr_permyriad: 26402596,
                        },
                        LogEntry::DCRewards {
                            dc_id: "dc1".to_string(),
                            node_type: "type3".to_string(),
                            rewardable_count: 3,
                            rewards_xdr_permyriad: expected_node_operator_a_rewards,
                        },
                    ]
                },
                node_operator_b_id => RewardsPerNodeProviderLog {
                    node_provider_id: node_operator_b_id,
                    entries: vec![
                        LogEntry::DCRewards {
                            dc_id: "dc2".to_string(),
                            node_type: "type1".to_string(),
                            rewardable_count: 2,
                            rewards_xdr_permyriad: expected_node_operator_b_rewards,
                        },
                    ]
                },
            }
        })
    );
}
