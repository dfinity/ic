use crate::canister::test::test_utils::{
    setup_thread_local_canister_for_test, TestState, CANISTER_TEST, VM,
};
use crate::canister::NodeRewardsCanister;
use crate::metrics::MetricsManager;
use futures_util::FutureExt;
use ic_nervous_system_canisters::registry::fake::FakeRegistry;
use ic_node_rewards_canister_api::provider_rewards_calculation::GetNodeProviderRewardsCalculationRequest;
use ic_node_rewards_canister_api::providers_rewards::{
    GetNodeProvidersRewardsRequest, NodeProvidersRewards,
};
use ic_node_rewards_canister_protobuf::pb::ic_node_rewards::v1::{
    NodeMetrics, SubnetMetricsKey, SubnetMetricsValue,
};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::{
    make_data_center_record_key, make_node_operator_record_key, make_node_record_key,
    NODE_REWARDS_TABLE_KEY,
};
use ic_types::PrincipalId;
use maplit::btreemap;
use rewards_calculation::rewards_calculator::test_utils::{
    create_rewards_table_for_region_test, test_node_id, test_provider_id, test_subnet_id,
};
use rewards_calculation::rewards_calculator_results::NodeProviderRewards;
use rewards_calculation::types::DayUtc;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;

fn setup_data_for_test_rewards_calculation(
    fake_registry: Arc<FakeRegistry>,
    metrics_manager: Rc<MetricsManager<VM>>,
) {
    let day1: DayUtc = DayUtc::try_from("2024-01-01").unwrap();
    let day2: DayUtc = DayUtc::try_from("2024-01-02").unwrap();
    let subnet1 = test_subnet_id(1);
    let subnet2 = test_subnet_id(2);
    let p1 = test_provider_id(1);
    let p2 = test_provider_id(2);

    // Provider 1 nodes
    let p1_node1_t1 = test_node_id(11); // Type1, CH, in Subnet1 on D1, D2
    let p1_node2_t3 = test_node_id(12); // Type3, CA, in Subnet1 on D1, unassigned D2
    let p1_node3_t31 = test_node_id(13); // Type3.1, NV, in Subnet1 on D1 only
    let p1_node4_unassigned = test_node_id(14); // Always unassigned
    let p1_node5_perf = test_node_id(15); // In Subnet1 on D1, bad performance

    // Provider 2 nodes
    let p2_node1 = test_node_id(21); // In Subnet2 on D1

    let rewards_table = create_rewards_table_for_region_test();
    fake_registry.encode_value_at_version(NODE_REWARDS_TABLE_KEY, 3, Some(rewards_table));

    // Node Operators
    let node_operator_a_id = PrincipalId::from_str("djduj-3qcaa-aaaaa-aaaap-4ai").unwrap();
    let node_operator_b_id = PrincipalId::from_str("ykqw2-6tyam-aaaaa-aaaap-4ai").unwrap();
    let node_operator_c_id = PrincipalId::from_str("jpjxp-djmaa-aaaaa-aaaap-4ai").unwrap();
    let node_operator_d_id = PrincipalId::from_str("qsgjb-riaaa-aaaaa-aaaga-cai").unwrap();

    fake_registry.encode_value_at_version(
        make_node_operator_record_key(node_operator_a_id),
        2,
        Some(NodeOperatorRecord {
            node_operator_principal_id: node_operator_a_id.to_vec(),
            node_allowance: 0,
            node_provider_principal_id: p1.to_vec(),
            dc_id: "dc1".to_string(),
            rewardable_nodes: btreemap! {
                "type1".to_string() => 3,
            },
            ipv6: None,
            max_rewardable_nodes: Default::default(),
        }),
    );

    fake_registry.encode_value_at_version(
        make_node_operator_record_key(node_operator_b_id),
        3,
        Some(NodeOperatorRecord {
            node_operator_principal_id: node_operator_b_id.to_vec(),
            node_allowance: 0,
            node_provider_principal_id: p1.to_vec(),
            dc_id: "dc2".to_string(),
            rewardable_nodes: btreemap! {
                "type3".to_string() => 1,
            },
            ipv6: None,
            max_rewardable_nodes: Default::default(),
        }),
    );

    fake_registry.encode_value_at_version(
        make_node_operator_record_key(node_operator_c_id),
        4,
        Some(NodeOperatorRecord {
            node_operator_principal_id: node_operator_c_id.to_vec(),
            node_allowance: 0,
            node_provider_principal_id: p1.to_vec(),
            dc_id: "dc3".to_string(),
            rewardable_nodes: btreemap! {
                "type3.1".to_string() => 1,
            },
            ipv6: None,
            max_rewardable_nodes: Default::default(),
        }),
    );

    fake_registry.encode_value_at_version(
        make_node_operator_record_key(node_operator_d_id),
        4,
        Some(NodeOperatorRecord {
            node_operator_principal_id: node_operator_d_id.to_vec(),
            node_allowance: 0,
            node_provider_principal_id: p2.to_vec(),
            dc_id: "dc1".to_string(),
            rewardable_nodes: btreemap! {
                "type1".to_string() => 1,
            },
            ipv6: None,
            max_rewardable_nodes: Default::default(),
        }),
    );

    // Data Centers

    fake_registry.encode_value_at_version(
        make_data_center_record_key("dc1"),
        1,
        Some(DataCenterRecord {
            id: "dc1".to_string(),
            region: "Europe,Switzerland".into(),
            owner: "David Bowie".to_string(),
            gps: None,
        }),
    );

    fake_registry.encode_value_at_version(
        make_data_center_record_key("dc2"),
        4,
        Some(DataCenterRecord {
            id: "dc2".to_string(),
            region: "North America,USA,California".into(),
            owner: "Taylor Swift".to_string(),
            gps: None,
        }),
    );

    fake_registry.encode_value_at_version(
        make_data_center_record_key("dc3"),
        4,
        Some(DataCenterRecord {
            id: "dc3".to_string(),
            region: "North America,USA,Nevada".into(),
            owner: "Pietro Di Marco".to_string(),
            gps: None,
        }),
    );

    // Nodes

    fake_registry.encode_value_at_version(
        make_node_record_key(p1_node1_t1),
        5,
        Some(NodeRecord {
            node_operator_id: node_operator_a_id.to_vec(),
            node_reward_type: Some(NodeRewardType::Type1 as i32),
            ..Default::default()
        }),
    );

    fake_registry.encode_value_at_version(
        make_node_record_key(p1_node2_t3),
        5,
        Some(NodeRecord {
            node_operator_id: node_operator_b_id.to_vec(),
            node_reward_type: Some(NodeRewardType::Type3 as i32),
            ..Default::default()
        }),
    );

    fake_registry.encode_value_at_version(
        make_node_record_key(p1_node3_t31),
        5,
        Some(NodeRecord {
            node_operator_id: node_operator_c_id.to_vec(),
            node_reward_type: Some(NodeRewardType::Type3dot1 as i32),
            ..Default::default()
        }),
    );
    // p1_node3_t31 stops being rewardable on day1
    fake_registry.set_value_at_version_with_timestamp(
        make_node_record_key(p1_node3_t31),
        6,
        day2.get(),
        None,
    );

    fake_registry.encode_value_at_version(
        make_node_record_key(p1_node4_unassigned),
        5,
        Some(NodeRecord {
            node_operator_id: node_operator_a_id.to_vec(),
            node_reward_type: Some(NodeRewardType::Type1 as i32),
            ..Default::default()
        }),
    );
    fake_registry.encode_value_at_version(
        make_node_record_key(p1_node5_perf),
        5,
        Some(NodeRecord {
            node_operator_id: node_operator_a_id.to_vec(),
            node_reward_type: Some(NodeRewardType::Type1 as i32),
            ..Default::default()
        }),
    );
    // p1_node5_perf stops being rewardable on day1
    fake_registry.set_value_at_version_with_timestamp(
        make_node_record_key(p1_node5_perf),
        6,
        day2.get(),
        None,
    );

    fake_registry.encode_value_at_version(
        make_node_record_key(p2_node1),
        5,
        Some(NodeRecord {
            node_operator_id: node_operator_d_id.to_vec(),
            node_reward_type: Some(NodeRewardType::Type1 as i32),
            ..Default::default()
        }),
    );
    // p1_node5_perf stops being rewardable on day1
    fake_registry.set_value_at_version_with_timestamp(
        make_node_record_key(p2_node1),
        6,
        day2.get(),
        None,
    );

    // Metrics
    let mut subnets_metrics = metrics_manager.subnets_metrics.borrow_mut();

    // Day 1 subnet 1
    subnets_metrics.insert(
        SubnetMetricsKey {
            timestamp_nanos: day1.unix_ts_at_day_end(),
            subnet_id: Some(subnet1.get()),
        },
        SubnetMetricsValue {
            nodes_metrics: vec![
                NodeMetrics {
                    node_id: Some(p1_node1_t1.get()),
                    num_blocks_proposed_total: 95,
                    num_blocks_failed_total: 5,
                },
                NodeMetrics {
                    node_id: Some(p1_node2_t3.get()),
                    num_blocks_proposed_total: 90,
                    num_blocks_failed_total: 10,
                },
                NodeMetrics {
                    node_id: Some(p1_node3_t31.get()),
                    num_blocks_proposed_total: 75,
                    num_blocks_failed_total: 25,
                },
                NodeMetrics {
                    node_id: Some(p1_node5_perf.get()),
                    num_blocks_proposed_total: 30,
                    num_blocks_failed_total: 70,
                },
            ],
        },
    );

    // Day 1 subnet 2
    subnets_metrics.insert(
        SubnetMetricsKey {
            timestamp_nanos: day1.unix_ts_at_day_end(),
            subnet_id: Some(subnet2.get()),
        },
        SubnetMetricsValue {
            nodes_metrics: vec![NodeMetrics {
                node_id: Some(p2_node1.get()),
                num_blocks_proposed_total: 80,
                num_blocks_failed_total: 20,
            }],
        },
    );

    // Day 2 subnet 1
    subnets_metrics.insert(
        SubnetMetricsKey {
            timestamp_nanos: day2.unix_ts_at_day_end(),
            subnet_id: Some(subnet1.get()),
        },
        SubnetMetricsValue {
            nodes_metrics: vec![NodeMetrics {
                node_id: Some(p1_node1_t1.get()),
                num_blocks_proposed_total: 193,
                num_blocks_failed_total: 7,
            }],
        },
    );
}

const EXPECTED_TEST_1: &str = r#"{
  "6fyp7-3ibaa-aaaaa-aaaap-4ai": {
    "rewards_total_xdr_permyriad": 137200,
    "base_rewards": [
      {
        "node_reward_type": "Type1",
        "region": "Europe,Switzerland",
        "monthly": "304375",
        "daily": "10000"
      },
      {
        "node_reward_type": "Type3",
        "region": "North America,USA,California",
        "monthly": "913125",
        "daily": "30000"
      },
      {
        "node_reward_type": "Type3dot1",
        "region": "North America,USA,Nevada",
        "monthly": "1217500",
        "daily": "40000"
      }
    ],
    "base_rewards_type3": [
      {
        "day": {
          "value": 1704153599999999999
        },
        "region": "North America:USA",
        "nodes_count": 2,
        "avg_rewards": "35000",
        "avg_coefficient": "0.80",
        "value": "31500.00"
      },
      {
        "day": {
          "value": 1704239999999999999
        },
        "region": "North America:USA",
        "nodes_count": 1,
        "avg_rewards": "30000",
        "avg_coefficient": "0.90",
        "value": "30000"
      }
    ],
    "nodes_results": [
      {
        "node_id": "zv7tz-zylaa-aaaaa-aaaap-2ai",
        "node_reward_type": "Type1",
        "region": "Europe,Switzerland",
        "dc_id": "dc1",
        "daily_results": [
          {
            "day": {
              "value": 1704153599999999999
            },
            "node_status": {
              "Assigned": {
                "node_metrics": {
                  "subnet_assigned": "yndj2-3ybaa-aaaaa-aaaap-yai",
                  "subnet_assigned_fr": "0.25",
                  "num_blocks_proposed": 95,
                  "num_blocks_failed": 5,
                  "original_fr": "0.05",
                  "relative_fr": "0"
                }
              }
            },
            "performance_multiplier": "1",
            "rewards_reduction": "0",
            "base_rewards": "10000",
            "adjusted_rewards": "10000"
          },
          {
            "day": {
              "value": 1704239999999999999
            },
            "node_status": {
              "Assigned": {
                "node_metrics": {
                  "subnet_assigned": "yndj2-3ybaa-aaaaa-aaaap-yai",
                  "subnet_assigned_fr": "0.02",
                  "num_blocks_proposed": 98,
                  "num_blocks_failed": 2,
                  "original_fr": "0.02",
                  "relative_fr": "0.00"
                }
              }
            },
            "performance_multiplier": "1",
            "rewards_reduction": "0",
            "base_rewards": "10000",
            "adjusted_rewards": "10000"
          }
        ]
      },
      {
        "node_id": "f6rsp-hqmaa-aaaaa-aaaap-2ai",
        "node_reward_type": "Type3",
        "region": "North America,USA,California",
        "dc_id": "dc2",
        "daily_results": [
          {
            "day": {
              "value": 1704153599999999999
            },
            "node_status": {
              "Assigned": {
                "node_metrics": {
                  "subnet_assigned": "yndj2-3ybaa-aaaaa-aaaap-yai",
                  "subnet_assigned_fr": "0.25",
                  "num_blocks_proposed": 90,
                  "num_blocks_failed": 10,
                  "original_fr": "0.10",
                  "relative_fr": "0"
                }
              }
            },
            "performance_multiplier": "1",
            "rewards_reduction": "0",
            "base_rewards": "31500.00",
            "adjusted_rewards": "31500.00"
          },
          {
            "day": {
              "value": 1704239999999999999
            },
            "node_status": {
              "Unassigned": {
                "extrapolated_fr": "0"
              }
            },
            "performance_multiplier": "1",
            "rewards_reduction": "0",
            "base_rewards": "30000",
            "adjusted_rewards": "30000"
          }
        ]
      },
      {
        "node_id": "ybquz-ianaa-aaaaa-aaaap-2ai",
        "node_reward_type": "Type3dot1",
        "region": "North America,USA,Nevada",
        "dc_id": "dc3",
        "daily_results": [
          {
            "day": {
              "value": 1704153599999999999
            },
            "node_status": {
              "Assigned": {
                "node_metrics": {
                  "subnet_assigned": "yndj2-3ybaa-aaaaa-aaaap-yai",
                  "subnet_assigned_fr": "0.25",
                  "num_blocks_proposed": 75,
                  "num_blocks_failed": 25,
                  "original_fr": "0.25",
                  "relative_fr": "0.00"
                }
              }
            },
            "performance_multiplier": "1",
            "rewards_reduction": "0",
            "base_rewards": "31500.00",
            "adjusted_rewards": "31500.00"
          }
        ]
      },
      {
        "node_id": "fnlpp-iyoaa-aaaaa-aaaap-2ai",
        "node_reward_type": "Type1",
        "region": "Europe,Switzerland",
        "dc_id": "dc1",
        "daily_results": [
          {
            "day": {
              "value": 1704153599999999999
            },
            "node_status": {
              "Unassigned": {
                "extrapolated_fr": "0.1125"
              }
            },
            "performance_multiplier": "0.9800",
            "rewards_reduction": "0.0200",
            "base_rewards": "10000",
            "adjusted_rewards": "9800.0000"
          },
          {
            "day": {
              "value": 1704239999999999999
            },
            "node_status": {
              "Unassigned": {
                "extrapolated_fr": "0"
              }
            },
            "performance_multiplier": "1",
            "rewards_reduction": "0",
            "base_rewards": "10000",
            "adjusted_rewards": "10000"
          }
        ]
      },
      {
        "node_id": "yskjz-hipaa-aaaaa-aaaap-2ai",
        "node_reward_type": "Type1",
        "region": "Europe,Switzerland",
        "dc_id": "dc1",
        "daily_results": [
          {
            "day": {
              "value": 1704153599999999999
            },
            "node_status": {
              "Assigned": {
                "node_metrics": {
                  "subnet_assigned": "yndj2-3ybaa-aaaaa-aaaap-yai",
                  "subnet_assigned_fr": "0.25",
                  "num_blocks_proposed": 30,
                  "num_blocks_failed": 70,
                  "original_fr": "0.70",
                  "relative_fr": "0.45"
                }
              }
            },
            "performance_multiplier": "0.44",
            "rewards_reduction": "0.56",
            "base_rewards": "10000",
            "adjusted_rewards": "4400.00"
          }
        ]
      }
    ]
  },
  "djduj-3qcaa-aaaaa-aaaap-4ai": {
    "rewards_total_xdr_permyriad": 10000,
    "base_rewards": [
      {
        "node_reward_type": "Type1",
        "region": "Europe,Switzerland",
        "monthly": "304375",
        "daily": "10000"
      }
    ],
    "base_rewards_type3": [],
    "nodes_results": [
      {
        "node_id": "6qmi3-pavaa-aaaaa-aaaap-2ai",
        "node_reward_type": "Type1",
        "region": "Europe,Switzerland",
        "dc_id": "dc1",
        "daily_results": [
          {
            "day": {
              "value": 1704153599999999999
            },
            "node_status": {
              "Assigned": {
                "node_metrics": {
                  "subnet_assigned": "fbysm-3acaa-aaaaa-aaaap-yai",
                  "subnet_assigned_fr": "0.20",
                  "num_blocks_proposed": 80,
                  "num_blocks_failed": 20,
                  "original_fr": "0.20",
                  "relative_fr": "0.00"
                }
              }
            },
            "performance_multiplier": "1",
            "rewards_reduction": "0",
            "base_rewards": "10000",
            "adjusted_rewards": "10000"
          }
        ]
      }
    ]
  }
}"#;
#[test]
fn test_get_node_providers_rewards() {
    use pretty_assertions::assert_eq;

    let (fake_registry, metrics_manager) = setup_thread_local_canister_for_test();
    setup_data_for_test_rewards_calculation(fake_registry, metrics_manager);
    let from = DayUtc::try_from("2024-01-01").unwrap();
    let to = DayUtc::try_from("2024-01-02").unwrap();

    let request = GetNodeProvidersRewardsRequest {
        from_nanos: from.unix_ts_at_day_start(),
        to_nanos: to.unix_ts_at_day_end(),
    };
    let result_endpoint = NodeRewardsCanister::get_node_providers_rewards::<TestState>(
        &CANISTER_TEST,
        request.clone(),
    )
    .now_or_never()
    .unwrap();

    let inner_results = CANISTER_TEST
        .with_borrow(|canister| canister.calculate_rewards::<TestState>(request))
        .unwrap();
    let expected: BTreeMap<PrincipalId, NodeProviderRewards> =
        serde_json::from_str(EXPECTED_TEST_1).unwrap();
    assert_eq!(inner_results.provider_results, expected);

    let expected = NodeProvidersRewards {
        rewards_xdr_permyriad: btreemap! {
            test_provider_id(1).0 => 137200,
            test_provider_id(2).0 => 10000,
        },
    };
    assert_eq!(result_endpoint, Ok(expected));
}

#[test]
fn test_get_node_provider_rewards_calculation_historical() {
    use pretty_assertions::assert_eq;

    let (fake_registry, metrics_manager) = setup_thread_local_canister_for_test();
    setup_data_for_test_rewards_calculation(fake_registry, metrics_manager);
    let from = DayUtc::try_from("2024-01-01").unwrap();
    let to = DayUtc::try_from("2024-01-02").unwrap();

    let request = GetNodeProvidersRewardsRequest {
        from_nanos: from.unix_ts_at_day_end(),
        to_nanos: to.unix_ts_at_day_end(),
    };

    // Invoke to populate historical rewards
    let _ = NodeRewardsCanister::get_node_providers_rewards::<TestState>(
        &CANISTER_TEST,
        request.clone(),
    )
    .now_or_never()
    .unwrap();

    let expected: BTreeMap<PrincipalId, NodeProviderRewards> =
        serde_json::from_str(EXPECTED_TEST_1).unwrap();

    for (provider_id, expected_rewards) in expected {
        let request = GetNodeProviderRewardsCalculationRequest {
            from_nanos: from.unix_ts_at_day_end(),
            to_nanos: to.unix_ts_at_day_end(),
            provider_id: provider_id.0,
        };

        let got = NodeRewardsCanister::get_node_provider_rewards_calculation::<TestState>(
            &CANISTER_TEST,
            request,
        )
        .unwrap();

        assert_eq!(
            got,
            expected_rewards.into(),
            "Mismatch for provider {:?}",
            provider_id
        );
    }
}
