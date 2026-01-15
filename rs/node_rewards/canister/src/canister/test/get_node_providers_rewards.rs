use crate::canister::NodeRewardsCanister;
use crate::canister::test::test_utils::{
    CANISTER_TEST, LAST_DAY_SYNCED, VM, setup_thread_local_canister_for_test,
};
use crate::chrono_utils::{last_unix_timestamp_nanoseconds, to_native_date};
use crate::metrics::MetricsManager;
use crate::pb::v1::{NodeMetrics, SubnetMetricsKey, SubnetMetricsValue};
use crate::storage::NaiveDateStorable;
use futures_util::FutureExt;
use ic_nervous_system_canisters::registry::fake::FakeRegistry;
use ic_node_rewards_canister_api::RewardsCalculationAlgorithmVersion;
use ic_node_rewards_canister_api::providers_rewards::{
    GetNodeProvidersRewardsRequest, NodeProvidersRewards,
};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::{
    NODE_REWARDS_TABLE_KEY, make_data_center_record_key, make_node_operator_record_key,
    make_node_record_key,
};
use ic_types::PrincipalId;
use maplit::btreemap;
use rewards_calculation::performance_based_algorithm::test_utils::{
    create_rewards_table_for_region_test, test_node_id, test_provider_id, test_subnet_id,
};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;

fn setup_data_for_test_rewards_calculation(
    fake_registry: Arc<FakeRegistry>,
    metrics_manager: Rc<MetricsManager<VM>>,
) {
    let day1 = to_native_date("2024-01-01");
    let day2 = to_native_date("2024-01-02");
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
        last_unix_timestamp_nanoseconds(&day2),
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
        last_unix_timestamp_nanoseconds(&day2),
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
        last_unix_timestamp_nanoseconds(&day2),
        None,
    );

    // Metrics
    let mut subnets_metrics = metrics_manager.subnets_metrics.borrow_mut();

    // Day 1 subnet 1
    subnets_metrics.insert(
        SubnetMetricsKey {
            timestamp_nanos: last_unix_timestamp_nanoseconds(&day1),
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
            timestamp_nanos: last_unix_timestamp_nanoseconds(&day1),
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
            timestamp_nanos: last_unix_timestamp_nanoseconds(&day2),
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
    LAST_DAY_SYNCED.with_borrow_mut(|cell| cell.set(Some(NaiveDateStorable(day2))).unwrap());
}

#[test]
fn test_get_node_providers_rewards() {
    use pretty_assertions::assert_eq;

    let (fake_registry, metrics_manager) = setup_thread_local_canister_for_test();
    setup_data_for_test_rewards_calculation(fake_registry, metrics_manager);
    NodeRewardsCanister::schedule_registry_sync(&CANISTER_TEST).now_or_never();
    let from = to_native_date("2024-01-01");
    let to = to_native_date("2024-01-02");

    let request = GetNodeProvidersRewardsRequest {
        from_day: from.into(),
        to_day: to.into(),
        algorithm_version: None,
    };
    let result_endpoint =
        NodeRewardsCanister::get_node_providers_rewards(&CANISTER_TEST, request.clone());

    let expected = NodeProvidersRewards {
        algorithm_version: RewardsCalculationAlgorithmVersion::default(),
        rewards_xdr_permyriad: btreemap! {
            test_provider_id(1).0 => 137200,
            test_provider_id(2).0 => 10000,
        },
    };
    assert_eq!(result_endpoint, Ok(expected));
}
