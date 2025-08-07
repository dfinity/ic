use crate::canister::test::test_utils::{
    setup_thread_local_canister_for_test, write_rewards_to_csv, TestState, CANISTER_TEST, VM,
};
use crate::canister::NodeRewardsCanister;
use crate::metrics::{ManagementCanisterClient, MetricsManager};
use crate::pb::v1::{NodeMetrics, SubnetMetricsKey, SubnetMetricsValue};
use candid::{CandidType, Decode};
use flate2::read::GzDecoder;
use futures_util::FutureExt;
use ic_cdk::api::call::{CallResult, RejectionCode};
use ic_management_canister_types::NodeMetricsHistoryRecord;
use ic_nervous_system_canisters::registry::fake::FakeRegistry;
use ic_node_rewards_canister_api::providers_rewards::{
    GetNodeProvidersRewardsRequest, NodeProvidersRewards,
};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_canister_client::StableCanisterRegistryClient;
use ic_registry_keys::{
    make_data_center_record_key, make_node_operator_record_key, make_node_record_key,
    NODE_REWARDS_TABLE_KEY,
};
use ic_registry_transport::pb::v1::RegistryDelta;
use ic_types::PrincipalId;
use indexmap::map::Entry;
use indexmap::IndexMap;
use maplit::btreemap;
use prost::Message;
use rewards_calculation::rewards_calculator::test_utils::{
    create_rewards_table_for_region_test, test_node_id, test_provider_id, test_subnet_id,
};
use rewards_calculation::rewards_calculator_results::{
    DayUtc, NodeStatus, RewardsCalculatorResults,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use tokio::fs;

fn setup_data_for_test_rewards_calculation(
    fake_registry: Arc<FakeRegistry>,
    metrics_manager: Rc<MetricsManager<VM>>,
) {
    let day1: DayUtc = "2024-01-01".into();
    let day2: DayUtc = "2024-01-02".into();
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
        day1.get(),
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
        day1.get(),
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
        day1.get(),
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

#[test]
fn test_get_node_providers_rewards() {
    let (fake_registry, metrics_manager) = setup_thread_local_canister_for_test();
    setup_data_for_test_rewards_calculation(fake_registry, metrics_manager);

    let request = GetNodeProvidersRewardsRequest {
        from: DayUtc::from("2024-01-01").get(),
        to: DayUtc::from("2024-01-02").get(),
    };
    let result_endpoint = NodeRewardsCanister::get_node_providers_rewards::<TestState>(
        &CANISTER_TEST,
        request.clone(),
    )
    .now_or_never()
    .unwrap();

    // Rewards Calculator Results
    //
    // +-Overall Performance for Provider: 6fyp7-3ibaa-aaaaa-aaaap-
    // | Day UTC    | Underperforming Nodes | Total Daily Rewards |
    // +------------+-----------------------+---------------------+
    // | 01-01-2024 | fnlpp                 | 87200.0000          |
    // |            | yskjz                 |                     |
    // +------------+-----------------------+---------------------+
    // | 02-01-2024 |                       | 50000               |
    // +------------+-----------------------+---------------------+
    //
    // Base Rewards Log:
    // Region: Europe,Switzerland, Type: type1, Base Rewards Daily: 10000, Coefficient: 0.80
    // Region: North America,USA,California, Type: type3, Base Rewards Daily: 30000, Coefficient: 0.90
    // Region: North America,USA,Nevada, Type: type3.1, Base Rewards Daily: 40000, Coefficient: 0.70
    // Type3* - Day: 01-01-2024 Region: North America:USA, Nodes Count: 2, Base Rewards Daily Avg: 35000, Coefficient Avg: 0.80, Base Rewards Daily: 31500.00
    // Type3* - Day: 02-01-2024 Region: North America:USA, Nodes Count: 1, Base Rewards Daily Avg: 30000, Coefficient Avg: 0.90, Base Rewards Daily: 30000
    //
    // +-NodeId: zv7tz-zylaa-aaaaa-aaaap-2ai-------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | Day UTC    | Status           | Subnet FR | Blocks Proposed/Failed | Original FR | FR relative/extrapolated | Performance Multiplier | Base Rewards | Adjusted Rewards |
    // +------------+------------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | 01-01-2024 | Assigned - yndj2 | 0.25      | 95/5                   | 0.05        | 0                        | 1                      | 10000        | 10000            |
    // +------------+------------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | 02-01-2024 | Assigned - yndj2 | 0.02      | 98/2                   | 0.02        | 0.00                     | 1                      | 10000        | 10000            |
    // +------------+------------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    //
    // +-NodeId: f6rsp-hqmaa-aaaaa-aaaap-2ai-------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | Day UTC    | Status           | Subnet FR | Blocks Proposed/Failed | Original FR | FR relative/extrapolated | Performance Multiplier | Base Rewards | Adjusted Rewards |
    // +------------+------------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | 01-01-2024 | Assigned - yndj2 | 0.25      | 90/10                  | 0.10        | 0                        | 1                      | 31500.00     | 31500.00         |
    // +------------+------------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | 02-01-2024 | Unassigned       | N/A       | N/A                    | N/A         | 0                        | 1                      | 30000        | 30000            |
    // +------------+------------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    //
    // +-NodeId: ybquz-ianaa-aaaaa-aaaap-2ai-------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | Day UTC    | Status           | Subnet FR | Blocks Proposed/Failed | Original FR | FR relative/extrapolated | Performance Multiplier | Base Rewards | Adjusted Rewards |
    // +------------+------------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | 01-01-2024 | Assigned - yndj2 | 0.25      | 75/25                  | 0.25        | 0.00                     | 1                      | 31500.00     | 31500.00         |
    // +------------+------------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    //
    // +-NodeId: fnlpp-iyoaa-aaaaa-aaaap-2ai-+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | Day UTC    | Status     | Subnet FR | Blocks Proposed/Failed | Original FR | FR relative/extrapolated | Performance Multiplier | Base Rewards | Adjusted Rewards |
    // +------------+------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | 01-01-2024 | Unassigned | N/A       | N/A                    | N/A         | 0.1125                   | 0.9800                 | 10000        | 9800.0000        |
    // +------------+------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | 02-01-2024 | Unassigned | N/A       | N/A                    | N/A         | 0                        | 1                      | 10000        | 10000            |
    // +------------+------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    //
    // +-NodeId: yskjz-hipaa-aaaaa-aaaap-2ai-------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | Day UTC    | Status           | Subnet FR | Blocks Proposed/Failed | Original FR | FR relative/extrapolated | Performance Multiplier | Base Rewards | Adjusted Rewards |
    // +------------+------------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | 01-01-2024 | Assigned - yndj2 | 0.25      | 30/70                  | 0.70        | 0.45                     | 0.44                   | 10000        | 4400.00          |
    // +------------+------------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    //
    // +-Overall Performance for Provider: djduj-3qcaa-aaaaa-aaaap-
    // | Day UTC    | Underperforming Nodes | Total Daily Rewards |
    // +------------+-----------------------+---------------------+
    // | 01-01-2024 |                       | 10000               |
    // +------------+-----------------------+---------------------+
    //
    // Base Rewards Log:
    // Region: Europe,Switzerland, Type: type1, Base Rewards Daily: 10000, Coefficient: 0.80
    //
    // +-NodeId: 6qmi3-pavaa-aaaaa-aaaap-2ai-------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | Day UTC    | Status           | Subnet FR | Blocks Proposed/Failed | Original FR | FR relative/extrapolated | Performance Multiplier | Base Rewards | Adjusted Rewards |
    // +------------+------------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+
    // | 01-01-2024 | Assigned - fbysm | 0.20      | 80/20                  | 0.20        | 0.00                     | 1                      | 10000        | 10000            |
    // +------------+------------------+-----------+------------------------+-------------+--------------------------+------------------------+--------------+------------------+

    let expected = NodeProvidersRewards {
        rewards_xdr_permyriad: btreemap! {
            test_provider_id(1).0 => 87200 + 50000,
            test_provider_id(2).0 => 10000,
        },
    };
    assert_eq!(result_endpoint.rewards, Some(expected));
}

pub async fn read_items(path: &str) -> Result<Vec<RegistryDelta>, Box<dyn std::error::Error>> {
    let data = fs::read(path).await?;
    let mut items = Vec::new();
    let mut buf = &data[..];

    while !buf.is_empty() {
        let item = RegistryDelta::decode_length_delimited(&mut buf)?;
        items.push(item);
    }

    Ok(items)
}

#[derive(Default, CandidType, candid::Deserialize)]
struct SubnetMetricsExport {
    metrics_by_subnet: BTreeMap<PrincipalId, Vec<NodeMetricsHistoryRecord>>,
}

#[test]
fn test_real() {
    let fake_registry = Arc::new(FakeRegistry::new());
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("canister")
        .join("test")
        .join("test_data")
        .join("registry");

    let mut file = File::open(&path).unwrap();
    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes).unwrap();
    let mut buf = &file_bytes[..];
    let mut registry = IndexMap::new();
    while !buf.is_empty() {
        let delta = RegistryDelta::decode_length_delimited(&mut buf).unwrap();

        for values in delta.values {
            let string_key = std::str::from_utf8(&delta.key[..]).unwrap().to_string();
            let value = if values.deletion_marker {
                None
            } else {
                Some(values.value)
            };

            match registry.get(&(
                string_key.clone(),
                values.version,
                values.timestamp_nanoseconds,
            )) {
                None => {}
                Some(existing) => {
                    let existing: &Option<Vec<u8>> = existing;
                    let record =
                        NodeOperatorRecord::decode(existing.clone().unwrap().as_slice()).unwrap();
                    println!("Duplicate {} {:?}", string_key.clone(), record)
                }
            }
            registry.insert(
                (string_key, values.version, values.timestamp_nanoseconds),
                value,
            );
        }
    }

    for ((string_key, version, timestamp_nanoseconds), value) in registry {
        fake_registry.set_value_at_version_with_timestamp(
            string_key,
            version,
            timestamp_nanoseconds,
            value,
        );
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("canister")
        .join("test")
        .join("test_data")
        .join("subnets_metrics_export.candid");
    let mut file = File::open(&path).unwrap();
    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes).unwrap();

    let mut buf = &file_bytes[..];
    let exported_metrics = Decode!(buf, SubnetMetricsExport).unwrap();
    let mut mock = crate::metrics::tests::mock::MockCanisterClient::new();
    mock.expect_node_metrics_history().returning(move |args| {
        match exported_metrics
            .metrics_by_subnet
            .get(&PrincipalId::from(args.subnet_id))
        {
            None => CallResult::Err((RejectionCode::Unknown, "Error".to_string())),
            Some(subnet_metrics) => CallResult::Ok(subnet_metrics.clone()),
        }
    });
    let metrics_manager = Rc::new(MetricsManager::new_test(mock));
    let canister = NodeRewardsCanister::new(
        Arc::new(StableCanisterRegistryClient::<TestState>::new(
            fake_registry,
        )),
        metrics_manager,
    );
    CANISTER_TEST.with_borrow_mut(|c| *c = canister);
    let request = GetNodeProvidersRewardsRequest {
        from: DayUtc::from("2025-06-14").get(),
        to: DayUtc::from("2025-07-13").get(),
    };

    println!("finished syncing");
    let result_endpoint = NodeRewardsCanister::get_node_providers_rewards::<TestState>(
        &CANISTER_TEST,
        request.clone(),
    )
    .now_or_never()
    .unwrap();
    let rewards_calculator_results: RewardsCalculatorResults = CANISTER_TEST
        .with_borrow(|canister| canister.calculate_rewards::<TestState>(request))
        .unwrap();

    write_rewards_to_csv(&rewards_calculator_results, "rewards_results")
        .expect("Failed to write rewards to CSV");
}
